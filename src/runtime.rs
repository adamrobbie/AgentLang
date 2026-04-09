use crate::ast::*;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{timeout, Duration, sleep};
use async_recursion::async_recursion;
use std::fs;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use rand::RngCore;
use bastion::prelude::*;
use tokio::sync::{oneshot, broadcast, mpsc};

pub struct Identity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self { signing_key, verifying_key }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub name: String,
    pub data: AnnotatedValue,
}

pub struct Context {
    pub working_variables: HashMap<String, AnnotatedValue>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_file: String,
    pub identity: Identity,
    pub active_contracts: HashMap<String, ContractInfo>,
    pub event_tx: broadcast::Sender<Event>,
}

#[derive(Clone)]
pub struct ContractInfo {
    pub issued_by: String,
    pub capabilities: Vec<Permission>,
    pub expires: Option<f64>,
}

impl Context {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            working_variables: HashMap::new(),
            session_variables: Arc::new(Mutex::new(HashMap::new())),
            long_term_file: "memory.json".to_string(),
            identity: Identity::generate(),
            active_contracts: HashMap::new(),
            event_tx,
        }
    }

    pub fn get_variable(&self, name: &str, scope: MemoryScope) -> Result<AnnotatedValue> {
        match scope {
            MemoryScope::Working => self.working_variables.get(name).cloned().ok_or_else(|| anyhow!("Not found")),
            MemoryScope::Session => self.session_variables.lock().unwrap().get(name).cloned().ok_or_else(|| anyhow!("Not found")),
            MemoryScope::LongTerm => {
                let memory = self.load_long_term()?;
                memory.get(name).cloned().ok_or_else(|| anyhow!("Not found"))
            },
            _ => Err(anyhow!("Scope not implemented")),
        }
    }

    pub fn set_variable(&mut self, name: String, value: AnnotatedValue, scope: MemoryScope) -> Result<()> {
        match scope {
            MemoryScope::Working => { self.working_variables.insert(name, value); },
            MemoryScope::Session => { self.session_variables.lock().unwrap().insert(name, value); },
            MemoryScope::LongTerm => {
                let mut memory = self.load_long_term()?;
                memory.insert(name, value);
                self.save_long_term(memory)?;
            },
            _ => return Err(anyhow!("Scope not implemented")),
        }
        Ok(())
    }

    fn load_long_term(&self) -> Result<HashMap<String, AnnotatedValue>> {
        if let Ok(data) = fs::read_to_string(&self.long_term_file) {
            Ok(serde_json::from_str(&data)?)
        } else { Ok(HashMap::new()) }
    }

    fn save_long_term(&self, memory: HashMap<String, AnnotatedValue>) -> Result<()> {
        let data = serde_json::to_string_pretty(&memory)?;
        fs::write(&self.long_term_file, data)?;
        Ok(())
    }
}

pub fn eval_expression(expr: &Expression, ctx: &Context) -> Result<AnnotatedValue> {
    match expr {
        Expression::Literal(val) => Ok(val.clone()),
        Expression::VariableRef(name) => ctx.get_variable(name, MemoryScope::Working),
        Expression::Annotated { expr, annotation } => {
            let mut val = eval_expression(expr, ctx)?;
            match annotation {
                Annotation::Confidence => val.confidence = Some(1.0),
                Annotation::Sensitive => val.is_sensitive = true,
                Annotation::Uncertain => val.is_uncertain = true,
                Annotation::Approximate => val.is_approximate = true,
            }
            Ok(val)
        }
    }
}

#[async_recursion]
pub async fn eval(statement: &Statement, ctx_arc: Arc<Mutex<Context>>) -> Result<()> {
    match statement {
        Statement::Goal { name, body, retry, on_fail, deadline } => {
            println!("--- Goal: {} (Supervised) ---", name);
            let retry_count = retry.unwrap_or(0);
            let body_clone = body.clone();
            let ctx_clone = ctx_arc.clone();
            let deadline_clone = *deadline;
            let name_clone = name.clone();

            let (tx, rx) = oneshot::channel();
            let tx_arc = Arc::new(Mutex::new(Some(tx)));
            let restart_strategy = RestartStrategy::default().with_restart_policy(RestartPolicy::Tries(retry_count));

            let _ = Bastion::supervisor(move |sp| {
                sp.with_restart_strategy(restart_strategy).children(|ch| {
                    let body = body_clone.clone();
                    let ctx = ctx_clone.clone();
                    let name = name_clone.clone();
                    let tx_arc = tx_arc.clone();
                    ch.with_exec(move |_| {
                        let body = body.clone();
                        let ctx = ctx.clone();
                        let name = name.clone();
                        let tx_arc = tx_arc.clone();
                        async move {
                            let body_fut = async {
                                for stmt in body { eval(&stmt, ctx.clone()).await?; }
                                Ok::<(), anyhow::Error>(())
                            };
                            let res = if let Some(secs) = deadline_clone {
                                match timeout(Duration::from_secs_f64(secs), body_fut).await {
                                    Ok(res) => res,
                                    Err(_) => Err(anyhow!("Timeout")),
                                }
                            } else { body_fut.await };
                            let mut lock = tx_arc.lock().unwrap();
                            if let Some(chan) = lock.take() { let _ = chan.send(res); }
                            Ok::<(), ()>(())
                        }
                    })
                })
            });

            match rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => {
                    if let Some(fallback) = on_fail {
                        println!("  Fallback for {}", name);
                        eval(fallback, ctx_arc.clone()).await?;
                        Ok(())
                    } else { Err(e) }
                }
                Err(_) => Err(anyhow!("Aborted")),
            }
        }
        Statement::Set { name, value } => {
            let mut ctx = ctx_arc.lock().unwrap();
            let val = eval_expression(value, &ctx)?;
            ctx.set_variable(name.clone(), val, MemoryScope::Working)?;
            Ok(())
        }
        Statement::If { condition, then_branch, else_branch } => {
            let is_true = {
                let ctx = ctx_arc.lock().unwrap();
                let cond = eval_expression(condition, &ctx)?;
                match cond.value { Value::Boolean(b) => b, Value::Number(n) => n != 0.0, Value::Text(s) => !s.is_empty() }
            };
            if is_true { for stmt in then_branch { eval(stmt, ctx_arc.clone()).await?; } }
            else if let Some(branch) = else_branch { for stmt in branch { eval(stmt, ctx_arc.clone()).await?; } }
            Ok(())
        }
        Statement::UseTool { tool_name, args: _, result_into } => {
            if tool_name == "fail_tool" { return Err(anyhow!("Fail")); }
            let mock_result = AnnotatedValue::from(Value::Text(format!("Result from {}", tool_name)));
            ctx_arc.lock().unwrap().set_variable(result_into.clone(), mock_result, MemoryScope::Working)?;
            Ok(())
        }
        Statement::Parallel { pattern, branches, result_into, deadline } => {
            println!("--- Parallel ({:?}) ---", pattern);
            let (tx, mut rx) = mpsc::channel(branches.len().max(1));
            
            for stmt in branches {
                let stmt = stmt.clone();
                let ctx = ctx_arc.clone();
                let tx = tx.clone();
                let _ = Bastion::children(move |ch| {
                    ch.with_exec(move |_| {
                        let stmt = stmt.clone();
                        let ctx = ctx.clone();
                        let tx = tx.clone();
                        async move {
                            let res = eval(&stmt, ctx).await;
                            let _ = tx.send(res.is_ok()).await;
                            Ok::<(), ()>(())
                        }
                    })
                });
            }

            let fut = async {
                let mut success_count = 0;
                for _ in 0..branches.len() {
                    if let Some(success) = rx.recv().await {
                        if success {
                            success_count += 1;
                            if *pattern == ParallelPattern::Race { break; }
                            if let ParallelPattern::GatherMin(min) = pattern {
                                if success_count >= *min { break; }
                            }
                        }
                    }
                }
                if let Some(var) = result_into {
                    ctx_arc.lock().unwrap().set_variable(var.clone(), AnnotatedValue::from(Value::Boolean(true)), MemoryScope::Working)?;
                }
                Ok::<(), anyhow::Error>(())
            };

            if let Some(secs) = deadline { timeout(Duration::from_secs_f64(*secs), fut).await??; } else { fut.await?; }
            Ok(())
        }
        Statement::Wait { duration } => { sleep(Duration::from_secs_f64(*duration)).await; Ok(()) }
        Statement::Remember { name, value, scope, .. } => {
            let mut ctx = ctx_arc.lock().unwrap();
            let val = eval_expression(value, &ctx)?;
            ctx.set_variable(name.clone(), val, *scope)?;
            Ok(())
        }
        Statement::Recall { name, into_var, scope, on_missing } => {
            let mut ctx = ctx_arc.lock().unwrap();
            match ctx.get_variable(name, *scope) {
                Ok(val) => { ctx.set_variable(into_var.clone(), val, MemoryScope::Working)?; },
                Err(_) => if let Some(expr) = on_missing {
                    let val = eval_expression(expr, &ctx)?;
                    ctx.set_variable(into_var.clone(), val, MemoryScope::Working)?;
                } else { return Err(anyhow!("Not found")); }
            }
            Ok(())
        }
        Statement::Forget { name, scope } => {
            let mut ctx = ctx_arc.lock().unwrap();
            match scope {
                MemoryScope::Working => { ctx.working_variables.remove(name); },
                MemoryScope::Session => { ctx.session_variables.lock().unwrap().remove(name); },
                MemoryScope::LongTerm => {
                    let mut memory = ctx.load_long_term()?;
                    memory.remove(name);
                    ctx.save_long_term(memory)?;
                },
                _ => return Err(anyhow!("Not implemented")),
            }
            Ok(())
        }
        Statement::Agent { name, id, trust_level, .. } => {
            println!("AGENT: {} (ID: {}, TRUST: {:?})", name, id, trust_level);
            Ok(())
        }
        Statement::Contract { name, issued_by, capabilities, expires } => {
            println!("CONTRACT: {} (Issued by: {})", name, issued_by);
            let mut ctx = ctx_arc.lock().unwrap();
            ctx.active_contracts.insert(name.clone(), ContractInfo {
                issued_by: issued_by.clone(),
                capabilities: capabilities.clone(),
                expires: *expires,
            });
            Ok(())
        }
        Statement::Emit { event, data } => {
            let val = { let ctx = ctx_arc.lock().unwrap(); eval_expression(data, &ctx)? };
            let ctx = ctx_arc.lock().unwrap();
            let _ = ctx.event_tx.send(Event { name: event.clone(), data: val });
            Ok(())
        }
        Statement::On { event, handler } => {
            let event_name = event.clone();
            let handler_clone = handler.clone();
            let ctx_clone = ctx_arc.clone();
            let mut rx = ctx_arc.lock().unwrap().event_tx.subscribe();
            let _ = Bastion::children(move |ch| {
                ch.with_exec(move |_| {
                    let event_name = event_name.clone();
                    let handler = handler_clone.clone();
                    let ctx = ctx_clone.clone();
                    let mut rx = rx.resubscribe();
                    async move {
                        while let Ok(ev) = rx.recv().await {
                            if ev.name == event_name {
                                let _ = eval(&handler, ctx.clone()).await;
                            }
                        }
                        Ok::<(), ()>(())
                    }
                })
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_bastion() {
        let _ = Bastion::init();
    }

    #[test]
    fn test_eval_expression_literal() {
        let ctx = Context::new();
        let expr = Expression::Literal(AnnotatedValue::from(Value::Number(42.0)));
        assert_eq!(eval_expression(&expr, &ctx).unwrap().value, Value::Number(42.0));
    }

    #[test]
    fn test_eval_expression_variable() {
        let mut ctx = Context::new();
        ctx.set_variable("x".to_string(), AnnotatedValue::from(Value::Boolean(true)), MemoryScope::Working).unwrap();
        let expr = Expression::VariableRef("x".to_string());
        assert_eq!(eval_expression(&expr, &ctx).unwrap().value, Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_set() {
        let ctx = Arc::new(Mutex::new(Context::new()));
        let stmt = Statement::Set {
            name: "y".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("hello".to_string()))),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.lock().unwrap().get_variable("y", MemoryScope::Working).unwrap().value, Value::Text("hello".to_string()));
    }

    #[tokio::test]
    async fn test_eval_parallel_gather() {
        init_bastion();
        let ctx = Arc::new(Mutex::new(Context::new()));
        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Gather,
            branches: vec![
                Statement::Set { name: "a".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))) },
                Statement::Set { name: "b".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Number(2.0))) },
            ],
            result_into: Some("done".to_string()),
            deadline: None,
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        let lock = ctx.lock().unwrap();
        assert_eq!(lock.get_variable("a", MemoryScope::Working).unwrap().value, Value::Number(1.0));
        assert_eq!(lock.get_variable("b", MemoryScope::Working).unwrap().value, Value::Number(2.0));
        assert_eq!(lock.get_variable("done", MemoryScope::Working).unwrap().value, Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_retry() {
        init_bastion();
        let ctx = Arc::new(Mutex::new(Context::new()));
        let stmt = Statement::Goal {
            name: "retry_goal".to_string(),
            body: vec![Statement::UseTool {
                tool_name: "fail_tool".to_string(),
                args: HashMap::new(),
                result_into: "res".to_string(),
            }],
            retry: Some(2),
            on_fail: None,
            deadline: None,
        };
        let res = eval(&stmt, ctx.clone()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_eval_remember_recall_session() {
        let ctx = Arc::new(Mutex::new(Context::new()));
        let remember = Statement::Remember {
            name: "foo".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("bar".to_string()))),
            scope: MemoryScope::Session,
            expires: None,
        };
        let recall = Statement::Recall {
            name: "foo".to_string(),
            into_var: "result".to_string(),
            scope: MemoryScope::Session,
            on_missing: None,
        };
        eval(&remember, ctx.clone()).await.unwrap();
        eval(&recall, ctx.clone()).await.unwrap();
        let lock = ctx.lock().unwrap();
        assert_eq!(lock.get_variable("result", MemoryScope::Working).unwrap().value, Value::Text("bar".to_string()));
    }

    #[test]
    fn test_identity_generation() {
        let id = Identity::generate();
        let message = b"hello agentlang";
        let signature = id.signing_key.sign(message);
        assert!(id.verifying_key.verify(message, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_contract_activation() {
        let ctx = Arc::new(Mutex::new(Context::new()));
        let contract = Statement::Contract {
            name: "test_contract".to_string(),
            issued_by: "registry.io".to_string(),
            capabilities: vec![Permission::CanUse("search".to_string())],
            expires: None,
        };
        eval(&contract, ctx.clone()).await.unwrap();
        assert!(ctx.lock().unwrap().active_contracts.contains_key("test_contract"));
    }

    #[tokio::test]
    async fn test_event_emit_on() {
        init_bastion();
        let ctx = Arc::new(Mutex::new(Context::new()));
        let on_stmt = Statement::On {
            event: "ping".to_string(),
            handler: Box::new(Statement::Set {
                name: "pong".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            }),
        };
        let emit_stmt = Statement::Emit {
            event: "ping".to_string(),
            data: Expression::Literal(AnnotatedValue::from(Value::Text("hello".to_string()))),
        };
        eval(&on_stmt, ctx.clone()).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        eval(&emit_stmt, ctx.clone()).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        let lock = ctx.lock().unwrap();
        assert_eq!(lock.get_variable("pong", MemoryScope::Working).unwrap().value, Value::Boolean(true));
    }
}
