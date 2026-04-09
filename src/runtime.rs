use crate::ast::*;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, sleep};
use async_recursion::async_recursion;
use std::fs;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use rand::RngCore;

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

pub struct Context {
    pub working_variables: HashMap<String, AnnotatedValue>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_file: String,
    pub identity: Identity,
    pub active_contracts: HashMap<String, ContractInfo>,
}

#[derive(Clone)]
pub struct ContractInfo {
    pub issued_by: String,
    pub capabilities: Vec<Permission>,
    pub expires: Option<f64>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            working_variables: HashMap::new(),
            session_variables: Arc::new(Mutex::new(HashMap::new())),
            long_term_file: "memory.json".to_string(),
            identity: Identity::generate(),
            active_contracts: HashMap::new(),
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

fn format_value(val: &AnnotatedValue) -> String {
    if val.is_sensitive { "[REDACTED]".to_string() } else { format!("{:?}", val.value) }
}

#[async_recursion]
pub async fn eval(statement: &Statement, ctx_arc: Arc<Mutex<Context>>) -> Result<()> {
    match statement {
        Statement::Goal { name: _, body, retry, on_fail, deadline } => {
            let max_attempts = retry.unwrap_or(0) + 1;
            let mut last_error = None;
            for _ in 1..=max_attempts {
                let body_fut = async {
                    for stmt in body { eval(stmt, ctx_arc.clone()).await?; }
                    Ok::<(), anyhow::Error>(())
                };
                let result = if let Some(secs) = deadline {
                    match timeout(Duration::from_secs_f64(*secs), body_fut).await {
                        Ok(res) => res,
                        Err(_) => Err(anyhow!("Timeout")),
                    }
                } else { body_fut.await };
                match result { Ok(_) => return Ok(()), Err(e) => last_error = Some(e) }
            }
            if let Some(fallback) = on_fail { eval(fallback, ctx_arc.clone()).await?; Ok(()) }
            else { Err(last_error.unwrap_or_else(|| anyhow!("Failed"))) }
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
            let fut = async {
                match pattern {
                    ParallelPattern::Gather | ParallelPattern::GatherAll | ParallelPattern::Race | ParallelPattern::GatherMin(_) => {
                        let mut set = JoinSet::new();
                        for stmt in branches {
                            let ctx_clone = ctx_arc.clone();
                            let stmt_clone = stmt.clone();
                            set.spawn(async move { eval(&stmt_clone, ctx_clone).await });
                        }
                        while let Some(res) = set.join_next().await { res??; if *pattern == ParallelPattern::Race { break; } }
                        set.abort_all();
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let lock = ctx.lock().unwrap();
        assert_eq!(lock.get_variable("a", MemoryScope::Working).unwrap().value, Value::Number(1.0));
        assert_eq!(lock.get_variable("b", MemoryScope::Working).unwrap().value, Value::Number(2.0));
        assert_eq!(lock.get_variable("done", MemoryScope::Working).unwrap().value, Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_retry() {
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
}
