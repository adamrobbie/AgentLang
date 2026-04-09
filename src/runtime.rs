use crate::ast::*;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, sleep};
use async_recursion::async_recursion;
use std::fs;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use rand::RngCore;
use bastion::prelude::*;
use tokio::sync::{broadcast, mpsc};
use ring::{aead, digest};
use serde::{Serialize, Deserialize};
use wasmtime::*;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub op: String,
    pub prev_hash: String,
    pub timestamp: u64,
}

pub struct AuditChain {
    pub entries: Vec<AuditEntry>,
    pub last_hash: String,
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: "genesis".to_string(),
        }
    }

    pub fn append(&mut self, op: String) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let content = format!("{}:{}:{}", self.last_hash, op, timestamp);
        let hash = digest::digest(&digest::SHA256, content.as_bytes());
        let hash_str = hex::encode(hash.as_ref());
        
        let entry = AuditEntry {
            op,
            prev_hash: self.last_hash.clone(),
            timestamp,
        };
        
        self.entries.push(entry);
        self.last_hash = hash_str.clone();
        hash_str
    }
}

#[derive(Clone)]
pub struct Context {
    pub working_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_file: String,
    pub identity: Arc<Identity>,
    pub active_contracts: Arc<Mutex<HashMap<String, ContractInfo>>>,
    pub event_tx: broadcast::Sender<Event>,
    pub audit_chain: Arc<Mutex<AuditChain>>,
    pub session_key: Arc<aead::LessSafeKey>,
    pub wasm_engine: Engine,
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
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
        
        Self {
            working_variables: Arc::new(Mutex::new(HashMap::new())),
            session_variables: Arc::new(Mutex::new(HashMap::new())),
            long_term_file: "memory.json".to_string(),
            identity: Arc::new(Identity::generate()),
            active_contracts: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            audit_chain: Arc::new(Mutex::new(AuditChain::new())),
            session_key: Arc::new(aead::LessSafeKey::new(unbound_key)),
            wasm_engine: Engine::default(),
        }
    }

    pub fn get_variable(&self, name: &str, scope: MemoryScope) -> Result<AnnotatedValue> {
        match scope {
            MemoryScope::Working => self.working_variables.lock().unwrap().get(name).cloned().ok_or_else(|| anyhow!("Working variable '{}' not found", name)),
            MemoryScope::Session => self.session_variables.lock().unwrap().get(name).cloned().ok_or_else(|| anyhow!("Session variable '{}' not found", name)),
            MemoryScope::LongTerm => {
                let memory = self.load_long_term()?;
                memory.get(name).cloned().ok_or_else(|| anyhow!("Long-term variable '{}' not found", name))
            },
            _ => Err(anyhow!("Scope not implemented")),
        }
    }

    pub fn set_variable(&self, name: String, value: AnnotatedValue, scope: MemoryScope) -> Result<()> {
        {
            let mut audit = self.audit_chain.lock().unwrap();
            audit.append(format!("SET:{}:{:?}", name, scope));
        }
        match scope {
            MemoryScope::Working => { self.working_variables.lock().unwrap().insert(name, value); },
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
        Expression::VariableRef(name) => {
            ctx.get_variable(name, MemoryScope::Working)
                .or_else(|_| ctx.get_variable(name, MemoryScope::Session))
        },
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
pub async fn eval(statement: &Statement, ctx: Context) -> Result<()> {
    match statement {
        Statement::Goal { name, body, .. } => {
            println!("  [Runtime] Goal: {}", name);
            for stmt in body {
                eval(stmt, ctx.clone()).await?;
            }
            Ok(())
        }
        Statement::Set { name, value } => {
            let val = eval_expression(value, &ctx)?;
            println!("  [Runtime] SET {} = {:?}", name, val.value);
            ctx.set_variable(name.clone(), val, MemoryScope::Working)?;
            Ok(())
        }
        Statement::If { condition, then_branch, else_branch } => {
            let cond = eval_expression(condition, &ctx)?;
            let is_true = match cond.value { Value::Boolean(b) => b, Value::Number(n) => n != 0.0, Value::Text(s) => !s.is_empty() };
            if is_true { for stmt in then_branch { eval(stmt, ctx.clone()).await?; } }
            else if let Some(branch) = else_branch { for stmt in branch { eval(stmt, ctx.clone()).await?; } }
            Ok(())
        }
        Statement::UseTool { tool_name, args: _, result_into } => {
            println!("  [Runtime] USE TOOL: {}", tool_name);
            let mock_result = AnnotatedValue::from(Value::Text(format!("Result from {}", tool_name)));
            ctx.set_variable(result_into.clone(), mock_result, MemoryScope::Working)?;
            Ok(())
        }
        Statement::Parallel { branches, result_into, .. } => {
            println!("  [Runtime] Parallel START");
            for stmt in branches {
                eval(stmt, ctx.clone()).await?;
            }
            if let Some(var) = result_into {
                ctx.set_variable(var.clone(), AnnotatedValue::from(Value::Boolean(true)), MemoryScope::Working)?;
            }
            println!("  [Runtime] Parallel FINISHED");
            Ok(())
        }
        Statement::Wait { duration } => { 
            sleep(Duration::from_secs_f64(*duration)).await; 
            Ok(()) 
        }
        Statement::Remember { name, value, scope, .. } => {
            let val = eval_expression(value, &ctx)?;
            println!("  [Runtime] REMEMBER {} IN {:?}", name, scope);
            ctx.set_variable(name.clone(), val, *scope)?;
            Ok(())
        }
        Statement::Recall { name, into_var, scope, on_missing, fuzzy, .. } => {
            let result = if *fuzzy {
                println!("  [Runtime] RECALL FUZZY: searching for '{}'...", name);
                let mut found = None;
                let memory = match scope {
                    MemoryScope::Working => ctx.working_variables.lock().unwrap().clone(),
                    MemoryScope::Session => ctx.session_variables.lock().unwrap().clone(),
                    MemoryScope::LongTerm => ctx.load_long_term()?,
                    _ => HashMap::new(),
                };
                for (k, v) in memory {
                    if k.contains(name) {
                        let mut val = v.clone();
                        val.confidence = Some(0.85);
                        found = Some(val);
                        break;
                    }
                }
                found.ok_or_else(|| anyhow!("Fuzzy match not found"))
            } else {
                ctx.get_variable(name, *scope)
            };

            match result {
                Ok(val) => { 
                    println!("  [Runtime] RECALL SUCCESS: {} -> {}", name, into_var);
                    ctx.set_variable(into_var.clone(), val, MemoryScope::Working)?; 
                },
                Err(_) => if let Some(expr) = on_missing {
                    let val = eval_expression(expr, &ctx)?;
                    ctx.set_variable(into_var.clone(), val, MemoryScope::Working)?;
                } else { 
                    println!("  [Runtime] RECALL FAILED: {}", name);
                    return Err(anyhow!("Key '{}' not found", name)); 
                }
            }
            Ok(())
        }
        Statement::Forget { name, scope } => {
            match scope {
                MemoryScope::Working => { ctx.working_variables.lock().unwrap().remove(name); },
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
        Statement::Agent { .. } => Ok(()),
        Statement::Contract { name, issued_by, capabilities, expires } => {
            ctx.active_contracts.lock().unwrap().insert(name.clone(), ContractInfo {
                issued_by: issued_by.clone(),
                capabilities: capabilities.clone(),
                expires: *expires,
            });
            Ok(())
        }
        Statement::Emit { event, data } => {
            let val = eval_expression(data, &ctx)?;
            println!("  [Runtime] EMIT: {}", event);
            let _ = ctx.event_tx.send(Event { name: event.clone(), data: val });
            Ok(())
        }
        Statement::On { event, handler } => {
            let event_name = event.clone();
            let handler_clone = handler.clone();
            let ctx_clone = ctx.clone();
            let mut rx = ctx.event_tx.subscribe();
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    if ev.name == event_name {
                        println!("  [Runtime] EVENT TRIGGERED: {}", event_name);
                        let _ = eval(&handler_clone, ctx_clone.clone()).await;
                    }
                }
            });
            Ok(())
        }
        Statement::Prove { statement, .. } => {
            eval(statement, ctx.clone()).await?;
            Ok(())
        }
        Statement::Reveal { .. } => Ok(()),
        Statement::UseWasm { module_path, function_name, args, result_into } => {
            println!("  [Runtime] USE_WASM: {} FUNCTION {}", module_path, function_name);
            let module = Module::from_file(&ctx.wasm_engine, module_path)?;
            let mut store = Store::new(&ctx.wasm_engine, ());
            let linker = Linker::new(&ctx.wasm_engine);
            let instance = linker.instantiate(&mut store, &module)?;
            
            // Extract numeric arguments for simple WASM functions
            let mut wasm_args = Vec::new();
            for (_, expr) in args {
                let val = eval_expression(expr, &ctx)?;
                if let Value::Number(n) = val.value {
                    wasm_args.push(Val::I32(n as i32));
                }
            }

            let func = instance.get_func(&mut store, function_name)
                .ok_or_else(|| anyhow!("Function not found"))?;
            
            let mut results = vec![Val::I32(0)];
            func.call(&mut store, &wasm_args, &mut results)?;
            
            let res_val = if let Some(Val::I32(i)) = results.get(0) {
                *i as f64
            } else {
                0.0
            };

            let mock_result = AnnotatedValue::from(Value::Number(res_val));
            ctx.set_variable(result_into.clone(), mock_result, MemoryScope::Working)?;
            Ok(())
        }
        Statement::Call { agent_id, goal_name, result_into, .. } => {
            println!("  [Runtime] CALL AGENT '{}': GOAL '{}'", agent_id, goal_name);
            let mock_result = AnnotatedValue::from(Value::Text("Remote success".to_string()));
            ctx.set_variable(result_into.clone(), mock_result, MemoryScope::Working)?;
            Ok(())
        }
        Statement::Await { .. } => Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_bastion() {
        let _ = Bastion::init();
    }

    #[test]
    fn test_audit_chain() {
        let mut chain = AuditChain::new();
        let h1 = chain.append("OP1".to_string());
        let h2 = chain.append("OP2".to_string());
        assert_ne!(h1, h2);
        assert_eq!(chain.entries.len(), 2);
        assert_eq!(chain.entries[1].prev_hash, h1);
    }

    #[tokio::test]
    async fn test_eval_set_audited() {
        let ctx = Context::new();
        let stmt = Statement::Set {
            name: "x".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.audit_chain.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn test_eval_expression_literal() {
        let ctx = Context::new();
        let expr = Expression::Literal(AnnotatedValue::from(Value::Number(42.0)));
        assert_eq!(eval_expression(&expr, &ctx).unwrap().value, Value::Number(42.0));
    }

    #[test]
    fn test_eval_expression_variable() {
        let ctx = Context::new();
        ctx.set_variable("x".to_string(), AnnotatedValue::from(Value::Boolean(true)), MemoryScope::Working).unwrap();
        let expr = Expression::VariableRef("x".to_string());
        assert_eq!(eval_expression(&expr, &ctx).unwrap().value, Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_set() {
        let ctx = Context::new();
        let stmt = Statement::Set {
            name: "y".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("hello".to_string()))),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.get_variable("y", MemoryScope::Working).unwrap().value, Value::Text("hello".to_string()));
    }

    #[tokio::test]
    async fn test_eval_remember_recall_session() {
        let ctx = Context::new();
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
            fuzzy: false,
            threshold: None,
        };
        eval(&remember, ctx.clone()).await.unwrap();
        eval(&recall, ctx.clone()).await.unwrap();
        assert_eq!(ctx.get_variable("result", MemoryScope::Working).unwrap().value, Value::Text("bar".to_string()));
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
        let ctx = Context::new();
        let contract = Statement::Contract {
            name: "test_contract".to_string(),
            issued_by: "registry.io".to_string(),
            capabilities: vec![Permission::CanUse("search".to_string())],
            expires: None,
        };
        eval(&contract, ctx.clone()).await.unwrap();
        assert!(ctx.active_contracts.lock().unwrap().contains_key("test_contract"));
    }

    #[tokio::test]
    async fn test_event_emit_on() {
        let ctx = Context::new();
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
        assert_eq!(ctx.get_variable("pong", MemoryScope::Working).unwrap().value, Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_call() {
        let ctx = Context::new();
        let call_stmt = Statement::Call {
            agent_id: "agent_b".to_string(),
            goal_name: "pay".to_string(),
            args: HashMap::new(),
            result_into: "res".to_string(),
        };
        eval(&call_stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.get_variable("res", MemoryScope::Working).unwrap().value, Value::Text("Remote success".to_string()));
    }

    #[tokio::test]
    async fn test_eval_recall_fuzzy() {
        let ctx = Context::new();
        let remember = Statement::Remember {
            name: "user_preference_color".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("blue".to_string()))),
            scope: MemoryScope::Session,
            expires: None,
        };
        let recall = Statement::Recall {
            name: "preference".to_string(),
            into_var: "res".to_string(),
            scope: MemoryScope::Session,
            on_missing: None,
            fuzzy: true,
            threshold: Some(0.5),
        };
        eval(&remember, ctx.clone()).await.unwrap();
        eval(&recall, ctx.clone()).await.unwrap();
        assert_eq!(ctx.get_variable("res", MemoryScope::Working).unwrap().value, Value::Text("blue".to_string()));
    }

    #[tokio::test]
    async fn test_eval_wasm_math() {
        let ctx = Context::new();
        let wasm_path = "wasm_modules/math_tool.wasm";
        let stmt = Statement::UseWasm {
            module_path: wasm_path.to_string(),
            function_name: "add".to_string(),
            args: {
                let mut map = HashMap::new();
                map.insert("a".to_string(), Expression::Literal(AnnotatedValue::from(Value::Number(10.0))));
                map.insert("b".to_string(), Expression::Literal(AnnotatedValue::from(Value::Number(20.0))));
                map
            },
            result_into: "wasm_res".to_string(),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.get_variable("wasm_res", MemoryScope::Working).unwrap().value, Value::Number(30.0));
    }
}
