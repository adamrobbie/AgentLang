use crate::ast::*;
use crate::crypto;
use anyhow::{Result, anyhow};

pub mod agent_rpc {
    tonic::include_proto!("agent");
}

pub mod registry_rpc {
    tonic::include_proto!("registry");
}

use agent_rpc::CallRequest;
use agent_rpc::agent_service_client::AgentServiceClient;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use registry_rpc::registry_service_client::RegistryServiceClient;
use registry_rpc::{GetSharedRequest, LookupRequest, PutSharedRequest};

use async_recursion::async_recursion;
use bastion::prelude::*;
use rand::RngCore;
use ring::{aead, digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
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
        Self {
            signing_key,
            verifying_key,
        }
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
    pub file_path: String,
}

impl AuditChain {
    pub fn new(file_path: String) -> Self {
        let mut chain = Self {
            entries: Vec::new(),
            last_hash: "genesis".to_string(),
            file_path: file_path.clone(),
        };

        if let Ok(data) = fs::read_to_string(&file_path)
            && let Ok(entries) = serde_json::from_str::<Vec<AuditEntry>>(&data)
        {
            for entry in &entries {
                let content = format!("{}:{}:{}", chain.last_hash, entry.op, entry.timestamp);
                let hash = digest::digest(&digest::SHA256, content.as_bytes());
                chain.last_hash = hex::encode(hash.as_ref());
                chain.entries.push(entry.clone());
            }
        }
        chain
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

        // Persist to disk
        if let Ok(data) = serde_json::to_string_pretty(&self.entries) {
            let _ = fs::write(&self.file_path, data);
        }

        hash_str
    }
}

pub fn format_value_safe(val: &AnnotatedValue) -> String {
    if val.is_sensitive {
        "[REDACTED]".to_string()
    } else {
        format!("{:?}", val.value)
    }
}

#[derive(Clone)]
pub struct Context {
    pub working_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_file: String,
    pub shared_file: String,
    pub identity: Arc<Identity>,
    pub active_contracts: Arc<Mutex<HashMap<String, ContractInfo>>>,
    pub event_tx: broadcast::Sender<Event>,
    pub audit_chain: Arc<Mutex<AuditChain>>,
    pub session_key: Arc<aead::LessSafeKey>,
    pub wasm_engine: Engine,
    pub proofs: Arc<Mutex<HashMap<String, crypto::StarkProof>>>,
    pub goals: Arc<Mutex<HashMap<String, Vec<Statement>>>>,
    pub registries: Arc<Mutex<Vec<String>>>,
    pub pending_calls:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Receiver<Result<AnnotatedValue>>>>>,
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

        // Phase 3.3: Mitigation for Plaintext Secrets
        // Use environment variable if present, otherwise fallback to agent.key file
        let key_file = "agent.key";
        let mut key_bytes = [0u8; 32];
        if let Ok(env_key) = std::env::var("AGENTLANG_MASTER_KEY") {
            let hash = digest::digest(&digest::SHA256, env_key.as_bytes());
            key_bytes.copy_from_slice(hash.as_ref());
            println!("  [Security] Using AGENTLANG_MASTER_KEY from environment.");
        } else if let Ok(existing_key) = fs::read(key_file) {
            let existing_key: Vec<u8> = existing_key;
            if existing_key.len() == 32 {
                key_bytes.copy_from_slice(&existing_key);
            } else {
                rand::thread_rng().fill_bytes(&mut key_bytes);
                let _ = fs::write(key_file, key_bytes);
            }
        } else {
            println!("  [Security] WARNING: Storing master key in plaintext on disk.");
            rand::thread_rng().fill_bytes(&mut key_bytes);
            let _ = fs::write(key_file, key_bytes);
        }
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();

        // Persist or load identity
        let id_file = "agent.id";
        let identity = if let Ok(existing_id) = fs::read(id_file) {
            let existing_id: Vec<u8> = existing_id;
            if existing_id.len() == 32 {
                let bytes: [u8; 32] = existing_id.try_into().unwrap();
                let signing_key = SigningKey::from_bytes(&bytes);
                let verifying_key = VerifyingKey::from(&signing_key);
                Identity {
                    signing_key,
                    verifying_key,
                }
            } else {
                let id = Identity::generate();
                let _ = fs::write(id_file, id.signing_key.to_bytes());
                id
            }
        } else {
            let id = Identity::generate();
            let _ = fs::write(id_file, id.signing_key.to_bytes());
            id
        };

        let mut wasm_config = wasmtime::Config::new();
        wasm_config.consume_fuel(true);
        let wasm_engine = Engine::new(&wasm_config).unwrap();

        Self {
            working_variables: Arc::new(Mutex::new(HashMap::new())),
            session_variables: Arc::new(Mutex::new(HashMap::new())),
            long_term_file: "memory.json".to_string(),
            shared_file: "shared_memory.json".to_string(),
            identity: Arc::new(identity),
            active_contracts: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            audit_chain: Arc::new(Mutex::new(AuditChain::new("audit.json".to_string()))),
            session_key: Arc::new(aead::LessSafeKey::new(unbound_key)),
            wasm_engine,
            proofs: Arc::new(Mutex::new(HashMap::new())),
            goals: Arc::new(Mutex::new(HashMap::new())),
            registries: Arc::new(Mutex::new(vec!["http://[::1]:50050".to_string()])),
            pending_calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_variable(&self, name: &str, scope: MemoryScope) -> Result<AnnotatedValue> {
        match scope {
            MemoryScope::Working => self
                .working_variables
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("Working variable '{}' not found", name)),
            MemoryScope::Session => self
                .session_variables
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("Session variable '{}' not found", name)),
            MemoryScope::LongTerm => {
                let memory = self.load_long_term()?;
                memory
                    .get(name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Long-term variable '{}' not found", name))
            }
            MemoryScope::Shared => {
                // Phase 1.3: Registry-backed shared memory (Federated)
                let registries = self.registries.lock().unwrap().clone();
                for reg_addr in registries {
                    if let Ok(mut client) = RegistryServiceClient::connect(reg_addr).await
                        && let Ok(res) = client
                            .get_shared_state(GetSharedRequest {
                                key: name.to_string(),
                            })
                            .await
                    {
                        let res = res.into_inner();
                        if res.found {
                            let val: AnnotatedValue = serde_json::from_slice(&res.value_json)?;
                            return Ok(val);
                        }
                    }
                }
                Err(anyhow!(
                    "Shared variable '{}' not found in any registry",
                    name
                ))
            }
        }
    }

    pub fn check_contracts(&self, required_capability: &str) -> Result<()> {
        let contracts = self.active_contracts.lock().unwrap();
        if contracts.is_empty() {
            return Ok(()); // Allow actions if no restrictive contracts are defined yet
        }

        let mut allowed = false;
        for (name, info) in contracts.iter() {
            if let Some(expiry) = info.expires {
                // For this prototype, we check if the duration is > 0
                if expiry <= 0.0 {
                    continue; // Skip expired contracts
                }
            }

            for perm in &info.capabilities {
                match perm {
                    Permission::CanUse(cap) if cap == "*" || cap == required_capability => {
                        allowed = true;
                    }
                    Permission::CannotUse(cap) if cap == "*" || cap == required_capability => {
                        return Err(anyhow!(
                            "Permission denied: Contract '{}' explicitly forbids '{}'",
                            name,
                            required_capability
                        ));
                    }
                    _ => {}
                }
            }
        }

        if allowed {
            Ok(())
        } else {
            Err(anyhow!(
                "Permission denied: No active contract allows '{}'",
                required_capability
            ))
        }
    }

    pub async fn set_variable(
        &self,
        name: String,
        value: AnnotatedValue,
        scope: MemoryScope,
    ) -> Result<()> {
        {
            let mut audit = self.audit_chain.lock().unwrap();
            audit.append(format!(
                "SET:{}:{:?}:{}",
                name,
                scope,
                format_value_safe(&value)
            ));
        }
        match scope {
            MemoryScope::Working => {
                self.working_variables.lock().unwrap().insert(name, value);
            }
            MemoryScope::Session => {
                self.session_variables.lock().unwrap().insert(name, value);
            }
            MemoryScope::LongTerm => {
                let mut memory = self.load_long_term()?;
                memory.insert(name, value);
                self.save_long_term(memory)?;
            }
            MemoryScope::Shared => {
                // Phase 1.3: Registry-backed shared memory (Federated)
                let value_json = serde_json::to_vec(&value)?;
                let registries = self.registries.lock().unwrap().clone();
                let mut success = false;
                for reg_addr in registries {
                    if let Ok(mut client) = RegistryServiceClient::connect(reg_addr).await
                        && let Ok(res) = client
                            .put_shared_state(PutSharedRequest {
                                key: name.clone(),
                                value_json: value_json.clone(),
                            })
                            .await
                        && res.into_inner().success
                    {
                        success = true;
                        break; // Successfully updated primary registry
                    }
                }
                if !success {
                    return Err(anyhow!(
                        "Failed to update shared variable '{}' in any registry",
                        name
                    ));
                }
            }
        }
        Ok(())
    }

    fn load_long_term(&self) -> Result<HashMap<String, AnnotatedValue>> {
        if let Ok(data) = fs::read_to_string(&self.long_term_file) {
            let data: String = data;
            let stored: HashMap<String, StoredValue> = serde_json::from_str(&data)?;
            let mut result = HashMap::new();
            for (k, v) in stored {
                match v {
                    StoredValue::Plain(val) => {
                        result.insert(k, val);
                    }
                    StoredValue::Encrypted { nonce, ciphertext } => {
                        let mut in_out = ciphertext.clone();
                        let nonce_fixed = aead::Nonce::try_assume_unique_for_key(&nonce)
                            .map_err(|_| anyhow!("Invalid nonce length"))?;

                        let decrypted = self
                            .session_key
                            .open_in_place(nonce_fixed, aead::Aad::empty(), &mut in_out)
                            .map_err(|_| anyhow!("Decryption failed for key '{}'", k))?;

                        let val: AnnotatedValue = serde_json::from_slice(decrypted)?;
                        result.insert(k, val);
                    }
                }
            }
            Ok(result)
        } else {
            Ok(HashMap::new())
        }
    }

    fn save_long_term(&self, memory: HashMap<String, AnnotatedValue>) -> Result<()> {
        let mut stored = HashMap::new();
        for (k, v) in memory {
            if v.is_sensitive {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

                let mut in_out = serde_json::to_vec(&v)?;
                self.session_key
                    .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
                    .map_err(|_| anyhow!("Encryption failed for key '{}'", k))?;

                stored.insert(
                    k,
                    StoredValue::Encrypted {
                        nonce: nonce_bytes.to_vec(),
                        ciphertext: in_out,
                    },
                );
            } else {
                stored.insert(k, StoredValue::Plain(v));
            }
        }
        let data = serde_json::to_string_pretty(&stored)?;
        fs::write(&self.long_term_file, data)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub enum StoredValue {
    Plain(AnnotatedValue),
    Encrypted { nonce: Vec<u8>, ciphertext: Vec<u8> },
}

#[async_recursion]
pub async fn eval_expression(expr: &Expression, ctx: &Context) -> Result<AnnotatedValue> {
    match expr {
        Expression::Literal(val) => Ok(val.clone()),
        Expression::VariableRef(name) => {
            if let Ok(v) = ctx.get_variable(name, MemoryScope::Working).await {
                Ok(v)
            } else {
                ctx.get_variable(name, MemoryScope::Session).await
            }
        }
        Expression::Annotated { expr, annotation } => {
            let mut val = eval_expression(expr, ctx).await?;
            match annotation {
                Annotation::Confidence => val.confidence = Some(1.0),
                Annotation::Sensitive => val.is_sensitive = true,
                Annotation::Uncertain => val.is_uncertain = true,
                Annotation::Approximate => val.is_approximate = true,
            }
            Ok(val)
        }
        Expression::BinaryOp { left, op, right } => {
            let l_val = eval_expression(left, ctx).await?;
            let r_val = eval_expression(right, ctx).await?;

            let is_approx = l_val.is_approximate || r_val.is_approximate;
            let tolerance = 0.05; // 5% tolerance

            match op {
                BinaryOperator::Add => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = AnnotatedValue::from(Value::Number(l + r));
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for ADD"))
                    }
                }
                BinaryOperator::Sub => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = AnnotatedValue::from(Value::Number(l - r));
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for SUB"))
                    }
                }
                BinaryOperator::Eq => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        if is_approx {
                            let diff = (l - r).abs();
                            let threshold = l.abs().max(r.abs()) * tolerance;
                            Ok(AnnotatedValue::from(Value::Boolean(diff <= threshold)))
                        } else {
                            Ok(AnnotatedValue::from(Value::Boolean(l == r)))
                        }
                    } else {
                        Ok(AnnotatedValue::from(Value::Boolean(
                            l_val.value == r_val.value,
                        )))
                    }
                }
                BinaryOperator::Gt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        if is_approx {
                            Ok(AnnotatedValue::from(Value::Boolean(
                                l > &(r * (1.0 - tolerance)),
                            )))
                        } else {
                            Ok(AnnotatedValue::from(Value::Boolean(l > r)))
                        }
                    } else {
                        Err(anyhow!("GT only supports numbers"))
                    }
                }
                BinaryOperator::Lt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        if is_approx {
                            Ok(AnnotatedValue::from(Value::Boolean(
                                l < &(r * (1.0 + tolerance)),
                            )))
                        } else {
                            Ok(AnnotatedValue::from(Value::Boolean(l < r)))
                        }
                    } else {
                        Err(anyhow!("LT only supports numbers"))
                    }
                }
            }
        }
    }
}

#[async_recursion]
pub async fn eval(statement: &Statement, ctx: Context) -> Result<()> {
    match statement {
        Statement::Goal {
            name,
            body,
            retry,
            on_fail,
            deadline,
            idempotent,
            fallback,
        } => {
            println!("  [Runtime] Goal: {}", name);
            ctx.goals.lock().unwrap().insert(name.clone(), body.clone());

            // 1. Idempotency check
            if *idempotent {
                let audit = ctx.audit_chain.lock().unwrap();
                if audit
                    .entries
                    .iter()
                    .any(|e| e.op.starts_with(&format!("GOAL_SUCCESS:{}", name)))
                {
                    println!(
                        "  [Runtime] Goal '{}' marked IDEMPOTENT and already succeeded. Skipping.",
                        name
                    );
                    return Ok(());
                }
            }

            let max_retries = retry.unwrap_or(0);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let body_clone = body.clone();
            let ctx_clone = ctx.clone();
            let name_clone = name.clone();

            // Create a dedicated supervisor for this goal (BEAM-style)
            Bastion::supervisor(|sup| {
                sup.children(|children| {
                    children.with_exec(move |_ctx: BastionContext| {
                        let body_inner = body_clone.clone();
                        let ctx_inner = ctx_clone.clone();
                        let tx_inner = tx.clone();
                        let max_retries_inner = max_retries;
                        let name_inner = name_clone.clone();

                        async move {
                            let mut current_attempt = 0;
                            loop {
                                current_attempt += 1;
                                let mut res = Ok(());
                                for stmt in &body_inner {
                                    if let Err(e) = eval(stmt, ctx_inner.clone()).await {
                                        res = Err(e);
                                        break;
                                    }
                                }

                                match res {
                                    Ok(_) => {
                                        {
                                            let mut audit = ctx_inner.audit_chain.lock().unwrap();
                                            audit.append(format!("GOAL_SUCCESS:{}", name_inner));
                                        }
                                        let _ = tx_inner.send(Ok(())).await;
                                        return Ok(());
                                    }
                                    Err(e) => {
                                        if current_attempt <= max_retries_inner {
                                            println!("  [Runtime] Goal '{}' attempt {} failed: {}. Retrying...", name_inner, current_attempt, e);
                                        } else {
                                            println!("  [Runtime] Goal '{}' exhausted all {} retries.", name_inner, max_retries_inner + 1);
                                            let _ = tx_inner.send(Err(e)).await;
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                        }
                    })
                })
            }).expect("Failed to spawn supervised Goal");

            let result = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), rx.recv()).await {
                    Ok(Some(res)) => res,
                    Ok(None) => Err(anyhow!("Goal communication channel closed")),
                    Err(_) => Err(anyhow!("Goal '{}' timed out after {}s", name, d)),
                }
            } else {
                match rx.recv().await {
                    Some(res) => res,
                    None => Err(anyhow!("Goal communication channel closed")),
                }
            };

            if let Err(e) = result {
                // Determine failure type for specialized ON_FAIL
                let error_msg = e.to_string();
                let failure_type = if error_msg.contains("timed out") {
                    "TIMEOUT"
                } else if error_msg.contains("Permission") {
                    "PERMISSION"
                } else {
                    "*"
                };

                if let Some(fail_stmt) = on_fail.get(failure_type).or_else(|| on_fail.get("*")) {
                    println!(
                        "  [Runtime] Goal '{}' failed ({}). Executing ON_FAIL.",
                        name, failure_type
                    );
                    eval(fail_stmt, ctx.clone()).await
                } else if let Some(fallback_expr) = fallback {
                    println!(
                        "  [Runtime] Goal '{}' failed. Returning FALLBACK value.",
                        name
                    );
                    let val = eval_expression(fallback_expr, &ctx).await?;
                    ctx.set_variable(format!("{}.result", name), val, MemoryScope::Working)
                        .await?;
                    Ok(())
                } else {
                    Err(e)
                }
            } else {
                Ok(())
            }
        }
        Statement::Set { name, value } => {
            let val = eval_expression(value, &ctx).await?;
            println!("  [Runtime] SET {} = {}", name, format_value_safe(&val));
            ctx.set_variable(name.clone(), val, MemoryScope::Working)
                .await?;
            Ok(())
        }
        Statement::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let cond = eval_expression(condition, &ctx).await?;
            let is_true = match cond.value {
                Value::Boolean(b) => b,
                Value::Number(n) => n != 0.0,
                Value::Text(s) => !s.is_empty(),
                Value::List(l) => !l.is_empty(),
            };
            if is_true {
                for stmt in then_branch {
                    eval(stmt, ctx.clone()).await?;
                }
            } else if let Some(branch) = else_branch {
                for stmt in branch {
                    eval(stmt, ctx.clone()).await?;
                }
            }
            Ok(())
        }
        Statement::UseTool {
            tool_name,
            args: _,
            result_into,
        } => {
            ctx.check_contracts(tool_name)?;
            println!("  [Runtime] USE TOOL: {}", tool_name);
            let mock_result =
                AnnotatedValue::from(Value::Text(format!("Result from {}", tool_name)));
            ctx.set_variable(result_into.clone(), mock_result, MemoryScope::Working)
                .await?;
            Ok(())
        }
        Statement::Parallel {
            pattern,
            branches,
            result_into,
            deadline,
        } => {
            println!("  [Runtime] Parallel START ({:?})", pattern);
            let mut join_set = tokio::task::JoinSet::new();
            for stmt in branches {
                let stmt_clone = stmt.clone();
                let ctx_clone = ctx.clone();
                join_set.spawn(async move { eval(&stmt_clone, ctx_clone).await });
            }

            let pattern_clone = pattern.clone();
            let parallel_future = async move {
                match pattern_clone {
                    ParallelPattern::Gather | ParallelPattern::GatherAll => {
                        let mut results = Vec::new();
                        while let Some(res) = join_set.join_next().await {
                            results.push(res?);
                        }
                        if pattern_clone == ParallelPattern::Gather {
                            for r in results {
                                r?;
                            }
                        }
                        Ok::<(), anyhow::Error>(())
                    }
                    ParallelPattern::Race => {
                        if let Some(res) = join_set.join_next().await {
                            res??;
                        }
                        Ok::<(), anyhow::Error>(())
                    }
                    ParallelPattern::GatherMin(n) => {
                        let mut success_count = 0;
                        while let Some(res) = join_set.join_next().await {
                            if res?.is_ok() {
                                success_count += 1;
                            }
                            if success_count >= n {
                                break;
                            }
                        }
                        Ok::<(), anyhow::Error>(())
                    }
                }
            };

            let result = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), parallel_future).await {
                    Ok(res) => res,
                    Err(_) => Err(anyhow!("Parallel block timed out after {}s", d)),
                }
            } else {
                parallel_future.await
            };

            if let Some(var) = result_into {
                ctx.set_variable(
                    var.clone(),
                    AnnotatedValue::from(Value::Boolean(result.is_ok())),
                    MemoryScope::Working,
                )
                .await?;
            }

            println!("  [Runtime] Parallel FINISHED: success={}", result.is_ok());
            result
        }
        Statement::ForEach { item, list, body } => {
            let list_val = eval_expression(list, &ctx).await?;
            if let Value::List(elements) = list_val.value {
                for element in elements {
                    ctx.set_variable(item.clone(), element, MemoryScope::Working)
                        .await?;
                    for stmt in body {
                        eval(stmt, ctx.clone()).await?;
                    }
                }
                Ok(())
            } else {
                Err(anyhow!(
                    "FOREACH expects a list, found {:?}",
                    list_val.value
                ))
            }
        }
        Statement::Repeat { condition, body } => {
            loop {
                let cond = eval_expression(condition, &ctx).await?;
                let is_true = match cond.value {
                    Value::Boolean(b) => b,
                    Value::Number(n) => n != 0.0,
                    Value::Text(s) => !s.is_empty(),
                    Value::List(l) => !l.is_empty(),
                };
                if is_true {
                    break;
                }

                for stmt in body {
                    eval(stmt, ctx.clone()).await?;
                }
            }
            Ok(())
        }
        Statement::Wait { duration } => {
            sleep(Duration::from_secs_f64(*duration)).await;
            Ok(())
        }
        Statement::Remember {
            name, value, scope, ..
        } => {
            let val = eval_expression(value, &ctx).await?;
            println!("  [Runtime] REMEMBER {} IN {:?}", name, scope);
            ctx.set_variable(name.clone(), val, *scope).await?;
            Ok(())
        }
        Statement::Recall {
            name,
            into_var,
            scope,
            on_missing,
            fuzzy,
            ..
        } => {
            let result = if *fuzzy {
                println!("  [Runtime] RECALL FUZZY: searching for '{}'...", name);
                let mut found = None;
                let memory: HashMap<String, AnnotatedValue> = match scope {
                    MemoryScope::Working => ctx.working_variables.lock().unwrap().clone(),
                    MemoryScope::Session => ctx.session_variables.lock().unwrap().clone(),
                    MemoryScope::LongTerm => ctx.load_long_term()?,
                    _ => HashMap::new(),
                };
                for (k, v) in memory {
                    let k: String = k;
                    let v: AnnotatedValue = v;
                    if k.contains(name) {
                        let mut val = v.clone();
                        val.confidence = Some(0.85);
                        found = Some(val);
                        break;
                    }
                }
                found.ok_or_else(|| anyhow!("Fuzzy match not found"))
            } else {
                ctx.get_variable(name, *scope).await
            };

            match result {
                Ok(val) => {
                    println!(
                        "  [Runtime] RECALL SUCCESS: {} -> {} (Value: {})",
                        name,
                        into_var,
                        format_value_safe(&val)
                    );
                    ctx.set_variable(into_var.clone(), val, MemoryScope::Working)
                        .await?;
                }
                Err(_) => {
                    if let Some(expr) = on_missing {
                        let val = eval_expression(expr, &ctx).await?;
                        ctx.set_variable(into_var.clone(), val, MemoryScope::Working)
                            .await?;
                    } else {
                        println!("  [Runtime] RECALL FAILED: {}", name);
                        return Err(anyhow!("Key '{}' not found", name));
                    }
                }
            }
            Ok(())
        }
        Statement::Forget { name, scope } => {
            match scope {
                MemoryScope::Working => {
                    ctx.working_variables.lock().unwrap().remove(name);
                }
                MemoryScope::Session => {
                    ctx.session_variables.lock().unwrap().remove(name);
                }
                MemoryScope::LongTerm => {
                    let mut memory = ctx.load_long_term()?;
                    memory.remove(name);
                    ctx.save_long_term(memory)?;
                }
                _ => return Err(anyhow!("Not implemented")),
            }
            Ok(())
        }
        Statement::Agent { .. } => Ok(()),
        Statement::Contract {
            name,
            issued_by,
            capabilities,
            expires,
        } => {
            ctx.active_contracts.lock().unwrap().insert(
                name.clone(),
                ContractInfo {
                    issued_by: issued_by.clone(),
                    capabilities: capabilities.clone(),
                    expires: *expires,
                },
            );
            Ok(())
        }
        Statement::Emit { event, data } => {
            let val = eval_expression(data, &ctx).await?;
            if val.is_sensitive {
                return Err(anyhow!(
                    "Privacy violation: Attempted to EMIT sensitive data for event '{}'",
                    event
                ));
            }
            println!(
                "  [Runtime] EMIT: {} (Data: {})",
                event,
                format_value_safe(&val)
            );
            let _ = ctx.event_tx.send(Event {
                name: event.clone(),
                data: val,
            });
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
                        for stmt in &handler_clone {
                            let _ = eval(stmt, ctx_clone.clone()).await;
                        }
                    }
                }
            });
            Ok(())
        }
        Statement::Prove {
            statements,
            proof_name,
        } => {
            println!(
                "  [Runtime] STARK: Generating proof for '{}'...",
                proof_name
            );
            // Phase 2.1: In a real system, we'd extract values from the 'statements' execution trace.
            // For this prototype, we prove a value derived from the hash of the resulting state.
            for stmt in statements {
                eval(stmt, ctx.clone()).await?;
            }

            let mut state_repr = String::new();
            {
                let vars = ctx.working_variables.lock().unwrap();
                let mut keys: Vec<_> = vars.keys().collect();
                keys.sort();
                for k in keys {
                    let v = vars.get(k).unwrap();
                    state_repr.push_str(&format!("{}:{:?}|", k, v.value));
                }
            }

            let hash = digest::digest(&digest::SHA256, state_repr.as_bytes());
            let hash_bytes = hash.as_ref();
            // Use first 4 bytes to determine steps, and next 4 as a "target" if we had one
            let steps =
                32 + (u32::from_be_bytes(hash_bytes[0..4].try_into().unwrap()) % 64) as usize;

            let proof = crypto::generate_proof(steps)?;
            ctx.proofs.lock().unwrap().insert(proof_name.clone(), proof);
            println!(
                "  [Runtime] STARK: Proof '{}' generated successfully ({} steps, state_hash={}).",
                proof_name,
                steps,
                hex::encode(&hash_bytes[0..8])
            );
            Ok(())
        }
        Statement::Reveal {
            proof_name,
            to_agent: _,
            result_into,
        } => {
            println!("  [Runtime] STARK: Verifying proof '{}'...", proof_name);
            let proof = {
                let proofs = ctx.proofs.lock().unwrap();
                proofs
                    .get(proof_name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Proof '{}' not found", proof_name))?
            };

            crypto::verify_proof(&proof)?;
            println!(
                "  [Runtime] STARK: Proof '{}' verified! (Public Input: col0={}, col1={})",
                proof_name, proof.col0_last, proof.col1_last
            );

            if let Some(var_name) = result_into {
                // Phase 2.1: In a production system, we'd decrypt the 'secret' committed to in the proof.
                // For this prototype, we store a confirmation of successful reveal.
                let reveal_val =
                    AnnotatedValue::from(Value::Text(format!("Unlocked via proof {}", proof_name)));
                ctx.set_variable(var_name.clone(), reveal_val, MemoryScope::Working)
                    .await?;
                println!(
                    "  [Runtime] REVEAL SUCCESS: Unlocked data stored in '{}'",
                    var_name
                );
            }
            Ok(())
        }
        Statement::UseWasm {
            module_path,
            function_name,
            args,
            result_into,
        } => {
            ctx.check_contracts(function_name)?;
            println!(
                "  [Runtime] USE_WASM: {} FUNCTION {}",
                module_path, function_name
            );
            let module = Module::from_file(&ctx.wasm_engine, module_path)?;
            let mut store = Store::new(&ctx.wasm_engine, ());
            store.set_fuel(1_000_000)?; // 1M fuel limit
            let linker = Linker::new(&ctx.wasm_engine);
            let instance = linker.instantiate(&mut store, &module)?;

            let func = instance
                .get_func(&mut store, function_name)
                .ok_or_else(|| anyhow!("Function '{}' not found in WASM module", function_name))?;

            let param_types: Vec<ValType> = func.ty(&store).params().collect();
            let mut wasm_args = Vec::new();

            // Map arguments to WASM types based on function signature
            for (i, (_name, expr)) in args.iter().enumerate() {
                if i >= param_types.len() {
                    break;
                }
                let val = eval_expression(expr, &ctx).await?;
                let p_type = &param_types[i];

                let wasm_val = match (p_type, &val.value) {
                    (ValType::I32, Value::Number(n)) => Val::I32(*n as i32),
                    (ValType::I32, Value::Text(s)) => {
                        // Phase 2.4: Handle strings by allocating in WASM memory
                        let memory = instance
                            .get_memory(&mut store, "memory")
                            .ok_or_else(|| anyhow!("Memory export not found for string passing"))?;
                        let alloc_func =
                            instance.get_func(&mut store, "alloc").ok_or_else(|| {
                                anyhow!("'alloc' export required to pass strings to WASM")
                            })?;

                        let mut alloc_res = vec![Val::I32(0)];
                        alloc_func.call(&mut store, &[Val::I32(s.len() as i32)], &mut alloc_res)?;
                        let ptr = alloc_res[0].i32().unwrap();

                        memory.write(&mut store, ptr as usize, s.as_bytes())?;
                        Val::I32(ptr)
                    }
                    (ValType::I64, Value::Number(n)) => Val::I64(*n as i64),
                    (ValType::F32, Value::Number(n)) => Val::F32((*n as f32).to_bits()),
                    (ValType::F64, Value::Number(n)) => Val::F64(n.to_bits()),
                    (ValType::I32, Value::Boolean(b)) => Val::I32(if *b { 1 } else { 0 }),
                    _ => {
                        return Err(anyhow!(
                            "WASM type mismatch for parameter {}: expected {:?}, got {:?}",
                            i,
                            p_type,
                            val.value
                        ));
                    }
                };
                wasm_args.push(wasm_val);
            }

            let result_types: Vec<ValType> = func.ty(&store).results().collect();
            let mut results = vec![Val::I32(0); result_types.len()];

            func.call(&mut store, &wasm_args, &mut results)?;

            let res_val = if let Some(res) = results.first() {
                match res {
                    Val::I32(ptr) => {
                        // Heuristic: If there's a memory export AND an alloc export,
                        // it's likely a pointer to a string.
                        let has_alloc = instance.get_func(&mut store, "alloc").is_some();
                        if has_alloc {
                            if let Some(memory) = instance.get_memory(&mut store, "memory") {
                                let data = memory.data(&store);
                                let ptr_usize = *ptr as usize;
                                if ptr_usize < data.len() && ptr_usize > 0 {
                                    let end = data[ptr_usize..]
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(data.len() - ptr_usize);
                                    if end > 0 {
                                        if let Ok(s) =
                                            std::str::from_utf8(&data[ptr_usize..ptr_usize + end])
                                        {
                                            Value::Text(s.to_string())
                                        } else {
                                            Value::Number(*ptr as f64)
                                        }
                                    } else {
                                        Value::Number(*ptr as f64)
                                    }
                                } else {
                                    Value::Number(*ptr as f64)
                                }
                            } else {
                                Value::Number(*ptr as f64)
                            }
                        } else {
                            Value::Number(*ptr as f64)
                        }
                    }
                    Val::I64(i) => Value::Number(*i as f64),
                    Val::F32(f) => Value::Number(f32::from_bits(*f) as f64),
                    Val::F64(f) => Value::Number(f64::from_bits(*f)),
                    _ => return Err(anyhow!("Unsupported WASM return type")),
                }
            } else {
                Value::Boolean(true) // Success but no return value
            };

            let mock_result = AnnotatedValue::from(res_val);
            ctx.set_variable(result_into.clone(), mock_result, MemoryScope::Working)
                .await?;
            Ok(())
        }
        Statement::Call {
            agent_id,
            goal_name,
            args,
            result_into,
        } => {
            ctx.check_contracts(goal_name)?;
            println!(
                "  [Runtime] CALL AGENT '{}': GOAL '{}' (Async)",
                agent_id, goal_name
            );

            // 1. Check for sensitive arguments FIRST (Privacy Policy)
            let mut rpc_args = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                if val.is_sensitive {
                    return Err(anyhow!(
                        "Privacy violation: Attempted to send sensitive argument '{}' to agent '{}'",
                        k,
                        agent_id
                    ));
                }
                rpc_args.insert(k.clone(), format!("{:?}", val.value));
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            ctx.pending_calls
                .lock()
                .unwrap()
                .insert(result_into.clone(), rx);

            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();

            tokio::spawn(async move {
                let res = async {
                    // 2. Lookup agent in registry (Federated lookup)
                    let mut lookup_res = None;
                    let registries = ctx_clone.registries.lock().unwrap().clone();

                    for reg_addr in registries {
                        if let Ok(mut reg_client) =
                            RegistryServiceClient::connect(reg_addr.clone()).await
                            && let Ok(res) = reg_client
                                .lookup_agent(LookupRequest {
                                    agent_id: agent_id_clone.clone(),
                                })
                                .await
                        {
                            let res = res.into_inner();
                            if res.found {
                                lookup_res = Some((reg_addr, res));
                                break;
                            }
                        }
                    }

                    let (_reg_addr, lookup_data) = lookup_res.ok_or_else(|| {
                        anyhow!(
                            "Agent '{}' not found in any registered registry",
                            agent_id_clone
                        )
                    })?;

                    // 3. Prepare sign
                    let caller_id = "PrimaryOrchestrator".to_string(); // In a real system, this comes from context
                    let payload = format!("{}:{}", goal_name_clone, caller_id);
                    let signature = ctx_clone
                        .identity
                        .signing_key
                        .sign(payload.as_bytes())
                        .to_bytes()
                        .to_vec();

                    let mut agent_client =
                        AgentServiceClient::connect(lookup_data.endpoint.clone())
                            .await
                            .map_err(|e| {
                                anyhow!(
                                    "Failed to connect to agent '{}' at {}: {}",
                                    agent_id_clone,
                                    lookup_data.endpoint,
                                    e
                                )
                            })?;

                    let response = agent_client
                        .call_goal(CallRequest {
                            goal_name: goal_name_clone,
                            args: rpc_args,
                            caller_id,
                            signature,
                        })
                        .await?
                        .into_inner();

                    if response.success {
                        Ok(AnnotatedValue::from(Value::Text(response.result_json)))
                    } else {
                        Err(anyhow!("Remote execution failed: {}", response.result_json))
                    }
                }
                .await;
                let _ = tx.send(res);
            });

            Ok(())
        }
        Statement::Await { call_id } => {
            println!("  [Runtime] AWAITING result for '{}'...", call_id);
            let rx = ctx
                .pending_calls
                .lock()
                .unwrap()
                .remove(call_id)
                .ok_or_else(|| anyhow!("No pending call found for ID '{}'", call_id))?;

            let result = rx
                .await
                .map_err(|_| anyhow!("Call task for '{}' panicked or was dropped", call_id))??;

            println!(
                "  [Runtime] AWAIT SUCCESS for '{}': {}",
                call_id,
                format_value_safe(&result)
            );
            ctx.set_variable(call_id.clone(), result, MemoryScope::Working)
                .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn init_bastion() {
        Bastion::init();
    }

    #[test]
    fn test_audit_chain() {
        let file_path = "test_audit.json".to_string();
        let _ = fs::remove_file(&file_path);
        let mut chain = AuditChain::new(file_path.clone());
        let h1 = chain.append("OP1".to_string());
        let h2 = chain.append("OP2".to_string());
        assert_ne!(h1, h2);
        assert_eq!(chain.entries.len(), 2);
        assert_eq!(chain.entries[1].prev_hash, h1);

        // Reload and verify persistence
        let chain2 = AuditChain::new(file_path.clone());
        assert_eq!(chain2.entries.len(), 2);
        assert_eq!(chain2.last_hash, h2);
        let _ = fs::remove_file(&file_path);
    }

    #[tokio::test]
    async fn test_eval_set_audited() {
        let audit_file = "test_eval_audit.json".to_string();
        let _ = fs::remove_file(&audit_file);
        let ctx = Context::new();
        {
            let mut audit = ctx.audit_chain.lock().unwrap();
            audit.file_path = audit_file.clone();
            audit.entries.clear();
            audit.last_hash = "genesis".to_string();
        }
        let stmt = Statement::Set {
            name: "x".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(ctx.audit_chain.lock().unwrap().entries.len(), 1);
        let _ = fs::remove_file(&audit_file);
    }

    #[tokio::test]
    async fn test_eval_expression_literal() {
        let ctx = Context::new();
        let expr = Expression::Literal(AnnotatedValue::from(Value::Number(42.0)));
        assert_eq!(
            eval_expression(&expr, &ctx).await.unwrap().value,
            Value::Number(42.0)
        );
    }

    #[tokio::test]
    async fn test_eval_expression_variable() {
        let ctx = Context::new();
        ctx.set_variable(
            "x".to_string(),
            AnnotatedValue::from(Value::Boolean(true)),
            MemoryScope::Working,
        )
        .await
        .unwrap();
        let expr = Expression::VariableRef("x".to_string());
        assert_eq!(
            eval_expression(&expr, &ctx).await.unwrap().value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_eval_set() {
        let ctx = Context::new();
        let stmt = Statement::Set {
            name: "y".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("hello".to_string()))),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("y", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("hello".to_string())
        );
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
        assert_eq!(
            ctx.get_variable("result", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("bar".to_string())
        );
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
        assert!(
            ctx.active_contracts
                .lock()
                .unwrap()
                .contains_key("test_contract")
        );
    }

    #[tokio::test]
    async fn test_event_emit_on() {
        let ctx = Context::new();
        let on_stmt = Statement::On {
            event: "ping".to_string(),
            handler: vec![Statement::Set {
                name: "pong".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            }],
        };
        let emit_stmt = Statement::Emit {
            event: "ping".to_string(),
            data: Expression::Literal(AnnotatedValue::from(Value::Text("hello".to_string()))),
        };
        eval(&on_stmt, ctx.clone()).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        eval(&emit_stmt, ctx.clone()).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        assert_eq!(
            ctx.get_variable("pong", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Boolean(true)
        );
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
        assert_eq!(
            ctx.get_variable("res", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("blue".to_string())
        );
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
                map.insert(
                    "a".to_string(),
                    Expression::Literal(AnnotatedValue::from(Value::Number(10.0))),
                );
                map.insert(
                    "b".to_string(),
                    Expression::Literal(AnnotatedValue::from(Value::Number(20.0))),
                );
                map
            },
            result_into: "wasm_res".to_string(),
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("wasm_res", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(30.0)
        );
    }

    #[tokio::test]
    async fn test_eval_remember_recall_encrypted() {
        let mut ctx = Context::new();
        ctx.long_term_file = "test_encrypted_memory.json".to_string();

        let remember = Statement::Remember {
            name: "secret_key".to_string(),
            value: Expression::Annotated {
                expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Text(
                    "top-secret-data".to_string(),
                )))),
                annotation: Annotation::Sensitive,
            },
            scope: MemoryScope::LongTerm,
            expires: None,
        };

        eval(&remember, ctx.clone()).await.unwrap();

        // Verify file content is actually JSON with StoredValue::Encrypted
        let file_data = fs::read_to_string(&ctx.long_term_file).unwrap();
        assert!(file_data.contains("Encrypted"));
        assert!(!file_data.contains("top-secret-data"));

        let recall = Statement::Recall {
            name: "secret_key".to_string(),
            into_var: "decrypted".to_string(),
            scope: MemoryScope::LongTerm,
            on_missing: None,
            fuzzy: false,
            threshold: None,
        };

        eval(&recall, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("decrypted", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("top-secret-data".to_string())
        );

        let _ = fs::remove_file(&ctx.long_term_file);
    }

    #[tokio::test]
    async fn test_eval_parallel_concurrency() {
        init_bastion();
        let ctx = Context::new();
        let start = std::time::Instant::now();
        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Gather,
            branches: vec![
                Statement::Wait { duration: 0.5 },
                Statement::Wait { duration: 0.5 },
                Statement::Wait { duration: 0.5 },
            ],
            result_into: Some("p_res".to_string()),
            deadline: None,
        };
        eval(&stmt, ctx.clone()).await.unwrap();
        let elapsed = start.elapsed();
        // If it was sequential, it would take 1.5s. Parallel should take ~0.5s.
        assert!(
            elapsed.as_secs_f64() < 1.0,
            "Parallel execution took too long: {:?}",
            elapsed
        );
        assert_eq!(
            ctx.get_variable("p_res", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_eval_goal_retry() {
        init_bastion();
        let ctx = Context::new();
        // This goal will fail because the variable 'undefined_var' doesn't exist.
        let mut on_fail = HashMap::new();
        on_fail.insert(
            "*".to_string(),
            Statement::Set {
                name: "failed".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            },
        );

        let stmt = Statement::Goal {
            name: "retry_goal".to_string(),
            body: vec![Statement::Recall {
                name: "undefined_var".to_string(),
                into_var: "res".to_string(),
                scope: MemoryScope::Working,
                on_missing: None,
                fuzzy: false,
                threshold: None,
            }],
            retry: Some(2),
            on_fail,
            deadline: None,
            idempotent: false,
            fallback: None,
        };
        // It should still return Ok(()) because on_fail handles it.
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("failed", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_eval_goal_timeout() {
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "timeout_goal".to_string(),
            body: vec![Statement::Wait { duration: 1.0 }],
            retry: None,
            on_fail: HashMap::new(),
            deadline: Some(0.1),
            idempotent: false,
            fallback: None,
        };
        let res = eval(&stmt, ctx.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_eval_loop_foreach() {
        let ctx = Context::new();
        let list = vec![
            AnnotatedValue::from(Value::Number(1.0)),
            AnnotatedValue::from(Value::Number(2.0)),
            AnnotatedValue::from(Value::Number(3.0)),
        ];
        ctx.set_variable(
            "my_list".to_string(),
            AnnotatedValue::from(Value::List(list)),
            MemoryScope::Working,
        )
        .await
        .unwrap();
        ctx.set_variable(
            "total".to_string(),
            AnnotatedValue::from(Value::Number(0.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let foreach = Statement::ForEach {
            item: "x".to_string(),
            list: Expression::VariableRef("my_list".to_string()),
            body: vec![Statement::Set {
                name: "total".to_string(),
                value: Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef("total".to_string())),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::VariableRef("x".to_string())),
                },
            }],
        };

        eval(&foreach, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("total", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(6.0)
        );
    }

    #[tokio::test]
    async fn test_eval_loop_repeat() {
        let ctx = Context::new();
        ctx.set_variable(
            "counter".to_string(),
            AnnotatedValue::from(Value::Number(0.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let repeat = Statement::Repeat {
            condition: Expression::BinaryOp {
                left: Box::new(Expression::VariableRef("counter".to_string())),
                op: BinaryOperator::Eq,
                right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                    3.0,
                )))),
            },
            body: vec![Statement::Set {
                name: "counter".to_string(),
                value: Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef("counter".to_string())),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                        1.0,
                    )))),
                },
            }],
        };

        eval(&repeat, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("counter", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(3.0)
        );
    }

    #[tokio::test]
    async fn test_eval_approximate_comparison() {
        let ctx = Context::new();
        // 49.9 == 50.0 should be true with 5% tolerance
        let expr = Expression::BinaryOp {
            left: Box::new(Expression::Annotated {
                expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                    49.9,
                )))),
                annotation: Annotation::Approximate,
            }),
            op: BinaryOperator::Eq,
            right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                50.0,
            )))),
        };
        let res = eval_expression(&expr, &ctx).await.unwrap();
        assert_eq!(res.value, Value::Boolean(true));

        // 40.0 == 50.0 should be false even with tolerance
        let expr2 = Expression::BinaryOp {
            left: Box::new(Expression::Annotated {
                expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                    40.0,
                )))),
                annotation: Annotation::Approximate,
            }),
            op: BinaryOperator::Eq,
            right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                50.0,
            )))),
        };
        let res2 = eval_expression(&expr2, &ctx).await.unwrap();
        assert_eq!(res2.value, Value::Boolean(false));
    }

    #[tokio::test]
    async fn test_goal_idempotent() {
        init_bastion();
        let ctx = Context::new();
        ctx.set_variable(
            "count".to_string(),
            AnnotatedValue::from(Value::Number(0.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let stmt = Statement::Goal {
            name: "inc".to_string(),
            body: vec![Statement::Set {
                name: "count".to_string(),
                value: Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef("count".to_string())),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                        1.0,
                    )))),
                },
            }],
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            idempotent: true,
            fallback: None,
        };

        // First run
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("count", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(1.0)
        );

        // Second run - should skip
        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("count", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(1.0)
        );
    }

    #[tokio::test]
    async fn test_goal_fallback() {
        init_bastion();
        let ctx = Context::new();
        // Goal that fails
        let stmt = Statement::Goal {
            name: "fail_goal".to_string(),
            body: vec![Statement::Wait { duration: 0.5 }],
            retry: None,
            on_fail: HashMap::new(),
            deadline: Some(0.1),
            idempotent: false,
            fallback: Some(Expression::Literal(AnnotatedValue::from(Value::Text(
                "fallback_active".to_string(),
            )))),
        };

        eval(&stmt, ctx.clone()).await.unwrap();
        assert_eq!(
            ctx.get_variable("fail_goal.result", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("fallback_active".to_string())
        );
    }

    #[tokio::test]
    async fn test_contract_expiry() {
        let ctx = Context::new();
        // Add an expired contract
        ctx.active_contracts.lock().unwrap().insert(
            "expired_contract".to_string(),
            ContractInfo {
                issued_by: "acme".to_string(),
                capabilities: vec![],
                expires: Some(0.0), // Expired
            },
        );

        let call = Statement::Call {
            agent_id: "other".to_string(),
            goal_name: "any".to_string(),
            args: HashMap::new(),
            result_into: "res".to_string(),
        };

        let res = eval(&call, ctx.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Permission denied"));
    }
}
