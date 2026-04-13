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
#[cfg(test)]
use std::sync::LazyLock;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use wasmtime::{Engine, Linker, Module, Store, Val, ValType};

pub fn ensure_bastion_started() {
    static BASTION_START: Once = Once::new();
    BASTION_START.call_once(|| {
        Bastion::init();
        Bastion::start();
    });
}

#[cfg(test)]
static BASTION_TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
pub async fn bastion_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    BASTION_TEST_MUTEX.lock().await
}

#[cfg(test)]
fn unique_test_path(prefix: &str) -> String {
    static TEST_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = TEST_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir()
        .join(format!("agentlang-{}-{}-{}", prefix, pid, id))
        .to_string_lossy()
        .into_owned()
}

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
    format_value_safe_inner(val)
}

fn format_value_safe_inner(val: &AnnotatedValue) -> String {
    if val.is_sensitive {
        return "[REDACTED]".to_string();
    }

    match &val.value {
        Value::List(items) => {
            let parts: Vec<String> = items.iter().map(format_value_safe_inner).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(fields) => {
            let mut parts: Vec<String> = fields
                .iter()
                .map(|(key, value)| format!("{}: {}", key, format_value_safe_inner(value)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(", "))
        }
        _ => format!("{:?}", val.value),
    }
}

fn merge_confidence(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn inherit_metadata(target: &mut AnnotatedValue, source: &AnnotatedValue) {
    target.confidence = merge_confidence(target.confidence, source.confidence);
    target.is_sensitive |= source.is_sensitive;
    target.is_uncertain |= source.is_uncertain;
    target.is_approximate |= source.is_approximate;
}

fn propagate_container_metadata(mut value: AnnotatedValue) -> AnnotatedValue {
    match &value.value {
        Value::List(items) => {
            for item in items {
                value.confidence = merge_confidence(value.confidence, item.confidence);
                value.is_approximate |= item.is_approximate;
                value.is_uncertain |= item.is_uncertain;
                value.is_sensitive |= item.is_sensitive;
            }
        }
        Value::Object(fields) => {
            for field in fields.values() {
                value.confidence = merge_confidence(value.confidence, field.confidence);
                value.is_approximate |= field.is_approximate;
                value.is_uncertain |= field.is_uncertain;
                value.is_sensitive |= field.is_sensitive;
            }
        }
        _ => {}
    }

    value
}

fn contains_sensitive_content(value: &AnnotatedValue) -> bool {
    value.is_sensitive
        || match &value.value {
            Value::List(items) => items.iter().any(contains_sensitive_content),
            Value::Object(fields) => fields.values().any(contains_sensitive_content),
            _ => false,
        }
}

fn contains_uncertain_content(value: &AnnotatedValue) -> bool {
    value.is_uncertain
        || match &value.value {
            Value::List(items) => items.iter().any(contains_uncertain_content),
            Value::Object(fields) => fields.values().any(contains_uncertain_content),
            _ => false,
        }
}

fn redact_sensitive_content(value: &AnnotatedValue) -> AnnotatedValue {
    if value.is_sensitive {
        let mut redacted = value.clone();
        redacted.value = Value::Text("[REDACTED]".to_string());
        return redacted;
    }

    let redacted_value = match &value.value {
        Value::List(items) => Value::List(items.iter().map(redact_sensitive_content).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), redact_sensitive_content(value)))
                .collect(),
        ),
        _ => value.value.clone(),
    };

    let mut redacted = value.clone();
    redacted.value = redacted_value;
    redacted
}

fn sanitize_recalled_value(value: AnnotatedValue, scope: MemoryScope) -> AnnotatedValue {
    match scope {
        MemoryScope::LongTerm | MemoryScope::Shared => redact_sensitive_content(&value),
        _ => value,
    }
}

fn ensure_value_safe_for_irreversible_action(value: &AnnotatedValue, action: &str) -> Result<()> {
    if contains_sensitive_content(value) {
        return Err(anyhow!(
            "Privacy violation: Attempted to {} sensitive data",
            action
        ));
    }

    if contains_uncertain_content(value) {
        return Err(anyhow!(
            "Verification required: Attempted to {} uncertain data",
            action
        ));
    }

    Ok(())
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
    pub goals: Arc<Mutex<HashMap<String, GoalDefinition>>>,
    pub registries: Arc<Mutex<Vec<String>>>,
    pub pending_calls: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Receiver<AnnotatedValue>>>>,
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
        #[cfg(test)]
        let key_file = unique_test_path("agent-key");
        #[cfg(not(test))]
        let key_file = "agent.key".to_string();
        let mut key_bytes = [0u8; 32];
        if let Ok(env_key) = std::env::var("AGENTLANG_MASTER_KEY") {
            let hash = digest::digest(&digest::SHA256, env_key.as_bytes());
            key_bytes.copy_from_slice(hash.as_ref());
            println!("  [Security] Using AGENTLANG_MASTER_KEY from environment.");
        } else if let Ok(existing_key) = fs::read(&key_file) {
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

        #[cfg(test)]
        let id_file = unique_test_path("agent-id");
        #[cfg(not(test))]
        let id_file = "agent.id".to_string();
        let identity = if let Ok(existing_id) = fs::read(&id_file) {
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
            long_term_file: {
                #[cfg(test)]
                {
                    unique_test_path("memory")
                }
                #[cfg(not(test))]
                {
                    "memory.json".to_string()
                }
            },
            shared_file: {
                #[cfg(test)]
                {
                    unique_test_path("shared-memory")
                }
                #[cfg(not(test))]
                {
                    "shared_memory.json".to_string()
                }
            },
            identity: Arc::new(identity),
            active_contracts: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            audit_chain: Arc::new(Mutex::new(AuditChain::new({
                #[cfg(test)]
                {
                    unique_test_path("audit")
                }
                #[cfg(not(test))]
                {
                    "audit.json".to_string()
                }
            }))),
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

fn apply_annotations(mut value: AnnotatedValue, annotations: &[Annotation]) -> AnnotatedValue {
    value = propagate_container_metadata(value);
    for annotation in annotations {
        match annotation {
            Annotation::Confidence => value.confidence = value.confidence.or(Some(1.0)),
            Annotation::Sensitive => value.is_sensitive = true,
            Annotation::Uncertain => value.is_uncertain = true,
            Annotation::Approximate => value.is_approximate = true,
        }
    }
    value
}

fn collect_changed_working_values(
    before: &HashMap<String, AnnotatedValue>,
    after: &HashMap<String, AnnotatedValue>,
    goal_name: &str,
) -> HashMap<String, AnnotatedValue> {
    after
        .iter()
        .filter_map(|(key, value)| {
            if key == goal_name || key == &format!("{}.result", goal_name) {
                return None;
            }

            match before.get(key) {
                Some(previous) if previous == value => None,
                _ => Some((key.clone(), value.clone())),
            }
        })
        .collect()
}

async fn build_goal_result(
    ctx: &Context,
    goal_name: &str,
    working_before: &HashMap<String, AnnotatedValue>,
    outputs: &[GoalOutput],
    result_into: &Option<String>,
) -> Result<AnnotatedValue> {
    let working_after = ctx.working_variables.lock().unwrap().clone();
    let mut fields = HashMap::new();

    if !outputs.is_empty() {
        for output in outputs {
            let value = working_after
                .get(&output.name)
                .cloned()
                .unwrap_or_else(|| AnnotatedValue::from(Value::Null));
            fields.insert(
                output.name.clone(),
                apply_annotations(value, &output.annotations),
            );
        }
    } else if let Some(result_var) = result_into {
        let value = working_after
            .get(result_var)
            .cloned()
            .unwrap_or_else(|| AnnotatedValue::from(Value::Null));
        fields.insert(result_var.clone(), value.clone());
        fields.insert("result".to_string(), value);
    } else {
        fields.extend(collect_changed_working_values(
            working_before,
            &working_after,
            goal_name,
        ));
    }

    Ok(AnnotatedValue::from(Value::Object(fields)))
}

async fn store_goal_result(ctx: &Context, goal_name: &str, result: AnnotatedValue) -> Result<()> {
    let flat_result = if let Value::Object(fields) = &result.value {
        fields.get("result").cloned()
    } else {
        None
    };

    ctx.set_variable(goal_name.to_string(), result, MemoryScope::Working)
        .await?;

    if let Some(value) = flat_result {
        ctx.set_variable(format!("{}.result", goal_name), value, MemoryScope::Working)
            .await?;
    }

    Ok(())
}

fn build_pending_call_envelope(
    call_id: &str,
    agent_id: &str,
    goal_name: &str,
    args: &HashMap<String, AnnotatedValue>,
) -> AnnotatedValue {
    let mut fields = HashMap::new();
    fields.insert(
        "call_id".to_string(),
        AnnotatedValue::from(Value::Text(call_id.to_string())),
    );
    fields.insert(
        "agent_id".to_string(),
        AnnotatedValue::from(Value::Text(agent_id.to_string())),
    );
    fields.insert(
        "goal_name".to_string(),
        AnnotatedValue::from(Value::Text(goal_name.to_string())),
    );
    fields.insert(
        "status".to_string(),
        AnnotatedValue::from(Value::Text("pending".to_string())),
    );
    fields.insert(
        "args".to_string(),
        AnnotatedValue::from(Value::Object(args.clone())),
    );
    fields.insert("result".to_string(), AnnotatedValue::from(Value::Null));
    AnnotatedValue::from(Value::Object(fields))
}

fn build_completed_call_envelope(
    call_id: &str,
    agent_id: &str,
    goal_name: &str,
    args: &HashMap<String, AnnotatedValue>,
    result: AnnotatedValue,
) -> AnnotatedValue {
    let mut fields = HashMap::new();
    fields.insert(
        "call_id".to_string(),
        AnnotatedValue::from(Value::Text(call_id.to_string())),
    );
    fields.insert(
        "agent_id".to_string(),
        AnnotatedValue::from(Value::Text(agent_id.to_string())),
    );
    fields.insert(
        "goal_name".to_string(),
        AnnotatedValue::from(Value::Text(goal_name.to_string())),
    );
    fields.insert(
        "status".to_string(),
        AnnotatedValue::from(Value::Text("completed".to_string())),
    );
    fields.insert(
        "args".to_string(),
        AnnotatedValue::from(Value::Object(args.clone())),
    );
    fields.insert("result".to_string(), result);
    AnnotatedValue::from(Value::Object(fields))
}

fn build_failed_call_envelope(
    call_id: &str,
    agent_id: &str,
    goal_name: &str,
    args: &HashMap<String, AnnotatedValue>,
    error: &str,
) -> AnnotatedValue {
    let mut fields = HashMap::new();
    fields.insert(
        "call_id".to_string(),
        AnnotatedValue::from(Value::Text(call_id.to_string())),
    );
    fields.insert(
        "agent_id".to_string(),
        AnnotatedValue::from(Value::Text(agent_id.to_string())),
    );
    fields.insert(
        "goal_name".to_string(),
        AnnotatedValue::from(Value::Text(goal_name.to_string())),
    );
    fields.insert(
        "status".to_string(),
        AnnotatedValue::from(Value::Text("error".to_string())),
    );
    fields.insert(
        "args".to_string(),
        AnnotatedValue::from(Value::Object(args.clone())),
    );
    fields.insert(
        "error".to_string(),
        AnnotatedValue::from(Value::Text(error.to_string())),
    );
    fields.insert("result".to_string(), AnnotatedValue::from(Value::Null));
    AnnotatedValue::from(Value::Object(fields))
}

async fn store_call_result(ctx: &Context, call_id: &str, envelope: AnnotatedValue) -> Result<()> {
    let flat_result = if let Value::Object(fields) = &envelope.value {
        fields.get("result").cloned()
    } else {
        None
    };

    ctx.set_variable(call_id.to_string(), envelope, MemoryScope::Working)
        .await?;

    if let Some(value) = flat_result {
        ctx.set_variable(format!("{}.result", call_id), value, MemoryScope::Working)
            .await?;
    }

    Ok(())
}

fn resolve_path(value: &AnnotatedValue, path: &VariablePath) -> Result<AnnotatedValue> {
    let mut current = value.clone();

    for segment in &path.segments {
        let current_source = current.clone();
        match segment {
            PathSegment::Field(field) => match &current_source.value {
                Value::Object(fields) => {
                    current = fields.get(field).cloned().ok_or_else(|| {
                        anyhow!(
                            "Field '{}' not found while resolving '{}.{}'",
                            field,
                            path.root,
                            field
                        )
                    })?;
                    inherit_metadata(&mut current, &current_source);
                }
                other => {
                    return Err(anyhow!(
                        "Cannot access field '{}' on non-object value {:?}",
                        field,
                        other
                    ));
                }
            },
            PathSegment::Index(index) => match &current_source.value {
                Value::List(items) => {
                    current = items.get(*index).cloned().ok_or_else(|| {
                        anyhow!(
                            "Index {} out of bounds while resolving '{}'",
                            index,
                            path.root
                        )
                    })?;
                    inherit_metadata(&mut current, &current_source);
                }
                other => {
                    return Err(anyhow!(
                        "Cannot index into non-list value {:?} at [{}]",
                        other,
                        index
                    ));
                }
            },
        }
    }

    Ok(propagate_container_metadata(current))
}

#[async_recursion]
pub async fn eval_expression(expr: &Expression, ctx: &Context) -> Result<AnnotatedValue> {
    match expr {
        Expression::Literal(val) => Ok(propagate_container_metadata(val.clone())),
        Expression::VariableRef(path) => {
            let root_value = if let Ok(v) = ctx.get_variable(&path.root, MemoryScope::Working).await
            {
                v
            } else {
                ctx.get_variable(&path.root, MemoryScope::Session).await?
            };

            resolve_path(&root_value, path)
        }
        Expression::Annotated { expr, annotation } => {
            let mut val = eval_expression(expr, ctx).await?;
            match annotation {
                Annotation::Confidence => val.confidence = Some(1.0),
                Annotation::Sensitive => val.is_sensitive = true,
                Annotation::Uncertain => val.is_uncertain = true,
                Annotation::Approximate => val.is_approximate = true,
            }
            Ok(propagate_container_metadata(val))
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
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for ADD"))
                    }
                }
                BinaryOperator::Sub => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = AnnotatedValue::from(Value::Number(l - r));
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for SUB"))
                    }
                }
                BinaryOperator::Eq => {
                    let mut res = if let (Value::Number(l), Value::Number(r)) =
                        (&l_val.value, &r_val.value)
                    {
                        if is_approx {
                            let diff = (l - r).abs();
                            let threshold = l.abs().max(r.abs()) * tolerance;
                            AnnotatedValue::from(Value::Boolean(diff <= threshold))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l == r))
                        }
                    } else {
                        AnnotatedValue::from(Value::Boolean(l_val.value == r_val.value))
                    };
                    inherit_metadata(&mut res, &l_val);
                    inherit_metadata(&mut res, &r_val);
                    Ok(res)
                }
                BinaryOperator::Gt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = if is_approx {
                            AnnotatedValue::from(Value::Boolean(l > &(r * (1.0 - tolerance))))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l > r))
                        };
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        Ok(res)
                    } else {
                        Err(anyhow!("GT only supports numbers"))
                    }
                }
                BinaryOperator::Lt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = if is_approx {
                            AnnotatedValue::from(Value::Boolean(l < &(r * (1.0 + tolerance))))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l < r))
                        };
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        Ok(res)
                    } else {
                        Err(anyhow!("LT only supports numbers"))
                    }
                }
            }
        }
    }
}

fn classify_goal_failure(error: &anyhow::Error) -> GoalFailureType {
    let error_msg = error.to_string().to_lowercase();

    if error_msg.contains("timed out") || error_msg.contains("timeout") {
        GoalFailureType::Timeout
    } else if error_msg.contains("permission denied") || error_msg.contains("privacy violation") {
        GoalFailureType::Permission
    } else if error_msg.contains("hallucination") {
        GoalFailureType::Hallucination
    } else if error_msg.contains("ambiguous") {
        GoalFailureType::Ambiguous
    } else if error_msg.contains("tool") {
        GoalFailureType::ToolFail
    } else {
        GoalFailureType::Any
    }
}

#[allow(unused_variables)]
#[async_recursion]
pub async fn eval(statement: &Statement, ctx: Context) -> Result<()> {
    match statement {
        Statement::Goal {
            name,
            body,
            outputs,
            result_into,
            retry,
            on_fail,
            deadline,
            wait,
            idempotent,
            audit_trail,
            fallback,
        } => {
            println!("  [Runtime] Goal: {}", name);
            ctx.goals.lock().unwrap().insert(
                name.clone(),
                GoalDefinition {
                    body: body.clone(),
                    outputs: outputs.clone(),
                    result_into: result_into.clone(),
                    retry: *retry,
                    on_fail: on_fail.clone(),
                    deadline: *deadline,
                    wait: *wait,
                    idempotent: *idempotent,
                    audit_trail: *audit_trail,
                    fallback: fallback.clone(),
                },
            );

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

            if let Some(delay) = wait {
                sleep(Duration::from_secs_f64(*delay)).await;
            }

            let max_retries = retry.unwrap_or(0);
            use tokio::task::JoinSet;

            let mut goal_tasks = JoinSet::new();
            let body_clone = body.clone();
            let ctx_clone = ctx.clone();
            let name_clone = name.clone();
            let outputs_clone = outputs.clone();
            let result_into_clone = result_into.clone();
            let working_before = ctx.working_variables.lock().unwrap().clone();
            let audit_enabled = *audit_trail;

            goal_tasks.spawn(async move {
                let mut current_attempt = 0;
                loop {
                    current_attempt += 1;
                    let mut res = Ok(());
                    for stmt in &body_clone {
                        if let Err(e) = eval(stmt, ctx_clone.clone()).await {
                            res = Err(e);
                            break;
                        }
                    }

                    match res {
                        Ok(_) => {
                            let goal_result = build_goal_result(
                                &ctx_clone,
                                &name_clone,
                                &working_before,
                                &outputs_clone,
                                &result_into_clone,
                            )
                            .await?;

                            store_goal_result(&ctx_clone, &name_clone, goal_result).await?;
                            if audit_enabled {
                                let mut audit = ctx_clone.audit_chain.lock().unwrap();
                                audit.append(format!("GOAL_SUCCESS:{}", name_clone));
                            }
                            return Ok::<(), anyhow::Error>(());
                        }
                        Err(e) => {
                            if current_attempt <= max_retries {
                                println!(
                                    "  [Runtime] Goal '{}' attempt {} failed: {}. Retrying...",
                                    name_clone, current_attempt, e
                                );
                            } else {
                                println!(
                                    "  [Runtime] Goal '{}' exhausted all {} retries.",
                                    name_clone,
                                    max_retries + 1
                                );
                                return Err(e);
                            }
                        }
                    }
                }
            });

            let result = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), goal_tasks.join_next())
                    .await
                {
                    Ok(Some(joined)) => joined.map_err(|e| anyhow!("Goal task failed: {}", e))?,
                    Ok(None) => Err(anyhow!("Goal task completed without a result")),
                    Err(_) => {
                        goal_tasks.abort_all();
                        while goal_tasks.join_next().await.is_some() {}
                        Err(anyhow!("Goal '{}' timed out after {}s", name, d))
                    }
                }
            } else {
                match goal_tasks.join_next().await {
                    Some(joined) => joined.map_err(|e| anyhow!("Goal task failed: {}", e))?,
                    None => Err(anyhow!("Goal task completed without a result")),
                }
            };

            if let Err(e) = result {
                let failure_type = classify_goal_failure(&e);

                if let Some(fail_stmt) = on_fail
                    .get(&failure_type)
                    .or_else(|| on_fail.get(&GoalFailureType::Any))
                {
                    println!(
                        "  [Runtime] Goal '{}' failed ({:?}). Executing ON_FAIL.",
                        name, failure_type
                    );
                    eval(fail_stmt, ctx.clone()).await
                } else if let Some(fallback_expr) = fallback {
                    println!(
                        "  [Runtime] Goal '{}' failed. Returning FALLBACK value.",
                        name
                    );
                    let val = eval_expression(fallback_expr, &ctx).await?;
                    store_goal_result(
                        &ctx,
                        name,
                        AnnotatedValue::from(Value::Object(HashMap::from([(
                            "result".to_string(),
                            val,
                        )]))),
                    )
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
                Value::Object(o) => !o.is_empty(),
                Value::Null => false,
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
                    Value::Object(o) => !o.is_empty(),
                    Value::Null => false,
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
            if *scope == MemoryScope::Shared {
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("write shared memory '{}'", name),
                )?;
            }
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
                    let recalled = sanitize_recalled_value(val, *scope);
                    println!(
                        "  [Runtime] RECALL SUCCESS: {} -> {} (Value: {})",
                        name,
                        into_var,
                        format_value_safe(&recalled)
                    );
                    ctx.set_variable(into_var.clone(), recalled, MemoryScope::Working)
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
            ensure_value_safe_for_irreversible_action(&val, &format!("emit event '{}'", event))?;
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

            let mut evaluated_args = HashMap::new();
            let mut rpc_args = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("send argument '{}' to agent '{}'", k, agent_id),
                )?;
                rpc_args.insert(k.clone(), serde_json::to_string(&val)?);
                evaluated_args.insert(k.clone(), val);
            }

            let pending_envelope =
                build_pending_call_envelope(result_into, agent_id, goal_name, &evaluated_args);
            store_call_result(&ctx, result_into, pending_envelope).await?;

            let (tx, rx) = tokio::sync::oneshot::channel();
            ctx.pending_calls
                .lock()
                .unwrap()
                .insert(result_into.clone(), rx);

            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();
            let result_into_clone = result_into.clone();
            let evaluated_args_clone = evaluated_args.clone();

            tokio::spawn(async move {
                let envelope_result: Result<AnnotatedValue> = async {
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

                    let caller_id = "PrimaryOrchestrator".to_string();
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
                            goal_name: goal_name_clone.clone(),
                            args: rpc_args,
                            caller_id,
                            signature,
                        })
                        .await?
                        .into_inner();

                    if response.success {
                        let result = serde_json::from_str::<AnnotatedValue>(&response.result_json)
                            .or_else(|_| {
                                Ok::<AnnotatedValue, serde_json::Error>(AnnotatedValue::from(
                                    Value::Text(response.result_json.clone()),
                                ))
                            })?;
                        Ok(build_completed_call_envelope(
                            &result_into_clone,
                            &agent_id_clone,
                            &goal_name_clone,
                            &evaluated_args_clone,
                            result,
                        ))
                    } else {
                        Ok(build_failed_call_envelope(
                            &result_into_clone,
                            &agent_id_clone,
                            &goal_name_clone,
                            &evaluated_args_clone,
                            &response.result_json,
                        ))
                    }
                }
                .await;

                let envelope = envelope_result.unwrap_or_else(|e| {
                    build_failed_call_envelope(
                        &result_into_clone,
                        &agent_id_clone,
                        &goal_name_clone,
                        &evaluated_args_clone,
                        &e.to_string(),
                    )
                });
                let _ = tx.send(envelope);
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

            let envelope = rx
                .await
                .map_err(|_| anyhow!("Call task for '{}' panicked or was dropped", call_id))?;

            println!(
                "  [Runtime] AWAIT RESOLVED for '{}': {}",
                call_id,
                format_value_safe(&envelope)
            );
            store_call_result(&ctx, call_id, envelope).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn init_bastion() {
        ensure_bastion_started();
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
        let expr = Expression::VariableRef(VariablePath::root("x"));
        assert_eq!(
            eval_expression(&expr, &ctx).await.unwrap().value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_eval_expression_nested_field_path_inherits_annotations() {
        let ctx = Context::new();
        let mut city = HashMap::new();
        city.insert(
            "confidence".to_string(),
            AnnotatedValue::from(Value::Number(0.92)),
        );
        let mut travel = AnnotatedValue::from(Value::Object(HashMap::from([(
            "city".to_string(),
            AnnotatedValue::from(Value::Object(city)),
        )])));
        travel.is_sensitive = true;
        travel.confidence = Some(0.7);

        ctx.set_variable("travel".to_string(), travel, MemoryScope::Working)
            .await
            .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "travel".to_string(),
            segments: vec![
                PathSegment::Field("city".to_string()),
                PathSegment::Field("confidence".to_string()),
            ],
        });

        let resolved = eval_expression(&expr, &ctx).await.unwrap();
        assert_eq!(resolved.value, Value::Number(0.92));
        assert!(resolved.is_sensitive);
        assert_eq!(resolved.confidence, Some(0.7));
    }

    #[tokio::test]
    async fn test_eval_expression_nested_index_path() {
        let ctx = Context::new();
        let first = AnnotatedValue::from(Value::Object(HashMap::from([(
            "price".to_string(),
            AnnotatedValue::from(Value::Number(199.0)),
        )])));
        let second = AnnotatedValue::from(Value::Object(HashMap::from([(
            "price".to_string(),
            AnnotatedValue::from(Value::Number(249.0)),
        )])));

        ctx.set_variable(
            "results".to_string(),
            AnnotatedValue::from(Value::List(vec![first, second])),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "results".to_string(),
            segments: vec![
                PathSegment::Index(0),
                PathSegment::Field("price".to_string()),
            ],
        });

        assert_eq!(
            eval_expression(&expr, &ctx).await.unwrap().value,
            Value::Number(199.0)
        );
    }

    #[tokio::test]
    async fn test_eval_expression_missing_field_errors() {
        let ctx = Context::new();
        ctx.set_variable(
            "profile".to_string(),
            AnnotatedValue::from(Value::Object(HashMap::new())),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "profile".to_string(),
            segments: vec![PathSegment::Field("name".to_string())],
        });

        let err = eval_expression(&expr, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Field 'name' not found"));
    }

    #[tokio::test]
    async fn test_eval_expression_out_of_bounds_index_errors() {
        let ctx = Context::new();
        ctx.set_variable(
            "items".to_string(),
            AnnotatedValue::from(Value::List(vec![AnnotatedValue::from(Value::Number(1.0))])),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "items".to_string(),
            segments: vec![PathSegment::Index(2)],
        });

        let err = eval_expression(&expr, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Index 2 out of bounds"));
    }

    #[tokio::test]
    async fn test_eval_expression_field_access_on_scalar_errors() {
        let ctx = Context::new();
        ctx.set_variable(
            "count".to_string(),
            AnnotatedValue::from(Value::Number(3.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "count".to_string(),
            segments: vec![PathSegment::Field("value".to_string())],
        });

        let err = eval_expression(&expr, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Cannot access field 'value'"));
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
    async fn test_eval_expression_binary_op_propagates_confidence_and_uncertainty() {
        let ctx = Context::new();
        let mut left = AnnotatedValue::from(Value::Number(10.0));
        left.confidence = Some(0.81);
        left.is_uncertain = true;
        let mut right = AnnotatedValue::from(Value::Number(5.0));
        right.confidence = Some(0.93);

        let expr = Expression::BinaryOp {
            left: Box::new(Expression::Literal(left)),
            op: BinaryOperator::Add,
            right: Box::new(Expression::Literal(right)),
        };

        let result = eval_expression(&expr, &ctx).await.unwrap();
        assert_eq!(result.value, Value::Number(15.0));
        assert_eq!(result.confidence, Some(0.81));
        assert!(result.is_uncertain);
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
        let recalled = ctx
            .get_variable("decrypted", MemoryScope::Working)
            .await
            .unwrap();
        assert_eq!(recalled.value, Value::Text("[REDACTED]".to_string()));
        assert!(recalled.is_sensitive);

        let _ = fs::remove_file(&ctx.long_term_file);
    }

    #[tokio::test]
    async fn test_eval_recall_long_term_redacts_sensitive_content() {
        let mut ctx = Context::new();
        ctx.long_term_file = unique_test_path("test-encrypted-memory");

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

        let recall = Statement::Recall {
            name: "secret_key".to_string(),
            into_var: "decrypted".to_string(),
            scope: MemoryScope::LongTerm,
            on_missing: None,
            fuzzy: false,
            threshold: None,
        };

        eval(&recall, ctx.clone()).await.unwrap();
        let recalled = ctx
            .get_variable("decrypted", MemoryScope::Working)
            .await
            .unwrap();
        assert_eq!(recalled.value, Value::Text("[REDACTED]".to_string()));
        assert!(recalled.is_sensitive);

        let _ = fs::remove_file(&ctx.long_term_file);
    }

    #[tokio::test]
    async fn test_emit_blocks_nested_sensitive_content() {
        let ctx = Context::new();
        let payload = Expression::Literal(AnnotatedValue::from(Value::Object(HashMap::from([(
            "secret".to_string(),
            AnnotatedValue {
                value: Value::Text("classified".to_string()),
                confidence: None,
                is_sensitive: true,
                is_uncertain: false,
                is_approximate: false,
            },
        )]))));

        let stmt = Statement::Emit {
            event: "alarm".to_string(),
            data: payload,
        };

        let err = eval(&stmt, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("emit event 'alarm' sensitive data")
        );
    }

    #[tokio::test]
    async fn test_call_blocks_uncertain_arguments() {
        let ctx = Context::new();
        let stmt = Statement::Call {
            agent_id: "AgentB".to_string(),
            goal_name: "test_goal".to_string(),
            args: HashMap::from([(
                "amount".to_string(),
                Expression::Annotated {
                    expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                        10.0,
                    )))),
                    annotation: Annotation::Uncertain,
                },
            )]),
            result_into: "remote_res".to_string(),
        };

        let err = eval(&stmt, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("send argument 'amount' to agent 'AgentB' uncertain data")
        );
    }

    #[tokio::test]
    async fn test_shared_remember_blocks_sensitive_content() {
        let ctx = Context::new();
        let stmt = Statement::Remember {
            name: "shared_secret".to_string(),
            value: Expression::Annotated {
                expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Text(
                    "classified".to_string(),
                )))),
                annotation: Annotation::Sensitive,
            },
            scope: MemoryScope::Shared,
            expires: None,
        };

        let err = eval(&stmt, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("write shared memory 'shared_secret' sensitive data")
        );
    }

    #[tokio::test]
    async fn test_eval_parallel_concurrency() {
        let _guard = bastion_test_guard().await;
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
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        // This goal will fail because the variable 'undefined_var' doesn't exist.
        let mut on_fail = HashMap::new();
        on_fail.insert(
            GoalFailureType::Any,
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
            outputs: vec![],
            result_into: None,
            retry: Some(2),
            on_fail,
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
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
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "timeout_goal".to_string(),
            body: vec![Statement::Wait { duration: 1.0 }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: Some(0.1),
            wait: None,
            idempotent: false,
            audit_trail: true,
            fallback: None,
        };
        let res = eval(&stmt, ctx.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_goal_wait_and_timeout_specific_on_fail() {
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let mut on_fail = HashMap::new();
        on_fail.insert(
            GoalFailureType::Timeout,
            Statement::Set {
                name: "timeout_handled".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            },
        );

        let stmt = Statement::Goal {
            name: "guarded_timeout_goal".to_string(),
            body: vec![Statement::Wait { duration: 0.2 }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail,
            deadline: Some(0.05),
            wait: None,
            idempotent: false,
            audit_trail: true,
            fallback: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        assert_eq!(
            ctx.get_variable("timeout_handled", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_goal_wait_directive_delays_execution() {
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "delayed_goal".to_string(),
            body: vec![Statement::Set {
                name: "delayed_value".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: Some(0.05),
            idempotent: false,
            audit_trail: true,
            fallback: None,
        };

        let start = std::time::Instant::now();
        eval(&stmt, ctx.clone()).await.unwrap();
        assert!(start.elapsed().as_secs_f64() >= 0.05);
        assert_eq!(
            ctx.get_variable("delayed_value", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_goal_audit_trail_false_skips_success_audit_entry() {
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "quiet_goal".to_string(),
            body: vec![Statement::Set {
                name: "quiet_value".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: false,
            fallback: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        let audit_entries = ctx.audit_chain.lock().unwrap().entries.clone();
        assert!(
            audit_entries
                .iter()
                .all(|entry| !entry.op.starts_with("GOAL_SUCCESS:quiet_goal"))
        );
    }

    #[tokio::test]
    async fn test_goal_outputs_store_structured_result_object() {
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "search_flights".to_string(),
            body: vec![
                Statement::Set {
                    name: "flights".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::List(vec![
                        AnnotatedValue::from(Value::Text("BA-123".to_string())),
                    ]))),
                },
                Statement::Set {
                    name: "confidence".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Number(0.91))),
                },
            ],
            outputs: vec![
                GoalOutput {
                    name: "flights".to_string(),
                    type_name: "list".to_string(),
                    annotations: vec![],
                },
                GoalOutput {
                    name: "confidence".to_string(),
                    type_name: "float".to_string(),
                    annotations: vec![Annotation::Confidence],
                },
            ],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
            fallback: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        let goal_result = ctx
            .get_variable("search_flights", MemoryScope::Working)
            .await
            .unwrap();

        match goal_result.value {
            Value::Object(fields) => {
                assert!(fields.contains_key("flights"));
                let confidence = fields.get("confidence").unwrap();
                assert_eq!(confidence.value, Value::Number(0.91));
                assert_eq!(confidence.confidence, Some(1.0));
            }
            other => panic!("expected object goal result, found {:?}", other),
        }

        let confidence_expr = Expression::VariableRef(VariablePath {
            root: "search_flights".to_string(),
            segments: vec![PathSegment::Field("confidence".to_string())],
        });
        assert_eq!(
            eval_expression(&confidence_expr, &ctx).await.unwrap().value,
            Value::Number(0.91)
        );
    }

    #[tokio::test]
    async fn test_goal_result_into_creates_result_aliases() {
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        let stmt = Statement::Goal {
            name: "summarize".to_string(),
            body: vec![Statement::Set {
                name: "summary".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Text("done".to_string()))),
            }],
            outputs: vec![],
            result_into: Some("summary".to_string()),
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
            fallback: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        assert_eq!(
            ctx.get_variable("summarize.result", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("done".to_string())
        );

        let result_expr = Expression::VariableRef(VariablePath {
            root: "summarize".to_string(),
            segments: vec![PathSegment::Field("result".to_string())],
        });
        assert_eq!(
            eval_expression(&result_expr, &ctx).await.unwrap().value,
            Value::Text("done".to_string())
        );
    }

    #[tokio::test]
    async fn test_pending_call_envelope_has_pending_status_and_null_result() {
        let args = HashMap::from([(
            "amount".to_string(),
            AnnotatedValue::from(Value::Number(42.0)),
        )]);

        let envelope = build_pending_call_envelope("call_1", "AgentB", "pay", &args);
        match envelope.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("status").unwrap().value,
                    Value::Text("pending".to_string())
                );
                assert_eq!(
                    fields.get("call_id").unwrap().value,
                    Value::Text("call_1".to_string())
                );
                assert_eq!(fields.get("result").unwrap().value, Value::Null);
                match &fields.get("args").unwrap().value {
                    Value::Object(arg_fields) => {
                        assert_eq!(arg_fields.get("amount").unwrap().value, Value::Number(42.0));
                    }
                    other => panic!("expected args object, found {:?}", other),
                }
            }
            other => panic!("expected pending envelope object, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_store_call_result_persists_envelope_and_result_alias() {
        let ctx = Context::new();
        let nested_result = AnnotatedValue::from(Value::Object(HashMap::from([(
            "result".to_string(),
            AnnotatedValue::from(Value::Text("ok".to_string())),
        )])));
        let envelope = build_completed_call_envelope(
            "call_2",
            "AgentB",
            "pay",
            &HashMap::new(),
            nested_result.clone(),
        );

        store_call_result(&ctx, "call_2", envelope).await.unwrap();

        let stored = ctx
            .get_variable("call_2", MemoryScope::Working)
            .await
            .unwrap();
        match stored.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("status").unwrap().value,
                    Value::Text("completed".to_string())
                );
            }
            other => panic!("expected stored envelope object, found {:?}", other),
        }

        let alias = ctx
            .get_variable("call_2.result", MemoryScope::Working)
            .await
            .unwrap();
        assert_eq!(alias.value, nested_result.value);
    }

    #[tokio::test]
    async fn test_await_stores_completed_call_envelope() {
        let ctx = Context::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        ctx.pending_calls
            .lock()
            .unwrap()
            .insert("call_3".to_string(), rx);

        let completed = build_completed_call_envelope(
            "call_3",
            "AgentB",
            "pay",
            &HashMap::new(),
            AnnotatedValue::from(Value::Object(HashMap::from([(
                "result".to_string(),
                AnnotatedValue::from(Value::Text("done".to_string())),
            )]))),
        );

        tx.send(completed).unwrap();

        eval(
            &Statement::Await {
                call_id: "call_3".to_string(),
            },
            ctx.clone(),
        )
        .await
        .unwrap();

        let stored = ctx
            .get_variable("call_3", MemoryScope::Working)
            .await
            .unwrap();
        match stored.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("status").unwrap().value,
                    Value::Text("completed".to_string())
                );
                match &fields.get("result").unwrap().value {
                    Value::Object(result_fields) => {
                        assert_eq!(
                            result_fields.get("result").unwrap().value,
                            Value::Text("done".to_string())
                        );
                    }
                    other => panic!("expected nested result object, found {:?}", other),
                }
            }
            other => panic!("expected completed envelope object, found {:?}", other),
        }
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
            list: Expression::VariableRef(VariablePath::root("my_list")),
            body: vec![Statement::Set {
                name: "total".to_string(),
                value: Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef(VariablePath::root("total"))),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::VariableRef(VariablePath::root("x"))),
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
                left: Box::new(Expression::VariableRef(VariablePath::root("counter"))),
                op: BinaryOperator::Eq,
                right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                    3.0,
                )))),
            },
            body: vec![Statement::Set {
                name: "counter".to_string(),
                value: Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef(VariablePath::root("counter"))),
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
        let _guard = bastion_test_guard().await;
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
                    left: Box::new(Expression::VariableRef(VariablePath::root("count"))),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                        1.0,
                    )))),
                },
            }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: true,
            audit_trail: true,
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
        let _guard = bastion_test_guard().await;
        init_bastion();
        let ctx = Context::new();
        // Goal that fails
        let stmt = Statement::Goal {
            name: "fail_goal".to_string(),
            body: vec![Statement::Wait { duration: 0.5 }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: Some(0.1),
            wait: None,
            idempotent: false,
            audit_trail: true,
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
