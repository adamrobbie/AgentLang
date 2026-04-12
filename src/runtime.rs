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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::pin::Pin;
#[cfg(test)]
use std::sync::LazyLock;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use wasmtime::*;

pub fn ensure_bastion_started() {
    static BASTION_START: Once = Once::new();
    BASTION_START.call_once(|| {
        Bastion::init();
        Bastion::start();
    });
}

type ToolAdapterFuture = Pin<Box<dyn Future<Output = Result<AnnotatedValue>> + Send>>;
type ToolAdapter = Arc<dyn Fn(HashMap<String, AnnotatedValue>) -> ToolAdapterFuture + Send + Sync>;

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
    pub tools: Arc<Mutex<HashMap<String, ToolDefinition>>>,
    pub tool_adapters: Arc<Mutex<HashMap<String, ToolAdapter>>>,
    pub approved_tool_actions: Arc<Mutex<HashSet<String>>>,
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
            tools: Arc::new(Mutex::new(HashMap::new())),
            tool_adapters: Arc::new(Mutex::new(HashMap::new())),
            approved_tool_actions: Arc::new(Mutex::new(HashSet::new())),
            registries: Arc::new(Mutex::new(vec!["http://[::1]:50050".to_string()])),
            pending_calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_tool_adapter<F, Fut>(&self, tool_name: &str, adapter: F)
    where
        F: Fn(HashMap<String, AnnotatedValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<AnnotatedValue>> + Send + 'static,
    {
        let wrapped: ToolAdapter = Arc::new(move |args| Box::pin(adapter(args)));
        self.tool_adapters
            .lock()
            .unwrap()
            .insert(tool_name.to_string(), wrapped);
    }

    pub fn get_tool_adapter(&self, tool_name: &str) -> Option<ToolAdapter> {
        self.tool_adapters.lock().unwrap().get(tool_name).cloned()
    }

    pub fn clear_tool_adapter(&self, tool_name: &str) {
        self.tool_adapters.lock().unwrap().remove(tool_name);
    }

    pub fn clear_all_tool_adapters(&self) {
        self.tool_adapters.lock().unwrap().clear();
    }

    pub fn approve_tool_action(&self, tool_name: &str) {
        self.approved_tool_actions
            .lock()
            .unwrap()
            .insert(tool_name.to_string());
    }

    pub fn revoke_tool_action(&self, tool_name: &str) {
        self.approved_tool_actions.lock().unwrap().remove(tool_name);
    }

    pub fn clear_tool_approvals(&self) {
        self.approved_tool_actions.lock().unwrap().clear();
    }

    fn consume_tool_approval(&self, tool_name: &str) -> bool {
        self.approved_tool_actions.lock().unwrap().remove(tool_name)
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

fn tool_capability_name(tool_name: &str) -> String {
    format!("tool:{}", tool_name)
}

fn default_tool_value(field: &ToolField) -> AnnotatedValue {
    let base = match field.type_name.as_str() {
        "text" => AnnotatedValue::from(Value::Text(format!("{} result", field.name))),
        "number" | "float" => AnnotatedValue::from(Value::Number(0.0)),
        "boolean" => AnnotatedValue::from(Value::Boolean(true)),
        "list" => AnnotatedValue::from(Value::List(Vec::new())),
        _ => AnnotatedValue::from(Value::Null),
    };
    apply_annotations(base, &field.annotations)
}

fn build_declared_tool_result(
    tool: &ToolDefinition,
    args: &HashMap<String, AnnotatedValue>,
) -> AnnotatedValue {
    let mut fields = HashMap::new();

    for output in &tool.output {
        let value = if output.name == "result" {
            args.values()
                .next()
                .cloned()
                .unwrap_or_else(|| default_tool_value(output))
        } else if let Some(input_value) = args.get(&output.name) {
            apply_annotations(input_value.clone(), &output.annotations)
        } else {
            default_tool_value(output)
        };
        fields.insert(output.name.clone(), value);
    }

    if fields.is_empty() {
        fields.insert(
            "result".to_string(),
            AnnotatedValue::from(Value::Text(format!("Executed tool {}", tool.name))),
        );
    } else if !fields.contains_key("result")
        && let Some(first_value) = fields.values().next().cloned()
    {
        fields.insert("result".to_string(), first_value);
    }

    AnnotatedValue::from(Value::Object(fields))
}

fn normalize_tool_result(tool: &ToolDefinition, result: AnnotatedValue) -> AnnotatedValue {
    let result = propagate_container_metadata(result);
    match result.value {
        Value::Object(mut fields) => {
            for output in &tool.output {
                if let Some(value) = fields.get_mut(&output.name) {
                    let updated = apply_annotations(value.clone(), &output.annotations);
                    *value = updated;
                }
            }

            if !fields.contains_key("result") {
                if let Some(first_output) = tool.output.first() {
                    if let Some(first_value) = fields.get(&first_output.name).cloned() {
                        fields.insert("result".to_string(), first_value);
                    }
                } else if let Some(first_value) = fields.values().next().cloned() {
                    fields.insert("result".to_string(), first_value);
                }
            }

            AnnotatedValue::from(Value::Object(fields))
        }
        other => AnnotatedValue::from(Value::Object(HashMap::from([(
            "result".to_string(),
            AnnotatedValue::from(other),
        )]))),
    }
}

fn ensure_tool_confirmation(ctx: &Context, tool: &ToolDefinition) -> Result<()> {
    if tool.side_effect && !tool.reversible && !ctx.consume_tool_approval(&tool.name) {
        return Err(anyhow!(
            "Tool '{}' requires confirmation before irreversible side effects",
            tool.name
        ));
    }

    Ok(())
}

fn validate_tool_invocation(
    ctx: &Context,
    tool: &ToolDefinition,
    args: &HashMap<String, AnnotatedValue>,
) -> Result<()> {
    for field in &tool.input {
        if field.required && !args.contains_key(&field.name) {
            return Err(anyhow!(
                "Tool '{}' missing required input '{}'",
                tool.name,
                field.name
            ));
        }
    }

    for arg_name in args.keys() {
        if !tool.input.iter().any(|field| field.name == *arg_name) {
            return Err(anyhow!(
                "Tool '{}' received undeclared input '{}'",
                tool.name,
                arg_name
            ));
        }
    }

    ensure_tool_confirmation(ctx, tool)?;

    Ok(())
}

async fn execute_declared_tool(
    ctx: &Context,
    tool: &ToolDefinition,
    args: &HashMap<String, AnnotatedValue>,
) -> Result<AnnotatedValue> {
    validate_tool_invocation(ctx, tool, args)?;

    let result = if let Some(adapter) = ctx.get_tool_adapter(&tool.name) {
        adapter(args.clone()).await?
    } else {
        build_declared_tool_result(tool, args)
    };

    Ok(normalize_tool_result(tool, result))
}

fn collect_changed_working_values_excluding(
    before: &HashMap<String, AnnotatedValue>,
    after: &HashMap<String, AnnotatedValue>,
    excluded_keys: &[String],
) -> HashMap<String, AnnotatedValue> {
    after
        .iter()
        .filter_map(|(key, value)| {
            if excluded_keys.iter().any(|excluded| excluded == key) {
                return None;
            }

            match before.get(key) {
                Some(previous) if previous == value => None,
                _ => Some((key.clone(), value.clone())),
            }
        })
        .collect()
}

fn collect_changed_working_values(
    before: &HashMap<String, AnnotatedValue>,
    after: &HashMap<String, AnnotatedValue>,
    goal_name: &str,
) -> HashMap<String, AnnotatedValue> {
    collect_changed_working_values_excluding(
        before,
        after,
        &[goal_name.to_string(), format!("{}.result", goal_name)],
    )
}

#[derive(Clone, Debug)]
struct ParallelBranchReport {
    index: usize,
    success: bool,
    result: AnnotatedValue,
    changes: HashMap<String, AnnotatedValue>,
    error: Option<String>,
}

impl ParallelBranchReport {
    fn to_value(&self) -> AnnotatedValue {
        let mut fields = HashMap::from([
            (
                "index".to_string(),
                AnnotatedValue::from(Value::Number(self.index as f64)),
            ),
            (
                "status".to_string(),
                AnnotatedValue::from(Value::Text(if self.success {
                    "ok".to_string()
                } else {
                    "error".to_string()
                })),
            ),
            ("result".to_string(), self.result.clone()),
            (
                "changes".to_string(),
                AnnotatedValue::from(Value::Object(self.changes.clone())),
            ),
        ]);

        if let Some(error) = &self.error {
            fields.insert(
                "error".to_string(),
                AnnotatedValue::from(Value::Text(error.clone())),
            );
        }

        AnnotatedValue::from(Value::Object(fields))
    }
}

fn clone_parallel_branch_context(
    ctx: &Context,
    working_seed: &HashMap<String, AnnotatedValue>,
    session_seed: &HashMap<String, AnnotatedValue>,
) -> Context {
    Context {
        working_variables: Arc::new(Mutex::new(working_seed.clone())),
        session_variables: Arc::new(Mutex::new(session_seed.clone())),
        long_term_file: ctx.long_term_file.clone(),
        shared_file: ctx.shared_file.clone(),
        identity: ctx.identity.clone(),
        active_contracts: ctx.active_contracts.clone(),
        event_tx: ctx.event_tx.clone(),
        audit_chain: ctx.audit_chain.clone(),
        session_key: ctx.session_key.clone(),
        wasm_engine: ctx.wasm_engine.clone(),
        proofs: ctx.proofs.clone(),
        goals: ctx.goals.clone(),
        tools: ctx.tools.clone(),
        tool_adapters: ctx.tool_adapters.clone(),
        approved_tool_actions: ctx.approved_tool_actions.clone(),
        registries: ctx.registries.clone(),
        pending_calls: ctx.pending_calls.clone(),
    }
}

fn extract_statement_result(
    statement: &Statement,
    after: &HashMap<String, AnnotatedValue>,
    changes: &HashMap<String, AnnotatedValue>,
) -> AnnotatedValue {
    let named_value = match statement {
        Statement::Goal { name, .. } => after
            .get(name)
            .cloned()
            .or_else(|| after.get(&format!("{}.result", name)).cloned()),
        Statement::UseTool { result_into, .. }
        | Statement::UseWasm { result_into, .. }
        | Statement::Call { result_into, .. } => after.get(result_into).cloned(),
        Statement::Set { name, .. }
        | Statement::Remember { name, .. }
        | Statement::Forget { name, .. } => after.get(name).cloned(),
        Statement::Recall { into_var, .. } => after.get(into_var).cloned(),
        Statement::Reveal {
            result_into: Some(result_into),
            ..
        }
        | Statement::Parallel {
            result_into: Some(result_into),
            ..
        } => after.get(result_into).cloned(),
        _ => None,
    };

    if let Some(value) = named_value {
        value
    } else if changes.len() == 1 {
        changes
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| AnnotatedValue::from(Value::Null))
    } else {
        AnnotatedValue::from(Value::Null)
    }
}

fn build_parallel_branch_report(
    index: usize,
    statement: &Statement,
    before: &HashMap<String, AnnotatedValue>,
    after: &HashMap<String, AnnotatedValue>,
    execution: Result<()>,
) -> ParallelBranchReport {
    let changes = collect_changed_working_values_excluding(before, after, &[]);
    let result = extract_statement_result(statement, after, &changes);

    match execution {
        Ok(()) => ParallelBranchReport {
            index,
            success: true,
            result,
            changes,
            error: None,
        },
        Err(error) => ParallelBranchReport {
            index,
            success: false,
            result,
            changes,
            error: Some(error.to_string()),
        },
    }
}

async fn merge_parallel_changes(ctx: &Context, reports: &[ParallelBranchReport]) -> Result<()> {
    let mut ordered_reports = reports.iter().collect::<Vec<_>>();
    ordered_reports.sort_by_key(|report| report.index);

    for report in ordered_reports.into_iter().filter(|report| report.success) {
        for (key, value) in &report.changes {
            ctx.set_variable(key.clone(), value.clone(), MemoryScope::Working)
                .await?;
        }
    }

    Ok(())
}

fn build_parallel_result(
    pattern: &ParallelPattern,
    reports: &[ParallelBranchReport],
) -> AnnotatedValue {
    let mut ordered_reports = reports.to_vec();
    ordered_reports.sort_by_key(|report| report.index);

    match pattern {
        ParallelPattern::Race => {
            let winner = ordered_reports
                .iter()
                .find(|report| report.success)
                .cloned()
                .unwrap_or_else(|| ParallelBranchReport {
                    index: 0,
                    success: false,
                    result: AnnotatedValue::from(Value::Null),
                    changes: HashMap::new(),
                    error: None,
                });

            AnnotatedValue::from(Value::Object(HashMap::from([
                (
                    "winner_index".to_string(),
                    AnnotatedValue::from(Value::Number(winner.index as f64)),
                ),
                ("winner".to_string(), winner.result.clone()),
                ("outcome".to_string(), winner.to_value()),
                ("result".to_string(), winner.result),
            ])))
        }
        _ => {
            let successes = ordered_reports
                .iter()
                .filter(|report| report.success)
                .count();
            let failures = ordered_reports.len().saturating_sub(successes);
            let outcomes = ordered_reports
                .iter()
                .map(|report| report.to_value())
                .collect::<Vec<_>>();
            let successful_results = ordered_reports
                .iter()
                .filter(|report| report.success)
                .map(|report| report.result.clone())
                .collect::<Vec<_>>();

            AnnotatedValue::from(Value::Object(HashMap::from([
                (
                    "results".to_string(),
                    AnnotatedValue::from(Value::List(outcomes)),
                ),
                (
                    "successes".to_string(),
                    AnnotatedValue::from(Value::Number(successes as f64)),
                ),
                (
                    "failures".to_string(),
                    AnnotatedValue::from(Value::Number(failures as f64)),
                ),
                (
                    "result".to_string(),
                    AnnotatedValue::from(Value::List(successful_results)),
                ),
            ])))
        }
    }
}

fn build_pending_remote_call_result(
    agent_id: &str,
    goal_name: &str,
    call_id: &str,
    args: &HashMap<String, AnnotatedValue>,
) -> AnnotatedValue {
    AnnotatedValue::from(Value::Object(HashMap::from([
        (
            "agent_id".to_string(),
            AnnotatedValue::from(Value::Text(agent_id.to_string())),
        ),
        (
            "goal".to_string(),
            AnnotatedValue::from(Value::Text(goal_name.to_string())),
        ),
        (
            "goal_name".to_string(),
            AnnotatedValue::from(Value::Text(goal_name.to_string())),
        ),
        (
            "call_id".to_string(),
            AnnotatedValue::from(Value::Text(call_id.to_string())),
        ),
        (
            "args".to_string(),
            AnnotatedValue::from(Value::Object(args.clone())),
        ),
        (
            "status".to_string(),
            AnnotatedValue::from(Value::Text("pending".to_string())),
        ),
        ("result".to_string(), AnnotatedValue::from(Value::Null)),
    ])))
}

fn build_remote_call_result(
    agent_id: &str,
    goal_name: &str,
    call_id: &str,
    args: &HashMap<String, AnnotatedValue>,
    outcome: Result<AnnotatedValue>,
) -> AnnotatedValue {
    let mut fields = HashMap::from([
        (
            "agent_id".to_string(),
            AnnotatedValue::from(Value::Text(agent_id.to_string())),
        ),
        (
            "goal".to_string(),
            AnnotatedValue::from(Value::Text(goal_name.to_string())),
        ),
        (
            "goal_name".to_string(),
            AnnotatedValue::from(Value::Text(goal_name.to_string())),
        ),
        (
            "call_id".to_string(),
            AnnotatedValue::from(Value::Text(call_id.to_string())),
        ),
        (
            "args".to_string(),
            AnnotatedValue::from(Value::Object(args.clone())),
        ),
    ]);

    match outcome {
        Ok(result) => {
            fields.insert(
                "status".to_string(),
                AnnotatedValue::from(Value::Text("completed".to_string())),
            );
            fields.insert("result".to_string(), result);
        }
        Err(error) => {
            fields.insert(
                "status".to_string(),
                AnnotatedValue::from(Value::Text("error".to_string())),
            );
            fields.insert(
                "error".to_string(),
                AnnotatedValue::from(Value::Text(error.to_string())),
            );
            fields.insert("result".to_string(), AnnotatedValue::from(Value::Null));
        }
    }

    AnnotatedValue::from(Value::Object(fields))
}

async fn execute_remote_call(
    ctx: Context,
    agent_id: String,
    goal_name: String,
    rpc_args: HashMap<String, String>,
) -> Result<AnnotatedValue> {
    let mut lookup_res = None;
    let registries = ctx.registries.lock().unwrap().clone();

    for reg_addr in registries {
        if let Ok(mut reg_client) = RegistryServiceClient::connect(reg_addr.clone()).await
            && let Ok(res) = reg_client
                .lookup_agent(LookupRequest {
                    agent_id: agent_id.clone(),
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

    let (_reg_addr, lookup_data) = lookup_res
        .ok_or_else(|| anyhow!("Agent '{}' not found in any registered registry", agent_id))?;

    let caller_id = "PrimaryOrchestrator".to_string();
    let payload = format!("{}:{}", goal_name, caller_id);
    let signature = ctx
        .identity
        .signing_key
        .sign(payload.as_bytes())
        .to_bytes()
        .to_vec();

    let mut agent_client = AgentServiceClient::connect(lookup_data.endpoint.clone())
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to connect to agent '{}' at {}: {}",
                agent_id,
                lookup_data.endpoint,
                e
            )
        })?;

    let response = agent_client
        .call_goal(CallRequest {
            goal_name,
            args: rpc_args,
            caller_id,
            signature,
        })
        .await?
        .into_inner();

    if response.success {
        serde_json::from_str::<AnnotatedValue>(&response.result_json)
            .or_else(|_| Ok(AnnotatedValue::from(Value::Text(response.result_json))))
    } else {
        Err(anyhow!("Remote execution failed: {}", response.result_json))
    }
}

async fn dispatch_remote_call(
    ctx: Context,
    agent_id: String,
    goal_name: String,
    call_id: String,
    args: HashMap<String, AnnotatedValue>,
) -> AnnotatedValue {
    let rpc_args = args
        .iter()
        .filter_map(|(key, value)| {
            serde_json::to_string(value)
                .ok()
                .map(|serialized| (key.clone(), serialized))
        })
        .collect::<HashMap<_, _>>();

    let outcome = execute_remote_call(ctx, agent_id.clone(), goal_name.clone(), rpc_args).await;
    build_remote_call_result(&agent_id, &goal_name, &call_id, &args, outcome)
}

async fn await_remote_call(ctx: Context, call_id: &str) -> Result<AnnotatedValue> {
    let receiver = ctx
        .pending_calls
        .lock()
        .unwrap()
        .remove(call_id)
        .ok_or_else(|| anyhow!("No pending call found for ID '{}'", call_id))?;

    receiver
        .await
        .map_err(|_| anyhow!("Call task for '{}' panicked or was dropped", call_id))
}

async fn store_remote_call_result(
    ctx: &Context,
    call_id: &str,
    envelope: AnnotatedValue,
) -> Result<()> {
    let flat_result = if let Value::Object(fields) = &envelope.value {
        fields.get("result").cloned()
    } else {
        None
    };

    ctx.set_variable(call_id.to_string(), envelope, MemoryScope::Working)
        .await?;

    if let Some(result) = flat_result {
        ctx.set_variable(format!("{}.result", call_id), result, MemoryScope::Working)
            .await?;
    }

    Ok(())
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
        Statement::Tool { definition } => {
            println!("  [Runtime] REGISTER TOOL: {}", definition.name);
            ctx.tools
                .lock()
                .unwrap()
                .insert(definition.name.clone(), definition.clone());
            Ok(())
        }
        Statement::UseTool {
            tool_name,
            args,
            result_into,
        } => {
            let capability = tool_capability_name(tool_name);
            ctx.check_contracts(&capability)?;

            let tool = {
                let tools = ctx.tools.lock().unwrap();
                tools
                    .get(tool_name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Tool '{}' is not declared", tool_name))?
            };

            println!("  [Runtime] USE TOOL: {}", tool_name);
            let mut evaluated_args = HashMap::new();
            for (arg_name, expr) in args {
                let value = eval_expression(expr, &ctx).await?;
                if tool.side_effect {
                    ensure_value_safe_for_irreversible_action(
                        &value,
                        &format!("send tool input '{}' to '{}'", arg_name, tool_name),
                    )?;
                }
                evaluated_args.insert(arg_name.clone(), value);
            }

            let execution = async { execute_declared_tool(&ctx, &tool, &evaluated_args).await };
            let result = if let Some(timeout_secs) = tool.timeout {
                match tokio::time::timeout(Duration::from_secs_f64(timeout_secs), execution).await {
                    Ok(res) => res,
                    Err(_) => {
                        return Err(anyhow!(
                            "Tool '{}' timed out after {}s",
                            tool_name,
                            timeout_secs
                        ));
                    }
                }
            } else {
                execution.await
            }?;

            ctx.set_variable(result_into.clone(), result, MemoryScope::Working)
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
            let working_seed = ctx.working_variables.lock().unwrap().clone();
            let session_seed = ctx.session_variables.lock().unwrap().clone();
            let branch_specs = branches
                .iter()
                .cloned()
                .enumerate()
                .collect::<Vec<(usize, Statement)>>();

            let mut join_set = tokio::task::JoinSet::new();
            for (index, stmt_clone) in branch_specs {
                let branch_ctx = clone_parallel_branch_context(&ctx, &working_seed, &session_seed);
                let branch_before = working_seed.clone();
                join_set.spawn(async move {
                    let execution = eval(&stmt_clone, branch_ctx.clone()).await;
                    let branch_after = branch_ctx.working_variables.lock().unwrap().clone();
                    build_parallel_branch_report(
                        index,
                        &stmt_clone,
                        &branch_before,
                        &branch_after,
                        execution,
                    )
                });
            }

            let pattern_clone = pattern.clone();
            let parallel_future = async move {
                let mut reports = Vec::new();
                match pattern_clone {
                    ParallelPattern::Gather | ParallelPattern::GatherAll => {
                        while let Some(res) = join_set.join_next().await {
                            let report = res?;
                            if pattern_clone == ParallelPattern::Gather && !report.success {
                                return Err(anyhow!(
                                    report
                                        .error
                                        .clone()
                                        .unwrap_or_else(|| "Parallel branch failed".to_string())
                                ));
                            }
                            reports.push(report);
                        }
                        Ok::<Vec<ParallelBranchReport>, anyhow::Error>(reports)
                    }
                    ParallelPattern::Race => {
                        while let Some(res) = join_set.join_next().await {
                            let report = res?;
                            let should_finish = report.success;
                            reports.push(report);
                            if should_finish {
                                join_set.abort_all();
                                while join_set.join_next().await.is_some() {}
                                break;
                            }
                        }

                        if reports.iter().any(|report| report.success) {
                            Ok::<Vec<ParallelBranchReport>, anyhow::Error>(reports)
                        } else {
                            let message = reports
                                .iter()
                                .find_map(|report| report.error.clone())
                                .unwrap_or_else(|| {
                                    "Race block completed without a winner".to_string()
                                });
                            Err(anyhow!(message))
                        }
                    }
                    ParallelPattern::GatherMin(n) => {
                        while let Some(res) = join_set.join_next().await {
                            let report = res?;
                            reports.push(report);
                            if reports.iter().filter(|report| report.success).count() >= n {
                                join_set.abort_all();
                                while join_set.join_next().await.is_some() {}
                                break;
                            }
                        }

                        if reports.iter().filter(|report| report.success).count() >= n {
                            Ok::<Vec<ParallelBranchReport>, anyhow::Error>(reports)
                        } else {
                            Err(anyhow!(
                                "Parallel block did not reach minimum successful branches ({})",
                                n
                            ))
                        }
                    }
                }
            };

            let reports = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), parallel_future).await {
                    Ok(res) => res,
                    Err(_) => Err(anyhow!("Parallel block timed out after {}s", d)),
                }
            } else {
                parallel_future.await
            }?;

            merge_parallel_changes(&ctx, &reports).await?;

            if let Some(var) = result_into {
                let aggregated = build_parallel_result(pattern, &reports);
                ctx.set_variable(var.clone(), aggregated, MemoryScope::Working)
                    .await?;
            }

            println!(
                "  [Runtime] Parallel FINISHED: success_count={}",
                reports.iter().filter(|report| report.success).count()
            );
            Ok(())
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
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("send argument '{}' to agent '{}'", k, agent_id),
                )?;
                evaluated_args.insert(k.clone(), val);
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            ctx.pending_calls
                .lock()
                .unwrap()
                .insert(result_into.clone(), rx);

            let pending_envelope =
                build_pending_remote_call_result(agent_id, goal_name, result_into, &evaluated_args);
            store_remote_call_result(&ctx, result_into, pending_envelope).await?;

            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();
            let call_id_clone = result_into.clone();
            tokio::spawn(async move {
                let envelope = dispatch_remote_call(
                    ctx_clone,
                    agent_id_clone,
                    goal_name_clone,
                    call_id_clone,
                    evaluated_args,
                )
                .await;
                let _ = tx.send(envelope);
            });

            Ok(())
        }
        Statement::Await { call_id } => {
            println!("  [Runtime] AWAITING result for '{}'...", call_id);
            let result = await_remote_call(ctx.clone(), call_id).await?;

            println!(
                "  [Runtime] AWAIT SUCCESS for '{}': {}",
                call_id,
                format_value_safe(&result)
            );
            store_remote_call_result(&ctx, call_id, result).await?;
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

        let result = ctx
            .get_variable("p_res", MemoryScope::Working)
            .await
            .unwrap();
        match result.value {
            Value::Object(fields) => {
                assert_eq!(fields.get("successes").unwrap().value, Value::Number(3.0));
                assert_eq!(fields.get("failures").unwrap().value, Value::Number(0.0));
                match &fields.get("result").unwrap().value {
                    Value::List(results) => assert_eq!(results.len(), 3),
                    other => panic!("expected aggregated result list, found {:?}", other),
                }
            }
            other => panic!("expected structured parallel result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_registration_and_use_store_structured_result() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "search".to_string(),
                description: Some("Search knowledge base".to_string()),
                category: ToolCategory::Read,
                version: Some("v1".to_string()),
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![
                    ToolField {
                        name: "result".to_string(),
                        type_name: "text".to_string(),
                        required: false,
                        annotations: vec![],
                    },
                    ToolField {
                        name: "confidence".to_string(),
                        type_name: "float".to_string(),
                        required: false,
                        annotations: vec![Annotation::Confidence],
                    },
                ],
                reversible: true,
                side_effect: false,
                timeout: Some(1.0),
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();

        let use_tool = Statement::UseTool {
            tool_name: "search".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text("flights".to_string()))),
            )]),
            result_into: "search_result".to_string(),
        };
        eval(&use_tool, ctx.clone()).await.unwrap();

        let result = ctx
            .get_variable("search_result", MemoryScope::Working)
            .await
            .unwrap();

        match result.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("flights".to_string())
                );
                let confidence = fields.get("confidence").unwrap();
                assert_eq!(confidence.value, Value::Number(0.0));
                assert_eq!(confidence.confidence, Some(1.0));
            }
            other => panic!("expected object tool result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_pending_remote_call_result_creates_pending_envelope() {
        let args = HashMap::from([(
            "city".to_string(),
            AnnotatedValue::from(Value::Text("Paris".to_string())),
        )]);

        let pending = build_pending_remote_call_result("AgentB", "plan_trip", "call_1", &args);

        match pending.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("status").unwrap().value,
                    Value::Text("pending".to_string())
                );
                assert_eq!(
                    fields.get("agent_id").unwrap().value,
                    Value::Text("AgentB".to_string())
                );
                assert_eq!(
                    fields.get("goal").unwrap().value,
                    Value::Text("plan_trip".to_string())
                );
                assert_eq!(
                    fields.get("goal_name").unwrap().value,
                    Value::Text("plan_trip".to_string())
                );
                assert_eq!(fields.get("result").unwrap().value, Value::Null);
                match &fields.get("args").unwrap().value {
                    Value::Object(arg_fields) => {
                        assert_eq!(
                            arg_fields.get("city").unwrap().value,
                            Value::Text("Paris".to_string())
                        );
                    }
                    other => panic!("expected args object, found {:?}", other),
                }
            }
            other => panic!("expected pending call envelope object, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_store_remote_call_result_persists_envelope_and_result_alias() {
        let ctx = Context::new();
        let args = HashMap::from([(
            "city".to_string(),
            AnnotatedValue::from(Value::Text("Paris".to_string())),
        )]);
        let envelope = build_remote_call_result(
            "AgentB",
            "plan_trip",
            "call_1",
            &args,
            Ok(AnnotatedValue::from(Value::Object(HashMap::from([(
                "destination".to_string(),
                AnnotatedValue::from(Value::Text("Paris".to_string())),
            )])))),
        );

        store_remote_call_result(&ctx, "call_1", envelope)
            .await
            .unwrap();

        let stored = ctx
            .get_variable("call_1", MemoryScope::Working)
            .await
            .unwrap();
        let alias = ctx
            .get_variable("call_1.result", MemoryScope::Working)
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
                            result_fields.get("destination").unwrap().value,
                            Value::Text("Paris".to_string())
                        );
                    }
                    other => panic!("expected nested result object, found {:?}", other),
                }
            }
            other => panic!("expected stored call envelope object, found {:?}", other),
        }

        match alias.value {
            Value::Object(result_fields) => {
                assert_eq!(
                    result_fields.get("destination").unwrap().value,
                    Value::Text("Paris".to_string())
                );
            }
            other => panic!("expected flat result alias object, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_await_remote_call_returns_completed_envelope() {
        let ctx = Context::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        ctx.pending_calls
            .lock()
            .unwrap()
            .insert("call_1".to_string(), rx);

        let args = HashMap::new();
        tokio::spawn(async move {
            let envelope = build_remote_call_result(
                "AgentB",
                "plan_trip",
                "call_1",
                &args,
                Ok(AnnotatedValue::from(Value::Text("done".to_string()))),
            );
            let _ = tx.send(envelope);
        });

        let awaited = await_remote_call(ctx, "call_1").await.unwrap();

        match awaited.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("status").unwrap().value,
                    Value::Text("completed".to_string())
                );
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("done".to_string())
                );
            }
            other => panic!("expected completed call envelope object, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_executes_registered_adapter() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "search".to_string(),
                description: Some("Search knowledge base".to_string()),
                category: ToolCategory::Read,
                version: Some("v1".to_string()),
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![
                    ToolField {
                        name: "result".to_string(),
                        type_name: "text".to_string(),
                        required: false,
                        annotations: vec![],
                    },
                    ToolField {
                        name: "confidence".to_string(),
                        type_name: "float".to_string(),
                        required: false,
                        annotations: vec![Annotation::Confidence],
                    },
                ],
                reversible: true,
                side_effect: false,
                timeout: Some(1.0),
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.register_tool_adapter("search", |args| async move {
            let query = args.get("query").cloned().unwrap();
            Ok(AnnotatedValue::from(Value::Object(HashMap::from([
                (
                    "result".to_string(),
                    AnnotatedValue::from(Value::Text(format!(
                        "adapter:{}",
                        format_value_safe(&query)
                    ))),
                ),
                (
                    "confidence".to_string(),
                    AnnotatedValue::from(Value::Number(0.87)),
                ),
            ]))))
        });

        let use_tool = Statement::UseTool {
            tool_name: "search".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text("flights".to_string()))),
            )]),
            result_into: "search_result".to_string(),
        };
        eval(&use_tool, ctx.clone()).await.unwrap();

        let result = ctx
            .get_variable("search_result", MemoryScope::Working)
            .await
            .unwrap();

        match result.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("adapter:Text(\"flights\")".to_string())
                );
                let confidence = fields.get("confidence").unwrap();
                assert_eq!(confidence.value, Value::Number(0.87));
                assert_eq!(confidence.confidence, Some(1.0));
            }
            other => panic!("expected object tool result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_without_adapter_falls_back_to_synthesized_result() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "search".to_string(),
                description: Some("Search knowledge base".to_string()),
                category: ToolCategory::Read,
                version: Some("v1".to_string()),
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![ToolField {
                    name: "result".to_string(),
                    type_name: "text".to_string(),
                    required: false,
                    annotations: vec![],
                }],
                reversible: true,
                side_effect: false,
                timeout: Some(1.0),
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();

        let use_tool = Statement::UseTool {
            tool_name: "search".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text("flights".to_string()))),
            )]),
            result_into: "search_result".to_string(),
        };
        eval(&use_tool, ctx.clone()).await.unwrap();

        let result = ctx
            .get_variable("search_result", MemoryScope::Working)
            .await
            .unwrap();

        match result.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("flights".to_string())
                );
            }
            other => panic!("expected object tool result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_timeout_from_registered_adapter() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "slow_search".to_string(),
                description: None,
                category: ToolCategory::Read,
                version: None,
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![ToolField {
                    name: "result".to_string(),
                    type_name: "text".to_string(),
                    required: false,
                    annotations: vec![],
                }],
                reversible: true,
                side_effect: false,
                timeout: Some(0.01),
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.register_tool_adapter("slow_search", |_args| async move {
            sleep(Duration::from_millis(50)).await;
            Ok(AnnotatedValue::from(Value::Text("too slow".to_string())))
        });

        let use_tool = Statement::UseTool {
            tool_name: "slow_search".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text("flights".to_string()))),
            )]),
            result_into: "search_result".to_string(),
        };

        let err = eval(&use_tool, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Tool 'slow_search' timed out after 0.01s")
        );
    }

    #[tokio::test]
    async fn test_declared_tool_adapter_scalar_result_is_wrapped() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "word_count".to_string(),
                description: None,
                category: ToolCategory::Read,
                version: None,
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![ToolField {
                    name: "count".to_string(),
                    type_name: "number".to_string(),
                    required: false,
                    annotations: vec![],
                }],
                reversible: true,
                side_effect: false,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.register_tool_adapter("word_count", |_args| async move {
            Ok(AnnotatedValue::from(Value::Number(3.0)))
        });

        let use_tool = Statement::UseTool {
            tool_name: "word_count".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text(
                    "three words here".to_string(),
                ))),
            )]),
            result_into: "word_count_result".to_string(),
        };
        eval(&use_tool, ctx.clone()).await.unwrap();

        let result = ctx
            .get_variable("word_count_result", MemoryScope::Working)
            .await
            .unwrap();

        match result.value {
            Value::Object(fields) => {
                assert_eq!(fields.get("result").unwrap().value, Value::Number(3.0));
            }
            other => panic!("expected object tool result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_missing_required_input_fails() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "search".to_string(),
                description: None,
                category: ToolCategory::Read,
                version: None,
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![],
                reversible: true,
                side_effect: false,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();

        let use_tool = Statement::UseTool {
            tool_name: "search".to_string(),
            args: HashMap::new(),
            result_into: "search_result".to_string(),
        };

        let err = eval(&use_tool, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Tool 'search' missing required input 'query'")
        );
    }

    #[tokio::test]
    async fn test_declared_tool_irreversible_side_effect_is_blocked() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "charge_card".to_string(),
                description: None,
                category: ToolCategory::Write,
                version: None,
                input: vec![ToolField {
                    name: "amount".to_string(),
                    type_name: "number".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![],
                reversible: false,
                side_effect: true,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();

        let use_tool = Statement::UseTool {
            tool_name: "charge_card".to_string(),
            args: HashMap::from([(
                "amount".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Number(42.0))),
            )]),
            result_into: "payment_result".to_string(),
        };

        let err = eval(&use_tool, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires confirmation before irreversible side effects")
        );
    }

    #[tokio::test]
    async fn test_declared_tool_irreversible_side_effect_executes_after_approval() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "charge_card".to_string(),
                description: None,
                category: ToolCategory::Write,
                version: None,
                input: vec![ToolField {
                    name: "amount".to_string(),
                    type_name: "number".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![],
                reversible: false,
                side_effect: true,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.approve_tool_action("charge_card");

        let use_tool = Statement::UseTool {
            tool_name: "charge_card".to_string(),
            args: HashMap::from([(
                "amount".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Number(42.0))),
            )]),
            result_into: "payment_result".to_string(),
        };

        eval(&use_tool, ctx.clone()).await.unwrap();

        let result = ctx
            .get_variable("payment_result", MemoryScope::Working)
            .await
            .unwrap();
        match result.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("Executed tool charge_card".to_string())
                );
            }
            other => panic!("expected object tool result, found {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_declared_tool_approval_is_single_use() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "charge_card".to_string(),
                description: None,
                category: ToolCategory::Write,
                version: None,
                input: vec![ToolField {
                    name: "amount".to_string(),
                    type_name: "number".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![],
                reversible: false,
                side_effect: true,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.approve_tool_action("charge_card");

        let use_tool = Statement::UseTool {
            tool_name: "charge_card".to_string(),
            args: HashMap::from([(
                "amount".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Number(42.0))),
            )]),
            result_into: "payment_result".to_string(),
        };

        eval(&use_tool, ctx.clone()).await.unwrap();

        let err = eval(&use_tool, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires confirmation before irreversible side effects")
        );
    }

    #[tokio::test]
    async fn test_declared_tool_requires_contract_capability() {
        let ctx = Context::new();
        let declare = Statement::Tool {
            definition: ToolDefinition {
                name: "search".to_string(),
                description: None,
                category: ToolCategory::Read,
                version: None,
                input: vec![ToolField {
                    name: "query".to_string(),
                    type_name: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                output: vec![],
                reversible: true,
                side_effect: false,
                timeout: None,
            },
        };
        eval(&declare, ctx.clone()).await.unwrap();
        ctx.active_contracts.lock().unwrap().insert(
            "restrictive".to_string(),
            ContractInfo {
                issued_by: "registry".to_string(),
                capabilities: vec![Permission::CannotUse("tool:search".to_string())],
                expires: None,
            },
        );

        let use_tool = Statement::UseTool {
            tool_name: "search".to_string(),
            args: HashMap::from([(
                "query".to_string(),
                Expression::Literal(AnnotatedValue::from(Value::Text("hotels".to_string()))),
            )]),
            result_into: "search_result".to_string(),
        };

        let err = eval(&use_tool, ctx.clone()).await.unwrap_err();
        assert!(err.to_string().contains("Permission denied"));
    }

    #[tokio::test]
    async fn test_parallel_gather_collects_branch_results() {
        let ctx = Context::new();
        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Gather,
            branches: vec![
                Statement::Set {
                    name: "alpha".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
                },
                Statement::Set {
                    name: "beta".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Text("ok".to_string()))),
                },
            ],
            result_into: Some("parallel_result".to_string()),
            deadline: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        let aggregated = ctx
            .get_variable("parallel_result", MemoryScope::Working)
            .await
            .unwrap();

        match &aggregated.value {
            Value::Object(fields) => {
                assert_eq!(fields.get("successes").unwrap().value, Value::Number(2.0));
                assert_eq!(fields.get("failures").unwrap().value, Value::Number(0.0));

                match &fields.get("result").unwrap().value {
                    Value::List(results) => {
                        assert_eq!(results.len(), 2);
                        assert_eq!(results[0].value, Value::Number(1.0));
                        assert_eq!(results[1].value, Value::Text("ok".to_string()));
                    }
                    other => panic!("expected successful result list, found {:?}", other),
                }

                match &fields.get("results").unwrap().value {
                    Value::List(outcomes) => {
                        assert_eq!(outcomes.len(), 2);
                    }
                    other => panic!("expected outcome list, found {:?}", other),
                }
            }
            other => panic!("expected aggregated object result, found {:?}", other),
        }

        let nested_expr = Expression::VariableRef(VariablePath {
            root: "parallel_result".to_string(),
            segments: vec![
                PathSegment::Field("results".to_string()),
                PathSegment::Index(1),
                PathSegment::Field("result".to_string()),
            ],
        });
        assert_eq!(
            eval_expression(&nested_expr, &ctx).await.unwrap().value,
            Value::Text("ok".to_string())
        );

        assert_eq!(
            ctx.get_variable("alpha", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(1.0)
        );
        assert_eq!(
            ctx.get_variable("beta", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("ok".to_string())
        );
    }

    #[tokio::test]
    async fn test_parallel_gather_all_collects_successes_and_failures() {
        let ctx = Context::new();
        let stmt = Statement::Parallel {
            pattern: ParallelPattern::GatherAll,
            branches: vec![
                Statement::Set {
                    name: "completed".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Number(7.0))),
                },
                Statement::If {
                    condition: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
                    then_branch: vec![
                        Statement::Set {
                            name: "should_not_merge".to_string(),
                            value: Expression::Literal(AnnotatedValue::from(Value::Number(99.0))),
                        },
                        Statement::Recall {
                            name: "missing".to_string(),
                            into_var: "never".to_string(),
                            scope: MemoryScope::Working,
                            on_missing: None,
                            fuzzy: false,
                            threshold: None,
                        },
                    ],
                    else_branch: None,
                },
            ],
            result_into: Some("parallel_all_result".to_string()),
            deadline: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        let aggregated = ctx
            .get_variable("parallel_all_result", MemoryScope::Working)
            .await
            .unwrap();

        match &aggregated.value {
            Value::Object(fields) => {
                assert_eq!(fields.get("successes").unwrap().value, Value::Number(1.0));
                assert_eq!(fields.get("failures").unwrap().value, Value::Number(1.0));

                match &fields.get("result").unwrap().value {
                    Value::List(results) => {
                        assert_eq!(results.len(), 1);
                        assert_eq!(results[0].value, Value::Number(7.0));
                    }
                    other => panic!("expected successful result list, found {:?}", other),
                }

                match &fields.get("results").unwrap().value {
                    Value::List(outcomes) => {
                        assert_eq!(outcomes.len(), 2);
                        match &outcomes[1].value {
                            Value::Object(failure_fields) => {
                                assert_eq!(
                                    failure_fields.get("status").unwrap().value,
                                    Value::Text("error".to_string())
                                );
                                assert!(failure_fields.contains_key("error"));
                            }
                            other => panic!("expected failure outcome object, found {:?}", other),
                        }
                    }
                    other => panic!("expected outcome list, found {:?}", other),
                }
            }
            other => panic!("expected aggregated object result, found {:?}", other),
        }

        assert_eq!(
            ctx.get_variable("completed", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Number(7.0)
        );
        assert!(
            ctx.get_variable("should_not_merge", MemoryScope::Working)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_race_first_into_stores_winner_details() {
        let ctx = Context::new();
        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Race,
            branches: vec![
                Statement::Wait { duration: 0.05 },
                Statement::Set {
                    name: "winner_payload".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Text(
                        "fast".to_string(),
                    ))),
                },
            ],
            result_into: Some("race_result".to_string()),
            deadline: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();

        let aggregated = ctx
            .get_variable("race_result", MemoryScope::Working)
            .await
            .unwrap();

        match &aggregated.value {
            Value::Object(fields) => {
                assert_eq!(
                    fields.get("winner_index").unwrap().value,
                    Value::Number(1.0)
                );
                assert_eq!(
                    fields.get("winner").unwrap().value,
                    Value::Text("fast".to_string())
                );
                assert_eq!(
                    fields.get("result").unwrap().value,
                    Value::Text("fast".to_string())
                );

                match &fields.get("outcome").unwrap().value {
                    Value::Object(outcome_fields) => {
                        assert_eq!(
                            outcome_fields.get("status").unwrap().value,
                            Value::Text("ok".to_string())
                        );
                    }
                    other => panic!("expected race outcome object, found {:?}", other),
                }
            }
            other => panic!("expected race object result, found {:?}", other),
        }

        let winner_expr = Expression::VariableRef(VariablePath {
            root: "race_result".to_string(),
            segments: vec![PathSegment::Field("winner".to_string())],
        });
        assert_eq!(
            eval_expression(&winner_expr, &ctx).await.unwrap().value,
            Value::Text("fast".to_string())
        );

        assert_eq!(
            ctx.get_variable("winner_payload", MemoryScope::Working)
                .await
                .unwrap()
                .value,
            Value::Text("fast".to_string())
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
