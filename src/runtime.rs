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
        let mut rng = rand::rng();
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

#[derive(Debug)]
pub struct AgentError {
    pub failure_type: GoalFailureType,
    pub message: String,
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.failure_type, self.message)
    }
}

impl std::error::Error for AgentError {}

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
        return Err(anyhow!(AgentError {
            failure_type: GoalFailureType::Permission,
            message: format!("Privacy violation: Attempted to {} sensitive data", action),
        }));
    }

    if contains_uncertain_content(value) {
        return Err(anyhow!(AgentError {
            failure_type: GoalFailureType::Permission,
            message: format!(
                "Verification required: Attempted to {} uncertain data",
                action
            ),
        }));
    }

    Ok(())
}

pub trait MemoryBackend: Send + Sync {
    fn load(&self, session_key: &aead::LessSafeKey) -> Result<HashMap<String, AnnotatedValue>>;
    fn save(
        &self,
        session_key: &aead::LessSafeKey,
        memory: HashMap<String, AnnotatedValue>,
    ) -> Result<()>;
    /// Perform a fuzzy search over `memory` for a key matching `query`.
    /// Only results with a confidence score >= `threshold` (default 0.0) are returned.
    fn fuzzy_search(
        &self,
        query: &str,
        memory: &HashMap<String, AnnotatedValue>,
        threshold: Option<f64>,
    ) -> Result<Option<AnnotatedValue>>;
}

pub struct JsonFileBackend {
    pub file_path: String,
}

impl MemoryBackend for JsonFileBackend {
    fn load(&self, session_key: &aead::LessSafeKey) -> Result<HashMap<String, AnnotatedValue>> {
        if let Ok(data) = fs::read_to_string(&self.file_path) {
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

                        let decrypted = session_key
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

    fn save(
        &self,
        session_key: &aead::LessSafeKey,
        memory: HashMap<String, AnnotatedValue>,
    ) -> Result<()> {
        let mut stored = HashMap::new();
        for (k, v) in memory {
            if v.is_sensitive {
                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

                let mut in_out = serde_json::to_vec(&v)?;
                session_key
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
        fs::write(&self.file_path, data)?;
        Ok(())
    }

    fn fuzzy_search(
        &self,
        query: &str,
        memory: &HashMap<String, AnnotatedValue>,
        threshold: Option<f64>,
    ) -> Result<Option<AnnotatedValue>> {
        // Prototype: substring key match. Production would use a vector similarity search.
        let min_confidence = threshold.unwrap_or(0.0);
        for (k, v) in memory {
            if k.contains(query) {
                let confidence = 0.85;
                if confidence >= min_confidence {
                    let mut val = v.clone();
                    val.confidence = Some(confidence);
                    return Ok(Some(val));
                }
            }
        }
        Ok(None)
    }
}

type ToolHandlerFn =
    Arc<dyn Fn(HashMap<String, AnnotatedValue>) -> Result<AnnotatedValue> + Send + Sync>;

#[derive(Clone)]
pub struct Context {
    pub working_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_backend: Arc<Box<dyn MemoryBackend>>,
    pub shared_backend: Arc<Box<dyn MemoryBackend>>,
    pub identity: Arc<Identity>,
    /// The human-readable agent ID this context is registered under.
    /// Defaults to a hex prefix of the verifying key; should be updated
    /// after successful registry registration.
    pub agent_id: Arc<Mutex<String>>,
    pub active_contracts: Arc<Mutex<HashMap<String, ContractInfo>>>,
    pub event_tx: broadcast::Sender<Event>,
    pub audit_chain: Arc<Mutex<AuditChain>>,
    pub session_key: Arc<aead::LessSafeKey>,
    pub wasm_engine: Engine,
    pub proofs: Arc<Mutex<HashMap<String, crypto::StarkProof>>>,
    pub goals: Arc<Mutex<HashMap<String, GoalDefinition>>>,
    pub tools: Arc<Mutex<HashMap<String, ToolDefinition>>>,
    pub tool_handlers: Arc<Mutex<HashMap<String, ToolHandlerFn>>>,
    pub tool_call_timestamps: Arc<Mutex<HashMap<String, Vec<std::time::Instant>>>>,
    pub registries: Arc<Mutex<Vec<String>>>,
    pub pending_calls: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Receiver<AnnotatedValue>>>>,
}

#[derive(Clone)]
pub struct ContractInfo {
    pub issued_by: String,
    pub capabilities: Vec<Permission>,
    pub budget: Option<f64>,
    pub requires_confirmation: bool,
    /// Absolute Unix timestamp (seconds) at which this contract expires, if any.
    pub expires_at: Option<u64>,
}

impl Context {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);

        #[cfg(test)]
        let key_file = unique_test_path("agent-key");
        #[cfg(not(test))]
        let key_file = "agent.key".to_string();
        let mut key_bytes = [0u8; 32];
        if let Ok(env_key) = std::env::var("AGENTLANG_MASTER_KEY") {
            let hash = digest::digest(&digest::SHA256, env_key.as_bytes());
            key_bytes.copy_from_slice(hash.as_ref());
        } else if let Ok(existing_key) = fs::read(&key_file) {
            let existing_key: Vec<u8> = existing_key;
            if existing_key.len() == 32 {
                key_bytes.copy_from_slice(&existing_key);
            } else {
                rand::rng().fill_bytes(&mut key_bytes);
                let _ = fs::write(key_file, key_bytes);
            }
        } else {
            rand::rng().fill_bytes(&mut key_bytes);
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

        // Default agent ID derived from the verifying key so each instance has a
        // stable unique identifier even before registry registration.
        let default_agent_id = hex::encode(&identity.verifying_key.to_bytes()[..4]);

        let mut wasm_config = wasmtime::Config::new();
        wasm_config.consume_fuel(true);
        let wasm_engine = Engine::new(&wasm_config).unwrap();

        Self {
            working_variables: Arc::new(Mutex::new(HashMap::new())),
            session_variables: Arc::new(Mutex::new(HashMap::new())),
            long_term_backend: Arc::new(Box::new(JsonFileBackend {
                file_path: {
                    #[cfg(test)]
                    {
                        unique_test_path("memory")
                    }
                    #[cfg(not(test))]
                    {
                        "memory.json".to_string()
                    }
                },
            })),
            shared_backend: Arc::new(Box::new(JsonFileBackend {
                file_path: {
                    #[cfg(test)]
                    {
                        unique_test_path("shared-memory")
                    }
                    #[cfg(not(test))]
                    {
                        "shared_memory.json".to_string()
                    }
                },
            })),
            identity: Arc::new(identity),
            agent_id: Arc::new(Mutex::new(default_agent_id)),
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
            tool_handlers: Arc::new(Mutex::new(HashMap::new())),
            tool_call_timestamps: Arc::new(Mutex::new(HashMap::new())),
            registries: Arc::new(Mutex::new(vec!["http://[::1]:50050".to_string()])),
            pending_calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub async fn get_variable(&self, name: &str, scope: MemoryScope) -> Result<AnnotatedValue> {
        match scope {
            MemoryScope::Working => self
                .working_variables
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("Working variable '{}' not found", name)),
            MemoryScope::Session => self
                .session_variables
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("Session variable '{}' not found", name)),
            MemoryScope::LongTerm => {
                let memory = self.long_term_backend.load(&self.session_key)?;
                memory
                    .get(name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Long-term variable '{}' not found", name))
            }
            MemoryScope::Shared => {
                let registries = self
                    .registries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
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
        let contracts = self.active_contracts.lock().unwrap_or_else(|e| e.into_inner());
        if contracts.is_empty() {
            return Ok(());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut allowed = false;
        for (name, info) in contracts.iter() {
            // Skip contracts that have passed their absolute expiry timestamp.
            if let Some(expires_at) = info.expires_at {
                if expires_at <= now {
                    continue;
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
            let mut audit = self
                .audit_chain
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            audit.append(format!(
                "SET:{}:{:?}:{}",
                name,
                scope,
                format_value_safe(&value)
            ));
        }
        match scope {
            MemoryScope::Working => {
                self.working_variables
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(name, value);
            }
            MemoryScope::Session => {
                self.session_variables
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(name, value);
            }
            MemoryScope::LongTerm => {
                let mut memory = self.long_term_backend.load(&self.session_key)?;
                memory.insert(name, value);
                self.long_term_backend.save(&self.session_key, memory)?;
            }
            MemoryScope::Shared => {
                let value_json = serde_json::to_vec(&value)?;
                let registries = self
                    .registries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
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
                        break;
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

    pub async fn set_variable_path(
        &self,
        path: &VariablePath,
        value: AnnotatedValue,
        scope: MemoryScope,
    ) -> Result<()> {
        if path.segments.is_empty() {
            return self.set_variable(path.root.clone(), value, scope).await;
        }

        let mut root_val = match self.get_variable(&path.root, scope).await {
            Ok(v) => v,
            Err(_) => AnnotatedValue::from(Value::Object(HashMap::new())),
        };

        fn update_recursive(
            current: &mut AnnotatedValue,
            segments: &[PathSegment],
            value: AnnotatedValue,
        ) -> Result<()> {
            if segments.is_empty() {
                *current = value;
                return Ok(());
            }

            match &segments[0] {
                PathSegment::Field(field) => {
                    if let Value::Object(ref mut fields) = current.value {
                        let next = fields
                            .entry(field.clone())
                            .or_insert_with(|| AnnotatedValue::from(Value::Object(HashMap::new())));
                        update_recursive(next, &segments[1..], value)
                    } else {
                        Err(anyhow!("Cannot set field '{}' on non-object", field))
                    }
                }
                PathSegment::Index(index) => {
                    if let Value::List(ref mut items) = current.value {
                        if *index >= items.len() {
                            items.resize(*index + 1, AnnotatedValue::from(Value::Null));
                        }
                        update_recursive(&mut items[*index], &segments[1..], value)
                    } else {
                        Err(anyhow!("Cannot index into non-list at {}", index))
                    }
                }
            }
        }

        update_recursive(&mut root_val, &path.segments, value)?;
        self.set_variable(path.root.clone(), root_val, scope).await
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
    result_into: &Option<VariablePath>,
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
    } else if let Some(path) = result_into {
        let value = if path.segments.is_empty() {
            working_after
                .get(&path.root)
                .cloned()
                .unwrap_or_else(|| AnnotatedValue::from(Value::Null))
        } else {
            // Traverse to find the value at path
            let root_val = working_after
                .get(&path.root)
                .cloned()
                .unwrap_or_else(|| AnnotatedValue::from(Value::Null));
            resolve_path(&root_val, path).unwrap_or_else(|_| AnnotatedValue::from(Value::Null))
        };
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
            PathSegment::Field(field) => {
                // Support virtual metadata fields
                match field.as_str() {
                    "confidence" => {
                        current =
                            AnnotatedValue::from(Value::Number(current.confidence.unwrap_or(1.0)));
                        continue;
                    }
                    "sensitive" => {
                        current = AnnotatedValue::from(Value::Boolean(current.is_sensitive));
                        continue;
                    }
                    "uncertain" => {
                        current = AnnotatedValue::from(Value::Boolean(current.is_uncertain));
                        continue;
                    }
                    "approximate" => {
                        current = AnnotatedValue::from(Value::Boolean(current.is_approximate));
                        continue;
                    }
                    _ => {}
                }

                match &current_source.value {
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
                }
            }
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
            let tolerance = 0.05;

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
    if let Some(agent_err) = error.downcast_ref::<AgentError>() {
        return agent_err.failure_type.clone();
    }

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
            confirm_with: _confirm_with,         // TODO: implement human-in-the-loop confirmation
            timeout_confirmation: _timeout_confirmation, // TODO: implement confirmation timeout
            fallback,
        } => {
            println!("  [Runtime] Goal: {}", name);
            ctx.goals
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    name.clone(),
                    GoalDefinition {
                        body: body.clone(),
                        outputs: outputs.clone(),
                        result_into: result_into.clone(),
                        retry: retry.map(|n| n as usize),
                        on_fail: on_fail.clone(),
                        deadline: *deadline,
                        wait: *wait,
                        idempotent: *idempotent,
                        audit_trail: *audit_trail,
                        // Preserve parsed values even though execution of these fields
                        // is not yet implemented; keeps GoalDefinition consistent with AST.
                        confirm_with: _confirm_with.clone(),
                        timeout_confirmation: *_timeout_confirmation,
                        fallback: None,
                    },
                );

            if *idempotent {
                let audit = ctx.audit_chain.lock().unwrap_or_else(|e| e.into_inner());
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
                                let mut audit = ctx_clone
                                    .audit_chain
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
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
                    eval(fail_stmt, ctx.clone()).await
                } else if let Some(fallback_stmt) = fallback {
                    eval(fallback_stmt, ctx.clone()).await
                } else {
                    Err(e)
                }
            } else {
                Ok(())
            }
        }
        Statement::Set { variable, value } => {
            let val = eval_expression(value, &ctx).await?;
            ctx.set_variable(variable.clone(), val, MemoryScope::Working)
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
            args,
            result_into,
        } => {
            ctx.check_contracts(tool_name)?;
            println!("  [Runtime] USE TOOL: {}", tool_name);

            // 1. Lookup Tool Definition
            let tool = {
                let tools = ctx.tools.lock().unwrap();
                tools.get(tool_name).cloned().ok_or_else(|| {
                    anyhow!(AgentError {
                        failure_type: GoalFailureType::ToolFail,
                        message: format!("Tool '{}' not found in registry", tool_name),
                    })
                })?
            };

            // 2. Rate Limiting
            if let Some(ref limit_str) = tool.rate_limit {
                // Simple implementation: "N/period" (e.g., "10/1m")
                let parts: Vec<&str> = limit_str.split('/').collect();
                if parts.len() == 2
                    && let Ok(max_calls) = parts[0].parse::<usize>()
                {
                    let period_secs = match parts[1] {
                        "1s" => 1,
                        "1m" => 60,
                        "1h" => 3600,
                        _ => 60, // Default to 1 minute
                    };

                    let mut timestamps = ctx
                        .tool_call_timestamps
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let calls = timestamps.entry(tool_name.clone()).or_default();
                    let now = std::time::Instant::now();

                    // Clean up old timestamps
                    calls.retain(|t| now.duration_since(*t).as_secs() < period_secs);

                    if calls.len() >= max_calls {
                        return Err(anyhow!(AgentError {
                            failure_type: GoalFailureType::ToolFail,
                            message: format!(
                                "Rate limit exceeded for tool '{}': {}",
                                tool_name, limit_str
                            ),
                        }));
                    }
                    calls.push(now);
                }
            }

            // 3. Evaluate and Validate Inputs
            let mut evaluated_args = HashMap::new();
            for (name, expr) in args {
                evaluated_args.insert(name.clone(), eval_expression(expr, &ctx).await?);
            }

            for input_field in &tool.inputs {
                if input_field.required && !evaluated_args.contains_key(&input_field.name) {
                    return Err(anyhow!(AgentError {
                        failure_type: GoalFailureType::ToolFail,
                        message: format!(
                            "Missing required input '{}' for tool '{}'",
                            input_field.name, tool_name
                        ),
                    }));
                }
                // Basic type hint validation (prototype)
                if let Some(arg_val) = evaluated_args.get(&input_field.name) {
                    match input_field.type_hint.as_str() {
                        "number" | "float" | "int" => {
                            if !matches!(arg_val.value, Value::Number(_)) {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::ToolFail,
                                    message: format!(
                                        "Type mismatch for '{}': expected number, found {:?}",
                                        input_field.name, arg_val.value
                                    ),
                                }));
                            }
                        }
                        "text" | "string" => {
                            if !matches!(arg_val.value, Value::Text(_)) {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::ToolFail,
                                    message: format!(
                                        "Type mismatch for '{}': expected text, found {:?}",
                                        input_field.name, arg_val.value
                                    ),
                                }));
                            }
                        }
                        _ => {} // Skip others for now
                    }
                }
            }

            // 4. Execute (Native or Mock)
            let execution_future = async {
                let handler = {
                    let handlers = ctx
                        .tool_handlers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    handlers.get(tool_name).cloned()
                };

                if let Some(h) = handler {
                    // Use spawn_blocking to ensure we don't freeze the executor
                    // and allow timeouts to interrupt.
                    let args_for_spawn = evaluated_args.clone();
                    tokio::task::spawn_blocking(move || h(args_for_spawn))
                        .await
                        .map_err(|e| anyhow!("Tool execution panicked: {}", e))?
                } else {
                    // Fallback: Mock result based on schema
                    let mut res_fields = HashMap::new();
                    for output_field in &tool.outputs {
                        let mock_val = match output_field.type_hint.as_str() {
                            "number" | "float" | "int" => Value::Number(1.0),
                            "boolean" => Value::Boolean(true),
                            _ => Value::Text(format!("Mock result for {}", output_field.name)),
                        };
                        res_fields
                            .insert(output_field.name.clone(), AnnotatedValue::from(mock_val));
                    }
                    Ok(AnnotatedValue::from(Value::Object(res_fields)))
                }
            };

            let result = if let Some(d) = tool.timeout {
                match tokio::time::timeout(Duration::from_secs_f64(d), execution_future).await {
                    Ok(res) => res,
                    Err(_) => Err(anyhow!(AgentError {
                        failure_type: GoalFailureType::Timeout,
                        message: format!("Tool '{}' timed out after {}s", tool_name, d),
                    })),
                }
            } else {
                execution_future.await
            };

            let final_val = match result {
                Ok(val) => {
                    // 5. Audit Trail for Side Effects
                    if tool.side_effect {
                        let mut audit = ctx
                            .audit_chain
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        audit.append(format!("TOOL_EXEC:{}:{:?}", tool_name, evaluated_args));
                    }
                    val
                }
                Err(e) => return Err(e),
            };

            // 6. Assign result
            if let Some(path) = result_into {
                ctx.set_variable_path(path, final_val, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Parallel {
            pattern,
            branches,
            result_into,
            deadline,
        } => {
            let mut join_set = tokio::task::JoinSet::new();
            for (i, branch) in branches.iter().enumerate() {
                let branch_clone = branch.clone();
                let ctx_clone = ctx.clone();
                let branch_index = i;
                join_set.spawn(async move {
                    // Track variable changes in this branch
                    let vars_before = ctx_clone
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    for stmt in &branch_clone {
                        eval(stmt, ctx_clone.clone()).await?;
                    }
                    let vars_after = ctx_clone
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let mut changes = HashMap::new();
                    for (k, v) in vars_after {
                        if vars_before.get(&k) != Some(&v) {
                            changes.insert(k, v);
                        }
                    }
                    Ok::<(usize, HashMap<String, AnnotatedValue>), anyhow::Error>((
                        branch_index,
                        changes,
                    ))
                });
            }

            let pattern_clone = pattern.clone();
            let parallel_future = async move {
                let mut results = HashMap::new();
                match pattern_clone {
                    ParallelPattern::Gather | ParallelPattern::GatherAll => {
                        let mut branch_errors = Vec::new();
                        while let Some(res) = join_set.join_next().await {
                            match res? {
                                Ok((idx, changes)) => {
                                    results.insert(
                                        format!("branch_{}", idx),
                                        AnnotatedValue::from(Value::Object(changes)),
                                    );
                                }
                                Err(e) => branch_errors.push(e),
                            }
                        }
                        if pattern_clone == ParallelPattern::Gather && !branch_errors.is_empty() {
                            return Err(branch_errors.remove(0));
                        }
                        Ok::<AnnotatedValue, anyhow::Error>(AnnotatedValue::from(Value::Object(
                            results,
                        )))
                    }
                    ParallelPattern::Race => {
                        while let Some(res) = join_set.join_next().await {
                            if let Ok(Ok((idx, changes))) = res {
                                join_set.abort_all();
                                results.insert(
                                    "winner".to_string(),
                                    AnnotatedValue::from(Value::Number(idx as f64)),
                                );
                                results.insert(
                                    "data".to_string(),
                                    AnnotatedValue::from(Value::Object(changes)),
                                );
                                return Ok(AnnotatedValue::from(Value::Object(results)));
                            }
                        }
                        Err(anyhow!("All branches in RACE failed"))
                    }
                    ParallelPattern::GatherMin(n) => {
                        let mut success_count = 0;
                        while let Some(res) = join_set.join_next().await {
                            if let Ok(Ok((idx, changes))) = res {
                                results.insert(
                                    format!("branch_{}", idx),
                                    AnnotatedValue::from(Value::Object(changes)),
                                );
                                success_count += 1;
                                if success_count >= n {
                                    // We have enough results; cancel remaining tasks.
                                    join_set.abort_all();
                                    break;
                                }
                            }
                        }
                        if success_count < n {
                            return Err(anyhow!(
                                "GATHER_MIN failed: only {} branches succeeded",
                                success_count
                            ));
                        }
                        Ok(AnnotatedValue::from(Value::Object(results)))
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

            match result {
                Ok(agg_val) => {
                    if let Some(path) = result_into {
                        ctx.set_variable_path(path, agg_val, MemoryScope::Working)
                            .await?;
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Statement::Delegate {
            agent_id,
            goal_name,
            args,
        } => {
            ctx.check_contracts(goal_name)?;
            println!(
                "  [Runtime] DELEGATING goal '{}' to agent '{}'",
                goal_name, agent_id
            );

            let mut rpc_args = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("delegate argument '{}' to agent '{}'", k, agent_id),
                )?;
                rpc_args.insert(k.clone(), format!("{:?}", val.value));
            }

            let caller_id = ctx
                .agent_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();

            tokio::spawn(async move {
                let _ = async {
                    let mut lookup_res = None;
                    let registries = ctx_clone
                        .registries
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();

                    for reg_addr in registries {
                        if let Ok(mut reg_client) =
                            RegistryServiceClient::connect(reg_addr.clone()).await
                            && let Ok(res) = reg_client
                                .lookup_agent(LookupRequest {
                                    agent_id: agent_id_clone.clone(),
                                    ttl: 3,
                                })
                                .await
                        {
                            let res = res.into_inner();
                            if res.found {
                                lookup_res = Some(res);
                                break;
                            }
                        }
                    }

                    if let Some(lookup_data) = lookup_res {
                        let payload = format!("{}:{}", goal_name_clone, caller_id);
                        let signature = ctx_clone
                            .identity
                            .signing_key
                            .sign(payload.as_bytes())
                            .to_bytes()
                            .to_vec();

                        if let Ok(mut agent_client) =
                            AgentServiceClient::connect(lookup_data.endpoint.clone()).await
                        {
                            let _ = agent_client
                                .call_goal(CallRequest {
                                    goal_name: goal_name_clone,
                                    args: rpc_args,
                                    caller_id,
                                    signature,
                                })
                                .await;
                        }
                    }
                }
                .await;
            });

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
            name,
            value,
            scope,
            expires,
        } => {
            let val = eval_expression(value, &ctx).await?;
            if *scope == MemoryScope::Shared {
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("write shared memory '{}'", name),
                )?;
            }
            ctx.set_variable(name.clone(), val, *scope).await?;

            // Schedule automatic removal after the requested duration.
            if let Some(expires_secs) = expires {
                let ctx_clone = ctx.clone();
                let name_clone = name.clone();
                let scope_clone = *scope;
                let delay = *expires_secs;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    match scope_clone {
                        MemoryScope::Working => {
                            ctx_clone
                                .working_variables
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&name_clone);
                        }
                        MemoryScope::Session => {
                            ctx_clone
                                .session_variables
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&name_clone);
                        }
                        MemoryScope::LongTerm => {
                            if let Ok(mut memory) =
                                ctx_clone.long_term_backend.load(&ctx_clone.session_key)
                            {
                                memory.remove(&name_clone);
                                let _ = ctx_clone
                                    .long_term_backend
                                    .save(&ctx_clone.session_key, memory);
                            }
                        }
                        MemoryScope::Shared => {} // Shared expiry is not supported via current registry protocol
                    }
                });
            }
            Ok(())
        }
        Statement::Recall {
            name,
            into_var,
            scope,
            on_missing,
            fuzzy,
            threshold,
        } => {
            let result = if *fuzzy {
                // Fuzzy search over Shared scope is not supported because the registry
                // protocol only provides point lookups, not full key enumeration.
                if *scope == MemoryScope::Shared {
                    return Err(anyhow!(
                        "Fuzzy RECALL is not supported for Shared scope; use exact RECALL instead"
                    ));
                }
                let memory: HashMap<String, AnnotatedValue> = match scope {
                    MemoryScope::Working => ctx
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    MemoryScope::Session => ctx
                        .session_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    MemoryScope::LongTerm => ctx.long_term_backend.load(&ctx.session_key)?,
                    MemoryScope::Shared => unreachable!(),
                };
                ctx.long_term_backend
                    .fuzzy_search(name, &memory, *threshold)?
                    .ok_or_else(|| anyhow!("Fuzzy match not found"))
            } else {
                ctx.get_variable(name, *scope).await
            };

            match result {
                Ok(val) => {
                    let recalled = sanitize_recalled_value(val, *scope);
                    ctx.set_variable(into_var.clone(), recalled, MemoryScope::Working)
                        .await?;
                }
                Err(_) => {
                    if let Some(expr) = on_missing {
                        let val = eval_expression(expr, &ctx).await?;
                        ctx.set_variable(into_var.clone(), val, MemoryScope::Working)
                            .await?;
                    } else {
                        return Err(anyhow!("Key '{}' not found", name));
                    }
                }
            }
            Ok(())
        }
        Statement::Forget { name, scope } => {
            match scope {
                MemoryScope::Working => {
                    ctx.working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(name);
                }
                MemoryScope::Session => {
                    ctx.session_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(name);
                }
                MemoryScope::LongTerm => {
                    let mut memory = ctx.long_term_backend.load(&ctx.session_key)?;
                    memory.remove(name);
                    ctx.long_term_backend.save(&ctx.session_key, memory)?;
                }
                MemoryScope::Shared => {
                    return Err(anyhow!(
                        "FORGET for Shared scope is not supported: \
                         the registry protocol does not provide a delete operation"
                    ));
                }
            }
            Ok(())
        }
        Statement::Agent { .. } => Ok(()),
        Statement::Contract {
            name,
            issued_by,
            capabilities,
            budget,
            requires_confirmation,
            expires,
        } => {
            // Convert the duration-based `expires` field to an absolute Unix timestamp
            // so that check_contracts can correctly compare against the current time.
            let expires_at = expires.map(|duration_secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_add(duration_secs as u64)
            });
            ctx.active_contracts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    name.clone(),
                    ContractInfo {
                        issued_by: issued_by.clone(),
                        capabilities: capabilities.clone(),
                        budget: *budget,
                        requires_confirmation: *requires_confirmation,
                        expires_at,
                    },
                );
            Ok(())
        }
        Statement::Emit { event, data } => {
            if let Some(expr) = data {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("emit event '{}'", event),
                )?;
                let _ = ctx.event_tx.send(Event {
                    name: event.clone(),
                    data: val,
                });
            } else {
                let _ = ctx.event_tx.send(Event {
                    name: event.clone(),
                    data: AnnotatedValue::from(Value::Null),
                });
            }
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
                        // Inject event payload
                        let mut event_obj = HashMap::new();
                        event_obj.insert("payload".to_string(), ev.data);
                        let _ = ctx_clone
                            .set_variable(
                                "event".to_string(),
                                AnnotatedValue::from(Value::Object(event_obj)),
                                MemoryScope::Working,
                            )
                            .await;

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
            claim,
            proof_name,
        } => {
            for stmt in statements {
                eval(stmt, ctx.clone()).await?;
            }

            let mut state_repr = String::new();
            {
                let vars = ctx
                    .working_variables
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut keys: Vec<_> = vars.keys().collect();
                keys.sort();
                for k in keys {
                    let v = vars.get(k).unwrap();
                    state_repr.push_str(&format!("{}:{:?}|", k, v.value));
                }
            }

            let hash = digest::digest(&digest::SHA256, state_repr.as_bytes());
            let hash_bytes = hash.as_ref();
            let mut steps =
                32 + (u32::from_be_bytes(hash_bytes[0..4].try_into().unwrap()) % 64) as usize;

            // Winterfell requires power-of-two trace length
            if !steps.is_power_of_two() {
                steps = steps.next_power_of_two();
            }

            let proof = crypto::generate_proof(steps, claim)?;
            ctx.proofs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(proof_name.clone(), proof);
            Ok(())
        }
        Statement::Reveal {
            proof_name,
            claim,
            to_agent: _,
            result_into,
        } => {
            let proof = {
                let proofs = ctx.proofs.lock().unwrap_or_else(|e| e.into_inner());
                proofs
                    .get(proof_name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Proof '{}' not found", proof_name))?
            };

            crypto::verify_proof(&proof, claim)?;

            if let Some(path) = result_into {
                let reveal_val = AnnotatedValue::from(Value::Text(format!(
                    "Unlocked via proof {} for claim {}",
                    proof_name, claim
                )));
                ctx.set_variable_path(path, reveal_val, MemoryScope::Working)
                    .await?;
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
            let module = Module::from_file(&ctx.wasm_engine, module_path)?;
            let mut store = Store::new(&ctx.wasm_engine, ());
            store.set_fuel(1_000_000)?;
            let linker = Linker::new(&ctx.wasm_engine);
            let instance = linker.instantiate(&mut store, &module)?;

            let func = instance
                .get_func(&mut store, function_name)
                .ok_or_else(|| anyhow!("Function '{}' not found in WASM module", function_name))?;

            let param_types: Vec<ValType> = func.ty(&store).params().collect();
            let mut wasm_args = Vec::new();

            for (i, (_name, expr)) in args.iter().enumerate() {
                if i >= param_types.len() {
                    break;
                }
                let val = eval_expression(expr, &ctx).await?;
                let p_type = &param_types[i];

                let wasm_val = match (p_type, &val.value) {
                    (ValType::I32, Value::Number(n)) => Val::I32(*n as i32),
                    (ValType::I32, Value::Text(s)) => {
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
                Value::Boolean(true)
            };

            let mock_result = AnnotatedValue::from(res_val);
            if let Some(path) = result_into {
                ctx.set_variable_path(path, mock_result, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Call {
            agent_id,
            goal_name,
            args,
            timeout,
            signed_by,
            result_into,
        } => {
            ctx.check_contracts(goal_name)?;
            let mut rpc_args = HashMap::new();
            let mut evaluated_args: HashMap<String, AnnotatedValue> = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("send argument '{}' to agent '{}'", k, agent_id),
                )?;
                rpc_args.insert(k.clone(), serde_json::to_string(&val)?);
                evaluated_args.insert(k.clone(), val);
            }

            let call_id_str = result_into
                .as_ref()
                .map(|p| p.root.clone())
                .unwrap_or_else(|| agent_id.clone());

            let pending_envelope =
                build_pending_call_envelope(&call_id_str, agent_id, goal_name, &evaluated_args);
            store_call_result(&ctx, &call_id_str, pending_envelope).await?;

            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Some(path) = result_into {
                ctx.pending_calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(path.root.clone(), rx);
            }

            let caller_id = ctx
                .agent_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();
            let timeout_val = *timeout;
            let _signed_by_val = signed_by.clone(); // TODO: verify incoming signature against registered key
            let result_into_clone = call_id_str;
            let evaluated_args_clone = evaluated_args.clone();

            tokio::spawn(async move {
                let res = async {
                    let mut lookup_res = None;
                    let registries = ctx_clone
                        .registries
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();

                    for reg_addr in registries {
                        if let Ok(mut reg_client) =
                            RegistryServiceClient::connect(reg_addr.clone()).await
                            && let Ok(res) = reg_client
                                .lookup_agent(LookupRequest {
                                    agent_id: agent_id_clone.clone(),
                                    ttl: 3,
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

                    let payload = format!("{}:{}", goal_name_clone, caller_id);
                    let signature = ctx_clone
                        .identity
                        .signing_key
                        .sign(payload.as_bytes())
                        .to_bytes()
                        .to_vec();

                    let mut agent_client =
                        AgentServiceClient::connect(lookup_data.endpoint.clone()).await?;

                    let rpc_call = agent_client.call_goal(CallRequest {
                        goal_name: goal_name_clone.clone(),
                        args: rpc_args,
                        caller_id,
                        signature,
                    });

                    let response = if let Some(d) = timeout_val {
                        match tokio::time::timeout(Duration::from_secs_f64(d), rpc_call).await {
                            Ok(res) => res?.into_inner(),
                            Err(_) => {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::Timeout,
                                    message: format!(
                                        "Call to '{}' timed out after {}s",
                                        agent_id_clone, d
                                    ),
                                }));
                            }
                        }
                    } else {
                        rpc_call.await?.into_inner()
                    };

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

                let envelope = res.unwrap_or_else(|e| {
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
        Statement::Await {
            call_id,
            result_into,
        } => {
            let rx = ctx
                .pending_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(call_id)
                .ok_or_else(|| anyhow!("No pending call found for ID '{}'", call_id))?;

            let envelope = rx
                .await
                .map_err(|_| anyhow!("Call task for '{}' panicked or was dropped", call_id))?;

            if let Some(path) = result_into {
                ctx.set_variable_path(path, envelope, MemoryScope::Working)
                    .await?;
            } else {
                ctx.set_variable(call_id.clone(), envelope, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Tool(def) => {
            println!("  [Runtime] Registering TOOL: {}", def.name);
            ctx.tools
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(def.name.clone(), def.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain() {
        let file_path = unique_test_path("test-audit");
        let _ = fs::remove_file(&file_path);
        let mut chain = AuditChain::new(file_path.clone());
        let h1 = chain.append("OP1".to_string());
        let h2 = chain.append("OP2".to_string());
        assert_ne!(h1, h2);
        assert_eq!(chain.entries.len(), 2);
        assert_eq!(chain.entries[1].prev_hash, h1);
        let _ = fs::remove_file(&file_path);
    }

    #[tokio::test]
    async fn test_set_variable_path() {
        let ctx = Context::new();
        let path = VariablePath {
            root: "trip".to_string(),
            segments: vec![PathSegment::Field("city".to_string())],
        };
        ctx.set_variable_path(
            &path,
            AnnotatedValue::from(Value::Text("London".to_string())),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let val = ctx
            .get_variable("trip", MemoryScope::Working)
            .await
            .unwrap();
        if let Value::Object(fields) = val.value {
            assert_eq!(
                fields.get("city").unwrap().value,
                Value::Text("London".to_string())
            );
        } else {
            panic!("Expected object");
        }
    }

    #[tokio::test]
    async fn test_eval_expression_complex_braces() {
        let ctx = Context::new();
        ctx.set_variable(
            "a".to_string(),
            AnnotatedValue::from(Value::Number(10.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();
        ctx.set_variable(
            "b".to_string(),
            AnnotatedValue::from(Value::Number(20.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::BinaryOp {
            left: Box::new(Expression::VariableRef(VariablePath::root("a"))),
            op: BinaryOperator::Add,
            right: Box::new(Expression::VariableRef(VariablePath::root("b"))),
        };

        assert_eq!(
            eval_expression(&expr, &ctx).await.unwrap().value,
            Value::Number(30.0)
        );
    }

    #[tokio::test]
    async fn test_on_handler_event_payload() {
        let ctx = Context::new();
        let on_stmt = Statement::On {
            event: "test_evt".to_string(),
            handler: vec![Statement::Set {
                variable: "res".to_string(),
                value: Expression::VariableRef(VariablePath {
                    root: "event".to_string(),
                    segments: vec![PathSegment::Field("payload".to_string())],
                }),
            }],
        };
        eval(&on_stmt, ctx.clone()).await.unwrap();

        let emit_stmt = Statement::Emit {
            event: "test_evt".to_string(),
            data: Some(Expression::Literal(AnnotatedValue::from(Value::Text(
                "hello".to_string(),
            )))),
        };
        eval(&emit_stmt, ctx.clone()).await.unwrap();

        sleep(Duration::from_millis(200)).await;
        let res = ctx.get_variable("res", MemoryScope::Working).await.unwrap();
        assert_eq!(res.value, Value::Text("hello".to_string()));
    }

    #[tokio::test]
    async fn test_virtual_metadata_access() {
        let ctx = Context::new();
        let mut val = AnnotatedValue::from(Value::Number(100.0));
        val.confidence = Some(0.85);
        val.is_sensitive = true;
        ctx.set_variable("price".to_string(), val, MemoryScope::Working)
            .await
            .unwrap();

        let expr_conf = Expression::VariableRef(VariablePath {
            root: "price".to_string(),
            segments: vec![PathSegment::Field("confidence".to_string())],
        });
        assert_eq!(
            eval_expression(&expr_conf, &ctx).await.unwrap().value,
            Value::Number(0.85)
        );

        let expr_sens = Expression::VariableRef(VariablePath {
            root: "price".to_string(),
            segments: vec![PathSegment::Field("sensitive".to_string())],
        });
        assert_eq!(
            eval_expression(&expr_sens, &ctx).await.unwrap().value,
            Value::Boolean(true)
        );
    }

    #[tokio::test]
    async fn test_structured_error_routing() {
        let _guard = bastion_test_guard().await;
        ensure_bastion_started();
        let ctx = Context::new();

        let mut on_fail = HashMap::new();
        on_fail.insert(
            GoalFailureType::Permission,
            Statement::Set {
                variable: "failed".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Text(
                    "permission_denied".to_string(),
                ))),
            },
        );

        // This goal should trigger a Permission error due to uncertain data in EMIT
        let goal_stmt = Statement::Goal {
            name: "guarded_goal".to_string(),
            body: vec![
                Statement::Set {
                    variable: "uncertain_data".to_string(),
                    value: Expression::Annotated {
                        expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                            1.0,
                        )))),
                        annotation: Annotation::Uncertain,
                    },
                },
                Statement::Emit {
                    event: "dangerous".to_string(),
                    data: Some(Expression::VariableRef(VariablePath::root(
                        "uncertain_data",
                    ))),
                },
            ],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail,
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
            confirm_with: None,
            timeout_confirmation: None,
            fallback: None,
        };

        eval(&goal_stmt, ctx.clone()).await.unwrap();
        let res = ctx
            .get_variable("failed", MemoryScope::Working)
            .await
            .unwrap();
        assert_eq!(res.value, Value::Text("permission_denied".to_string()));
    }

    #[tokio::test]
    async fn test_real_tool_system() {
        let ctx = Context::new();

        // 1. Register a tool handler
        {
            let mut handlers = ctx.tool_handlers.lock().unwrap();
            handlers.insert(
                "add_numbers".to_string(),
                Arc::new(|args| {
                    let a = args.get("a").unwrap().value.clone();
                    let b = args.get("b").unwrap().value.clone();
                    if let (Value::Number(nv_a), Value::Number(nv_b)) = (a, b) {
                        Ok(AnnotatedValue::from(Value::Number(nv_a + nv_b)))
                    } else {
                        Err(anyhow!("Invalid types"))
                    }
                }),
            );
        }

        // 2. Execute TOOL declaration
        let tool_def = ToolDefinition {
            name: "add_numbers".to_string(),
            description: Some("Adds two numbers".to_string()),
            category: Some(ToolCategory::Read),
            version: Some("1.0.0".to_string()),
            inputs: vec![
                ToolField {
                    name: "a".to_string(),
                    type_hint: "number".to_string(),
                    required: true,
                    annotations: vec![],
                },
                ToolField {
                    name: "b".to_string(),
                    type_hint: "number".to_string(),
                    required: true,
                    annotations: vec![],
                },
            ],
            outputs: vec![ToolField {
                name: "result".to_string(),
                type_hint: "number".to_string(),
                required: true,
                annotations: vec![],
            }],
            reversible: false,
            side_effect: false,
            rate_limit: None,
            timeout: Some(1.0),
        };
        eval(&Statement::Tool(tool_def), ctx.clone()).await.unwrap();

        // 3. Use the tool
        let mut args = HashMap::new();
        args.insert(
            "a".to_string(),
            Expression::Literal(AnnotatedValue::from(Value::Number(10.0))),
        );
        args.insert(
            "b".to_string(),
            Expression::Literal(AnnotatedValue::from(Value::Number(20.0))),
        );

        let use_stmt = Statement::UseTool {
            tool_name: "add_numbers".to_string(),
            args,
            result_into: Some(VariablePath::root("res")),
        };

        eval(&use_stmt, ctx.clone()).await.unwrap();
        let res = ctx.get_variable("res", MemoryScope::Working).await.unwrap();
        assert_eq!(res.value, Value::Number(30.0));

        // 4. Test validation failure (missing arg)
        let invalid_use = Statement::UseTool {
            tool_name: "add_numbers".to_string(),
            args: HashMap::new(),
            result_into: None,
        };
        let err = eval(&invalid_use, ctx.clone()).await.unwrap_err();
        assert!(err.to_string().contains("Missing required input 'a'"));
    }

    #[tokio::test]
    async fn test_parallel_aggregation() {
        let _guard = bastion_test_guard().await;
        ensure_bastion_started();
        let ctx = Context::new();

        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Gather,
            branches: vec![
                vec![Statement::Set {
                    variable: "x".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
                }],
                vec![Statement::Set {
                    variable: "y".to_string(),
                    value: Expression::Literal(AnnotatedValue::from(Value::Number(2.0))),
                }],
            ],
            result_into: Some(VariablePath::root("res")),
            deadline: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();
        let res = ctx.get_variable("res", MemoryScope::Working).await.unwrap();
        if let Value::Object(branches) = res.value {
            assert!(branches.contains_key("branch_0"));
            assert!(branches.contains_key("branch_1"));
            if let Value::Object(ref branch_0) = branches.get("branch_0").unwrap().value {
                assert_eq!(branch_0.get("x").unwrap().value, Value::Number(1.0));
            } else {
                panic!("branch_0 should be an object");
            }
        } else {
            panic!("Parallel result should be an object, found {:?}", res.value);
        }
    }

    #[tokio::test]
    async fn test_race_aggregation() {
        let _guard = bastion_test_guard().await;
        ensure_bastion_started();
        let ctx = Context::new();

        let stmt = Statement::Parallel {
            pattern: ParallelPattern::Race,
            branches: vec![vec![Statement::Set {
                variable: "x".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
            }]],
            result_into: Some(VariablePath::root("res")),
            deadline: None,
        };

        eval(&stmt, ctx.clone()).await.unwrap();
        let res = ctx.get_variable("res", MemoryScope::Working).await.unwrap();
        if let Value::Object(fields) = res.value {
            assert!(fields.contains_key("winner"));
            assert!(fields.contains_key("data"));
        } else {
            panic!("Race result should be an object");
        }
    }

    #[tokio::test]
    async fn test_semantic_proof_binding() {
        let ctx = Context::new();

        let prove_stmt = Statement::Prove {
            statements: vec![Statement::Set {
                variable: "x".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
            }],
            claim: "balance_above_100".to_string(),
            proof_name: "p1".to_string(),
        };
        eval(&prove_stmt, ctx.clone()).await.unwrap();

        // 1. Reveal with correct claim
        let reveal_correct = Statement::Reveal {
            proof_name: "p1".to_string(),
            claim: "balance_above_100".to_string(),
            to_agent: None,
            result_into: Some(VariablePath::root("res_ok")),
        };
        eval(&reveal_correct, ctx.clone()).await.unwrap();
        assert!(
            ctx.get_variable("res_ok", MemoryScope::Working)
                .await
                .is_ok()
        );

        // 2. Reveal with wrong claim (should fail)
        let reveal_wrong = Statement::Reveal {
            proof_name: "p1".to_string(),
            claim: "is_admin".to_string(),
            to_agent: None,
            result_into: Some(VariablePath::root("res_fail")),
        };
        let err = eval(&reveal_wrong, ctx.clone()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Proof was not generated for this claim")
        );
    }

    #[tokio::test]
    async fn test_goal_retry_exhaustion() {
        let _guard = bastion_test_guard().await;
        ensure_bastion_started();
        let ctx = Context::new();
        let goal_stmt = Statement::Goal {
            name: "fail_forever".to_string(),
            body: vec![Statement::Recall {
                name: "nonexistent".to_string(),
                into_var: "x".to_string(),
                scope: MemoryScope::Working,
                on_missing: None,
                fuzzy: false,
                threshold: None,
            }],
            outputs: vec![],
            result_into: None,
            retry: Some(1),
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
            confirm_with: None,
            timeout_confirmation: None,
            fallback: None,
        };
        let res = eval(&goal_stmt, ctx.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_goal_idempotency() {
        let _guard = bastion_test_guard().await;
        ensure_bastion_started();
        let ctx = Context::new();
        let goal_name = "once".to_string();

        // Mock a success entry in audit log
        {
            let mut audit = ctx.audit_chain.lock().unwrap();
            audit.append(format!("GOAL_SUCCESS:{}", goal_name));
        }

        let goal_stmt = Statement::Goal {
            name: goal_name,
            body: vec![Statement::Set {
                variable: "run".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            }],
            outputs: vec![],
            result_into: None,
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: true,
            audit_trail: true,
            confirm_with: None,
            timeout_confirmation: None,
            fallback: None,
        };

        eval(&goal_stmt, ctx.clone()).await.unwrap();
        // Variable should NOT be set because it skipped
        assert!(ctx.get_variable("run", MemoryScope::Working).await.is_err());
    }

    #[tokio::test]
    async fn test_tool_rate_limiting() {
        let ctx = Context::new();
        let tool_def = ToolDefinition {
            name: "limited".to_string(),
            description: None,
            category: None,
            version: None,
            inputs: vec![],
            outputs: vec![],
            reversible: false,
            side_effect: false,
            rate_limit: Some("1/1m".to_string()),
            timeout: None,
        };
        eval(&Statement::Tool(tool_def), ctx.clone()).await.unwrap();

        let use_stmt = Statement::UseTool {
            tool_name: "limited".to_string(),
            args: HashMap::new(),
            result_into: None,
        };

        // First call ok
        eval(&use_stmt, ctx.clone()).await.unwrap();
        // Second call fails
        let err = eval(&use_stmt, ctx.clone()).await.unwrap_err();
        assert!(err.to_string().contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn test_tool_timeout() {
        let ctx = Context::new();
        {
            let mut handlers = ctx.tool_handlers.lock().unwrap();
            handlers.insert(
                "slow".to_string(),
                Arc::new(|_| {
                    // Use a loop to simulate long work that doesn't yield if we're on a single thread
                    // but actually the runtime should be multi-threaded in tests by default.
                    // The issue is likely that timeout needs the future to yield.
                    std::thread::sleep(Duration::from_millis(500));
                    Ok(AnnotatedValue::from(Value::Null))
                }),
            );
        }
        let tool_def = ToolDefinition {
            name: "slow".to_string(),
            description: None,
            category: None,
            version: None,
            inputs: vec![],
            outputs: vec![],
            reversible: false,
            side_effect: false,
            rate_limit: None,
            timeout: Some(0.01), // Very short timeout
        };
        eval(&Statement::Tool(tool_def), ctx.clone()).await.unwrap();

        let use_stmt = Statement::UseTool {
            tool_name: "slow".to_string(),
            args: HashMap::new(),
            result_into: None,
        };
        let err = eval(&use_stmt, ctx.clone()).await.unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_set_variable_path_index_expansion() {
        let ctx = Context::new();
        ctx.set_variable(
            "list".to_string(),
            AnnotatedValue::from(Value::List(vec![])),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let path = VariablePath {
            root: "list".to_string(),
            segments: vec![PathSegment::Index(2)],
        };
        ctx.set_variable_path(
            &path,
            AnnotatedValue::from(Value::Number(42.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let val = ctx
            .get_variable("list", MemoryScope::Working)
            .await
            .unwrap();
        if let Value::List(items) = val.value {
            assert_eq!(items.len(), 3);
            assert_eq!(items[2].value, Value::Number(42.0));
            assert_eq!(items[0].value, Value::Null);
        } else {
            panic!("Expected list");
        }
    }

    #[tokio::test]
    async fn test_eval_expression_binary_op_errors() {
        let ctx = Context::new();
        let l = Expression::Literal(AnnotatedValue::from(Value::Text("a".to_string())));
        let r = Expression::Literal(AnnotatedValue::from(Value::Number(1.0)));

        let expr = Expression::BinaryOp {
            left: Box::new(l),
            op: BinaryOperator::Add,
            right: Box::new(r),
        };
        assert!(eval_expression(&expr, &ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_delegate_execution_no_crash() {
        let ctx = Context::new();
        let stmt = Statement::Delegate {
            agent_id: "nonexistent".to_string(),
            goal_name: "test".to_string(),
            args: HashMap::new(),
        };
        // Should return Ok(()) immediately as it's async fire-and-forget
        assert!(eval(&stmt, ctx.clone()).await.is_ok());
    }

    #[tokio::test]
    async fn test_eval_expression_nested_path_errors() {
        let ctx = Context::new();
        ctx.set_variable(
            "obj".to_string(),
            AnnotatedValue::from(Value::Number(1.0)),
            MemoryScope::Working,
        )
        .await
        .unwrap();

        let expr = Expression::VariableRef(VariablePath {
            root: "obj".to_string(),
            segments: vec![PathSegment::Field("any".to_string())],
        });
        assert!(eval_expression(&expr, &ctx).await.is_err());
    }
}
