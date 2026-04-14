use crate::ast::*;
use crate::crypto;
use super::audit::{AuditChain, Event, format_value_safe};
use super::memory::{JsonFileBackend, MemoryBackend};
use super::registry_rpc::registry_service_client::RegistryServiceClient;
use super::registry_rpc::{GetSharedRequest, PutSharedRequest};
use anyhow::{Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use ring::{aead, digest};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use wasmtime::Engine;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

pub type ToolHandlerFn =
    Arc<dyn Fn(HashMap<String, AnnotatedValue>) -> Result<AnnotatedValue> + Send + Sync>;

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

#[derive(Clone)]
pub struct Context {
    pub working_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub session_variables: Arc<Mutex<HashMap<String, AnnotatedValue>>>,
    pub long_term_backend: Arc<Box<dyn MemoryBackend>>,
    pub shared_backend: Arc<Box<dyn MemoryBackend>>,
    pub identity: Arc<Identity>,
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

#[cfg(test)]
pub fn unique_test_path(prefix: &str) -> String {
    static TEST_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = TEST_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir()
        .join(format!("agentlang-{}-{}-{}", prefix, pid, id))
        .to_string_lossy()
        .into_owned()
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
        let contracts = self
            .active_contracts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if contracts.is_empty() {
            return Ok(());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut allowed = false;
        for (name, info) in contracts.iter() {
            if let Some(expires_at) = info.expires_at
                && expires_at <= now
            {
                continue;
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
            let mut audit = self.audit_chain.lock().unwrap_or_else(|e| e.into_inner());
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
