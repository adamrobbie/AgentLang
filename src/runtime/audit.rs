use crate::ast::{AnnotatedValue, GoalFailureType, Value};
use ring::digest;
use serde::{Deserialize, Serialize};
use std::fs;

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

        if let Ok(data) = serde_json::to_string_pretty(&self.entries) {
            let _ = fs::write(&self.file_path, data);
        }

        hash_str
    }
}

pub fn format_value_safe(val: &AnnotatedValue) -> String {
    format_value_safe_inner(val)
}

pub fn format_value_safe_inner(val: &AnnotatedValue) -> String {
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
