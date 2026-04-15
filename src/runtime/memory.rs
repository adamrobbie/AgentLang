use super::audit::AgentError;
use crate::ast::{AnnotatedValue, GoalFailureType, MemoryScope, PathSegment, Value, VariablePath};
use anyhow::{Result, anyhow};
use rand::RngCore;
use ring::aead;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

pub fn merge_confidence(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub fn inherit_metadata(target: &mut AnnotatedValue, source: &AnnotatedValue) {
    target.confidence = merge_confidence(target.confidence, source.confidence);
    target.is_sensitive |= source.is_sensitive;
    target.is_uncertain |= source.is_uncertain;
    target.is_approximate |= source.is_approximate;
}

pub fn propagate_container_metadata(mut value: AnnotatedValue) -> AnnotatedValue {
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

pub fn contains_sensitive_content(value: &AnnotatedValue) -> bool {
    value.is_sensitive
        || match &value.value {
            Value::List(items) => items.iter().any(contains_sensitive_content),
            Value::Object(fields) => fields.values().any(contains_sensitive_content),
            _ => false,
        }
}

pub fn contains_uncertain_content(value: &AnnotatedValue) -> bool {
    value.is_uncertain
        || match &value.value {
            Value::List(items) => items.iter().any(contains_uncertain_content),
            Value::Object(fields) => fields.values().any(contains_uncertain_content),
            _ => false,
        }
}

pub fn redact_sensitive_content(value: &AnnotatedValue) -> AnnotatedValue {
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

pub fn sanitize_recalled_value(value: AnnotatedValue, scope: MemoryScope) -> AnnotatedValue {
    match scope {
        MemoryScope::LongTerm | MemoryScope::Shared => redact_sensitive_content(&value),
        _ => value,
    }
}

pub fn ensure_value_safe_for_irreversible_action(
    value: &AnnotatedValue,
    action: &str,
) -> Result<()> {
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
    fn fuzzy_search(
        &self,
        query: &str,
        memory: &HashMap<String, AnnotatedValue>,
        threshold: Option<f64>,
    ) -> Result<Option<AnnotatedValue>>;
}

#[derive(Serialize, Deserialize)]
pub enum StoredValue {
    Plain(AnnotatedValue),
    Encrypted { nonce: Vec<u8>, ciphertext: Vec<u8> },
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

pub fn resolve_path(value: &AnnotatedValue, path: &VariablePath) -> Result<AnnotatedValue> {
    let mut current = value.clone();

    for segment in &path.segments {
        let current_source = current.clone();
        match segment {
            PathSegment::Field(field) => {
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
