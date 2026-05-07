use super::audit::AgentError;
use super::context::Context;
use super::exec_log::{self, LogEntry, Operands};
use super::memory::{propagate_container_metadata, resolve_path};
use crate::ast::*;
use anyhow::Result;
use std::collections::HashMap;

pub fn apply_annotations(mut value: AnnotatedValue, annotations: &[Annotation]) -> AnnotatedValue {
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

pub fn collect_changed_working_values(
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

pub async fn build_goal_result(
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

pub async fn store_goal_result(
    ctx: &Context,
    goal_name: &str,
    result: AnnotatedValue,
) -> Result<()> {
    let flat_result = if let Value::Object(fields) = &result.value {
        fields.get("result").cloned()
    } else {
        None
    };

    // Phase 3e: store_goal_result mutates `working_variables` exactly
    // like `Statement::Set`, but historically did so without recording
    // an exec-log entry. That left replay (`LogTrace::from_log_and_commit`)
    // unaware of the write, so the replay's running SMT root diverged
    // from `MemoryCommit::from_context` post-body — breaking the C7
    // root-carry constraint at step (last_real → anti-pad). Emit a SET
    // log entry per write so the AIR's `mroot` column ends at the same
    // root the envelope advertises.
    ctx.record_log(LogEntry {
        operands: Operands::Set {
            name_hash: exec_log::hash(goal_name.as_bytes()),
            value_hash: exec_log::hash(format!("{:?}", result.value).as_bytes()),
        },
    });
    ctx.set_variable(goal_name.to_string(), result, MemoryScope::Working)
        .await?;

    if let Some(value) = flat_result {
        let result_name = format!("{}.result", goal_name);
        ctx.record_log(LogEntry {
            operands: Operands::Set {
                name_hash: exec_log::hash(result_name.as_bytes()),
                value_hash: exec_log::hash(format!("{:?}", value.value).as_bytes()),
            },
        });
        ctx.set_variable(result_name, value, MemoryScope::Working)
            .await?;
    }

    Ok(())
}

pub fn classify_goal_failure(error: &anyhow::Error) -> GoalFailureType {
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
