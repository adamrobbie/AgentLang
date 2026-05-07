use super::context::Context;
use super::exec_log::{self, LogEntry, Operands};
use crate::ast::{AnnotatedValue, MemoryScope, Value};
use anyhow::Result;
use std::collections::HashMap;

pub fn build_pending_call_envelope(
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

pub fn build_completed_call_envelope(
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

pub fn build_failed_call_envelope(
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

pub async fn store_call_result(
    ctx: &Context,
    call_id: &str,
    envelope: AnnotatedValue,
) -> Result<()> {
    let flat_result = if let Value::Object(fields) = &envelope.value {
        fields.get("result").cloned()
    } else {
        None
    };

    // Phase 3e: pair every working_variables write with a SET log entry
    // so `LogTrace::from_log_and_commit` replay produces the same final
    // SMT root as `MemoryCommit::from_context` after the body — otherwise
    // the AIR's C7 root-carry constraint fails on the first transition
    // out of the (silent) write into the anti-pad rows.
    ctx.record_log(LogEntry {
        operands: Operands::Set {
            name_hash: exec_log::hash(call_id.as_bytes()),
            value_hash: exec_log::hash(format!("{:?}", envelope.value).as_bytes()),
        },
    });
    ctx.set_variable(call_id.to_string(), envelope, MemoryScope::Working)
        .await?;

    if let Some(value) = flat_result {
        let result_name = format!("{}.result", call_id);
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
