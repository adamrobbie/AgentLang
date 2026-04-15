use super::context::Context;
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

    ctx.set_variable(call_id.to_string(), envelope, MemoryScope::Working)
        .await?;

    if let Some(value) = flat_result {
        ctx.set_variable(format!("{}.result", call_id), value, MemoryScope::Working)
            .await?;
    }

    Ok(())
}
