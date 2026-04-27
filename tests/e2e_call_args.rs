//! Round-trip test for goal arguments across an agent-to-agent CALL.
//!
//! AgentB defines an `echo` goal that exposes its `x` arg through an output
//! field. The orchestrator CALLs it with a few different value types and
//! asserts the value comes back with the same Value variant. If this fails,
//! the suspect is `MyAgentService::call_goal` in src/lib.rs which decodes
//! `args` by trying `parse::<f64>()` then falling back to `Value::Text` —
//! while `Statement::Call` in src/runtime/eval.rs serializes the arg as a
//! full JSON-encoded `AnnotatedValue`, so the receiver never gets a clean
//! number/bool/list/object back.

mod common;

use AgentLang::{ast, runtime};
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn call_arg_roundtrip_preserves_value_types() -> Result<()> {
    let _tmp = common::isolated_cwd();

    let registry = common::spawn_registry().await;

    let ctx_b = runtime::Context::new();
    {
        let mut goals = ctx_b.goals.lock().unwrap();
        goals.insert(
            "echo".to_string(),
            ast::GoalDefinition {
                // No body — `x` is already injected into working memory by
                // MyAgentService::call_goal before the goal runs. We just
                // expose it via outputs so the result envelope contains it.
                body: vec![],
                outputs: vec![ast::GoalOutput {
                    name: "x".to_string(),
                    type_name: "any".to_string(),
                    annotations: vec![],
                }],
                result_into: None,
                retry: None,
                on_fail: HashMap::new(),
                deadline: None,
                wait: None,
                idempotent: false,
                audit_trail: false,
                confirm_with: None,
                timeout_confirmation: None,
                fallback: None,
            },
        );
    }
    common::spawn_and_register_agent(ctx_b.clone(), "AgentB", &registry.url).await?;

    let ctx = runtime::Context::new();
    common::spawn_and_register_agent(ctx.clone(), "Orchestrator", &registry.url).await?;

    // --- Case 1: Number -----------------------------------------------------
    let echoed = round_trip(&ctx, ast::Value::Number(42.0)).await?;
    assert!(
        matches!(echoed, ast::Value::Number(n) if (n - 42.0).abs() < f64::EPSILON),
        "Number arg should round-trip as Number, got {:?}",
        echoed
    );

    // --- Case 2: Boolean ----------------------------------------------------
    let echoed = round_trip(&ctx, ast::Value::Boolean(true)).await?;
    assert!(
        matches!(echoed, ast::Value::Boolean(true)),
        "Boolean arg should round-trip as Boolean(true), got {:?}",
        echoed
    );

    // --- Case 3: Text -------------------------------------------------------
    let echoed = round_trip(&ctx, ast::Value::Text("hello".to_string())).await?;
    assert!(
        matches!(&echoed, ast::Value::Text(s) if s == "hello"),
        "Text arg should round-trip as Text(\"hello\"), got {:?}",
        echoed
    );

    // --- Case 4: List of mixed -------------------------------------------------
    let list = ast::Value::List(vec![
        ast::AnnotatedValue::from(ast::Value::Number(1.0)),
        ast::AnnotatedValue::from(ast::Value::Text("two".to_string())),
    ]);
    let echoed = round_trip(&ctx, list).await?;
    assert!(
        matches!(&echoed, ast::Value::List(items) if items.len() == 2),
        "List arg should round-trip as a 2-element List, got {:?}",
        echoed
    );

    // --- Case 5: Nested object -------------------------------------------------
    let mut obj = HashMap::new();
    obj.insert(
        "k".to_string(),
        ast::AnnotatedValue::from(ast::Value::Number(7.0)),
    );
    let echoed = round_trip(&ctx, ast::Value::Object(obj)).await?;
    assert!(
        matches!(&echoed, ast::Value::Object(fields)
            if matches!(fields.get("k").map(|v| &v.value), Some(ast::Value::Number(n)) if (*n - 7.0).abs() < f64::EPSILON)),
        "Object arg should round-trip with nested k=7, got {:?}",
        echoed
    );

    Ok(())
}

/// Issue a CALL "AgentB" GOAL "echo" x = `value`, AWAIT it, and pull the
/// echoed `x` back out of the result envelope.
async fn round_trip(ctx: &runtime::Context, value: ast::Value) -> Result<ast::Value> {
    let mut args = HashMap::new();
    args.insert(
        "x".to_string(),
        ast::Expression::Literal(ast::AnnotatedValue::from(value.clone())),
    );

    let result_path = ast::VariablePath::root("echo_call");
    let call_stmt = ast::Statement::Call {
        agent_id: "AgentB".to_string(),
        goal_name: "echo".to_string(),
        args,
        timeout: Some(5.0),
        signed_by: None,
        result_into: Some(result_path.clone()),
    };
    runtime::eval(&call_stmt, ctx.clone()).await?;

    let await_stmt = ast::Statement::Await {
        call_id: "echo_call".to_string(),
        result_into: Some(result_path),
    };
    runtime::eval(&await_stmt, ctx.clone()).await?;

    // Give the spawned RPC a moment to settle into ctx.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let envelope = ctx
        .get_variable("echo_call", ast::MemoryScope::Working)
        .await?;

    // Envelope is { call_id, agent_id, goal_name, status, args, result }.
    // `result` is the goal's result Object: { x: <echoed value> }.
    let ast::Value::Object(env_fields) = envelope.value else {
        anyhow::bail!("expected envelope to be Object, got {:?}", envelope.value);
    };
    let result = env_fields
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("envelope missing `result` field"))?;
    let ast::Value::Object(result_fields) = &result.value else {
        anyhow::bail!(
            "expected result to be Object {{ x: ... }}, got {:?}",
            result.value
        );
    };
    let x = result_fields
        .get("x")
        .ok_or_else(|| anyhow::anyhow!("result missing `x` field"))?;

    Ok(x.value.clone())
}
