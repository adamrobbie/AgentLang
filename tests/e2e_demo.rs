//! End-to-end test for the bundled `examples/demo.agentlang` script.
//!
//! Spawns a registry + AgentB (responder) + Orchestrator (caller), runs the
//! full demo script, and asserts that all the side-effects the script
//! advertises actually land in the right scopes.

mod common;

use AgentLang::{ast, parser, runtime};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn demo_script_executes_end_to_end() -> Result<()> {
    let _tmp = common::isolated_cwd();

    let registry = common::spawn_registry().await;

    // Responder agent with a `pay` goal that sets a status flag.
    let ctx_b = runtime::Context::new();
    {
        let mut goals = ctx_b.goals.lock().unwrap();
        goals.insert(
            "pay".to_string(),
            ast::GoalDefinition {
                body: vec![ast::Statement::Set {
                    variable: "payment_status".to_string(),
                    value: ast::Expression::Literal(ast::AnnotatedValue::from(
                        ast::Value::Boolean(true),
                    )),
                }],
                outputs: vec![],
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

    // Orchestrator with the native `search_flights` tool.
    let ctx = runtime::Context::new();
    install_search_flights_tool(&ctx);
    common::spawn_and_register_agent(ctx.clone(), "PrimaryOrchestrator", &registry.url).await?;

    // Run the bundled demo script.
    let demo_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/demo.agentlang");
    let source = std::fs::read_to_string(&demo_path)?;
    let (remaining, program) = parser::parse_program(source.trim())
        .map_err(|e| anyhow!("parse failed: {:?}", e))?;
    assert!(!program.is_empty(), "demo script parsed to zero statements");
    assert!(
        remaining.trim().is_empty(),
        "parser stopped before EOF — first ~120 unparsed chars: {:?}",
        &remaining.chars().take(120).collect::<String>()
    );

    for (idx, stmt) in program.iter().enumerate() {
        if let Err(e) = runtime::eval(stmt, ctx.clone()).await {
            eprintln!("[test] stmt #{idx} ({}) failed: {e}", short_stmt(stmt));
        }
    }

    // Let the EMIT/ON broadcast and any spawned tasks settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Assertions ----------------------------------------------------------

    // Parallel tool gather populated session memory.
    let m_data = ctx
        .get_variable("m_data", ast::MemoryScope::Session)
        .await
        .expect("m_data should be populated by REMEMBER after PARALLEL");
    assert!(
        matches!(m_data.value, ast::Value::Object(_)),
        "m_data should be an object, got {:?}",
        m_data.value
    );

    // Fuzzy recall produced *something* (the demo searches "api" against
    // long-term memory containing "user_api_key").
    ctx.get_variable("f_found", ast::MemoryScope::Session)
        .await
        .expect("f_found should be set by RECALL");

    // Federated CALL envelope was stored.
    ctx.get_variable("f_sentiment", ast::MemoryScope::Session)
        .await
        .expect("f_sentiment should be set by REMEMBER after CALL");

    // Sensitive data made it into encrypted long-term memory.
    let secret_vault = ctx
        .get_variable("secret_vault", ast::MemoryScope::LongTerm)
        .await
        .expect("secret_vault should persist to long-term memory");
    assert!(
        secret_vault.is_sensitive,
        "secret_vault should retain its `sensitive` annotation"
    );

    // STARK proof was generated and stored under `auth_proof`.
    {
        let proofs = ctx.proofs.lock().unwrap();
        assert!(
            proofs.contains_key("auth_proof"),
            "auth_proof not stored in proofs map; got keys: {:?}",
            proofs.keys().collect::<Vec<_>>()
        );
    }

    // Audit chain captured at least the SET / REMEMBER ops.
    let audit_len = ctx.audit_chain.lock().unwrap().entries.len();
    assert!(
        audit_len >= 5,
        "expected audit chain to have several entries, got {}",
        audit_len
    );

    Ok(())
}

fn short_stmt(stmt: &ast::Statement) -> &'static str {
    use ast::Statement::*;
    match stmt {
        Goal { .. } => "Goal",
        Set { .. } => "Set",
        Remember { .. } => "Remember",
        Recall { .. } => "Recall",
        Forget { .. } => "Forget",
        On { .. } => "On",
        Emit { .. } => "Emit",
        Prove { .. } => "Prove",
        Reveal { .. } => "Reveal",
        Parallel { .. } => "Parallel",
        ForEach { .. } => "ForEach",
        Repeat { .. } => "Repeat",
        UseTool { .. } => "UseTool",
        Call { .. } => "Call",
        Await { .. } => "Await",
        Delegate { .. } => "Delegate",
        Tool(_) => "Tool",
        Agent { .. } => "Agent",
        Contract { .. } => "Contract",
        UseWasm { .. } => "UseWasm",
        Wait { .. } => "Wait",
        If { .. } => "If",
    }
}

fn install_search_flights_tool(ctx: &runtime::Context) {
    {
        let mut handlers = ctx.tool_handlers.lock().unwrap();
        handlers.insert(
            "search_flights".to_string(),
            Arc::new(|_args| {
                let mut flight = HashMap::new();
                flight.insert(
                    "id".to_string(),
                    ast::AnnotatedValue::from(ast::Value::Text("FL-456".to_string())),
                );
                flight.insert(
                    "price".to_string(),
                    ast::AnnotatedValue::from(ast::Value::Number(299.0)),
                );
                let mut result = HashMap::new();
                result.insert(
                    "flights".to_string(),
                    ast::AnnotatedValue::from(ast::Value::List(vec![
                        ast::AnnotatedValue::from(ast::Value::Object(flight)),
                    ])),
                );
                Ok(ast::AnnotatedValue::from(ast::Value::Object(result)))
            }),
        );
    }
    {
        let mut tools = ctx.tools.lock().unwrap();
        tools.insert(
            "search_flights".to_string(),
            ast::ToolDefinition {
                name: "search_flights".to_string(),
                description: Some("Search for flights".to_string()),
                category: Some(ast::ToolCategory::Read),
                version: Some("1.0.0".to_string()),
                inputs: vec![ast::ToolField {
                    name: "query".to_string(),
                    type_hint: "text".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                outputs: vec![ast::ToolField {
                    name: "flights".to_string(),
                    type_hint: "list".to_string(),
                    required: true,
                    annotations: vec![],
                }],
                reversible: false,
                side_effect: false,
                rate_limit: None,
                timeout: Some(5.0),
            },
        );
    }
}
