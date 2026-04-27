//! Contract enforcement: a CONTRACT with `CANNOT USE <tool>` causes any
//! `USE <tool>` statement to fail with a `Permission denied` error. When that
//! USE is wrapped in a GOAL with `ON_FAIL[PERMISSION] <handler>`, the handler
//! must fire — proving that:
//!   1. `check_contracts` actually blocks the call.
//!   2. `classify_goal_failure` routes "Permission denied" to
//!      `GoalFailureType::Permission`.
//!   3. The Goal's on_fail dispatch picks up the typed handler.

mod common;

use AgentLang::{ast, parser, runtime};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;

fn register_noop_tool(ctx: &runtime::Context, name: &str) {
    {
        let mut handlers = ctx.tool_handlers.lock().unwrap();
        handlers.insert(
            name.to_string(),
            Arc::new(|_args| Ok(ast::AnnotatedValue::from(ast::Value::Null))),
        );
    }
    {
        let mut tools = ctx.tools.lock().unwrap();
        tools.insert(
            name.to_string(),
            ast::ToolDefinition {
                name: name.to_string(),
                description: None,
                category: Some(ast::ToolCategory::Read),
                version: Some("1.0.0".to_string()),
                inputs: vec![],
                outputs: vec![],
                reversible: true,
                side_effect: false,
                rate_limit: None,
                timeout: None,
            },
        );
    }
}

async fn run_program(ctx: &runtime::Context, src: &str) -> Result<()> {
    let (rest, program) = parser::parse_program(src.trim())
        .map_err(|e| anyhow!("parse failed: {:?}", e))?;
    assert!(
        rest.trim().is_empty(),
        "parser did not consume entire program; left: {:?}",
        rest
    );
    for stmt in &program {
        runtime::eval(stmt, ctx.clone()).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn cannot_use_contract_routes_to_permission_handler() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();
    register_noop_tool(&ctx, "forbidden_tool");

    // Forbid `forbidden_tool` then attempt to USE it inside a GOAL whose
    // ON_FAIL[PERMISSION] handler flips a sentinel.
    let src = r#"
        CONTRACT restricted ISSUED_BY authority CANNOT USE forbidden_tool END

        GOAL guarded
          ON_FAIL[PERMISSION] SET permission_blocked = true
          USE forbidden_tool RESULT INTO {ignored} END
        END
    "#;

    run_program(&ctx, src).await?;

    let blocked = ctx
        .get_variable("permission_blocked", ast::MemoryScope::Working)
        .await?;
    assert!(
        matches!(blocked.value, ast::Value::Boolean(true)),
        "ON_FAIL[PERMISSION] handler did not fire; permission_blocked = {:?}",
        blocked.value
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn can_use_contract_does_not_trigger_handler() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();
    register_noop_tool(&ctx, "allowed_tool");

    // The contract permits the tool, so the GOAL completes normally and the
    // ON_FAIL handler must NOT run.
    let src = r#"
        CONTRACT permitter ISSUED_BY authority CAN USE allowed_tool END

        GOAL happy
          ON_FAIL[PERMISSION] SET permission_blocked = true
          USE allowed_tool RESULT INTO {ok} END
        END
    "#;

    run_program(&ctx, src).await?;

    // Sentinel must remain unset.
    let blocked = ctx
        .get_variable("permission_blocked", ast::MemoryScope::Working)
        .await;
    assert!(
        blocked.is_err(),
        "permission_blocked should not be set when contract permits the tool, got {:?}",
        blocked.ok()
    );

    // Tool actually executed: the result envelope is stored at `ok`.
    let _ = ctx.get_variable("ok", ast::MemoryScope::Working).await?;

    // Spot-check that contracts deny things they don't list.
    let denied = ctx.check_contracts("something_else");
    assert!(denied.is_err(), "non-listed capability should be denied");

    let _unused: HashMap<String, ()> = HashMap::new();
    Ok(())
}
