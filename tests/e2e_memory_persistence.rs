//! Sensitive values stored in the LongTerm scope are AEAD-encrypted with a key
//! derived from `AGENTLANG_MASTER_KEY`. This test asserts:
//!
//! 1. A sensitive REMEMBER survives across `Context` drop/recreate when the
//!    master key is unchanged.
//! 2. A non-sensitive REMEMBER survives the same drop/recreate (stored as
//!    `Plain`, no key dependency).
//! 3. A `Context::new()` instantiated with a *different* master key fails to
//!    decrypt the encrypted entry — the failure surfaces from RECALL via the
//!    backend's `load()` returning an error.
//!
//! Both env-var mutation and shared-cwd mutation make this test mutually
//! exclusive with the other e2e tests, so it runs under `serial_test::serial`.

mod common;

use AgentLang::{ast, runtime};
use anyhow::Result;

const KEY_A: &str = "test-key-alpha-0001";
const KEY_B: &str = "test-key-bravo-9999";

fn set_master_key(value: &str) {
    // SAFETY: tests are serialized via `serial_test::serial` so no other thread
    // is reading or mutating env vars during this test.
    unsafe { std::env::set_var("AGENTLANG_MASTER_KEY", value) };
}

fn clear_master_key() {
    unsafe { std::env::remove_var("AGENTLANG_MASTER_KEY") };
}

fn sensitive_text(s: &str) -> ast::AnnotatedValue {
    let mut v = ast::AnnotatedValue::from(ast::Value::Text(s.to_string()));
    v.is_sensitive = true;
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn long_term_sensitive_round_trips_with_same_master_key() -> Result<()> {
    let _tmp = common::isolated_cwd();
    set_master_key(KEY_A);

    // --- Write phase ---------------------------------------------------------
    {
        let ctx = runtime::Context::new();

        let sensitive_val = sensitive_text("sk-secret-abc");
        ctx.set_variable(
            "api_key".to_string(),
            sensitive_val,
            ast::MemoryScope::LongTerm,
        )
        .await?;

        let plain_val = ast::AnnotatedValue::from(ast::Value::Text("Paris".to_string()));
        ctx.set_variable("city".to_string(), plain_val, ast::MemoryScope::LongTerm)
            .await?;
    }

    // --- Reload with same key ------------------------------------------------
    {
        let ctx = runtime::Context::new();

        let api_key = ctx
            .get_variable("api_key", ast::MemoryScope::LongTerm)
            .await?;
        assert!(
            matches!(&api_key.value, ast::Value::Text(s) if s == "sk-secret-abc"),
            "sensitive long-term value should decrypt under same master key, got {:?}",
            api_key.value
        );
        assert!(
            api_key.is_sensitive,
            "sensitive flag should round-trip through encryption"
        );

        let city = ctx
            .get_variable("city", ast::MemoryScope::LongTerm)
            .await?;
        assert!(
            matches!(&city.value, ast::Value::Text(s) if s == "Paris"),
            "plain long-term value should round-trip, got {:?}",
            city.value
        );
    }

    clear_master_key();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn long_term_sensitive_fails_to_decrypt_under_different_master_key() -> Result<()> {
    let _tmp = common::isolated_cwd();
    set_master_key(KEY_A);

    // --- Write phase under KEY_A --------------------------------------------
    {
        let ctx = runtime::Context::new();
        let sensitive_val = sensitive_text("sk-secret-xyz");
        ctx.set_variable(
            "api_key".to_string(),
            sensitive_val,
            ast::MemoryScope::LongTerm,
        )
        .await?;
    }

    // --- Swap to KEY_B and try to read --------------------------------------
    set_master_key(KEY_B);
    {
        let ctx = runtime::Context::new();
        let result = ctx
            .get_variable("api_key", ast::MemoryScope::LongTerm)
            .await;
        assert!(
            result.is_err(),
            "RECALL under wrong master key must fail; got Ok({:?})",
            result.ok()
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Decryption failed") || err_msg.contains("decrypt"),
            "expected decryption failure in error, got: {err_msg}"
        );
    }

    clear_master_key();
    Ok(())
}
