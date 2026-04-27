//! Drive `Statement::Prove` + `Statement::Reveal` through the runtime, then
//! tamper with the stored `StarkProof` bytes and confirm REVEAL surfaces a
//! verification failure rather than silently accepting the corrupted proof.
//!
//! Most cases inject a pre-built proof via `crypto::generate_proof(64, ...)`
//! to keep the test deterministic — they exercise only the REVEAL eval path.
//! The `prove_then_reveal_through_runtime` case drives `Statement::Prove` end
//! to end so we still cover the full PROVE → REVEAL pipeline.

mod common;

use AgentLang::{ast, crypto, runtime};
use anyhow::Result;

const CLAIM: &str = "balance_above_100";
const PROOF_NAME: &str = "balance_proof";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn reveal_succeeds_then_fails_after_proof_bytes_tampered() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();

    let proof = crypto::generate_proof(64, CLAIM)?;
    {
        let mut proofs = ctx.proofs.lock().unwrap();
        proofs.insert(PROOF_NAME.to_string(), proof);
    }

    let result_path = ast::VariablePath::root("unlocked");
    let reveal = ast::Statement::Reveal {
        proof_name: PROOF_NAME.to_string(),
        claim: CLAIM.to_string(),
        to_agent: None,
        result_into: Some(result_path.clone()),
    };

    // --- First REVEAL succeeds and writes the unlock receipt ----------------
    runtime::eval(&reveal, ctx.clone()).await?;
    let unlocked = ctx
        .get_variable("unlocked", ast::MemoryScope::Working)
        .await?;
    assert!(
        matches!(&unlocked.value, ast::Value::Text(s) if s.contains(PROOF_NAME) && s.contains(CLAIM)),
        "unlock receipt missing proof/claim references; got {:?}",
        unlocked.value
    );

    // --- Tamper with proof bytes; REVEAL must now fail ----------------------
    {
        let mut proofs = ctx.proofs.lock().unwrap();
        let stored = proofs
            .get_mut(PROOF_NAME)
            .expect("proof was inserted above");
        let target = stored
            .proof
            .iter_mut()
            .nth(100)
            .expect("proof body should be longer than 100 bytes");
        *target ^= 0xFF;
    }

    let err = runtime::eval(&reveal, ctx.clone())
        .await
        .expect_err("REVEAL of tampered proof must fail");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("stark") || msg.to_lowercase().contains("verif"),
        "expected STARK verification failure in error, got: {msg}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn reveal_fails_when_claim_does_not_match_proof() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();

    let proof = crypto::generate_proof(64, CLAIM)?;
    {
        let mut proofs = ctx.proofs.lock().unwrap();
        proofs.insert(PROOF_NAME.to_string(), proof);
    }

    let reveal = ast::Statement::Reveal {
        proof_name: PROOF_NAME.to_string(),
        claim: "different_claim".to_string(),
        to_agent: None,
        result_into: None,
    };
    let err = runtime::eval(&reveal, ctx.clone())
        .await
        .expect_err("REVEAL with mismatched claim must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("not generated for this claim") || msg.to_lowercase().contains("claim"),
        "expected claim-mismatch error, got: {msg}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn prove_then_reveal_through_runtime() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();

    // Body intentionally seeds a varied working state so the hash-derived
    // trace length is non-trivial — this is the path that was previously
    // flaky for n>=128 before crypto.rs widened col0/col1 to u128.
    let body = vec![
        ast::Statement::Set {
            variable: "balance".to_string(),
            value: ast::Expression::Literal(ast::AnnotatedValue::from(ast::Value::Number(
                250.0,
            ))),
        },
        ast::Statement::Set {
            variable: "approved".to_string(),
            value: ast::Expression::Literal(ast::AnnotatedValue::from(ast::Value::Boolean(
                true,
            ))),
        },
    ];

    let prove = ast::Statement::Prove {
        statements: body,
        claim: CLAIM.to_string(),
        proof_name: PROOF_NAME.to_string(),
    };
    runtime::eval(&prove, ctx.clone()).await?;

    let result_path = ast::VariablePath::root("unlocked");
    let reveal = ast::Statement::Reveal {
        proof_name: PROOF_NAME.to_string(),
        claim: CLAIM.to_string(),
        to_agent: None,
        result_into: Some(result_path),
    };
    runtime::eval(&reveal, ctx.clone()).await?;

    let unlocked = ctx
        .get_variable("unlocked", ast::MemoryScope::Working)
        .await?;
    assert!(
        matches!(&unlocked.value, ast::Value::Text(s) if s.contains(PROOF_NAME)),
        "PROVE→REVEAL did not write unlock receipt; got {:?}",
        unlocked.value
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn reveal_fails_when_proof_name_unknown() -> Result<()> {
    let _tmp = common::isolated_cwd();
    let ctx = runtime::Context::new();

    let reveal = ast::Statement::Reveal {
        proof_name: "ghost_proof".to_string(),
        claim: CLAIM.to_string(),
        to_agent: None,
        result_into: None,
    };
    let err = runtime::eval(&reveal, ctx.clone())
        .await
        .expect_err("REVEAL of unknown proof must fail");
    assert!(
        format!("{err}").contains("not found"),
        "expected 'not found' error for unknown proof, got: {err}"
    );

    Ok(())
}
