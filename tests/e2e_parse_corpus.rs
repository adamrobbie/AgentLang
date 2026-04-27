//! Golden parse + eval corpus. Each `.agentlang` file under `tests/fixtures/`
//! is parsed with `parser::parse_program` and then evaluated statement-by-
//! statement. Fixtures are deliberately self-contained — no CALL / DELEGATE /
//! Shared scope, since those need spawned servers — so that a regression
//! anywhere in the parser or core eval surfaces here without external setup.

mod common;

use AgentLang::{parser, runtime};
use anyhow::{Result, anyhow};
use std::path::PathBuf;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn parse_corpus_parses_and_evaluates() -> Result<()> {
    let _tmp = common::isolated_cwd();

    let fixtures_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&fixtures_dir)
        .map_err(|e| anyhow!("read_dir {:?}: {}", fixtures_dir, e))?
        .filter_map(|res| res.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("agentlang"))
        .collect();
    entries.sort();

    assert!(
        !entries.is_empty(),
        "no .agentlang fixtures found under {:?}",
        fixtures_dir
    );

    for path in &entries {
        let source = std::fs::read_to_string(path)?;
        let trimmed = source.trim();

        let (remaining, program) = parser::parse_program(trimmed)
            .map_err(|e| anyhow!("parse failed for {:?}: {:?}", path, e))?;
        assert!(
            remaining.trim().is_empty(),
            "parser stopped before EOF in {:?}; first 120 chars left: {:?}",
            path,
            remaining.chars().take(120).collect::<String>()
        );
        assert!(
            !program.is_empty(),
            "fixture {:?} parsed to zero statements",
            path
        );

        // Each fixture gets its own fresh Context so leftover state from one
        // doesn't contaminate the next.
        let ctx = runtime::Context::new();
        for (idx, stmt) in program.iter().enumerate() {
            runtime::eval(stmt, ctx.clone()).await.map_err(|e| {
                anyhow!(
                    "eval failed for {:?} stmt #{idx}: {e}",
                    path.file_name().unwrap_or_default()
                )
            })?;
        }
    }

    Ok(())
}
