//! Smoke-test the `AgentLang demo` subcommand end-to-end via the actual
//! compiled binary. Catches regressions in CLI argument parsing,
//! `tokio::main` setup, and the wired-up runtime that bench/library tests
//! can miss.
//!
//! The binary is located via `CARGO_BIN_EXE_AgentLang`, which Cargo populates
//! for integration tests. The demo subcommand binds fixed ports
//! (50050/50051/50052), so we probe them up front: if anything is already
//! holding them (e.g. a running registry from another test), we skip rather
//! than fail.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const DEMO_PORTS: [u16; 3] = [50050, 50051, 50052];
const DEMO_TIMEOUT: Duration = Duration::from_secs(60);

fn ports_free(ports: &[u16]) -> bool {
    ports.iter().all(|&p| {
        TcpListener::bind(("::1", p))
            .or_else(|_| TcpListener::bind(("127.0.0.1", p)))
            .is_ok()
    })
}

#[test]
fn demo_subcommand_executes_and_prints_known_markers() {
    if !ports_free(&DEMO_PORTS) {
        eprintln!(
            "[e2e_cli] Skipping: one of {:?} is already bound (likely another test)",
            DEMO_PORTS
        );
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = env!("CARGO_BIN_EXE_AgentLang");

    let mut child = Command::new(bin)
        .arg("demo")
        .current_dir(&manifest_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn AgentLang binary");

    // Manual wait-with-timeout because std::process doesn't ship one.
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait failed") {
            break s;
        }
        if start.elapsed() > DEMO_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "demo subcommand did not exit within {:?}; check for hangs in run_demo()",
                DEMO_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut stderr);
    }

    assert!(
        status.success(),
        "demo exited non-zero (code={:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        status.code(),
        stdout,
        stderr
    );

    for marker in [
        "AgentLang 1.0 - Production Runtime Execution",
        "Parsing integrated program",
        "Executing main program",
        "Final Execution State Verified",
        "Audit Log Size:",
    ] {
        assert!(
            stdout.contains(marker),
            "expected marker {:?} in demo stdout; full output:\n{}",
            marker,
            stdout
        );
    }
}
