//! Shared helpers for AgentLang e2e integration tests.

use AgentLang::registry_rpc::RegisterRequest;
use AgentLang::registry_rpc::registry_service_client::RegistryServiceClient;
use AgentLang::{MyAgentService, MyRegistryService, runtime, start_agent, start_registry};
use anyhow::Result;
use ed25519_dalek::Signer;
use std::net::TcpListener;
use std::time::Duration;

pub fn free_port() -> u16 {
    TcpListener::bind("[::1]:0")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Sets the process working directory to a fresh tempdir so that
/// `agent.key` / `agent.id` / `memory.json` / `audit.json` writes from
/// `Context::new()` don't collide with the repo root or other tests.
///
/// The returned guard must be kept alive for the lifetime of the test —
/// dropping it deletes the temp dir.
pub fn isolated_cwd() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("create tempdir");
    std::env::set_current_dir(tmp.path()).expect("set cwd");
    tmp
}

pub struct RunningRegistry {
    pub url: String,
}

pub async fn spawn_registry() -> RunningRegistry {
    let port = free_port();
    let addr: std::net::SocketAddr = format!("[::1]:{}", port).parse().unwrap();
    let svc = MyRegistryService::new();
    tokio::spawn(async move {
        let _ = start_registry(svc, addr).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    RunningRegistry {
        url: format!("http://[::1]:{}", port),
    }
}

/// Spawn an agent server bound to a free port, register it with `registry_url`,
/// and update the context's `agent_id` and `registries` accordingly.
pub async fn spawn_and_register_agent(
    ctx: runtime::Context,
    agent_id: &str,
    registry_url: &str,
) -> Result<()> {
    *ctx.registries
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = vec![registry_url.to_string()];

    let port = free_port();
    let addr: std::net::SocketAddr = format!("[::1]:{}", port).parse()?;
    let endpoint = format!("http://[::1]:{}", port);

    let svc = MyAgentService {
        ctx: ctx.clone(),
        registries: vec![registry_url.to_string()],
    };
    tokio::spawn(async move {
        let _ = start_agent(svc, addr).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let payload = format!("{}:{}", agent_id, endpoint);
    let signature = ctx
        .identity
        .signing_key
        .sign(payload.as_bytes())
        .to_bytes()
        .to_vec();

    let mut client = RegistryServiceClient::connect(registry_url.to_string()).await?;
    client
        .register_agent(RegisterRequest {
            agent_id: agent_id.to_string(),
            endpoint,
            public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
            signature,
        })
        .await?;

    *ctx.agent_id
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = agent_id.to_string();
    Ok(())
}
