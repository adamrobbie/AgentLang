//! TLS configuration helpers for the registry/agent gRPC services.
//!
//! TLS is opt-in and driven entirely by environment variables so that tests
//! and the local demo continue to work over plaintext without changes:
//!
//! - **Server side** — `start_registry` / `start_agent` call [`server_config`].
//!   When both `AGENTLANG_TLS_CERT` and `AGENTLANG_TLS_KEY` are set (paths to
//!   PEM files), the server binds with TLS; otherwise it stays plaintext.
//! - **Client side** — every place that used to call
//!   `RegistryServiceClient::connect(url)` or `AgentServiceClient::connect(url)`
//!   now goes through [`connect_registry`] / [`connect_agent`]. They look at
//!   the URL scheme: `https://` switches on TLS (using `AGENTLANG_TLS_CA` if
//!   set, otherwise webpki bundled roots), `http://` stays plaintext.
//!
//! This split lets the same binary serve plaintext locally and TLS in
//! production without recompilation, and lets a deployment opt one side in
//! before the other (e.g. TLS-fronted registry but plaintext intra-cluster
//! agent calls during a rollout).
use crate::agent_rpc::agent_service_client::AgentServiceClient;
use crate::registry_rpc::registry_service_client::RegistryServiceClient;
use anyhow::{Result, anyhow};
use std::fs;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, ServerTlsConfig};

/// Build a server-side TLS config from `AGENTLANG_TLS_CERT` + `AGENTLANG_TLS_KEY`.
///
/// Returns `Ok(None)` (plaintext) if neither variable is set. Returns an
/// error if exactly one is set, or if either path can't be read — failing
/// fast is safer than silently falling back to plaintext when an operator
/// thought they were enabling TLS.
pub fn server_config() -> Result<Option<ServerTlsConfig>> {
    let cert = std::env::var("AGENTLANG_TLS_CERT").ok();
    let key = std::env::var("AGENTLANG_TLS_KEY").ok();
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = fs::read(&cert_path).map_err(|e| {
                anyhow!("Failed to read AGENTLANG_TLS_CERT='{}': {}", cert_path, e)
            })?;
            let key_pem = fs::read(&key_path).map_err(|e| {
                anyhow!("Failed to read AGENTLANG_TLS_KEY='{}': {}", key_path, e)
            })?;
            let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
            Ok(Some(ServerTlsConfig::new().identity(identity)))
        }
        _ => Err(anyhow!(
            "AGENTLANG_TLS_CERT and AGENTLANG_TLS_KEY must both be set or both unset"
        )),
    }
}

fn build_endpoint(url: &str) -> Result<Endpoint> {
    let endpoint = Endpoint::from_shared(url.to_string())
        .map_err(|e| anyhow!("Invalid URL '{}': {}", url, e))?;

    if !url.starts_with("https://") {
        return Ok(endpoint);
    }

    let mut tls = ClientTlsConfig::new().with_webpki_roots();
    if let Ok(ca_path) = std::env::var("AGENTLANG_TLS_CA") {
        let ca_pem = fs::read(&ca_path)
            .map_err(|e| anyhow!("Failed to read AGENTLANG_TLS_CA='{}': {}", ca_path, e))?;
        tls = tls.ca_certificate(Certificate::from_pem(ca_pem));
    }
    endpoint
        .tls_config(tls)
        .map_err(|e| anyhow!("Failed to apply TLS config: {}", e))
}

pub async fn connect_registry(url: &str) -> Result<RegistryServiceClient<Channel>> {
    let chan = build_endpoint(url)?
        .connect()
        .await
        .map_err(|e| anyhow!("Failed to connect registry '{}': {}", url, e))?;
    Ok(RegistryServiceClient::new(chan))
}

pub async fn connect_agent(url: &str) -> Result<AgentServiceClient<Channel>> {
    let chan = build_endpoint(url)?
        .connect()
        .await
        .map_err(|e| anyhow!("Failed to connect agent '{}': {}", url, e))?;
    Ok(AgentServiceClient::new(chan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_tls_env() {
        // SAFETY: tests use `serial_test::serial` so no concurrent env
        // mutation, and the `unsafe` API on `set_var`/`remove_var` exists
        // only because env access is process-global, not because the
        // operations are otherwise unsound here.
        unsafe {
            std::env::remove_var("AGENTLANG_TLS_CERT");
            std::env::remove_var("AGENTLANG_TLS_KEY");
            std::env::remove_var("AGENTLANG_TLS_CA");
        }
    }

    #[test]
    #[serial]
    fn server_config_returns_none_when_unset() {
        clear_tls_env();
        assert!(server_config().unwrap().is_none());
    }

    #[test]
    #[serial]
    fn server_config_errors_when_only_cert_set() {
        clear_tls_env();
        unsafe { std::env::set_var("AGENTLANG_TLS_CERT", "/tmp/nonexistent.pem") };
        let res = server_config();
        clear_tls_env();
        assert!(res.is_err(), "must error when only one of CERT/KEY is set");
    }

    #[test]
    #[serial]
    fn server_config_errors_when_paths_missing() {
        clear_tls_env();
        unsafe {
            std::env::set_var("AGENTLANG_TLS_CERT", "/tmp/agentlang_no_such_cert");
            std::env::set_var("AGENTLANG_TLS_KEY", "/tmp/agentlang_no_such_key");
        }
        let res = server_config();
        clear_tls_env();
        assert!(res.is_err(), "must error when paths don't resolve");
    }
}
