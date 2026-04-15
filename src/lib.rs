#![allow(non_snake_case)]
pub mod ast;
pub mod crypto;
pub mod parser;
pub mod runtime;

use anyhow::Result;
use ed25519_dalek::{Verifier, VerifyingKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status, transport::Server};

pub mod agent_rpc {
    tonic::include_proto!("agent");
}

pub mod registry_rpc {
    tonic::include_proto!("registry");
}

use agent_rpc::agent_service_server::{AgentService, AgentServiceServer};
use agent_rpc::{CallRequest, CallResponse};
use registry_rpc::registry_service_client::RegistryServiceClient;
use registry_rpc::registry_service_server::{RegistryService, RegistryServiceServer};
use registry_rpc::{
    GetSharedRequest, GetSharedResponse, LookupRequest, LookupResponse, PutSharedRequest,
    PutSharedResponse, RegisterRequest, RegisterResponse,
};

type AgentRegistry = Arc<Mutex<HashMap<String, (String, Vec<u8>)>>>;
type SharedState = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub struct MyRegistryService {
    pub agents: AgentRegistry,
    pub shared_state: SharedState,
    pub peer_registries: Vec<String>,
}

impl MyRegistryService {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            shared_state: Arc::new(Mutex::new(HashMap::new())),
            peer_registries: Vec::new(),
        }
    }
}

impl Default for MyRegistryService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl RegistryService for MyRegistryService {
    async fn register_agent(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        let pub_key_bytes: [u8; 32] = req
            .public_key
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid public key: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&req.signature)
            .map_err(|_| Status::invalid_argument("Invalid signature format"))?;

        let payload = format!("{}:{}", req.agent_id, req.endpoint);
        if verifying_key
            .verify(payload.as_bytes(), &signature)
            .is_err()
        {
            return Err(Status::unauthenticated(
                "Invalid agent registration signature",
            ));
        }

        println!(
            "  [Registry] Registering agent '{}' at {}",
            req.agent_id, req.endpoint
        );
        self.agents
            .lock()
            .unwrap()
            .insert(req.agent_id, (req.endpoint, req.public_key));
        Ok(Response::new(RegisterResponse { success: true }))
    }

    async fn lookup_agent(
        &self,
        request: Request<LookupRequest>,
    ) -> Result<Response<LookupResponse>, Status> {
        let req = request.into_inner();

        {
            let agents = self.agents.lock().unwrap();
            if let Some((endpoint, pub_key)) = agents.get(&req.agent_id) {
                return Ok(Response::new(LookupResponse {
                    endpoint: endpoint.clone(),
                    public_key: pub_key.clone(),
                    found: true,
                }));
            }
        }

        let ttl = if req.ttl == 0 { 3 } else { req.ttl };
        if ttl > 1 {
            for peer in &self.peer_registries {
                if let Ok(mut client) = RegistryServiceClient::connect(peer.clone()).await {
                    let federated_req = LookupRequest {
                        agent_id: req.agent_id.clone(),
                        ttl: ttl - 1,
                    };
                    if let Ok(res) = client.lookup_agent(federated_req).await {
                        let res: LookupResponse = res.into_inner();
                        if res.found {
                            println!(
                                "  [Registry] Federated lookup SUCCESS for '{}' via peer {}",
                                req.agent_id, peer
                            );
                            return Ok(Response::new(res));
                        }
                    }
                }
            }
        }

        Ok(Response::new(LookupResponse {
            found: false,
            ..Default::default()
        }))
    }

    async fn put_shared_state(
        &self,
        request: Request<PutSharedRequest>,
    ) -> Result<Response<PutSharedResponse>, Status> {
        let req = request.into_inner();
        println!("  [Registry] PutSharedState: key='{}'", req.key);
        self.shared_state
            .lock()
            .unwrap()
            .insert(req.key, req.value_json);
        Ok(Response::new(PutSharedResponse { success: true }))
    }

    async fn get_shared_state(
        &self,
        request: Request<GetSharedRequest>,
    ) -> Result<Response<GetSharedResponse>, Status> {
        let req = request.into_inner();
        let state = self.shared_state.lock().unwrap();
        if let Some(val) = state.get(&req.key) {
            Ok(Response::new(GetSharedResponse {
                value_json: val.clone(),
                found: true,
            }))
        } else {
            Ok(Response::new(GetSharedResponse {
                found: false,
                ..Default::default()
            }))
        }
    }
}

pub struct MyAgentService {
    pub ctx: runtime::Context,
    pub registries: Vec<String>,
}

#[tonic::async_trait]
impl AgentService for MyAgentService {
    async fn call_goal(
        &self,
        request: Request<CallRequest>,
    ) -> Result<Response<CallResponse>, Status> {
        let req = request.into_inner();
        println!(
            "  [RPC] Received call for goal '{}' from '{}'",
            req.goal_name, req.caller_id
        );

        let mut lookup_res = None;
        for reg_addr in &self.registries {
            if let Ok(mut client) = RegistryServiceClient::connect(reg_addr.clone()).await
                && let Ok(res) = client
                    .lookup_agent(LookupRequest {
                        agent_id: req.caller_id.clone(),
                        ttl: 3,
                    })
                    .await
            {
                let res = res.into_inner();
                if res.found {
                    lookup_res = Some(res);
                    break;
                }
            }
        }

        let lookup_data = lookup_res.ok_or_else(|| {
            Status::unauthenticated("Caller not found in any registered registry")
        })?;

        let pub_key_bytes: [u8; 32] = lookup_data
            .public_key
            .try_into()
            .map_err(|_| Status::internal("Invalid public key in registry"))?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|e| Status::internal(format!("Invalid verifying key: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&req.signature)
            .map_err(|_| Status::invalid_argument("Invalid signature format"))?;

        let payload = format!("{}:{}", req.goal_name, req.caller_id);
        if verifying_key
            .verify(payload.as_bytes(), &signature)
            .is_err()
        {
            return Err(Status::unauthenticated("Invalid signature"));
        }

        let goal_body = {
            let goals = self.ctx.goals.lock().unwrap();
            goals.get(&req.goal_name).cloned()
        };

        if let Some(goal_definition) = goal_body {
            let isolated_ctx = runtime::Context::new();

            for (name, val_str) in req.args {
                let value = if let Ok(n) = val_str.parse::<f64>() {
                    ast::Value::Number(n)
                } else if val_str == "true" {
                    ast::Value::Boolean(true)
                } else if val_str == "false" {
                    ast::Value::Boolean(false)
                } else {
                    ast::Value::Text(val_str.trim_matches('"').to_string())
                };

                isolated_ctx
                    .set_variable(
                        name,
                        ast::AnnotatedValue::from(value),
                        ast::MemoryScope::Working,
                    )
                    .await
                    .map_err(|e| Status::internal(format!("Failed to set argument: {}", e)))?;
            }

            let goal_stmt = ast::Statement::Goal {
                name: req.goal_name.clone(),
                body: goal_definition.body,
                outputs: goal_definition.outputs,
                result_into: goal_definition.result_into,
                retry: goal_definition.retry.map(|n| n as u32),
                on_fail: goal_definition.on_fail,
                deadline: goal_definition.deadline,
                wait: goal_definition.wait,
                idempotent: goal_definition.idempotent,
                audit_trail: goal_definition.audit_trail,
                confirm_with: goal_definition.confirm_with,
                timeout_confirmation: goal_definition.timeout_confirmation,
                fallback: None,
            };

            if let Err(e) = runtime::eval(&goal_stmt, isolated_ctx.clone()).await {
                return Ok(Response::new(CallResponse {
                    result_json: format!("{{\"error\": \"{}\"}}", e),
                    success: false,
                }));
            }

            let result_name = req.goal_name;
            let result = isolated_ctx
                .get_variable(&result_name, ast::MemoryScope::Working)
                .await
                .map_err(|e| Status::internal(format!("Failed to read goal result: {}", e)))?;
            let result_json = serde_json::to_string(&result)
                .map_err(|e| Status::internal(format!("Failed to serialize goal result: {}", e)))?;

            Ok(Response::new(CallResponse {
                result_json,
                success: true,
            }))
        } else {
            Err(Status::not_found(format!(
                "Goal '{}' not found",
                req.goal_name
            )))
        }
    }
}

pub async fn start_registry(service: MyRegistryService, addr: std::net::SocketAddr) -> Result<()> {
    Server::builder()
        .add_service(RegistryServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

pub async fn start_agent(service: MyAgentService, addr: std::net::SocketAddr) -> Result<()> {
    Server::builder()
        .add_service(AgentServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use tonic::Request;

    #[tokio::test]
    async fn test_registry_local_ops() {
        let registry = MyRegistryService::new();

        // 1. Register
        let ctx = runtime::Context::new();
        let agent_id = "agent1".to_string();
        let endpoint = "http://localhost:1".to_string();
        let payload = format!("{}:{}", agent_id, endpoint);
        let signature = ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        let reg_req = RegisterRequest {
            agent_id: agent_id.clone(),
            endpoint: endpoint.clone(),
            public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
            signature,
        };

        let res = registry
            .register_agent(Request::new(reg_req))
            .await
            .unwrap()
            .into_inner();
        assert!(res.success);

        // 2. Lookup
        let lookup_req = LookupRequest {
            agent_id: agent_id.clone(),
            ttl: 0,
        };
        let res = registry
            .lookup_agent(Request::new(lookup_req))
            .await
            .unwrap()
            .into_inner();
        assert!(res.found);
        assert_eq!(res.endpoint, endpoint);

        // 3. Shared State
        let put_req = PutSharedRequest {
            key: "k1".to_string(),
            value_json: b"v1".to_vec(),
        };
        registry
            .put_shared_state(Request::new(put_req))
            .await
            .unwrap();

        let get_req = GetSharedRequest {
            key: "k1".to_string(),
        };
        let res = registry
            .get_shared_state(Request::new(get_req))
            .await
            .unwrap()
            .into_inner();
        assert!(res.found);
        assert_eq!(res.value_json, b"v1");
    }

    #[tokio::test]
    async fn test_agent_service_call_not_found() {
        let ctx = runtime::Context::new();
        let service = MyAgentService {
            ctx,
            registries: Vec::new(),
        };

        let req = CallRequest {
            goal_name: "missing".to_string(),
            args: HashMap::new(),
            caller_id: "caller".to_string(),
            signature: Vec::new(),
        };

        // This should fail because the caller isn't in any registry
        let res = service.call_goal(Request::new(req)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), Status::unauthenticated("").code());
    }

    #[tokio::test]
    async fn test_federated_lookup_logic() {
        let mut reg1 = MyRegistryService::new();
        let reg2 = MyRegistryService::new();

        // Mock reg2 addr
        let addr2 = "http://[::1]:50099".to_string();
        reg1.peer_registries.push(addr2.clone());

        // 1. Register agent in reg2
        let ctx = runtime::Context::new();
        let agent_id = "target_agent".to_string();
        let endpoint = "http://localhost:99".to_string();
        let payload = format!("{}:{}", agent_id, endpoint);
        let signature = ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        let reg_req = RegisterRequest {
            agent_id: agent_id.clone(),
            endpoint: endpoint.clone(),
            public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
            signature,
        };
        reg2.register_agent(Request::new(reg_req)).await.unwrap();

        // 2. Start reg2 server
        let socket_addr2: std::net::SocketAddr = "[::1]:50099".parse().unwrap();
        tokio::spawn(async move {
            let _ = start_registry(reg2, socket_addr2).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 3. Lookup via reg1 (should federate to reg2)
        let lookup_req = LookupRequest {
            agent_id: agent_id.clone(),
            ttl: 3,
        };
        let res = reg1
            .lookup_agent(Request::new(lookup_req))
            .await
            .unwrap()
            .into_inner();

        assert!(res.found);
        assert_eq!(res.endpoint, endpoint);
    }

    #[tokio::test]
    async fn test_registry_error_paths() {
        let registry = MyRegistryService::new();

        // 1. Invalid Public Key Length
        let reg_req = RegisterRequest {
            public_key: vec![0u8; 10], // Too short
            ..Default::default()
        };
        let res = registry.register_agent(Request::new(reg_req)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), Status::invalid_argument("").code());

        // 2. Invalid Signature
        let ctx_test = runtime::Context::new();
        let valid_pub_key = ctx_test.identity.verifying_key.to_bytes().to_vec();
        let reg_req = RegisterRequest {
            public_key: valid_pub_key,
            signature: vec![0u8; 64], // Wrong signature for this key
            ..Default::default()
        };
        let res = registry.register_agent(Request::new(reg_req)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), Status::unauthenticated("").code());

        // 3. Shared State Not Found
        let get_req = GetSharedRequest {
            key: "missing".to_string(),
        };
        let res = registry
            .get_shared_state(Request::new(get_req))
            .await
            .unwrap()
            .into_inner();
        assert!(!res.found);
    }

    #[tokio::test]
    async fn test_agent_service_successful_call() {
        let ctx = runtime::Context::new();
        // Register a goal
        {
            let mut goals = ctx.goals.lock().unwrap();
            goals.insert(
                "hello".to_string(),
                ast::GoalDefinition {
                    body: vec![],
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

        let registry = MyRegistryService::new();
        // Register the caller in the registry
        let caller_id = "caller".to_string();
        let endpoint = "http://localhost:1".to_string();
        let payload = format!("{}:{}", caller_id, endpoint);
        let signature = ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        registry
            .register_agent(Request::new(RegisterRequest {
                agent_id: caller_id.clone(),
                endpoint,
                public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            }))
            .await
            .unwrap();

        // Start registry server so the service can verify the caller
        let reg_addr = "http://[::1]:50111".to_string();
        let socket_addr: std::net::SocketAddr = "[::1]:50111".parse().unwrap();
        tokio::spawn(async move {
            let _ = start_registry(registry, socket_addr).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let service = MyAgentService {
            ctx: ctx.clone(),
            registries: vec![reg_addr],
        };

        // Prepare signed call
        let goal_name = "hello".to_string();
        let call_payload = format!("{}:{}", goal_name, caller_id);
        let call_signature = ctx
            .identity
            .signing_key
            .sign(call_payload.as_bytes())
            .to_bytes()
            .to_vec();

        let req = CallRequest {
            goal_name,
            args: HashMap::new(),
            caller_id,
            signature: call_signature,
        };

        let res = service
            .call_goal(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        assert!(res.success);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Coverage-boosting lib tests
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_registry_service_default() {
        let reg = MyRegistryService::default();
        assert!(reg.agents.lock().unwrap().is_empty());
        assert!(reg.shared_state.lock().unwrap().is_empty());
        assert!(reg.peer_registries.is_empty());
    }

    /// call_goal with numeric, boolean, and text args covers the arg-parsing
    /// branches (lines 238-256 in lib.rs).
    #[tokio::test]
    async fn test_agent_service_call_with_typed_args() {
        let ctx = runtime::Context::new();
        {
            let mut goals = ctx.goals.lock().unwrap();
            goals.insert(
                "echo_goal".to_string(),
                ast::GoalDefinition {
                    body: vec![],
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

        let registry = MyRegistryService::new();
        let caller_ctx = runtime::Context::new();
        let caller_id = "caller2".to_string();
        let endpoint = "http://localhost:2".to_string();
        let payload = format!("{}:{}", caller_id, endpoint);
        let signature = caller_ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        registry
            .register_agent(Request::new(RegisterRequest {
                agent_id: caller_id.clone(),
                endpoint,
                public_key: caller_ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            }))
            .await
            .unwrap();

        let reg_addr = "http://[::1]:50112".to_string();
        let socket_addr: std::net::SocketAddr = "[::1]:50112".parse().unwrap();
        tokio::spawn(async move {
            let _ = start_registry(registry, socket_addr).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let service = MyAgentService {
            ctx: ctx.clone(),
            registries: vec![reg_addr],
        };

        let goal_name = "echo_goal".to_string();
        let call_payload = format!("{}:{}", goal_name, caller_id);
        let call_signature = caller_ctx
            .identity
            .signing_key
            .sign(call_payload.as_bytes())
            .to_bytes()
            .to_vec();

        // Pass three args: a number, a bool, and a string
        let mut args = HashMap::new();
        args.insert("num_arg".to_string(), "3.14".to_string());
        args.insert("bool_arg".to_string(), "true".to_string());
        args.insert("text_arg".to_string(), "\"hello\"".to_string());

        let req = CallRequest {
            goal_name: goal_name.clone(),
            args,
            caller_id,
            signature: call_signature,
        };

        let res = service
            .call_goal(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        assert!(res.success);
    }

    /// Goal body that fails should return success=false with an error payload.
    #[tokio::test]
    async fn test_agent_service_goal_body_fails() {
        let ctx = runtime::Context::new();
        {
            let mut goals = ctx.goals.lock().unwrap();
            goals.insert(
                "bad_goal".to_string(),
                ast::GoalDefinition {
                    body: vec![
                        // RECALL a non-existent key with no on_missing → will error
                        ast::Statement::Recall {
                            name: "nonexistent_key_xyz".to_string(),
                            into_var: "x".to_string(),
                            scope: ast::MemoryScope::Working,
                            on_missing: None,
                            fuzzy: false,
                            threshold: None,
                        },
                    ],
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

        let registry = MyRegistryService::new();
        let caller_ctx = runtime::Context::new();
        let caller_id = "caller3".to_string();
        let endpoint = "http://localhost:3".to_string();
        let payload = format!("{}:{}", caller_id, endpoint);
        let signature = caller_ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        registry
            .register_agent(Request::new(RegisterRequest {
                agent_id: caller_id.clone(),
                endpoint,
                public_key: caller_ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            }))
            .await
            .unwrap();

        let reg_addr = "http://[::1]:50113".to_string();
        let socket_addr: std::net::SocketAddr = "[::1]:50113".parse().unwrap();
        tokio::spawn(async move {
            let _ = start_registry(registry, socket_addr).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let service = MyAgentService {
            ctx: ctx.clone(),
            registries: vec![reg_addr],
        };

        let goal_name = "bad_goal".to_string();
        let call_payload = format!("{}:{}", goal_name, caller_id);
        let call_signature = caller_ctx
            .identity
            .signing_key
            .sign(call_payload.as_bytes())
            .to_bytes()
            .to_vec();

        let req = CallRequest {
            goal_name,
            args: HashMap::new(),
            caller_id,
            signature: call_signature,
        };

        let res = service
            .call_goal(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        assert!(!res.success);
        assert!(res.result_json.contains("error"));
    }

    /// Caller is found in registry but goal is not registered → Status::not_found
    #[tokio::test]
    async fn test_agent_service_goal_not_found() {
        let ctx = runtime::Context::new(); // no goals registered

        let registry = MyRegistryService::new();
        let caller_ctx = runtime::Context::new();
        let caller_id = "caller4".to_string();
        let endpoint = "http://localhost:4".to_string();
        let payload = format!("{}:{}", caller_id, endpoint);
        let signature = caller_ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        registry
            .register_agent(Request::new(RegisterRequest {
                agent_id: caller_id.clone(),
                endpoint,
                public_key: caller_ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            }))
            .await
            .unwrap();

        let reg_addr = "http://[::1]:50114".to_string();
        let socket_addr: std::net::SocketAddr = "[::1]:50114".parse().unwrap();
        tokio::spawn(async move {
            let _ = start_registry(registry, socket_addr).await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let service = MyAgentService {
            ctx: ctx.clone(),
            registries: vec![reg_addr],
        };

        let goal_name = "missing_goal".to_string();
        let call_payload = format!("{}:{}", goal_name, caller_id);
        let call_signature = caller_ctx
            .identity
            .signing_key
            .sign(call_payload.as_bytes())
            .to_bytes()
            .to_vec();

        let req = CallRequest {
            goal_name,
            args: HashMap::new(),
            caller_id,
            signature: call_signature,
        };

        let res = service.call_goal(Request::new(req)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), tonic::Code::NotFound);
    }
}
