mod ast;
mod crypto;
mod parser;
mod runtime;

use anyhow::Result;
use tonic::{Request, Response, Status, transport::Server};

pub mod agent_rpc {
    tonic::include_proto!("agent");
}

pub mod registry_rpc {
    tonic::include_proto!("registry");
}

use agent_rpc::agent_service_server::{AgentService, AgentServiceServer};
use agent_rpc::{CallRequest, CallResponse};
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use registry_rpc::registry_service_server::{RegistryService, RegistryServiceServer};
use registry_rpc::registry_service_client::RegistryServiceClient;
use registry_rpc::{
    GetSharedRequest, GetSharedResponse, LookupRequest, LookupResponse, PutSharedRequest,
    PutSharedResponse, RegisterRequest, RegisterResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type AgentRegistry = Arc<Mutex<HashMap<String, (String, Vec<u8>)>>>;

type SharedState = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub struct MyRegistryService {
    pub agents: AgentRegistry,
    pub shared_state: SharedState,
    pub peer_registries: Vec<String>,
}

#[tonic::async_trait]
impl RegistryService for MyRegistryService {
    async fn register_agent(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        // Phase 3.1: Verify signature
        let pub_key_bytes: [u8; 32] = req
            .public_key
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid public key: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&req.signature)
            .map_err(|_| Status::invalid_argument("Invalid signature format"))?;

        // The agent must sign its ID and endpoint
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
        
        // 1. Try local lookup
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

        // 2. Try federated lookup if ttl > 0
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
                            println!("  [Registry] Federated lookup SUCCESS for '{}' via peer {}", req.agent_id, peer);
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

        // 1. Lookup caller in registry (Federated)
        let mut lookup_res = None;
        for reg_addr in &self.registries {
            if let Ok(mut client) =
                registry_rpc::registry_service_client::RegistryServiceClient::connect(
                    reg_addr.clone(),
                )
                .await
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

        // 2. Verify signature
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

        // 3. Execute goal
        let goal_body = {
            let goals = self.ctx.goals.lock().unwrap();
            goals.get(&req.goal_name).cloned()
        };

        if let Some(goal_definition) = goal_body {
            // Execute in an isolated context
            let isolated_ctx = runtime::Context::new();

            // Phase 1.1: Inject arguments into the isolated context
            for (name, val_str) in req.args {
                // Simple heuristic parsing for the prototype (ideally use JSON serialization)
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
                fallback: None, // Simplified
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

#[tokio::main]
async fn main() -> Result<()> {
    runtime::ensure_bastion_started();

    println!("====================================================");
    println!("   AgentLang 1.0 - Production Runtime Execution     ");
    println!("====================================================");

    let registry_addr = "http://[::1]:50050";
    let registry_service_addr = "[::1]:50050".parse().unwrap();
    let registries = vec![registry_addr.to_string()];
    let registry = MyRegistryService {
        agents: Arc::new(Mutex::new(HashMap::new())),
        shared_state: Arc::new(Mutex::new(HashMap::new())),
        peer_registries: Vec::new(),
    };

    // 1. Start Registry
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(RegistryServiceServer::new(registry))
            .serve(registry_service_addr)
            .await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 2. Start AgentB (Target)
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
                audit_trail: true,
                confirm_with: None,
                timeout_confirmation: None,
                fallback: None,
            },
        );
    }
    let service_b = MyAgentService {
        ctx: ctx_b.clone(),
        registries: registries.clone(),
    };
    tokio::spawn(async move {
        let addr = "[::1]:50052".parse().unwrap();
        let _ = Server::builder()
            .add_service(AgentServiceServer::new(service_b))
            .serve(addr)
            .await;
    });

    // 3. Register AgentB
    {
        let agent_id = "AgentB".to_string();
        let endpoint = "http://[::1]:50052".to_string();
        let payload = format!("{}:{}", agent_id, endpoint);
        let signature = ctx_b
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        let mut client = registry_rpc::registry_service_client::RegistryServiceClient::connect(
            registry_addr.to_string(),
        )
        .await?;
        client
            .register_agent(RegisterRequest {
                agent_id,
                endpoint,
                public_key: ctx_b.identity.verifying_key.to_bytes().to_vec(),
                signature,
            })
            .await?;
    }

    // 4. Start Primary Orchestrator
    let ctx = runtime::Context::new();
    {
        let mut handlers = ctx.tool_handlers.lock().unwrap();
        handlers.insert("search_flights".to_string(), std::sync::Arc::new(|args| {
            let query = args.get("query").map(|v| format!("{:?}", v.value)).unwrap_or_default();
            println!("  [Native Tool] search_flights executed with query: {}", query);
            
            let mut flight = HashMap::new();
            flight.insert("id".to_string(), ast::AnnotatedValue::from(ast::Value::Text("FL-456".to_string())));
            flight.insert("price".to_string(), ast::AnnotatedValue::from(ast::Value::Number(299.0)));
            
            let mut result = HashMap::new();
            result.insert("flights".to_string(), ast::AnnotatedValue::from(ast::Value::List(vec![ast::AnnotatedValue::from(ast::Value::Object(flight))])));
            Ok(ast::AnnotatedValue::from(ast::Value::Object(result)))
        }));

        let mut tools = ctx.tools.lock().unwrap();
        tools.insert("search_flights".to_string(), ast::ToolDefinition {
            name: "search_flights".to_string(),
            description: Some("Search for flights".to_string()),
            category: Some(ast::ToolCategory::Read),
            version: Some("1.0.0".to_string()),
            inputs: vec![ast::ToolField { name: "query".to_string(), type_hint: "text".to_string(), required: true, annotations: vec![] }],
            outputs: vec![ast::ToolField { name: "flights".to_string(), type_hint: "list".to_string(), required: true, annotations: vec![] }],
            reversible: false,
            side_effect: false,
            rate_limit: None,
            timeout: Some(5.0),
        });
    }
    let service_a = MyAgentService {
        ctx: ctx.clone(),
        registries: registries.clone(),
    };
    tokio::spawn(async move {
        let addr = "[::1]:50051".parse().unwrap();
        let _ = Server::builder()
            .add_service(AgentServiceServer::new(service_a))
            .serve(addr)
            .await;
    });

    // 5. Register Orchestrator
    {
        let agent_id = "PrimaryOrchestrator".to_string();
        let endpoint = "http://[::1]:50051".to_string();
        let payload = format!("{}:{}", agent_id, endpoint);
        let signature = ctx
            .identity
            .signing_key
            .sign(payload.as_bytes())
            .to_bytes()
            .to_vec();

        let mut client = registry_rpc::registry_service_client::RegistryServiceClient::connect(
            registry_addr.to_string(),
        )
        .await?;
        client
            .register_agent(RegisterRequest {
                agent_id,
                endpoint,
                public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            })
            .await?;
    }

    // Integrated demonstration
    let source = r#"
REMEMBER "user_api_key" VALUE "sk-secret-123" AS sensitive SCOPE long_term END
REMEMBER "agent_name" VALUE "PrimaryOrchestrator" SCOPE session END
ON "alert" SET event_processed = true END
GOAL fetch_data 
  PARALLEL
    USE search_flights query "BTC" RESULT INTO {res1} END
    USE search_flights query "ETH" RESULT INTO {res2} END
  GATHER INTO {parallel_res}
  END
  REMEMBER "m_data" VALUE {parallel_res} SCOPE session END 
END
RECALL "api" INTO {found} FUZZY true SCOPE long_term END
REMEMBER "f_found" VALUE {found} SCOPE session END
GOAL federated_call 
  CALL "AgentB" GOAL "pay" RESULT INTO {my_call} END
  RETRY 2
  DEADLINE 5s
  AWAIT {my_call}
END
REMEMBER "f_sentiment" VALUE {my_call} SCOPE session END
PROVE {
  SET confidential_data = "top_secret" AS sensitive
  REMEMBER "secret_vault" VALUE {confidential_data} SCOPE long_term END
} AS auth_proof
REVEAL auth_proof INTO {secret}
EMIT "alert" DATA "done"
"#;

    println!("Parsing program...");
    match parser::parse_program(source.trim()) {
        Ok((_, program)) => {
            println!("Executing main program ({} statements)...", program.len());
            for stmt in program {
                runtime::eval(&stmt, ctx.clone()).await?;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            println!("\n====================================================");
            println!("   Final Execution State Verified                   ");
            println!("====================================================");

            if let Ok(v) = ctx.get_variable("f_found", ast::MemoryScope::Session).await {
                println!("Fuzzy Recall Result: {:?}", v.value);
            }
            if let Ok(v) = ctx
                .get_variable("f_sentiment", ast::MemoryScope::Session)
                .await
            {
                println!("Federated Call Result: {:?}", v.value);
            }
            if let Ok(v) = ctx.get_variable("m_data", ast::MemoryScope::Session).await {
                println!("Market Data Result: {:?}", v.value);
            }

            println!(
                "Audit Log Size: {} entries",
                ctx.audit_chain.lock().unwrap().entries.len()
            );
            println!("====================================================");
            bastion::prelude::Bastion::stop();
        }
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::*;

    #[tokio::test]
    async fn test_grpc_inter_agent_call() {
        let _guard = runtime::bastion_test_guard().await;
        // Setup registry
        let registry_addr = "http://[::1]:50060";
        let registry_service_addr = "[::1]:50060".parse().unwrap();
        let registry = MyRegistryService {
            agents: Arc::new(Mutex::new(HashMap::new())),
            shared_state: Arc::new(Mutex::new(HashMap::new())),
            peer_registries: Vec::new(),
        };

        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(RegistryServiceServer::new(registry))
                .serve(registry_service_addr)
                .await;
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        // Initialize Bastion for goal supervision used by remote goal execution.
        runtime::ensure_bastion_started();

        // Setup Agent B
        let ctx_b = Context::new();
        let registries = vec![registry_addr.to_string()];
        {
            let mut reg = ctx_b.registries.lock().unwrap();
            *reg = registries.clone();
        }
        {
            let mut goals = ctx_b.goals.lock().unwrap();
            goals.insert(
                "test_goal".to_string(),
                ast::GoalDefinition {
                    body: vec![ast::Statement::Set {
                        variable: "test_res".to_string(),
                        value: ast::Expression::Literal(ast::AnnotatedValue::from(
                            ast::Value::Text("hello from remote".to_string()),
                        )),
                    }],
                    outputs: vec![],
                    result_into: None,
                    retry: None,
                    on_fail: HashMap::new(),
                    deadline: None,
                    wait: None,
                    idempotent: false,
                    audit_trail: true,
                    confirm_with: None,
                    timeout_confirmation: None,
                    fallback: None,
                },
            );
        }
        let service_b = MyAgentService {
            ctx: ctx_b.clone(),
            registries: registries.clone(),
        };
        tokio::spawn(async move {
            let addr = "[::1]:50062".parse().unwrap();
            let _ = Server::builder()
                .add_service(AgentServiceServer::new(service_b))
                .serve(addr)
                .await;
        });

        // Register Agent B
        {
            let agent_id = "AgentB".to_string();
            let endpoint = "http://[::1]:50062".to_string();
            let payload = format!("{}:{}", agent_id, endpoint);
            let signature = ctx_b
                .identity
                .signing_key
                .sign(payload.as_bytes())
                .to_bytes()
                .to_vec();

            let mut client =
                crate::registry_rpc::registry_service_client::RegistryServiceClient::connect(
                    registry_addr.to_string(),
                )
                .await
                .unwrap();
            client
                .register_agent(RegisterRequest {
                    agent_id,
                    endpoint,
                    public_key: ctx_b.identity.verifying_key.to_bytes().to_vec(),
                    signature,
                })
                .await
                .unwrap();
        }

        // Setup Agent A (Orchestrator)
        let ctx_a = Context::new();
        {
            let mut reg = ctx_a.registries.lock().unwrap();
            *reg = registries.clone();
        }
        // Register Agent A so B can verify it
        {
            let agent_id = "PrimaryOrchestrator".to_string();
            let endpoint = "http://[::1]:50061".to_string();
            let payload = format!("{}:{}", agent_id, endpoint);
            let signature = ctx_a
                .identity
                .signing_key
                .sign(payload.as_bytes())
                .to_bytes()
                .to_vec();

            let mut client =
                crate::registry_rpc::registry_service_client::RegistryServiceClient::connect(
                    registry_addr.to_string(),
                )
                .await
                .unwrap();
            client
                .register_agent(RegisterRequest {
                    agent_id,
                    endpoint,
                    public_key: ctx_a.identity.verifying_key.to_bytes().to_vec(),
                    signature,
                })
                .await
                .unwrap();
        }

        // Perform CALL
        let call_stmt = ast::Statement::Call {
            agent_id: "AgentB".to_string(),
            goal_name: "test_goal".to_string(),
            args: HashMap::new(),
            timeout: None,
            signed_by: None,
            result_into: Some(ast::VariablePath::root("remote_res")),
        };

        eval(&call_stmt, ctx_a.clone()).await.unwrap();

        // Wait for result
        let await_stmt = ast::Statement::Await {
            call_id: "remote_res".to_string(),
            result_into: None,
        };
        eval(&await_stmt, ctx_a.clone()).await.unwrap();

        let res = ctx_a
            .get_variable("remote_res", ast::MemoryScope::Working)
            .await
            .unwrap();
        match res.value {
            ast::Value::Object(fields) => {
                assert_eq!(
                    fields.get("test_res").unwrap().value,
                    ast::Value::Text("hello from remote".to_string())
                );
            }
            other => panic!(
                "expected structured remote result object, found {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_registry_federation() {
        let _guard = runtime::bastion_test_guard().await;
        
        // 1. Start Registry A (Secondary)
        let addr_a = "http://[::1]:50070";
        let svc_addr_a = "[::1]:50070".parse().unwrap();
        let reg_a = MyRegistryService {
            agents: Arc::new(Mutex::new(HashMap::new())),
            shared_state: Arc::new(Mutex::new(HashMap::new())),
            peer_registries: Vec::new(),
        };
        tokio::spawn(async move {
            let _ = Server::builder().add_service(RegistryServiceServer::new(reg_a)).serve(svc_addr_a).await;
        });

        // 2. Start Registry B (Primary, with A as peer)
        let addr_b = "http://[::1]:50071";
        let svc_addr_b = "[::1]:50071".parse().unwrap();
        let reg_b = MyRegistryService {
            agents: Arc::new(Mutex::new(HashMap::new())),
            shared_state: Arc::new(Mutex::new(HashMap::new())),
            peer_registries: vec![addr_a.to_string()],
        };
        tokio::spawn(async move {
            let _ = Server::builder().add_service(RegistryServiceServer::new(reg_b)).serve(svc_addr_b).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // 3. Register Agent X in Registry A
        let ctx_x = runtime::Context::new();
        let agent_id = "AgentX".to_string();
        let endpoint = "http://[::1]:50072".to_string();
        let payload = format!("{}:{}", agent_id, endpoint);
        let signature = ctx_x.identity.signing_key.sign(payload.as_bytes()).to_bytes().to_vec();

        let mut client_a = RegistryServiceClient::connect(addr_a.to_string()).await.unwrap();
        client_a.register_agent(RegisterRequest {
            agent_id: agent_id.clone(),
            endpoint,
            public_key: ctx_x.identity.verifying_key.to_bytes().to_vec(),
            signature,
        }).await.unwrap();

        // 4. Lookup Agent X via Registry B
        let mut client_b = RegistryServiceClient::connect(addr_b.to_string()).await.unwrap();
        let res = client_b.lookup_agent(LookupRequest {
            agent_id: agent_id.clone(),
            ttl: 3,
        }).await.unwrap().into_inner();

        assert!(res.found);
        assert_eq!(res.endpoint, "http://[::1]:50072");
    }
}
