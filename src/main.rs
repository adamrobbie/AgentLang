use AgentLang::ast;
use AgentLang::parser;
use AgentLang::registry_rpc::RegisterRequest;
use AgentLang::runtime;
use AgentLang::*;
use anyhow::Result;
use ed25519_dalek::Signer;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    runtime::ensure_bastion_started();

    println!("====================================================");
    println!("   AgentLang 1.0 - Production Runtime Execution     ");
    println!("====================================================");

    let registry_addr = "http://[::1]:50050";
    let registry_service_addr = "[::1]:50050".parse().unwrap();
    let registries = vec![registry_addr.to_string()];
    let registry = MyRegistryService::new();

    // 1. Start Registry
    tokio::spawn(async move {
        let _ = start_registry(registry, registry_service_addr).await;
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
        let _ = start_agent(service_b, addr).await;
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

        let mut client =
            AgentLang::registry_rpc::registry_service_client::RegistryServiceClient::connect(
                registry_addr.to_string(),
            )
            .await?;
        client
            .register_agent(RegisterRequest {
                agent_id: agent_id.clone(),
                endpoint,
                public_key: ctx_b.identity.verifying_key.to_bytes().to_vec(),
                signature,
            })
            .await?;

        // Inform the context of its registered identity so outgoing RPC calls sign
        // with the correct caller_id rather than a hardcoded placeholder.
        *ctx_b.agent_id.lock().unwrap_or_else(|e| e.into_inner()) = agent_id;
    }

    // 4. Start Primary Orchestrator
    let ctx = runtime::Context::new();
    {
        let mut handlers = ctx.tool_handlers.lock().unwrap();
        handlers.insert(
            "search_flights".to_string(),
            std::sync::Arc::new(|args| {
                let query = args
                    .get("query")
                    .map(|v| format!("{:?}", v.value))
                    .unwrap_or_default();
                println!(
                    "  [Native Tool] search_flights executed with query: {}",
                    query
                );

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
                    ast::AnnotatedValue::from(ast::Value::List(vec![ast::AnnotatedValue::from(
                        ast::Value::Object(flight),
                    )])),
                );
                Ok(ast::AnnotatedValue::from(ast::Value::Object(result)))
            }),
        );

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
    let service_a = MyAgentService {
        ctx: ctx.clone(),
        registries: registries.clone(),
    };
    tokio::spawn(async move {
        let addr = "[::1]:50051".parse().unwrap();
        let _ = start_agent(service_a, addr).await;
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

        let mut client =
            AgentLang::registry_rpc::registry_service_client::RegistryServiceClient::connect(
                registry_addr.to_string(),
            )
            .await?;
        client
            .register_agent(RegisterRequest {
                agent_id: agent_id.clone(),
                endpoint,
                public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
                signature,
            })
            .await?;

        // Update the context so that outgoing CALL/DELEGATE operations use the
        // registered ID when signing requests instead of a stale default.
        *ctx.agent_id.lock().unwrap_or_else(|e| e.into_inner()) = agent_id;
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
REVEAL auth_proof FOR "auth_proof" INTO {secret}
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
