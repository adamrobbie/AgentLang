use AgentLang::ast;
use AgentLang::parser;
use AgentLang::registry_rpc::RegisterRequest;
use AgentLang::runtime;
use AgentLang::runtime::mcp;
use AgentLang::*;
use anyhow::{Context, Result};
use ariadne::{Color, Label, Report, ReportKind, Source};
use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "AgentLang")]
#[command(about = "AgentLang Runner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the AgentLang registry server
    Registry {
        #[arg(short, long, default_value = "50050")]
        port: u16,
    },
    /// Start a local agent and optionally run a script
    Agent {
        /// The port this agent will listen on
        #[arg(short, long, default_value = "50051")]
        port: u16,
        /// The Agent ID
        #[arg(short, long, default_value = "PrimaryOrchestrator")]
        id: String,
        /// Path to an .agentlang script to execute after starting
        #[arg(short, long)]
        script: Option<String>,
        /// URL of the registry server
        #[arg(short, long, default_value = "http://[::1]:50050")]
        registry: String,
        /// Command and arguments to run an MCP server (can be provided multiple times)
        #[arg(long = "mcp", num_args = 1..)]
        mcp_servers: Vec<String>,
    },
    /// Run the integrated multi-agent demo
    Demo,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    runtime::ensure_bastion_started();

    match cli.command {
        Commands::Registry { port } => run_registry(port).await?,
        Commands::Agent { port, id, script, registry, mcp_servers } => run_agent(port, id, script, registry, mcp_servers).await?,
        Commands::Demo => run_demo().await?,
    }

    Ok(())
}

async fn run_registry(port: u16) -> Result<()> {
    let addr = format!("[::1]:{}", port).parse()?;
    println!("Starting Registry on {}", addr);
    let registry = MyRegistryService::new();
    start_registry(registry, addr).await?;
    Ok(())
}

async fn run_agent(port: u16, id: String, script_path: Option<String>, registry_addr: String, mcp_servers: Vec<String>) -> Result<()> {
    let ctx = runtime::Context::new();
    
    // Load MCP Servers if provided
    for cmd in mcp_servers {
        let parts: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        if !parts.is_empty() {
            let exe = parts[0].clone();
            let args = parts[1..].to_vec();
            println!("Starting MCP Server: {}", cmd);
            mcp::load_mcp_servers(Arc::new(ctx.clone()), exe, args).await?;
        }
    }
    
    // Default Tools
    {
        let mut handlers = ctx.tool_handlers.lock().unwrap();
        handlers.insert(
            "search_flights".to_string(),
            std::sync::Arc::new(|args| {
                let query = args
                    .get("query")
                    .map(|v| format!("{:?}", v.value))
                    .unwrap_or_default();
                println!("  [Native Tool] search_flights executed with query: {}", query);
                let mut flight = HashMap::new();
                flight.insert("id".to_string(), ast::AnnotatedValue::from(ast::Value::Text("FL-456".to_string())));
                flight.insert("price".to_string(), ast::AnnotatedValue::from(ast::Value::Number(299.0)));
                let mut result = HashMap::new();
                result.insert("flights".to_string(), ast::AnnotatedValue::from(ast::Value::List(vec![ast::AnnotatedValue::from(ast::Value::Object(flight))])));
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

    let service = MyAgentService {
        ctx: ctx.clone(),
        registries: vec![registry_addr.clone()],
    };
    
    let addr = format!("[::1]:{}", port).parse()?;
    
    let id_clone = id.clone();
    tokio::spawn(async move {
        println!("Starting Agent {} on {}", id_clone, addr);
        let _ = start_agent(service, addr).await;
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Register
    let endpoint = format!("http://[::1]:{}", port);
    let payload = format!("{}:{}", id, endpoint);
    let signature = ctx.identity.signing_key.sign(payload.as_bytes()).to_bytes().to_vec();

    let mut client = AgentLang::registry_rpc::registry_service_client::RegistryServiceClient::connect(registry_addr.clone()).await?;
    client.register_agent(RegisterRequest {
        agent_id: id.clone(),
        endpoint,
        public_key: ctx.identity.verifying_key.to_bytes().to_vec(),
        signature,
    }).await?;
    *ctx.agent_id.lock().unwrap() = id.clone();

    if let Some(path) = script_path {
        let source = fs::read_to_string(&path).context("Failed to read script file")?;
        println!("Executing script: {}", path);
        match parser::parse_program(source.trim()) {
            Ok((_, program)) => {
                for stmt in program {
                    if let Err(e) = runtime::eval(&stmt, ctx.clone()).await {
                        eprintln!("Execution error: {:?}", e);
                    }
                }
            }
            Err(e) => {
                let filename: String = path.clone();
                Report::build(ReportKind::Error, (filename.clone(), 0..0))
                    .with_message("Parse error in AgentLang script")
                    .with_label(
                        Label::new((filename.clone(), 0..source.len()))
                            .with_message(format!("{:?}", e))
                            .with_color(Color::Red),
                    )
                    .finish()
                    .eprint((filename, Source::from(source)))
                    .unwrap();
            }
        }
    } else {
        println!("Agent {} running. Press Ctrl+C to exit.", id);
        tokio::signal::ctrl_c().await?;
    }
    
    Ok(())
}

async fn run_demo() -> Result<()> {

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
    let script_content = fs::read_to_string("examples/demo.agentlang")
        .context("Failed to read examples/demo.agentlang")?;

    println!("Parsing integrated program...");
    match parser::parse_program(script_content.trim()) {
        Ok((_, program)) => {
            println!("Executing main program ({} statements)...", program.len());
            for stmt in program {
                if let Err(e) = runtime::eval(&stmt, ctx.clone()).await {
                    eprintln!("Execution error: {:?}", e);
                }
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
                let filename = "examples/demo.agentlang".to_string();
                Report::build(ReportKind::Error, (filename.clone(), 0..0))
                    .with_message("Parse error in integrated demo script")
                    .with_label(
                        Label::new((filename.clone(), 0..script_content.len()))
                            .with_message(format!("{:?}", e))
                            .with_color(Color::Red),
                    )
                    .finish()
                    .eprint((filename, Source::from(script_content)))
                    .unwrap();
        }
    }

    Ok(())
}
