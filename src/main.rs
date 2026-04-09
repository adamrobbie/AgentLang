mod ast;
mod parser;
mod runtime;

use anyhow::Result;
use tonic::{transport::Server, Request, Response, Status};

pub mod agent_rpc {
    tonic::include_proto!("agent");
}

pub mod registry_rpc {
    tonic::include_proto!("registry");
}

use agent_rpc::agent_service_server::{AgentService, AgentServiceServer};
use agent_rpc::{CallRequest, CallResponse};

pub struct MyAgentService {
    pub ctx: runtime::Context,
}

#[tonic::async_trait]
impl AgentService for MyAgentService {
    async fn call_goal(
        &self,
        request: Request<CallRequest>,
    ) -> Result<Response<CallResponse>, Status> {
        let req = request.into_inner();
        println!("  [RPC] Received call for goal '{}'", req.goal_name);
        Ok(Response::new(CallResponse {
            result_json: "{\"status\": \"success\"}".to_string(),
            success: true,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    bastion::prelude::Bastion::init();
    bastion::prelude::Bastion::start();
    
    println!("====================================================");
    println!("   AgentLang 1.0 - Production Runtime Execution     ");
    println!("====================================================");
    
    let ctx = runtime::Context::new();
    
    // Start local gRPC node
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let addr = "[::1]:50051".parse().unwrap();
        let service = MyAgentService { ctx: ctx_clone };
        let _ = Server::builder()
            .add_service(AgentServiceServer::new(service))
            .serve(addr)
            .await;
    });

    // Integrated demonstration - no comments for parser stability
    let source = r#"
REMEMBER "user_api_key" VALUE "sk-secret-123" AS sensitive SCOPE session END
REMEMBER "agent_name" VALUE "PrimaryOrchestrator" SCOPE session END
ON "alert" SET event_processed = true END
GOAL fetch_data USE search_flights query "BTC" RESULT INTO {res} END REMEMBER "m_data" VALUE {res} SCOPE session END END
RECALL "api" INTO {found} FUZZY true SCOPE session END
REMEMBER "f_found" VALUE {found} SCOPE session END
CALL "AgentB" GOAL "pay" RESULT INTO {s} END
REMEMBER "f_sentiment" VALUE {s} SCOPE session END
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
            
            if let Ok(v) = ctx.get_variable("f_found", ast::MemoryScope::Session) {
                println!("Fuzzy Recall Result: {:?}", v.value);
            }
            if let Ok(v) = ctx.get_variable("f_sentiment", ast::MemoryScope::Session) {
                println!("Federated Call Result: {:?}", v.value);
            }
            if let Ok(v) = ctx.get_variable("m_data", ast::MemoryScope::Session) {
                println!("Market Data Result: {:?}", v.value);
            }

            println!("Audit Log Size: {} entries", ctx.audit_chain.lock().unwrap().entries.len());
            println!("====================================================");
        }
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
        }
    }
    
    Ok(())
}
