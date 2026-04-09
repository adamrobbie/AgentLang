mod ast;
mod parser;
mod runtime;

use anyhow::Result;
use tonic::{transport::Server, Request, Response, Status};
use std::sync::{Arc, Mutex};

pub mod agent_rpc {
    tonic::include_proto!("agent");
}

pub mod registry_rpc {
    tonic::include_proto!("registry");
}

use agent_rpc::agent_service_server::{AgentService, AgentServiceServer};
use agent_rpc::{CallRequest, CallResponse};

pub struct MyAgentService {
    pub ctx: Arc<Mutex<runtime::Context>>,
}

#[tonic::async_trait]
impl AgentService for MyAgentService {
    async fn call_goal(
        &self,
        request: Request<CallRequest>,
    ) -> Result<Response<CallResponse>, Status> {
        let req = request.into_inner();
        println!("RPC: Received call for goal '{}' from agent '{}'", req.goal_name, req.caller_id);
        
        // Simulating goal execution for Phase 5
        Ok(Response::new(CallResponse {
            result_json: "{\"status\": \"success\"}".to_string(),
            success: true,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    bastion::prelude::Bastion::init();
    
    println!("--- AgentLang 1.0 (Federated & Sandboxed) ---");
    
    let ctx = Arc::new(Mutex::new(runtime::Context::new()));
    
    // Spawn gRPC server in the background
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let addr = "[::1]:50051".parse().unwrap();
        let service = MyAgentService { ctx: ctx_clone };
        
        println!("gRPC: Agent listening on {}", addr);
        Server::builder()
            .add_service(AgentServiceServer::new(service))
            .serve(addr)
            .await.unwrap();
    });

    let source = r#"
GOAL plan_trip
  SET origin = "London"
  SET destination = "New York"
  
  REMEMBER user_name VALUE "Alice" SCOPE session END

  IF true
    USE search_flights
      from {origin}
      to {destination}
      RESULT INTO {flights}
    END
    
    RECALL user_name INTO {name} SCOPE session END
    SET final_status = {flights}
  END
END
    "#;
    
    match parser::parse_program(source) {
        Ok((_, program)) => {
            for stmt in program {
                runtime::eval(&stmt, ctx.clone()).await?;
            }
            
            println!("\n--- Final State ---");
            let lock = ctx.lock().unwrap();
            println!("final_status: {:?}", lock.get_variable("final_status", ast::MemoryScope::Working)?);
        }
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
        }
    }
    
    Ok(())
}
