mod ast;
mod parser;
mod runtime;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("--- AgentLang Interpreter (Phase 1) ---");
    
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
            let ctx = std::sync::Arc::new(std::sync::Mutex::new(runtime::Context::new()));
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
