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
  
  IF true
    USE search_flights
      from {origin}
      to {destination}
      RESULT INTO {flights}
    END
    
    SET final_status = {flights}
  END
END
    "#;
    
    match parser::parse_program(source) {
        Ok((_, program)) => {
            let mut ctx = runtime::Context::new();
            for stmt in program {
                runtime::eval(&stmt, &mut ctx).await?;
            }
            
            println!("\n--- Final State ---");
            println!("final_status: {:?}", ctx.get_variable("final_status")?);
        }
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
        }
    }
    
    Ok(())
}
