use crate::ast::*;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub struct Context {
    pub variables: HashMap<String, Value>,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn get_variable(&self, name: &str) -> Result<Value> {
        self.variables
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("Variable '{}' not found", name))
    }

    pub fn set_variable(&mut self, name: String, value: Value) {
        self.variables.insert(name, value);
    }
}

pub fn eval_expression(expr: &Expression, ctx: &Context) -> Result<Value> {
    match expr {
        Expression::Literal(val) => Ok(val.clone()),
        Expression::VariableRef(name) => ctx.get_variable(name),
    }
}

pub async fn eval(statement: &Statement, ctx: &mut Context) -> Result<()> {
    match statement {
        Statement::Goal { name, body } => {
            println!("--- Executing Goal: {} ---", name);
            for stmt in body {
                Box::pin(eval(stmt, ctx)).await?;
            }
        }
        Statement::Set { name, value } => {
            let val = eval_expression(value, ctx)?;
            println!("SET {} = {:?}", name, val);
            ctx.set_variable(name.clone(), val);
        }
        Statement::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let cond_val = eval_expression(condition, ctx)?;
            let is_true = match cond_val {
                Value::Boolean(b) => b,
                Value::Number(n) => n != 0.0,
                Value::Text(s) => !s.is_empty(),
            };

            if is_true {
                for stmt in then_branch {
                    Box::pin(eval(stmt, ctx)).await?;
                }
            } else if let Some(branch) = else_branch {
                for stmt in branch {
                    Box::pin(eval(stmt, ctx)).await?;
                }
            }
        }
        Statement::UseTool {
            tool_name,
            args,
            result_into,
        } => {
            println!("USE TOOL: {}", tool_name);
            let mut evaluated_args = HashMap::new();
            for (arg_name, arg_expr) in args {
                evaluated_args.insert(arg_name.clone(), eval_expression(arg_expr, ctx)?);
            }
            println!("  Args: {:?}", evaluated_args);

            // Mock tool execution for Phase 1
            let mock_result = Value::Text(format!("Mock result from {}", tool_name));
            println!("  RESULT INTO {}: {:?}", result_into, mock_result);
            ctx.set_variable(result_into.clone(), mock_result);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_expression_literal() {
        let ctx = Context::new();
        let expr = Expression::Literal(Value::Number(42.0));
        assert_eq!(eval_expression(&expr, &ctx).unwrap(), Value::Number(42.0));
    }

    #[test]
    fn test_eval_expression_variable() {
        let mut ctx = Context::new();
        ctx.set_variable("x".to_string(), Value::Boolean(true));
        let expr = Expression::VariableRef("x".to_string());
        assert_eq!(eval_expression(&expr, &ctx).unwrap(), Value::Boolean(true));
    }

    #[tokio::test]
    async fn test_eval_set() {
        let mut ctx = Context::new();
        let stmt = Statement::Set {
            name: "y".to_string(),
            value: Expression::Literal(Value::Text("hello".to_string())),
        };
        eval(&stmt, &mut ctx).await.unwrap();
        assert_eq!(ctx.get_variable("y").unwrap(), Value::Text("hello".to_string()));
    }

    #[tokio::test]
    async fn test_eval_if_then() {
        let mut ctx = Context::new();
        let stmt = Statement::If {
            condition: Expression::Literal(Value::Boolean(true)),
            then_branch: vec![Statement::Set {
                name: "res".to_string(),
                value: Expression::Literal(Value::Number(1.0)),
            }],
            else_branch: None,
        };
        eval(&stmt, &mut ctx).await.unwrap();
        assert_eq!(ctx.get_variable("res").unwrap(), Value::Number(1.0));
    }

    #[tokio::test]
    async fn test_eval_if_else() {
        let mut ctx = Context::new();
        let stmt = Statement::If {
            condition: Expression::Literal(Value::Boolean(false)),
            then_branch: vec![Statement::Set {
                name: "res".to_string(),
                value: Expression::Literal(Value::Number(1.0)),
            }],
            else_branch: Some(vec![Statement::Set {
                name: "res".to_string(),
                value: Expression::Literal(Value::Number(2.0)),
            }]),
        };
        eval(&stmt, &mut ctx).await.unwrap();
        assert_eq!(ctx.get_variable("res").unwrap(), Value::Number(2.0));
    }
}
