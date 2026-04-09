use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Set { name: String, value: Expression },
    If { condition: Expression, then_branch: Vec<Statement>, else_branch: Option<Vec<Statement>> },
    UseTool { tool_name: String, args: HashMap<String, Expression>, result_into: String },
    Goal { name: String, body: Vec<Statement> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Literal(Value),
    VariableRef(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Text(String),
    Number(f64),
    Boolean(bool),
}
