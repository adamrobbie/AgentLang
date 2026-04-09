use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Set {
        name: String,
        value: Expression,
    },
    If {
        condition: Expression,
        then_branch: Vec<Statement>,
        else_branch: Option<Vec<Statement>>,
    },
    UseTool {
        tool_name: String,
        args: HashMap<String, Expression>,
        result_into: String,
    },
    Goal {
        name: String,
        body: Vec<Statement>,
        retry: Option<usize>,
        on_fail: Option<Box<Statement>>,
        deadline: Option<f64>,
    },
    Parallel {
        pattern: ParallelPattern,
        branches: Vec<Statement>,
        result_into: Option<String>,
        deadline: Option<f64>,
    },
    Wait {
        duration: f64,
    },
    Remember {
        name: String,
        value: Expression,
        scope: MemoryScope,
        expires: Option<f64>,
    },
    Recall {
        name: String,
        into_var: String,
        scope: MemoryScope,
        on_missing: Option<Expression>,
        fuzzy: bool,
        threshold: Option<f64>,
    },
    Forget {
        name: String,
        scope: MemoryScope,
    },
    Agent {
        name: String,
        id: String,
        registry: String,
        signed_by: String,
        trust_level: TrustLevel,
    },
    Contract {
        name: String,
        issued_by: String,
        capabilities: Vec<Permission>,
        expires: Option<f64>,
    },
    Emit {
        event: String,
        data: Expression,
    },
    On {
        event: String,
        handler: Box<Statement>,
    },
    Prove {
        statement: Box<Statement>,
        proof_name: String,
    },
    Reveal {
        proof_name: String,
        to_agent: Option<String>,
    },
    UseWasm {
        module_path: String,
        function_name: String,
        args: HashMap<String, Expression>,
        result_into: String,
    },
    Call {
        agent_id: String,
        goal_name: String,
        args: HashMap<String, Expression>,
        result_into: String,
    },
    Await {
        call_id: String, // Simplified for now as result_into var
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrustLevel {
    Verified,
    Trusted,
    Sandboxed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Permission {
    CanUse(String),
    CannotUse(String),
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum MemoryScope {
    Working,
    Session,
    LongTerm,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParallelPattern {
    Gather,
    Race,
    GatherMin(usize),
    GatherAll,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Literal(AnnotatedValue),
    VariableRef(String),
    Annotated {
        expr: Box<Expression>,
        annotation: Annotation,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Annotation {
    Confidence,
    Sensitive,
    Uncertain,
    Approximate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotatedValue {
    pub value: Value,
    pub confidence: Option<f64>,
    pub is_sensitive: bool,
    pub is_uncertain: bool,
    pub is_approximate: bool,
}

impl From<Value> for AnnotatedValue {
    fn from(value: Value) -> Self {
        Self {
            value,
            confidence: None,
            is_sensitive: false,
            is_uncertain: false,
            is_approximate: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Text(String),
    Number(f64),
    Boolean(bool),
}
