use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Statement {
    Set {
        variable: String,
        value: Expression,
    },
    UseTool {
        tool_name: String,
        args: HashMap<String, Expression>,
        result_into: Option<VariablePath>,
    },
    Tool(ToolDefinition),
    Goal {
        name: String,
        body: Vec<Statement>,
        outputs: Vec<GoalOutput>,
        result_into: Option<VariablePath>,
        retry: Option<u32>,
        on_fail: HashMap<GoalFailureType, Statement>,
        deadline: Option<f64>,
        wait: Option<f64>,
        idempotent: bool,
        audit_trail: bool,
        confirm_with: Option<String>,
        timeout_confirmation: Option<f64>,
        fallback: Option<Box<Statement>>,
    },
    Parallel {
        branches: Vec<Vec<Statement>>,
        result_into: Option<VariablePath>,
        deadline: Option<f64>,
        pattern: ParallelPattern,
    },
    If {
        condition: Expression,
        then_branch: Vec<Statement>,
        else_branch: Option<Vec<Statement>>,
    },
    ForEach {
        item: String,
        list: Expression,
        body: Vec<Statement>,
    },
    Repeat {
        condition: Expression,
        body: Vec<Statement>,
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
        budget: Option<f64>,
        requires_confirmation: bool,
        expires: Option<f64>,
    },
    Emit {
        event: String,
        data: Option<Expression>,
    },
    On {
        event: String,
        handler: Vec<Statement>,
    },
    Prove {
        statements: Vec<Statement>,
        claim: String,
        proof_name: String,
    },
    Reveal {
        proof_name: String,
        claim: String,
        to_agent: Option<String>,
        result_into: Option<VariablePath>,
    },
    UseWasm {
        module_path: String,
        function_name: String,
        args: Vec<(String, Expression)>,
        result_into: Option<VariablePath>,
    },
    Call {
        agent_id: String,
        goal_name: String,
        args: HashMap<String, Expression>,
        timeout: Option<f64>,
        signed_by: Option<String>,
        result_into: Option<VariablePath>,
    },
    Delegate {
        agent_id: String,
        goal_name: String,
        args: HashMap<String, Expression>,
    },
    Await {
        call_id: String,
        result_into: Option<VariablePath>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GoalFailureType {
    ToolFail,
    Timeout,
    Hallucination,
    Ambiguous,
    Permission,
    Any,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoalOutput {
    pub name: String,
    pub type_name: String,
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    Read,
    Write,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolField {
    pub name: String,
    pub type_hint: String,
    pub required: bool,
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: Option<String>,
    pub category: Option<ToolCategory>,
    pub version: Option<String>,
    pub inputs: Vec<ToolField>,
    pub outputs: Vec<ToolField>,
    pub reversible: bool,
    pub side_effect: bool,
    pub rate_limit: Option<String>,
    pub timeout: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoalDefinition {
    pub body: Vec<Statement>,
    pub outputs: Vec<GoalOutput>,
    pub result_into: Option<VariablePath>,
    pub retry: Option<usize>,
    pub on_fail: HashMap<GoalFailureType, Statement>,
    pub deadline: Option<f64>,
    pub wait: Option<f64>,
    pub idempotent: bool,
    pub audit_trail: bool,
    pub confirm_with: Option<String>,
    pub timeout_confirmation: Option<f64>,
    pub fallback: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParallelPattern {
    Gather,
    GatherAll,
    GatherMin(usize),
    Race,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryScope {
    Working,
    Session,
    LongTerm,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Verified,
    Trusted,
    Sandboxed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    CanUse(String),
    CannotUse(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariablePath {
    pub root: String,
    pub segments: Vec<PathSegment>,
}

impl VariablePath {
    pub fn root(name: &str) -> Self {
        Self {
            root: name.to_string(),
            segments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathSegment {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    Literal(AnnotatedValue),
    VariableRef(VariablePath),
    BinaryOp {
        left: Box<Expression>,
        op: BinaryOperator,
        right: Box<Expression>,
    },
    Annotated {
        expr: Box<Expression>,
        annotation: Annotation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOperator {
    Eq,
    Gt,
    Lt,
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    List(Vec<AnnotatedValue>),
    Object(HashMap<String, AnnotatedValue>),
    Null,
}
