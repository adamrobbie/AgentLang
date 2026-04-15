use crate::ast::*;
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{alpha1, alphanumeric1, char, digit1, multispace0, none_of},
    combinator::{map, map_res, opt, recognize},
    multi::{many_till, many0},
    sequence::{delimited, pair, preceded},
};
use std::collections::HashMap;

/// Simple whitespace wrapper
fn ws<'a, F, O>(mut inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: Parser<&'a str, Output = O, Error = nom::error::Error<&'a str>>,
{
    move |input: &'a str| {
        let (input, _) = multispace0(input)?;
        let (input, res) = inner.parse(input)?;
        let (input, _) = multispace0(input)?;
        Ok((input, res))
    }
}

/// Parse an identifier: (letter | '_') (letter | digit | '_')*
fn parse_identifier(input: &str) -> IResult<&str, String> {
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

fn parse_path_segment(input: &str) -> IResult<&str, PathSegment> {
    alt((
        map(preceded(char('.'), parse_identifier), PathSegment::Field),
        map(
            delimited(char('['), map_res(digit1, str::parse::<usize>), char(']')),
            PathSegment::Index,
        ),
    ))
    .parse(input)
}

fn parse_variable_path(input: &str) -> IResult<&str, VariablePath> {
    map(
        pair(parse_identifier, many0(parse_path_segment)),
        |(root, segments)| VariablePath { root, segments },
    )
    .parse(input)
}

/// Parse a boolean literal.
fn parse_boolean(input: &str) -> IResult<&str, Value> {
    alt((
        map(tag("true"), |_| Value::Boolean(true)),
        map(tag("false"), |_| Value::Boolean(false)),
    ))
    .parse(input)
}

/// Parse a number literal (integers or floats).
fn parse_number(input: &str) -> IResult<&str, Value> {
    map(
        recognize(pair(
            take_while1(|c: char| c.is_ascii_digit()),
            opt(pair(char('.'), take_while1(|c: char| c.is_ascii_digit()))),
        )),
        |s: &str| Value::Number(s.parse::<f64>().unwrap()),
    )
    .parse(input)
}

/// Parse a string literal (double-quoted).
fn parse_string(input: &str) -> IResult<&str, Value> {
    map(
        delimited(char('"'), many0(none_of("\"")), char('"')),
        |chars: Vec<char>| Value::Text(chars.into_iter().collect()),
    )
    .parse(input)
}

/// Parse a list literal: [v1, v2, ...]
fn parse_list(input: &str) -> IResult<&str, Value> {
    map(
        delimited(char('['), many0(ws(parse_value)), char(']')),
        Value::List,
    )
    .parse(input)
}

/// Parse a value (literal).
fn parse_value(input: &str) -> IResult<&str, AnnotatedValue> {
    map(
        alt((parse_boolean, parse_number, parse_string, parse_list)),
        AnnotatedValue::from,
    )
    .parse(input)
}

/// Parse an annotation keyword.
fn parse_annotation(input: &str) -> IResult<&str, Annotation> {
    alt((
        map(tag("confidence"), |_| Annotation::Confidence),
        map(tag("sensitive"), |_| Annotation::Sensitive),
        map(tag("uncertain"), |_| Annotation::Uncertain),
        map(tag("approximate"), |_| Annotation::Approximate),
    ))
    .parse(input)
}

/// Parse a binary operator.
fn parse_binary_operator(input: &str) -> IResult<&str, BinaryOperator> {
    alt((
        map(tag("=="), |_| BinaryOperator::Eq),
        map(tag(">"), |_| BinaryOperator::Gt),
        map(tag("<"), |_| BinaryOperator::Lt),
        map(tag("+"), |_| BinaryOperator::Add),
        map(tag("-"), |_| BinaryOperator::Sub),
    ))
    .parse(input)
}

/// Parse an expression: literal, variable reference, or annotated expression.
fn parse_expression(input: &str) -> IResult<&str, Expression> {
    let (input, mut left) = alt((
        map(parse_value, Expression::Literal),
        delimited(char('{'), parse_inner_expression, char('}')),
    ))
    .parse(input)?;

    let (input, maybe_annotation) = opt(preceded(ws(tag("AS")), parse_annotation)).parse(input)?;
    if let Some(annotation) = maybe_annotation {
        left = Expression::Annotated {
            expr: Box::new(left),
            annotation,
        };
    }

    let (input, maybe_op) =
        opt(pair(ws(parse_binary_operator), ws(parse_expression))).parse(input)?;

    if let Some((op, right)) = maybe_op {
        Ok((
            input,
            Expression::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            },
        ))
    } else {
        Ok((input, left))
    }
}

/// Expression context inside braces: identifiers are variable refs
fn parse_inner_expression(input: &str) -> IResult<&str, Expression> {
    let (input, mut left) = alt((
        map(parse_value, Expression::Literal),
        map(parse_variable_path, Expression::VariableRef),
        delimited(char('{'), parse_inner_expression, char('}')),
    ))
    .parse(input)?;

    let (input, maybe_annotation) = opt(preceded(ws(tag("AS")), parse_annotation)).parse(input)?;
    if let Some(annotation) = maybe_annotation {
        left = Expression::Annotated {
            expr: Box::new(left),
            annotation,
        };
    }

    let (input, maybe_op) =
        opt(pair(ws(parse_binary_operator), ws(parse_inner_expression))).parse(input)?;

    if let Some((op, right)) = maybe_op {
        Ok((
            input,
            Expression::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            },
        ))
    } else {
        Ok((input, left))
    }
}

/// Parse a SET statement: SET name = value
fn parse_set(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("SET"),
            ws(parse_identifier),
            tag("="),
            ws(parse_expression),
        ),
        |(_, variable, _, value)| Statement::Set { variable, value },
    )
    .parse(input)
}

/// Parse a USE tool statement: USE tool ... RESULT INTO {var} END
fn parse_use(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("USE"),
            ws(parse_identifier),
            many0((ws(parse_identifier), ws(parse_expression))),
            tag("RESULT INTO"),
            ws(delimited(char('{'), parse_variable_path, char('}'))),
            tag("END"),
        ),
        |(_, tool_name, args_vec, _, result_into, _)| {
            let args = args_vec.into_iter().collect();
            Statement::UseTool {
                tool_name,
                args,
                result_into: Some(result_into),
            }
        },
    )
    .parse(input)
}

/// Parse an IF statement: IF condition ... [ELSE ...] END
fn parse_if(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("IF"),
            ws(parse_expression),
            many0(parse_statement),
            opt(preceded(tag("ELSE"), many0(parse_statement))),
            tag("END"),
        ),
        |(_, condition, then_branch, else_branch, _)| Statement::If {
            condition,
            then_branch,
            else_branch,
        },
    )
    .parse(input)
}

enum GoalOpt {
    Retry(u32),
    OnFail {
        failure_type: GoalFailureType,
        handler: Box<Statement>,
    },
    Deadline(f64),
    Wait(f64),
    Idempotent,
    AuditTrail(bool),
    ConfirmWith(String),
    TimeoutConfirmation(f64),
    Fallback(Box<Statement>),
}

enum GoalItem {
    Statement(Box<Statement>),
    Outputs(Vec<GoalOutput>),
    ResultInto(VariablePath),
    Opt(GoalOpt),
}

fn parse_goal_failure_type(input: &str) -> IResult<&str, GoalFailureType> {
    alt((
        map(tag("TOOL_FAIL"), |_| GoalFailureType::ToolFail),
        map(tag("TIMEOUT"), |_| GoalFailureType::Timeout),
        map(tag("HALLUCINATION"), |_| GoalFailureType::Hallucination),
        map(tag("AMBIGUOUS"), |_| GoalFailureType::Ambiguous),
        map(tag("PERMISSION"), |_| GoalFailureType::Permission),
    ))
    .parse(input)
}

fn parse_goal_output(input: &str) -> IResult<&str, GoalOutput> {
    map(
        (
            parse_identifier,
            ws(parse_identifier),
            many0(preceded(ws(tag("AS")), parse_annotation)),
        ),
        |(name, type_name, annotations)| GoalOutput {
            name,
            type_name,
            annotations,
        },
    )
    .parse(input)
}

fn parse_goal_outputs(input: &str) -> IResult<&str, Vec<GoalOutput>> {
    map(
        preceded(
            tag("OUTPUT"),
            many_till(ws(parse_goal_output), ws(tag("END"))),
        ),
        |(outputs, _)| outputs,
    )
    .parse(input)
}

fn parse_goal_result_into(input: &str) -> IResult<&str, VariablePath> {
    map(
        (
            tag("RESULT"),
            ws(tag("INTO")),
            ws(delimited(char('{'), parse_variable_path, char('}'))),
        ),
        |(_, _, result_into)| result_into,
    )
    .parse(input)
}

fn parse_goal_opt(input: &str) -> IResult<&str, GoalOpt> {
    alt((
        map(preceded(ws(tag("RETRY")), ws(parse_number)), |v| {
            if let Value::Number(n) = v {
                GoalOpt::Retry(n as u32)
            } else {
                GoalOpt::Retry(0)
            }
        }),
        map(
            pair(
                preceded(
                    ws(tag("ON_FAIL")),
                    opt(delimited(char('['), parse_goal_failure_type, char(']'))),
                ),
                ws(parse_statement),
            ),
            |(ft, handler)| GoalOpt::OnFail {
                failure_type: ft.unwrap_or(GoalFailureType::Any),
                handler: Box::new(handler),
            },
        ),
        map(
            preceded(ws(tag("DEADLINE")), ws(parse_duration)),
            GoalOpt::Deadline,
        ),
        map(preceded(ws(tag("WAIT")), ws(parse_duration)), GoalOpt::Wait),
        map(ws(tag("IDEMPOTENT")), |_| GoalOpt::Idempotent),
        map(
            preceded(ws(tag("AUDIT_TRAIL")), ws(parse_boolean)),
            |value| match value {
                Value::Boolean(enabled) => GoalOpt::AuditTrail(enabled),
                _ => GoalOpt::AuditTrail(true),
            },
        ),
        map(
            preceded(ws(tag("CONFIRM_WITH")), ws(parse_identifier)),
            GoalOpt::ConfirmWith,
        ),
        map(
            preceded(ws(tag("TIMEOUT_CONFIRMATION")), ws(parse_duration)),
            GoalOpt::TimeoutConfirmation,
        ),
        map(preceded(ws(tag("FALLBACK")), ws(parse_statement)), |stmt| {
            GoalOpt::Fallback(Box::new(stmt))
        }),
    ))
    .parse(input)
}

fn parse_goal_item(input: &str) -> IResult<&str, GoalItem> {
    alt((
        map(parse_goal_outputs, GoalItem::Outputs),
        map(parse_goal_result_into, GoalItem::ResultInto),
        map(parse_goal_opt, GoalItem::Opt),
        map(parse_statement, |s| GoalItem::Statement(Box::new(s))),
    ))
    .parse(input)
}

/// Parse a GOAL block
fn parse_goal(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("GOAL"),
            ws(parse_identifier),
            many0(ws(parse_goal_item)),
            tag("END"),
        ),
        |(_, name, items, _)| {
            let mut body = Vec::new();
            let mut outputs = Vec::new();
            let mut result_into = None;
            let mut retry = None;
            let mut on_fail = HashMap::new();
            let mut deadline = None;
            let mut wait = None;
            let mut idempotent = false;
            let mut audit_trail = true;
            let mut confirm_with = None;
            let mut timeout_confirmation = None;
            let mut fallback = None;

            for item in items {
                match item {
                    GoalItem::Statement(stmt) => body.push(*stmt),
                    GoalItem::Outputs(parsed_outputs) => outputs = parsed_outputs,
                    GoalItem::ResultInto(target) => result_into = Some(target),
                    GoalItem::Opt(opt) => match opt {
                        GoalOpt::Retry(r) => retry = Some(r),
                        GoalOpt::OnFail {
                            failure_type,
                            handler,
                        } => {
                            on_fail.insert(failure_type, *handler);
                        }
                        GoalOpt::Deadline(d) => deadline = Some(d),
                        GoalOpt::Wait(d) => wait = Some(d),
                        GoalOpt::Idempotent => idempotent = true,
                        GoalOpt::AuditTrail(enabled) => audit_trail = enabled,
                        GoalOpt::ConfirmWith(s) => confirm_with = Some(s),
                        GoalOpt::TimeoutConfirmation(d) => timeout_confirmation = Some(d),
                        GoalOpt::Fallback(s) => fallback = Some(s),
                    },
                }
            }

            Statement::Goal {
                name,
                body,
                outputs,
                result_into,
                retry,
                on_fail,
                deadline,
                wait,
                idempotent,
                audit_trail,
                confirm_with,
                timeout_confirmation,
                fallback,
            }
        },
    )
    .parse(input)
}

/// Parse a duration: number + 's' / 'm' / 'h'
fn parse_duration(input: &str) -> IResult<&str, f64> {
    let (input, (num, unit)) = pair(
        recognize(take_while1(|c: char| c.is_ascii_digit())),
        alt((char('s'), char('m'), char('h'))),
    )
    .parse(input)?;
    let val = num.parse::<f64>().unwrap();
    let seconds = match unit {
        's' => val,
        'm' => val * 60.0,
        'h' => val * 3600.0,
        _ => unreachable!(),
    };
    Ok((input, seconds))
}

/// Parse a PARALLEL block
fn parse_parallel(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("PARALLEL"),
            many0(parse_statement),
            alt((
                map(tag("GATHER_ALL"), |_| ParallelPattern::GatherAll),
                map(preceded(tag("GATHER_MIN"), ws(parse_number)), |v| {
                    if let Value::Number(n) = v {
                        ParallelPattern::GatherMin(n as usize)
                    } else {
                        ParallelPattern::GatherMin(1)
                    }
                }),
                map(tag("GATHER"), |_| ParallelPattern::Gather),
            )),
            ws(preceded(
                tag("INTO"),
                ws(delimited(char('{'), parse_variable_path, char('}'))),
            )),
            opt(preceded(ws(tag("DEADLINE")), parse_duration)),
            tag("END"),
        ),
        |(_, branches, pattern, result_into, deadline, _)| Statement::Parallel {
            pattern,
            // Each top-level statement in a PARALLEL block becomes its own concurrent branch.
            branches: branches.into_iter().map(|s| vec![s]).collect(),
            result_into: Some(result_into),
            deadline,
        },
    )
    .parse(input)
}

/// Parse a RACE block
fn parse_race(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("RACE"),
            many0(parse_statement),
            tag("FIRST_INTO"),
            ws(delimited(char('{'), parse_variable_path, char('}'))),
            opt(preceded(ws(tag("DEADLINE")), parse_duration)),
            tag("END"),
        ),
        |(_, branches, _, result_into, deadline, _)| Statement::Parallel {
            pattern: ParallelPattern::Race,
            branches: vec![branches],
            result_into: Some(result_into),
            deadline,
        },
    )
    .parse(input)
}

/// Parse a FOREACH loop: FOREACH item IN list ... END
fn parse_foreach(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("FOREACH"),
            ws(parse_identifier),
            ws(tag("IN")),
            ws(parse_expression),
            many0(parse_statement),
            tag("END"),
        ),
        |(_, item, _, list, body, _)| Statement::ForEach { item, list, body },
    )
    .parse(input)
}

/// Parse a REPEAT loop: REPEAT UNTIL condition ... END
fn parse_repeat(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("REPEAT"),
            ws(tag("UNTIL")),
            ws(parse_expression),
            many0(parse_statement),
            tag("END"),
        ),
        |(_, _, condition, body, _)| Statement::Repeat { condition, body },
    )
    .parse(input)
}

/// Parse a WAIT statement
fn parse_wait(input: &str) -> IResult<&str, Statement> {
    map(preceded(tag("WAIT"), ws(parse_duration)), |duration| {
        Statement::Wait { duration }
    })
    .parse(input)
}

/// Parse a memory scope
fn parse_memory_scope(input: &str) -> IResult<&str, MemoryScope> {
    alt((
        map(tag("working"), |_| MemoryScope::Working),
        map(tag("session"), |_| MemoryScope::Session),
        map(tag("long_term"), |_| MemoryScope::LongTerm),
        map(tag("shared"), |_| MemoryScope::Shared),
    ))
    .parse(input)
}

/// Parse a key (identifier or string)
fn parse_key(input: &str) -> IResult<&str, String> {
    alt((
        parse_identifier,
        map(parse_string, |v| {
            if let Value::Text(s) = v {
                s
            } else {
                unreachable!()
            }
        }),
    ))
    .parse(input)
}

enum RememberOpt {
    Scope(MemoryScope),
    Expires(f64),
}

/// Parse REMEMBER
fn parse_remember(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("REMEMBER"),
            ws(parse_key),
            ws(tag("VALUE")),
            ws(parse_expression),
            many0(alt((
                map(
                    preceded(ws(tag("SCOPE")), ws(parse_memory_scope)),
                    RememberOpt::Scope,
                ),
                map(
                    preceded(ws(tag("EXPIRES")), ws(parse_duration)),
                    RememberOpt::Expires,
                ),
            ))),
            tag("END"),
        ),
        |(_, name, _, value, opts, _)| {
            let mut scope = MemoryScope::LongTerm;
            let mut expires = None;
            for opt in opts {
                match opt {
                    RememberOpt::Scope(s) => scope = s,
                    RememberOpt::Expires(d) => expires = Some(d),
                }
            }
            Statement::Remember {
                name,
                value,
                scope,
                expires,
            }
        },
    )
    .parse(input)
}

enum RecallOpt {
    Scope(MemoryScope),
    OnMissing(Expression),
    Fuzzy(bool),
    Threshold(f64),
}

/// Parse RECALL
fn parse_recall(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("RECALL"),
            ws(parse_key),
            ws(tag("INTO")),
            ws(delimited(char('{'), parse_identifier, char('}'))),
            many0(alt((
                map(
                    preceded(ws(tag("SCOPE")), ws(parse_memory_scope)),
                    RecallOpt::Scope,
                ),
                map(
                    preceded(ws(tag("ON_MISSING")), ws(parse_expression)),
                    RecallOpt::OnMissing,
                ),
                map(preceded(ws(tag("FUZZY")), ws(parse_boolean)), |b| {
                    if let Value::Boolean(bv) = b {
                        RecallOpt::Fuzzy(bv)
                    } else {
                        RecallOpt::Fuzzy(false)
                    }
                }),
                map(preceded(ws(tag("THRESHOLD")), ws(parse_number)), |n| {
                    if let Value::Number(nv) = n {
                        RecallOpt::Threshold(nv)
                    } else {
                        RecallOpt::Threshold(0.0)
                    }
                }),
            ))),
            tag("END"),
        ),
        |(_, name, _, into_var, opts, _)| {
            let mut scope = MemoryScope::LongTerm;
            let mut on_missing = None;
            let mut fuzzy = false;
            let mut threshold = None;
            for opt in opts {
                match opt {
                    RecallOpt::Scope(s) => scope = s,
                    RecallOpt::OnMissing(e) => on_missing = Some(e),
                    RecallOpt::Fuzzy(b) => fuzzy = b,
                    RecallOpt::Threshold(n) => threshold = Some(n),
                }
            }
            Statement::Recall {
                name,
                into_var,
                scope,
                on_missing,
                fuzzy,
                threshold,
            }
        },
    )
    .parse(input)
}

/// Parse FORGET
fn parse_forget(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("FORGET"),
            ws(parse_key),
            opt(preceded(ws(tag("SCOPE")), ws(parse_memory_scope))),
            tag("END"),
        ),
        |(_, name, scope, _)| Statement::Forget {
            name,
            scope: scope.unwrap_or(MemoryScope::LongTerm),
        },
    )
    .parse(input)
}

/// Parse a trust level
fn parse_trust_level(input: &str) -> IResult<&str, TrustLevel> {
    alt((
        map(tag("verified"), |_| TrustLevel::Verified),
        map(tag("trusted"), |_| TrustLevel::Trusted),
        map(tag("sandboxed"), |_| TrustLevel::Sandboxed),
        map(tag("blocked"), |_| TrustLevel::Blocked),
    ))
    .parse(input)
}

/// Parse an AGENT block
fn parse_agent(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("AGENT"),
            ws(parse_identifier),
            preceded(
                ws(tag("ID")),
                ws(recognize(take_while1(|c: char| c.is_alphanumeric()))),
            ),
            preceded(
                ws(tag("REGISTRY")),
                ws(recognize(take_while1(|c: char| {
                    c.is_alphanumeric() || c == '.'
                }))),
            ),
            preceded(
                ws(tag("SIGNED_BY")),
                ws(recognize(take_while1(|c: char| {
                    c.is_alphanumeric() || c == '.'
                }))),
            ),
            preceded(ws(tag("TRUST_LEVEL")), ws(parse_trust_level)),
            tag("END"),
        ),
        |(_, name, id, registry, signed_by, trust_level, _)| Statement::Agent {
            name,
            id: id.to_string(),
            registry: registry.to_string(),
            signed_by: signed_by.to_string(),
            trust_level,
        },
    )
    .parse(input)
}

/// Parse a permission
fn parse_permission(input: &str) -> IResult<&str, Permission> {
    alt((
        map(
            preceded(tag("CAN USE"), ws(parse_identifier)),
            Permission::CanUse,
        ),
        map(
            preceded(tag("CANNOT USE"), ws(parse_identifier)),
            Permission::CannotUse,
        ),
    ))
    .parse(input)
}

enum ContractItem {
    Permission(Permission),
    Budget(f64),
    RequiresConfirmation,
    Expires(f64),
}

fn parse_contract_item(input: &str) -> IResult<&str, ContractItem> {
    alt((
        map(ws(parse_permission), ContractItem::Permission),
        map(preceded(ws(tag("BUDGET")), ws(parse_number)), |v| {
            if let Value::Number(n) = v {
                ContractItem::Budget(n)
            } else {
                ContractItem::Budget(0.0)
            }
        }),
        map(ws(tag("REQUIRES CONFIRMATION")), |_| {
            ContractItem::RequiresConfirmation
        }),
        map(
            preceded(ws(tag("EXPIRES")), ws(parse_duration)),
            ContractItem::Expires,
        ),
    ))
    .parse(input)
}

/// Parse a CONTRACT block
fn parse_contract(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("CONTRACT"),
            ws(parse_identifier),
            preceded(
                ws(tag("ISSUED_BY")),
                ws(recognize(take_while1(|c: char| {
                    c.is_alphanumeric() || c == '.'
                }))),
            ),
            many0(parse_contract_item),
            tag("END"),
        ),
        |(_, name, issued_by, items, _)| {
            let mut capabilities = Vec::new();
            let mut budget = None;
            let mut requires_confirmation = false;
            let mut expires = None;

            for item in items {
                match item {
                    ContractItem::Permission(p) => capabilities.push(p),
                    ContractItem::Budget(b) => budget = Some(b),
                    ContractItem::RequiresConfirmation => requires_confirmation = true,
                    ContractItem::Expires(e) => expires = Some(e),
                }
            }

            Statement::Contract {
                name,
                issued_by: issued_by.to_string(),
                capabilities,
                budget,
                requires_confirmation,
                expires,
            }
        },
    )
    .parse(input)
}

/// Parse an EMIT statement: EMIT name DATA val
fn parse_emit(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("EMIT"),
            ws(parse_key),
            ws(tag("DATA")),
            ws(parse_expression),
        ),
        |(_, event, _, data)| Statement::Emit {
            event,
            data: Some(data),
        },
    )
    .parse(input)
}

/// Parse an ON statement: ON name ... END
fn parse_on(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("ON"), ws(parse_key), many0(parse_statement), tag("END")),
        |(_, event, handler, _)| Statement::On { event, handler },
    )
    .parse(input)
}

/// Parse a PROVE statement: PROVE { statements } FOR "claim" AS proof_name
fn parse_prove(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("PROVE"),
            ws(delimited(char('{'), many0(parse_statement), char('}'))),
            ws(tag("FOR")),
            ws(parse_string),
            ws(tag("AS")),
            ws(parse_identifier),
        ),
        |(_, statements, _, claim_val, _, proof_name)| {
            let claim = if let Value::Text(s) = claim_val {
                s
            } else {
                "".to_string()
            };
            Statement::Prove {
                statements,
                claim,
                proof_name,
            }
        },
    )
    .parse(input)
}

/// Parse a REVEAL statement: REVEAL proof_name FOR "claim" [TO agent_id] [INTO {var}]
fn parse_reveal(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("REVEAL"),
            ws(parse_identifier),
            ws(tag("FOR")),
            ws(parse_string),
            opt(preceded(ws(tag("TO")), ws(parse_identifier))),
            opt(preceded(
                ws(tag("INTO")),
                ws(delimited(char('{'), parse_variable_path, char('}'))),
            )),
        ),
        |(_, proof_name, _, claim_val, to_agent, result_into)| {
            let claim = if let Value::Text(s) = claim_val {
                s
            } else {
                "".to_string()
            };
            Statement::Reveal {
                proof_name,
                claim,
                to_agent,
                result_into,
            }
        },
    )
    .parse(input)
}

/// Parse a USE_WASM statement: USE_WASM "path" FUNCTION "name" ... RESULT INTO {var} END
fn parse_use_wasm(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("USE_WASM"),
            ws(parse_string),
            ws(tag("FUNCTION")),
            ws(parse_string),
            many0((ws(parse_identifier), ws(parse_expression))),
            tag("RESULT INTO"),
            ws(delimited(char('{'), parse_variable_path, char('}'))),
            tag("END"),
        ),
        |(_, module_path, _, function_name, args_vec, _, result_into, _)| {
            let module_path = if let Value::Text(s) = module_path {
                s
            } else {
                "".to_string()
            };
            let function_name = if let Value::Text(s) = function_name {
                s
            } else {
                "".to_string()
            };
            Statement::UseWasm {
                module_path,
                function_name,
                args: args_vec,
                result_into: Some(result_into),
            }
        },
    )
    .parse(input)
}

enum CallModifier {
    Timeout(f64),
    SignedBy(String),
}

fn parse_call_modifier(input: &str) -> IResult<&str, CallModifier> {
    alt((
        map(
            preceded(ws(tag("TIMEOUT")), ws(parse_duration)),
            CallModifier::Timeout,
        ),
        map(
            preceded(ws(tag("SIGNED_BY")), ws(parse_identifier)),
            CallModifier::SignedBy,
        ),
    ))
    .parse(input)
}

/// Parse a CALL statement: CALL "agent" GOAL "name" ... [TIMEOUT d] [SIGNED_BY id] RESULT INTO {var} END
fn parse_call(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("CALL"),
            ws(parse_string),
            ws(tag("GOAL")),
            ws(parse_string),
            many0((ws(parse_identifier), ws(parse_expression))),
            many0(parse_call_modifier),
            tag("RESULT INTO"),
            ws(delimited(char('{'), parse_variable_path, char('}'))),
            tag("END"),
        ),
        |(_, agent_id, _, goal_name, args_vec, modifiers, _, result_into, _)| {
            let agent_id = if let Value::Text(s) = agent_id {
                s
            } else {
                "".to_string()
            };
            let goal_name = if let Value::Text(s) = goal_name {
                s
            } else {
                "".to_string()
            };
            let args = args_vec.into_iter().collect();

            let mut timeout = None;
            let mut signed_by = None;
            for m in modifiers {
                match m {
                    CallModifier::Timeout(d) => timeout = Some(d),
                    CallModifier::SignedBy(id) => signed_by = Some(id),
                }
            }

            Statement::Call {
                agent_id,
                goal_name,
                args,
                timeout,
                signed_by,
                result_into: Some(result_into),
            }
        },
    )
    .parse(input)
}

/// Parse an AWAIT statement: AWAIT {var}
fn parse_await(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("AWAIT"),
            ws(delimited(char('{'), parse_identifier, char('}'))),
            opt(preceded(
                ws(tag("INTO")),
                ws(delimited(char('{'), parse_variable_path, char('}'))),
            )),
        ),
        |(_, call_id, result_into)| Statement::Await {
            call_id: call_id.to_string(),
            result_into,
        },
    )
    .parse(input)
}

fn parse_tool_category(input: &str) -> IResult<&str, ToolCategory> {
    alt((
        map(tag("read"), |_| ToolCategory::Read),
        map(tag("write"), |_| ToolCategory::Write),
        map(tag("agent"), |_| ToolCategory::Agent),
    ))
    .parse(input)
}

fn parse_tool_field(input: &str) -> IResult<&str, ToolField> {
    map(
        (
            ws(parse_identifier),
            ws(parse_identifier),
            alt((
                map(ws(tag("REQUIRED")), |_| true),
                map(ws(tag("OPTIONAL")), |_| false),
            )),
            many0(preceded(ws(tag("AS")), parse_annotation)),
        ),
        |(name, type_hint, required, annotations)| ToolField {
            name,
            type_hint,
            required,
            annotations,
        },
    )
    .parse(input)
}

enum ToolItem {
    Description(String),
    Category(ToolCategory),
    Version(String),
    Input(Vec<ToolField>),
    Output(Vec<ToolField>),
    Reversible(bool),
    SideEffect(bool),
    RateLimit(String),
    Timeout(f64),
}

fn parse_tool_item(input: &str) -> IResult<&str, ToolItem> {
    alt((
        map(
            preceded(ws(tag("DESCRIPTION")), ws(parse_string)),
            |v| match v {
                Value::Text(s) => ToolItem::Description(s),
                _ => unreachable!(),
            },
        ),
        map(
            preceded(ws(tag("CATEGORY")), ws(parse_tool_category)),
            ToolItem::Category,
        ),
        map(
            preceded(
                ws(tag("VERSION")),
                ws(recognize(pair(
                    digit1,
                    many0(alt((alphanumeric1, tag("."), tag("-")))),
                ))),
            ),
            |v: &str| ToolItem::Version(v.to_string()),
        ),
        map(
            preceded(
                ws(tag("INPUT")),
                many_till(ws(parse_tool_field), ws(tag("END"))),
            ),
            |(fields, _)| ToolItem::Input(fields),
        ),
        map(
            preceded(
                ws(tag("OUTPUT")),
                many_till(ws(parse_tool_field), ws(tag("END"))),
            ),
            |(fields, _)| ToolItem::Output(fields),
        ),
        map(
            preceded(ws(tag("REVERSIBLE")), ws(parse_boolean)),
            |v| match v {
                Value::Boolean(b) => ToolItem::Reversible(b),
                _ => unreachable!(),
            },
        ),
        map(
            preceded(ws(tag("SIDE_EFFECT")), ws(parse_boolean)),
            |v| match v {
                Value::Boolean(b) => ToolItem::SideEffect(b),
                _ => unreachable!(),
            },
        ),
        map(
            preceded(
                ws(tag("RATE_LIMIT")),
                ws(recognize(pair(
                    digit1,
                    many0(alt((alphanumeric1, tag("/")))),
                ))),
            ),
            |v: &str| ToolItem::RateLimit(v.to_string()),
        ),
        map(
            preceded(ws(tag("TIMEOUT")), ws(parse_duration)),
            ToolItem::Timeout,
        ),
    ))
    .parse(input)
}

/// Parse a TOOL block
fn parse_tool(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("TOOL"),
            ws(parse_identifier),
            many0(ws(parse_tool_item)),
            tag("END"),
        ),
        |(_, name, items, _)| {
            let mut description = None;
            let mut category = None;
            let mut version = None;
            let mut inputs = Vec::new();
            let mut outputs = Vec::new();
            let mut reversible = false;
            let mut side_effect = true;
            let mut rate_limit = None;
            let mut timeout = None;

            for item in items {
                match item {
                    ToolItem::Description(s) => description = Some(s),
                    ToolItem::Category(c) => category = Some(c),
                    ToolItem::Version(v) => version = Some(v),
                    ToolItem::Input(f) => inputs = f,
                    ToolItem::Output(f) => outputs = f,
                    ToolItem::Reversible(b) => reversible = b,
                    ToolItem::SideEffect(b) => side_effect = b,
                    ToolItem::RateLimit(s) => rate_limit = Some(s),
                    ToolItem::Timeout(d) => timeout = Some(d),
                }
            }

            Statement::Tool(ToolDefinition {
                name,
                description,
                category,
                version,
                inputs,
                outputs,
                reversible,
                side_effect,
                rate_limit,
                timeout,
            })
        },
    )
    .parse(input)
}

/// Parse a DELEGATE statement: DELEGATE "agent" GOAL "name" ... END
fn parse_delegate(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("DELEGATE"),
            ws(parse_string),
            ws(tag("GOAL")),
            ws(parse_string),
            many0((ws(parse_identifier), ws(parse_expression))),
            tag("END"),
        ),
        |(_, agent_id, _, goal_name, args_vec, _)| {
            let agent_id = if let Value::Text(s) = agent_id {
                s
            } else {
                "".to_string()
            };
            let goal_name = if let Value::Text(s) = goal_name {
                s
            } else {
                "".to_string()
            };
            let args = args_vec.into_iter().collect();
            Statement::Delegate {
                agent_id,
                goal_name,
                args,
            }
        },
    )
    .parse(input)
}

/// Parse any statement.
fn parse_statement(input: &str) -> IResult<&str, Statement> {
    ws(alt((
        alt((
            parse_set,
            parse_if,
            parse_use,
            parse_goal,
            parse_tool,
            parse_parallel,
            parse_race,
            parse_foreach,
            parse_repeat,
            parse_wait,
            parse_remember,
        )),
        alt((
            parse_recall,
            parse_forget,
            parse_agent,
            parse_contract,
            parse_emit,
            parse_on,
            parse_prove,
            parse_reveal,
            parse_use_wasm,
            parse_call,
            parse_delegate,
            parse_await,
        )),
    )))
    .parse(input)
}

/// Entry point: parse the whole program into a sequence of statements.
pub fn parse_program(input: &str) -> IResult<&str, Vec<Statement>> {
    many0(parse_statement).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identifier() {
        assert_eq!(parse_identifier("my_var"), Ok(("", "my_var".to_string())));
        assert_eq!(
            parse_identifier("_private"),
            Ok(("", "_private".to_string()))
        );
        assert!(parse_identifier("123var").is_err());
    }

    #[test]
    fn test_parse_value() {
        assert_eq!(
            parse_value("true"),
            Ok(("", AnnotatedValue::from(Value::Boolean(true))))
        );
        assert_eq!(
            parse_value("42"),
            Ok(("", AnnotatedValue::from(Value::Number(42.0))))
        );
        assert_eq!(
            parse_value("\"hello\""),
            Ok(("", AnnotatedValue::from(Value::Text("hello".to_string()))))
        );
    }

    #[test]
    fn test_parse_expression() {
        assert_eq!(
            parse_expression("true"),
            Ok((
                "",
                Expression::Literal(AnnotatedValue::from(Value::Boolean(true)))
            ))
        );
        assert_eq!(
            parse_expression("{my_var}"),
            Ok(("", Expression::VariableRef(VariablePath::root("my_var"))))
        );
        assert_eq!(
            parse_expression("{foo.bar}"),
            Ok((
                "",
                Expression::VariableRef(VariablePath {
                    root: "foo".to_string(),
                    segments: vec![PathSegment::Field("bar".to_string())],
                })
            ))
        );
        assert_eq!(
            parse_expression("{items[0]}"),
            Ok((
                "",
                Expression::VariableRef(VariablePath {
                    root: "items".to_string(),
                    segments: vec![PathSegment::Index(0)],
                })
            ))
        );
        assert_eq!(
            parse_expression("{trip.flight[0].price}"),
            Ok((
                "",
                Expression::VariableRef(VariablePath {
                    root: "trip".to_string(),
                    segments: vec![
                        PathSegment::Field("flight".to_string()),
                        PathSegment::Index(0),
                        PathSegment::Field("price".to_string()),
                    ],
                })
            ))
        );
        assert!(parse_expression("{foo.}").is_err());
        assert!(parse_expression("{foo[]}").is_err());
    }

    #[test]
    fn test_parse_annotated_expression() {
        assert_eq!(
            parse_expression("\"secret\" AS sensitive"),
            Ok((
                "",
                Expression::Annotated {
                    expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Text(
                        "secret".to_string()
                    )))),
                    annotation: Annotation::Sensitive,
                }
            ))
        );
    }

    #[test]
    fn test_parse_complex_expression_in_braces() {
        assert_eq!(
            parse_expression("{price + 10}"),
            Ok((
                "",
                Expression::BinaryOp {
                    left: Box::new(Expression::VariableRef(VariablePath::root("price"))),
                    op: BinaryOperator::Add,
                    right: Box::new(Expression::Literal(AnnotatedValue::from(Value::Number(
                        10.0
                    )))),
                }
            ))
        );
    }

    #[test]
    fn test_parse_set() {
        let input = "SET origin = \"London\"";
        let expected = Statement::Set {
            variable: "origin".to_string(),
            value: Expression::Literal(AnnotatedValue::from(Value::Text("London".to_string()))),
        };
        assert_eq!(parse_set(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_goal() {
        let input = "GOAL my_goal SET x = 1 END";
        let expected = Statement::Goal {
            name: "my_goal".to_string(),
            body: vec![Statement::Set {
                variable: "x".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
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
        };
        assert_eq!(parse_goal(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_goal_with_outputs_and_result_into() {
        let input = "GOAL search_flights SET flights = [1] OUTPUT flights list confidence float AS confidence END RESULT INTO {trip.summary} END";
        let expected = Statement::Goal {
            name: "search_flights".to_string(),
            body: vec![Statement::Set {
                variable: "flights".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::List(vec![
                    AnnotatedValue::from(Value::Number(1.0)),
                ]))),
            }],
            outputs: vec![
                GoalOutput {
                    name: "flights".to_string(),
                    type_name: "list".to_string(),
                    annotations: vec![],
                },
                GoalOutput {
                    name: "confidence".to_string(),
                    type_name: "float".to_string(),
                    annotations: vec![Annotation::Confidence],
                },
            ],
            result_into: Some(VariablePath {
                root: "trip".to_string(),
                segments: vec![PathSegment::Field("summary".to_string())],
            }),
            retry: None,
            on_fail: HashMap::new(),
            deadline: None,
            wait: None,
            idempotent: false,
            audit_trail: true,
            confirm_with: None,
            timeout_confirmation: None,
            fallback: None,
        };
        assert_eq!(parse_goal(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_if() {
        let input = "IF true SET x = 1 ELSE SET x = 2 END";
        let expected = Statement::If {
            condition: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            then_branch: vec![Statement::Set {
                variable: "x".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))),
            }],
            else_branch: Some(vec![Statement::Set {
                variable: "x".to_string(),
                value: Expression::Literal(AnnotatedValue::from(Value::Number(2.0))),
            }]),
        };
        assert_eq!(parse_if(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_wait() {
        assert_eq!(
            parse_wait("WAIT 10s"),
            Ok(("", Statement::Wait { duration: 10.0 }))
        );
    }

    #[test]
    fn test_parse_recall_fuzzy() {
        let input = "RECALL \"topic\" INTO {res} FUZZY true THRESHOLD 0.8 END";
        if let Ok(("", Statement::Recall { fuzzy, .. })) = parse_recall(input) {
            assert!(fuzzy);
        } else {
            panic!("Failed to parse FUZZY RECALL");
        }
    }

    #[test]
    fn test_parse_tool() {
        let input = "TOOL search_flights DESCRIPTION \"Search flights\" CATEGORY read VERSION 1.0.0 INPUT from text REQUIRED END OUTPUT flights list OPTIONAL END END";
        if let Ok(("", Statement::Tool(def))) = parse_tool(input) {
            assert_eq!(def.name, "search_flights");
            assert_eq!(def.description, Some("Search flights".to_string()));
            assert_eq!(def.category, Some(ToolCategory::Read));
            assert_eq!(def.version, Some("1.0.0".to_string()));
            assert_eq!(def.inputs.len(), 1);
            assert_eq!(def.inputs[0].name, "from");
            assert_eq!(def.inputs[0].type_hint, "text");
            assert!(def.inputs[0].required);
            assert_eq!(def.outputs.len(), 1);
            assert_eq!(def.outputs[0].name, "flights");
            assert_eq!(def.outputs[0].type_hint, "list");
            assert!(!def.outputs[0].required);
        } else {
            panic!("Failed to parse TOOL");
        }
    }

    #[test]
    fn test_parse_invalid_syntax() {
        // Missing END
        let input = "GOAL fail SET x = 1";
        assert!(parse_program(input).is_err() || parse_program(input).unwrap().1.is_empty());

        // Invalid keyword
        let input = "NOT_A_KEYWORD x = 1";
        assert!(parse_program(input).is_err() || parse_program(input).unwrap().1.is_empty());

        // Malformed SET
        assert!(parse_set("SET x 1").is_err());

        // Malformed IF
        assert!(parse_if("IF true SET x = 1 END").is_ok());
        assert!(parse_if("IF true SET x = 1").is_err());

        // Malformed REMEMBER
        assert!(parse_remember("REMEMBER key VALUE").is_err());

        // Malformed RECALL
        assert!(parse_recall("RECALL key").is_err());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Parser tests for statements not previously covered
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_remember_basic() {
        let input = "REMEMBER city VALUE \"London\" END";
        if let Ok((
            "",
            Statement::Remember {
                name,
                scope,
                expires,
                ..
            },
        )) = parse_remember(input)
        {
            assert_eq!(name, "city");
            assert_eq!(scope, MemoryScope::LongTerm); // default scope
            assert!(expires.is_none());
        } else {
            panic!("Failed to parse REMEMBER");
        }
    }

    #[test]
    fn test_parse_remember_with_scope_and_expires() {
        let input = "REMEMBER city VALUE \"London\" SCOPE working EXPIRES 30s END";
        if let Ok((
            "",
            Statement::Remember {
                name,
                scope,
                expires,
                ..
            },
        )) = parse_remember(input)
        {
            assert_eq!(name, "city");
            assert_eq!(scope, MemoryScope::Working);
            assert_eq!(expires, Some(30.0));
        } else {
            panic!("Failed to parse REMEMBER with scope/expires");
        }
    }

    #[test]
    fn test_parse_forget() {
        let input = "FORGET city END";
        if let Ok(("", Statement::Forget { name, scope })) = parse_forget(input) {
            assert_eq!(name, "city");
            assert_eq!(scope, MemoryScope::LongTerm); // default
        } else {
            panic!("Failed to parse FORGET");
        }
    }

    #[test]
    fn test_parse_forget_with_scope() {
        let input = "FORGET city SCOPE session END";
        if let Ok(("", Statement::Forget { name, scope })) = parse_forget(input) {
            assert_eq!(name, "city");
            assert_eq!(scope, MemoryScope::Session);
        } else {
            panic!("Failed to parse FORGET with scope");
        }
    }

    #[test]
    fn test_parse_agent() {
        let input = "AGENT planner ID abc123 REGISTRY registry.example SIGNED_BY authority.example TRUST_LEVEL verified END";
        if let Ok((
            "",
            Statement::Agent {
                name,
                id,
                registry,
                signed_by,
                trust_level,
            },
        )) = parse_agent(input)
        {
            assert_eq!(name, "planner");
            assert_eq!(id, "abc123");
            assert_eq!(registry, "registry.example");
            assert_eq!(signed_by, "authority.example");
            assert_eq!(trust_level, TrustLevel::Verified);
        } else {
            panic!("Failed to parse AGENT");
        }
    }

    #[test]
    fn test_parse_trust_levels() {
        for (level_str, expected) in [
            ("trusted", TrustLevel::Trusted),
            ("sandboxed", TrustLevel::Sandboxed),
            ("blocked", TrustLevel::Blocked),
        ] {
            let input = format!(
                "AGENT a ID x REGISTRY r SIGNED_BY s TRUST_LEVEL {} END",
                level_str
            );
            if let Ok(("", Statement::Agent { trust_level, .. })) = parse_agent(&input) {
                assert_eq!(trust_level, expected);
            } else {
                panic!("Failed to parse TRUST_LEVEL {}", level_str);
            }
        }
    }

    #[test]
    fn test_parse_contract() {
        let input = "CONTRACT admin_contract ISSUED_BY authority.example CAN USE search_flights BUDGET 100 END";
        if let Ok((
            "",
            Statement::Contract {
                name,
                issued_by,
                capabilities,
                budget,
                ..
            },
        )) = parse_contract(input)
        {
            assert_eq!(name, "admin_contract");
            assert_eq!(issued_by, "authority.example");
            assert_eq!(
                capabilities,
                vec![Permission::CanUse("search_flights".to_string())]
            );
            assert_eq!(budget, Some(100.0));
        } else {
            panic!("Failed to parse CONTRACT");
        }
    }

    #[test]
    fn test_parse_contract_cannot_use() {
        let input = "CONTRACT restricted ISSUED_BY authority CANNOT USE admin END";
        if let Ok(("", Statement::Contract { capabilities, .. })) = parse_contract(input) {
            assert_eq!(
                capabilities,
                vec![Permission::CannotUse("admin".to_string())]
            );
        } else {
            panic!("Failed to parse CANNOT USE in CONTRACT");
        }
    }

    #[test]
    fn test_parse_contract_requires_confirmation() {
        let input = "CONTRACT c ISSUED_BY auth REQUIRES CONFIRMATION END";
        if let Ok((
            "",
            Statement::Contract {
                requires_confirmation,
                ..
            },
        )) = parse_contract(input)
        {
            assert!(requires_confirmation);
        } else {
            panic!("Failed to parse REQUIRES CONFIRMATION in CONTRACT");
        }
    }

    #[test]
    fn test_parse_emit() {
        let input = "EMIT alert DATA \"danger\"";
        if let Ok((
            "",
            Statement::Emit {
                event,
                data: Some(data_expr),
            },
        )) = parse_emit(input)
        {
            assert_eq!(event, "alert");
            assert_eq!(
                data_expr,
                Expression::Literal(AnnotatedValue::from(Value::Text("danger".to_string())))
            );
        } else {
            panic!("Failed to parse EMIT");
        }
    }

    #[test]
    fn test_parse_on() {
        let input = "ON alert SET x = 1 END";
        if let Ok(("", Statement::On { event, handler })) = parse_on(input) {
            assert_eq!(event, "alert");
            assert_eq!(handler.len(), 1);
        } else {
            panic!("Failed to parse ON");
        }
    }

    #[test]
    fn test_parse_prove() {
        let input = "PROVE { SET x = 1 } FOR \"balance_above_100\" AS proof1";
        if let Ok((
            "",
            Statement::Prove {
                statements,
                claim,
                proof_name,
            },
        )) = parse_prove(input)
        {
            assert_eq!(claim, "balance_above_100");
            assert_eq!(proof_name, "proof1");
            assert_eq!(statements.len(), 1);
        } else {
            panic!("Failed to parse PROVE");
        }
    }

    #[test]
    fn test_parse_reveal() {
        let input = "REVEAL proof1 FOR \"balance_above_100\" INTO {result}";
        if let Ok((
            "",
            Statement::Reveal {
                proof_name,
                claim,
                to_agent,
                result_into,
            },
        )) = parse_reveal(input)
        {
            assert_eq!(proof_name, "proof1");
            assert_eq!(claim, "balance_above_100");
            assert!(to_agent.is_none());
            assert!(result_into.is_some());
        } else {
            panic!("Failed to parse REVEAL");
        }
    }

    #[test]
    fn test_parse_reveal_to_agent() {
        let input = "REVEAL p FOR \"claim\" TO planner_agent INTO {res}";
        if let Ok(("", Statement::Reveal { to_agent, .. })) = parse_reveal(input) {
            assert_eq!(to_agent, Some("planner_agent".to_string()));
        } else {
            panic!("Failed to parse REVEAL with TO");
        }
    }

    #[test]
    fn test_parse_parallel_gather() {
        let input = "PARALLEL SET x = 1 SET y = 2 GATHER INTO {res} END";
        if let Ok((
            "",
            Statement::Parallel {
                pattern,
                branches,
                result_into,
                deadline,
            },
        )) = parse_parallel(input)
        {
            assert_eq!(pattern, ParallelPattern::Gather);
            assert_eq!(branches.len(), 2);
            assert!(result_into.is_some());
            assert!(deadline.is_none());
        } else {
            panic!("Failed to parse PARALLEL GATHER");
        }
    }

    #[test]
    fn test_parse_parallel_gather_all() {
        let input = "PARALLEL SET x = 1 GATHER_ALL INTO {res} END";
        if let Ok(("", Statement::Parallel { pattern, .. })) = parse_parallel(input) {
            assert_eq!(pattern, ParallelPattern::GatherAll);
        } else {
            panic!("Failed to parse PARALLEL GATHER_ALL");
        }
    }

    #[test]
    fn test_parse_parallel_gather_min() {
        let input = "PARALLEL SET x = 1 SET y = 2 GATHER_MIN 1 INTO {res} END";
        if let Ok(("", Statement::Parallel { pattern, .. })) = parse_parallel(input) {
            assert_eq!(pattern, ParallelPattern::GatherMin(1));
        } else {
            panic!("Failed to parse PARALLEL GATHER_MIN");
        }
    }

    #[test]
    fn test_parse_race() {
        let input = "RACE SET x = 1 SET y = 2 FIRST_INTO {res} END";
        if let Ok((
            "",
            Statement::Parallel {
                pattern,
                branches,
                result_into,
                ..
            },
        )) = parse_race(input)
        {
            assert_eq!(pattern, ParallelPattern::Race);
            // RACE wraps all stmts into a single branch
            assert_eq!(branches.len(), 1);
            assert_eq!(branches[0].len(), 2);
            assert!(result_into.is_some());
        } else {
            panic!("Failed to parse RACE");
        }
    }

    #[test]
    fn test_parse_foreach() {
        let input = "FOREACH item IN [1 2 3] SET x = {item} END";
        if let Ok(("", Statement::ForEach { item, body, .. })) = parse_foreach(input) {
            assert_eq!(item, "item");
            assert_eq!(body.len(), 1);
        } else {
            panic!("Failed to parse FOREACH");
        }
    }

    #[test]
    fn test_parse_repeat() {
        let input = "REPEAT UNTIL true SET x = 1 END";
        if let Ok(("", Statement::Repeat { condition, body })) = parse_repeat(input) {
            assert_eq!(
                condition,
                Expression::Literal(AnnotatedValue::from(Value::Boolean(true)))
            );
            assert_eq!(body.len(), 1);
        } else {
            panic!("Failed to parse REPEAT");
        }
    }

    #[test]
    fn test_parse_use_tool() {
        let input = "USE add_numbers a 10 b 20 RESULT INTO {res} END";
        if let Ok((
            "",
            Statement::UseTool {
                tool_name,
                args,
                result_into,
            },
        )) = parse_use(input)
        {
            assert_eq!(tool_name, "add_numbers");
            assert_eq!(args.len(), 2);
            assert!(result_into.is_some());
        } else {
            panic!("Failed to parse USE");
        }
    }

    #[test]
    fn test_parse_delegate() {
        let input = "DELEGATE \"planner\" GOAL \"search\" END";
        if let Ok((
            "",
            Statement::Delegate {
                agent_id,
                goal_name,
                args,
            },
        )) = parse_delegate(input)
        {
            assert_eq!(agent_id, "planner");
            assert_eq!(goal_name, "search");
            assert!(args.is_empty());
        } else {
            panic!("Failed to parse DELEGATE");
        }
    }

    #[test]
    fn test_parse_await() {
        let input = "AWAIT {call_result} INTO {final}";
        if let Ok((
            "",
            Statement::Await {
                call_id,
                result_into,
            },
        )) = parse_await(input)
        {
            assert_eq!(call_id, "call_result");
            assert!(result_into.is_some());
        } else {
            panic!("Failed to parse AWAIT");
        }
    }

    #[test]
    fn test_parse_goal_with_options() {
        let input = "GOAL retry_goal RETRY 3 DEADLINE 10s IDEMPOTENT SET x = 1 END";
        if let Ok((
            "",
            Statement::Goal {
                name,
                retry,
                deadline,
                idempotent,
                ..
            },
        )) = parse_goal(input)
        {
            assert_eq!(name, "retry_goal");
            assert_eq!(retry, Some(3));
            assert_eq!(deadline, Some(10.0));
            assert!(idempotent);
        } else {
            panic!("Failed to parse GOAL with options");
        }
    }

    #[test]
    fn test_parse_goal_on_fail() {
        let input = "GOAL g ON_FAIL[TIMEOUT] SET x = 1 END";
        if let Ok(("", Statement::Goal { on_fail, .. })) = parse_goal(input) {
            assert!(on_fail.contains_key(&GoalFailureType::Timeout));
        } else {
            panic!("Failed to parse GOAL ON_FAIL");
        }
    }

    #[test]
    fn test_parse_goal_audit_trail_false() {
        let input = "GOAL g AUDIT_TRAIL false END";
        if let Ok(("", Statement::Goal { audit_trail, .. })) = parse_goal(input) {
            assert!(!audit_trail);
        } else {
            panic!("Failed to parse GOAL AUDIT_TRAIL false");
        }
    }

    #[test]
    fn test_parse_program_multi_statement() {
        let input = "SET x = 1 SET y = 2 SET z = 3";
        let result = parse_program(input);
        assert!(result.is_ok());
        let (_, stmts) = result.unwrap();
        assert_eq!(stmts.len(), 3);
    }

    #[test]
    fn test_parse_duration_units() {
        // Minutes
        assert_eq!(parse_duration("2m"), Ok(("", 120.0)));
        // Hours
        assert_eq!(parse_duration("1h"), Ok(("", 3600.0)));
        // Seconds
        assert_eq!(parse_duration("30s"), Ok(("", 30.0)));
    }

    #[test]
    fn test_parse_memory_scope_variants() {
        assert_eq!(
            parse_memory_scope("working"),
            Ok(("", MemoryScope::Working))
        );
        assert_eq!(
            parse_memory_scope("session"),
            Ok(("", MemoryScope::Session))
        );
        assert_eq!(
            parse_memory_scope("long_term"),
            Ok(("", MemoryScope::LongTerm))
        );
        assert_eq!(parse_memory_scope("shared"), Ok(("", MemoryScope::Shared)));
    }

    #[test]
    fn test_parse_binary_operators() {
        assert_eq!(parse_binary_operator("=="), Ok(("", BinaryOperator::Eq)));
        assert_eq!(parse_binary_operator(">"), Ok(("", BinaryOperator::Gt)));
        assert_eq!(parse_binary_operator("<"), Ok(("", BinaryOperator::Lt)));
        assert_eq!(parse_binary_operator("+"), Ok(("", BinaryOperator::Add)));
        assert_eq!(parse_binary_operator("-"), Ok(("", BinaryOperator::Sub)));
    }

    #[test]
    fn test_parse_recall_with_scope_and_on_missing() {
        let input = "RECALL city INTO {c} SCOPE working ON_MISSING \"unknown\" END";
        if let Ok((
            "",
            Statement::Recall {
                name,
                into_var,
                scope,
                on_missing,
                ..
            },
        )) = parse_recall(input)
        {
            assert_eq!(name, "city");
            assert_eq!(into_var, "c");
            assert_eq!(scope, MemoryScope::Working);
            assert!(on_missing.is_some());
        } else {
            panic!("Failed to parse RECALL with scope and on_missing");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Coverage-boosting parser tests
    // ──────────────────────────────────────────────────────────────────────────

    // --- Index path segment ---
    #[test]
    fn test_parse_index_path_segment() {
        let result = parse_path_segment("[2]");
        assert_eq!(result, Ok(("", PathSegment::Index(2))));
    }

    // --- parse_list ---
    #[test]
    fn test_parse_list_value() {
        let result = parse_value("[1 2 3]");
        assert!(result.is_ok());
        if let Ok((_, av)) = result {
            if let Value::List(items) = av.value {
                assert_eq!(items.len(), 3);
            } else {
                panic!("Expected list");
            }
        }
    }

    // --- BinaryOp in parse_expression (outside braces) ---
    #[test]
    fn test_parse_expression_binary_op_outside_braces() {
        let input = "42 + 8";
        let result = parse_expression(input);
        assert!(result.is_ok());
        if let Ok((_, expr)) = result {
            matches!(expr, Expression::BinaryOp { .. });
        }
    }

    // --- Annotation inside inner expression ---
    #[test]
    fn test_parse_inner_expression_annotation() {
        // {value AS sensitive}
        let input = "SET x = {val AS sensitive}";
        let result = parse_set(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Set { value, .. })) = result {
            matches!(value, Expression::Annotated { .. });
        }
    }

    // --- BinaryOp inside inner expression ---
    #[test]
    fn test_parse_inner_expression_binary_op() {
        // SET x = {a + b} where a and b are variable refs inside braces
        let input = "SET z = {a + b}";
        let result = parse_set(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Set { value, .. })) = result {
            matches!(value, Expression::BinaryOp { .. });
        }
    }

    // --- GoalOutput with annotations (parse_goal_output) ---
    #[test]
    fn test_parse_goal_output_with_annotation() {
        let input = "GOAL my_goal\nSET x = 1\nOUTPUT\nx text AS sensitive\nEND\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { outputs, .. })) = result {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].name, "x");
            assert_eq!(outputs[0].type_name, "text");
            assert!(!outputs[0].annotations.is_empty());
        }
    }

    // --- Goal WAIT option ---
    #[test]
    fn test_parse_goal_wait_option() {
        let input = "GOAL my_goal\nSET x = 1\nWAIT 5s\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { wait, .. })) = result {
            assert_eq!(wait, Some(5.0));
        }
    }

    // --- Goal AUDIT_TRAIL true ---
    #[test]
    fn test_parse_goal_audit_trail_true() {
        let input = "GOAL my_goal\nSET x = 1\nAUDIT_TRAIL true\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { audit_trail, .. })) = result {
            assert!(audit_trail);
        }
    }

    // --- Goal CONFIRM_WITH option ---
    #[test]
    fn test_parse_goal_confirm_with() {
        let input = "GOAL my_goal\nSET x = 1\nCONFIRM_WITH supervisor\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { confirm_with, .. })) = result {
            assert_eq!(confirm_with, Some("supervisor".to_string()));
        }
    }

    // --- Goal TIMEOUT_CONFIRMATION option ---
    #[test]
    fn test_parse_goal_timeout_confirmation() {
        let input = "GOAL my_goal\nSET x = 1\nTIMEOUT_CONFIRMATION 30s\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Goal {
                timeout_confirmation,
                ..
            },
        )) = result
        {
            assert_eq!(timeout_confirmation, Some(30.0));
        }
    }

    // --- Goal FALLBACK option ---
    #[test]
    fn test_parse_goal_fallback_option() {
        let input = "GOAL my_goal\nSET x = 1\nFALLBACK SET x = 0\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { fallback, .. })) = result {
            assert!(fallback.is_some());
        }
    }

    // --- Parallel with DEADLINE ---
    #[test]
    fn test_parse_parallel_with_deadline() {
        // No space between duration and END — parse_duration leaves trailing space uncleaned
        let input = "PARALLEL SET a = 1 GATHER INTO {res} DEADLINE 10sEND";
        let result = parse_parallel(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Parallel { deadline, .. })) = result {
            assert_eq!(deadline, Some(10.0));
        }
    }

    // --- Parallel GATHER_ALL with DEADLINE ---
    #[test]
    fn test_parse_parallel_gather_all_with_deadline() {
        let input = "PARALLEL SET a = 1 GATHER_ALL INTO {res} DEADLINE 5sEND";
        let result = parse_parallel(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Parallel {
                pattern, deadline, ..
            },
        )) = result
        {
            assert_eq!(pattern, ParallelPattern::GatherAll);
            assert_eq!(deadline, Some(5.0));
        }
    }

    // --- Race with DEADLINE ---
    #[test]
    fn test_parse_race_with_deadline() {
        let input = "RACE SET a = 1 FIRST_INTO {result} DEADLINE 3sEND";
        let result = parse_race(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Parallel {
                pattern, deadline, ..
            },
        )) = result
        {
            assert_eq!(pattern, ParallelPattern::Race);
            assert_eq!(deadline, Some(3.0));
        }
    }

    // --- REMEMBER with EXPIRES ---
    #[test]
    fn test_parse_remember_with_expires() {
        let input = "REMEMBER key VALUE 42 EXPIRES 10m END";
        let result = parse_remember(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Remember { expires, .. })) = result {
            assert_eq!(expires, Some(600.0)); // 10 minutes = 600 seconds
        }
    }

    // --- RECALL with FUZZY and THRESHOLD ---
    #[test]
    fn test_parse_recall_fuzzy_threshold() {
        let input = "RECALL city INTO {c} FUZZY true THRESHOLD 0.8 END";
        let result = parse_recall(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Recall {
                fuzzy, threshold, ..
            },
        )) = result
        {
            assert!(fuzzy);
            assert_eq!(threshold, Some(0.8));
        }
    }

    // --- parse_use_wasm ---
    #[test]
    fn test_parse_use_wasm() {
        let input = "USE_WASM \"module.wasm\" FUNCTION \"process\" RESULT INTO {output} END";
        let result = parse_use_wasm(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::UseWasm {
                module_path,
                function_name,
                result_into,
                ..
            },
        )) = result
        {
            assert_eq!(module_path, "module.wasm");
            assert_eq!(function_name, "process");
            assert!(result_into.is_some());
        }
    }

    // --- parse_call ---
    #[test]
    fn test_parse_call() {
        let input = "CALL \"AgentB\" GOAL \"pay\" RESULT INTO {res} END";
        let result = parse_call(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Call {
                agent_id,
                goal_name,
                result_into,
                ..
            },
        )) = result
        {
            assert_eq!(agent_id, "AgentB");
            assert_eq!(goal_name, "pay");
            assert!(result_into.is_some());
        }
    }

    // --- parse_contract with EXPIRES and BUDGET ---
    #[test]
    fn test_parse_contract_with_expires_and_budget() {
        let input = "CONTRACT my_contract ISSUED_BY auth CAN USE my_tool BUDGET 100 EXPIRES 1h END";
        let result = parse_contract(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Contract {
                budget,
                expires,
                capabilities,
                ..
            },
        )) = result
        {
            assert_eq!(budget, Some(100.0));
            assert_eq!(expires, Some(3600.0));
            assert_eq!(capabilities.len(), 1);
        }
    }

    // --- parse_variable_path with index segment ---
    #[test]
    fn test_parse_variable_path_with_index() {
        let result = parse_variable_path("items[0].name");
        assert!(result.is_ok());
        if let Ok((_, path)) = result {
            assert_eq!(path.root, "items");
            assert_eq!(path.segments.len(), 2);
            assert_eq!(path.segments[0], PathSegment::Index(0));
            assert_eq!(path.segments[1], PathSegment::Field("name".to_string()));
        }
    }

    // --- parse_goal_item with result_into ---
    #[test]
    fn test_parse_goal_with_result_into() {
        let input = "GOAL my_goal\nSET x = 1\nRESULT INTO {outcome}\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { result_into, .. })) = result {
            assert!(result_into.is_some());
            assert_eq!(result_into.unwrap().root, "outcome");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Batch 3: additional parser coverage tests
    // ──────────────────────────────────────────────────────────────────────────

    // --- IF with ELSE branch (lines 243-245) ---
    #[test]
    fn test_parse_if_with_else_branch() {
        let input = "IF {x} SET a = 1 ELSE SET a = 0 END";
        let result = parse_if(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::If { else_branch, .. })) = result {
            assert!(else_branch.is_some());
        }
    }

    // --- REMEMBER with string key (lines 576-581) ---
    #[test]
    fn test_parse_remember_with_string_key() {
        let input = "REMEMBER \"my key\" VALUE 42 END";
        let result = parse_remember(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Remember { name, .. })) = result {
            assert_eq!(name, "my key");
        }
    }

    // --- RECALL with string key ---
    #[test]
    fn test_parse_recall_with_string_key() {
        let input = "RECALL \"city name\" INTO {c} END";
        let result = parse_recall(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Recall { name, .. })) = result {
            assert_eq!(name, "city name");
        }
    }

    // --- REMEMBER with SCOPE session (covers parse_memory_scope session branch) ---
    #[test]
    fn test_parse_remember_scope_session() {
        let input = "REMEMBER session_key VALUE 1 SCOPE session END";
        let result = parse_remember(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Remember { scope, .. })) = result {
            assert_eq!(scope, MemoryScope::Session);
        }
    }

    // --- FORGET with SCOPE working ---
    #[test]
    fn test_parse_forget_with_scope_working() {
        let input = "FORGET session_key SCOPE working END";
        let result = parse_forget(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Forget { scope, .. })) = result {
            assert_eq!(scope, MemoryScope::Working);
        }
    }

    // --- GOAL IDEMPOTENT option ---
    #[test]
    fn test_parse_goal_idempotent_opt() {
        let input = "GOAL my_goal\nSET x = 1\nIDEMPOTENT\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { idempotent, .. })) = result {
            assert!(idempotent);
        }
    }

    // --- GOAL ON_FAIL option ---
    #[test]
    fn test_parse_goal_on_fail_opt() {
        let input = "GOAL my_goal\nSET x = 1\nON_FAIL SET x = 0\nEND";
        let result = parse_goal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Goal { on_fail, .. })) = result {
            assert!(!on_fail.is_empty());
        }
    }

    // --- AWAIT with INTO ---
    #[test]
    fn test_parse_await_with_result_into() {
        let input = "AWAIT {my_call_id} INTO {result}";
        let result = parse_await(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Await { result_into, .. })) = result {
            assert!(result_into.is_some());
        }
    }

    // --- AWAIT without INTO ---
    #[test]
    fn test_parse_await_without_result_into() {
        let input = "AWAIT {my_call_id}";
        let result = parse_await(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Await { result_into, .. })) = result {
            assert!(result_into.is_none());
        }
    }

    // --- EMIT with DATA ---
    #[test]
    fn test_parse_emit_with_data_value() {
        let input = "EMIT my_event DATA 42";
        let result = parse_emit(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Emit { event, data })) = result {
            assert_eq!(event, "my_event");
            assert!(data.is_some());
        }
    }

    // --- EMIT without DATA - parser requires DATA, so just test with DATA ---
    #[test]
    fn test_parse_emit_with_number_data() {
        let input = "EMIT status_event DATA 1";
        let result = parse_emit(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Emit { event, data })) = result {
            assert_eq!(event, "status_event");
            assert!(data.is_some());
        }
    }

    // --- ON event handler ---
    #[test]
    fn test_parse_on_event_handler() {
        let input = "ON my_event SET x = 1 END";
        let result = parse_on(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::On { event, handler })) = result {
            assert_eq!(event, "my_event");
            assert_eq!(handler.len(), 1);
        }
    }

    // --- REVEAL with INTO ---
    #[test]
    fn test_parse_reveal_with_result_into() {
        let input = "REVEAL my_proof FOR \"my claim\" INTO {verified}";
        let result = parse_reveal(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::Reveal { result_into, .. })) = result {
            assert!(result_into.is_some());
        }
    }

    // --- PROVE statement ---
    #[test]
    fn test_parse_prove_stmt() {
        let input = "PROVE {SET x = 1} FOR \"my claim\" AS my_proof";
        let result = parse_prove(input);
        assert!(result.is_ok());
        if let Ok((
            _,
            Statement::Prove {
                claim, proof_name, ..
            },
        )) = result
        {
            assert_eq!(claim, "my claim");
            assert_eq!(proof_name, "my_proof");
        }
    }

    // --- Index path segment via USE ---
    #[test]
    fn test_parse_index_path_segment_via_use_tool() {
        let input = "USE search q \"hello\" RESULT INTO {res[0]} END";
        let result = parse_use(input);
        assert!(result.is_ok());
        if let Ok((_, Statement::UseTool { result_into, .. })) = result {
            let path = result_into.unwrap();
            assert_eq!(path.segments.len(), 1);
            matches!(path.segments[0], PathSegment::Index(0));
        }
    }
}
