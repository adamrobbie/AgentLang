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
                map(tag("GATHER"), |_| ParallelPattern::Gather),
                map(tag("GATHER_ALL"), |_| ParallelPattern::GatherAll),
                map(preceded(tag("GATHER_MIN"), ws(parse_number)), |v| {
                    if let Value::Number(n) = v {
                        ParallelPattern::GatherMin(n as usize)
                    } else {
                        ParallelPattern::GatherMin(1)
                    }
                }),
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
            branches: vec![branches],
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
        |(call_id, _, result_into)| Statement::Await {
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
}
