use crate::ast::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0, none_of},
    combinator::{map, opt, recognize},
    multi::many0,
    sequence::{delimited, pair, preceded},
    IResult, Parser,
};

/// Consume whitespace and optional comments.
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

/// Parse a value (literal).
fn parse_value(input: &str) -> IResult<&str, AnnotatedValue> {
    map(alt((parse_boolean, parse_number, parse_string)), |v| {
        AnnotatedValue::from(v)
    })
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

/// Parse an expression: literal, variable reference, or annotated expression.
fn parse_expression(input: &str) -> IResult<&str, Expression> {
    let (input, base_expr) = alt((
        map(parse_value, Expression::Literal),
        map(
            delimited(char('{'), parse_identifier, char('}')),
            Expression::VariableRef,
        ),
    ))
    .parse(input)?;

    let (input, maybe_annotation) = opt(preceded(ws(tag("AS")), parse_annotation)).parse(input)?;

    if let Some(annotation) = maybe_annotation {
        Ok((input, Expression::Annotated { expr: Box::new(base_expr), annotation }))
    } else {
        Ok((input, base_expr))
    }
}

/// Parse a SET statement: SET name = value
fn parse_set(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("SET"), ws(parse_identifier), tag("="), ws(parse_expression)),
        |(_, name, _, value)| Statement::Set { name, value },
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
            ws(delimited(char('{'), parse_identifier, char('}'))),
            tag("END"),
        ),
        |(_, tool_name, args_vec, _, result_into, _)| {
            let args = args_vec.into_iter().collect();
            Statement::UseTool { tool_name, args, result_into }
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
        |(_, condition, then_branch, else_branch, _)| Statement::If { condition, then_branch, else_branch },
    )
    .parse(input)
}

/// Parse a GOAL block: GOAL name ... [RETRY n] [ON_FAIL GOAL x] [DEADLINE d] END
fn parse_goal(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("GOAL"),
            ws(parse_identifier),
            many0(parse_statement),
            opt(preceded(ws(tag("RETRY")), ws(parse_number))),
            opt(preceded(ws(tag("ON_FAIL")), ws(parse_statement))),
            opt(preceded(ws(tag("DEADLINE")), ws(parse_duration))),
            tag("END"),
        ),
        |(_, name, body, retry_val, on_fail, deadline, _)| {
            let retry = retry_val.and_then(|v| if let Value::Number(n) = v { Some(n as usize) } else { None });
            Statement::Goal { name, body, retry, on_fail: on_fail.map(Box::new), deadline }
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
    let seconds = match unit { 's' => val, 'm' => val * 60.0, 'h' => val * 3600.0, _ => unreachable!() };
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
                map(preceded(tag("GATHER_MIN"), ws(parse_number)), |v| if let Value::Number(n) = v { ParallelPattern::GatherMin(n as usize) } else { ParallelPattern::GatherMin(1) }),
            )),
            ws(preceded(tag("INTO"), ws(delimited(char('{'), parse_identifier, char('}'))))),
            opt(preceded(ws(tag("DEADLINE")), parse_duration)),
            tag("END"),
        ),
        |(_, branches, pattern, result_into, deadline, _)| Statement::Parallel { pattern, branches, result_into: Some(result_into), deadline },
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
            ws(delimited(char('{'), parse_identifier, char('}'))),
            opt(preceded(ws(tag("DEADLINE")), parse_duration)),
            tag("END"),
        ),
        |(_, branches, _, result_into, deadline, _)| Statement::Parallel { pattern: ParallelPattern::Race, branches, result_into: Some(result_into), deadline },
    )
    .parse(input)
}

/// Parse a WAIT statement
fn parse_wait(input: &str) -> IResult<&str, Statement> {
    map(preceded(tag("WAIT"), ws(parse_duration)), |duration| Statement::Wait { duration }).parse(input)
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

/// Parse REMEMBER
fn parse_remember(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("REMEMBER"), ws(parse_identifier), ws(tag("VALUE")), ws(parse_expression), opt(preceded(ws(tag("SCOPE")), ws(parse_memory_scope))), opt(preceded(ws(tag("EXPIRES")), ws(parse_duration))), tag("END")),
        |(_, name, _, value, scope, expires, _)| Statement::Remember { name, value, scope: scope.unwrap_or(MemoryScope::LongTerm), expires },
    ).parse(input)
}

/// Parse RECALL
fn parse_recall(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("RECALL"), ws(parse_identifier), ws(tag("INTO")), ws(delimited(char('{'), parse_identifier, char('}'))), opt(preceded(ws(tag("SCOPE")), ws(parse_memory_scope))), opt(preceded(ws(tag("ON_MISSING")), ws(parse_expression))), tag("END")),
        |(_, name, _, into_var, scope, on_missing, _)| Statement::Recall { name, into_var, scope: scope.unwrap_or(MemoryScope::LongTerm), on_missing },
    ).parse(input)
}

/// Parse FORGET
fn parse_forget(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("FORGET"), ws(parse_identifier), opt(preceded(ws(tag("SCOPE")), ws(parse_memory_scope))), tag("END")),
        |(_, name, scope, _)| Statement::Forget { name, scope: scope.unwrap_or(MemoryScope::LongTerm) },
    ).parse(input)
}

/// Parse a trust level
fn parse_trust_level(input: &str) -> IResult<&str, TrustLevel> {
    alt((
        map(tag("verified"), |_| TrustLevel::Verified),
        map(tag("trusted"), |_| TrustLevel::Trusted),
        map(tag("sandboxed"), |_| TrustLevel::Sandboxed),
        map(tag("blocked"), |_| TrustLevel::Blocked),
    )).parse(input)
}

/// Parse an AGENT block
fn parse_agent(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("AGENT"),
            ws(parse_identifier),
            preceded(ws(tag("ID")), ws(recognize(take_while1(|c: char| c.is_alphanumeric())))),
            preceded(ws(tag("REGISTRY")), ws(recognize(take_while1(|c: char| c.is_alphanumeric() || c == '.')))),
            preceded(ws(tag("SIGNED_BY")), ws(recognize(take_while1(|c: char| c.is_alphanumeric() || c == '.')))),
            preceded(ws(tag("TRUST_LEVEL")), ws(parse_trust_level)),
            tag("END"),
        ),
        |(_, name, id, registry, signed_by, trust_level, _)| Statement::Agent {
            name, id: id.to_string(), registry: registry.to_string(), signed_by: signed_by.to_string(), trust_level
        }
    ).parse(input)
}

/// Parse a permission
fn parse_permission(input: &str) -> IResult<&str, Permission> {
    alt((
        map(preceded(tag("CAN USE"), ws(parse_identifier)), Permission::CanUse),
        map(preceded(tag("CANNOT USE"), ws(parse_identifier)), Permission::CannotUse),
    )).parse(input)
}

/// Parse a CONTRACT block
fn parse_contract(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("CONTRACT"),
            ws(parse_identifier),
            preceded(ws(tag("ISSUED_BY")), ws(recognize(take_while1(|c: char| c.is_alphanumeric() || c == '.')))),
            many0(ws(parse_permission)),
            opt(preceded(ws(tag("EXPIRES")), ws(parse_duration))),
            tag("END"),
        ),
        |(_, name, issued_by, capabilities, expires, _)| Statement::Contract {
            name, issued_by: issued_by.to_string(), capabilities, expires
        }
    ).parse(input)
}

/// Parse an EMIT statement: EMIT name DATA val
fn parse_emit(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("EMIT"), ws(parse_identifier), ws(tag("DATA")), ws(parse_expression)),
        |(_, event, _, data)| Statement::Emit { event, data }
    ).parse(input)
}

/// Parse an ON statement: ON name handler
fn parse_on(input: &str) -> IResult<&str, Statement> {
    map(
        (tag("ON"), ws(parse_identifier), ws(parse_statement)),
        |(_, event, handler)| Statement::On { event, handler: Box::new(handler) }
    ).parse(input)
}

/// Parse a PROVE statement: PROVE { statement } AS proof_name
fn parse_prove(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("PROVE"),
            ws(delimited(char('{'), parse_statement, char('}'))),
            ws(tag("AS")),
            ws(parse_identifier),
        ),
        |(_, statement, _, proof_name)| Statement::Prove { statement: Box::new(statement), proof_name }
    ).parse(input)
}

/// Parse a REVEAL statement: REVEAL proof_name [TO agent_id]
fn parse_reveal(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("REVEAL"),
            ws(parse_identifier),
            opt(preceded(ws(tag("TO")), ws(parse_identifier))),
        ),
        |(_, proof_name, to_agent)| Statement::Reveal { proof_name, to_agent }
    ).parse(input)
}

/// Parse any statement.
fn parse_statement(input: &str) -> IResult<&str, Statement> {
    ws(alt((
        parse_set, parse_if, parse_use, parse_goal, parse_parallel, parse_race,
        parse_wait, parse_remember, parse_recall, parse_forget, parse_agent, parse_contract,
        parse_emit, parse_on, parse_prove, parse_reveal
    ))).parse(input)
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
        assert_eq!(parse_identifier("_private"), Ok(("", "_private".to_string())));
        assert!(parse_identifier("123var").is_err());
    }

    #[test]
    fn test_parse_value() {
        assert_eq!(parse_value("true"), Ok(("", AnnotatedValue::from(Value::Boolean(true)))));
        assert_eq!(parse_value("42"), Ok(("", AnnotatedValue::from(Value::Number(42.0)))));
        assert_eq!(parse_value("\"hello\""), Ok(("", AnnotatedValue::from(Value::Text("hello".to_string())))));
    }

    #[test]
    fn test_parse_expression() {
        assert_eq!(parse_expression("true"), Ok(("", Expression::Literal(AnnotatedValue::from(Value::Boolean(true))))));
        assert_eq!(parse_expression("{my_var}"), Ok(("", Expression::VariableRef("my_var".to_string()))));
    }

    #[test]
    fn test_parse_annotated_expression() {
        assert_eq!(
            parse_expression("\"secret\" AS sensitive"),
            Ok(("", Expression::Annotated {
                expr: Box::new(Expression::Literal(AnnotatedValue::from(Value::Text("secret".to_string())))),
                annotation: Annotation::Sensitive,
            }))
        );
    }

    #[test]
    fn test_parse_set() {
        let input = "SET origin = \"London\"";
        let expected = Statement::Set { name: "origin".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Text("London".to_string()))) };
        assert_eq!(parse_set(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_goal() {
        let input = "GOAL my_goal SET x = 1 END";
        let expected = Statement::Goal { name: "my_goal".to_string(), body: vec![Statement::Set { name: "x".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))) }], retry: None, on_fail: None, deadline: None };
        assert_eq!(parse_goal(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_if() {
        let input = "IF true SET x = 1 ELSE SET x = 2 END";
        let expected = Statement::If {
            condition: Expression::Literal(AnnotatedValue::from(Value::Boolean(true))),
            then_branch: vec![Statement::Set { name: "x".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Number(1.0))) }],
            else_branch: Some(vec![Statement::Set { name: "x".to_string(), value: Expression::Literal(AnnotatedValue::from(Value::Number(2.0))) }]),
        };
        assert_eq!(parse_if(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_wait() {
        assert_eq!(parse_wait("WAIT 10s"), Ok(("", Statement::Wait { duration: 10.0 })));
    }

    #[test]
    fn test_parse_remember() {
        let input = "REMEMBER pref VALUE \"high\" SCOPE session END";
        if let Ok(("", Statement::Remember { name, scope, .. })) = parse_remember(input) {
            assert_eq!(name, "pref");
            assert_eq!(scope, MemoryScope::Session);
        } else { panic!("Failed to parse REMEMBER"); }
    }

    #[test]
    fn test_parse_agent() {
        let input = "AGENT my_agent ID 0x123 REGISTRY acme.io SIGNED_BY acme.io TRUST_LEVEL verified END";
        if let Ok(("", Statement::Agent { name, trust_level, .. })) = parse_agent(input) {
            assert_eq!(name, "my_agent");
            assert_eq!(trust_level, TrustLevel::Verified);
        } else { panic!("Failed to parse AGENT"); }
    }

    #[test]
    fn test_parse_contract() {
        let input = "CONTRACT my_perms ISSUED_BY acme.io CAN USE search_flights CANNOT USE charge_card EXPIRES 1h END";
        if let Ok(("", Statement::Contract { name, capabilities, .. })) = parse_contract(input) {
            assert_eq!(name, "my_perms");
            assert_eq!(capabilities.len(), 2);
            assert_eq!(capabilities[0], Permission::CanUse("search_flights".to_string()));
        } else { panic!("Failed to parse CONTRACT"); }
    }

    #[test]
    fn test_parse_emit() {
        let input = "EMIT flight_found DATA {flights}";
        if let Ok(("", Statement::Emit { event, .. })) = parse_emit(input) {
            assert_eq!(event, "flight_found");
        } else { panic!("Failed to parse EMIT"); }
    }

    #[test]
    fn test_parse_on() {
        let input = "ON flight_found GOAL notify END";
        if let Ok(("", Statement::On { event, .. })) = parse_on(input) {
            assert_eq!(event, "flight_found");
        } else { panic!("Failed to parse ON"); }
    }

    #[test]
    fn test_parse_prove() {
        let input = "PROVE { SET x = 1 } AS my_proof";
        if let Ok(("", Statement::Prove { proof_name, .. })) = parse_prove(input) {
            assert_eq!(proof_name, "my_proof");
        } else { panic!("Failed to parse PROVE"); }
    }

    #[test]
    fn test_parse_reveal() {
        let input = "REVEAL my_proof TO other_agent";
        if let Ok(("", Statement::Reveal { proof_name, to_agent })) = parse_reveal(input) {
            assert_eq!(proof_name, "my_proof");
            assert_eq!(to_agent, Some("other_agent".to_string()));
        } else { panic!("Failed to parse REVEAL"); }
    }
}
