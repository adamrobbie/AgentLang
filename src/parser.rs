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
fn parse_value(input: &str) -> IResult<&str, Value> {
    alt((parse_boolean, parse_number, parse_string)).parse(input)
}

/// Parse an expression: literal or variable reference.
fn parse_expression(input: &str) -> IResult<&str, Expression> {
    alt((
        map(parse_value, Expression::Literal),
        map(
            delimited(char('{'), parse_identifier, char('}')),
            Expression::VariableRef,
        ),
    ))
    .parse(input)
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
            Statement::UseTool {
                tool_name,
                args,
                result_into,
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

/// Parse a GOAL block: GOAL name ... END
fn parse_goal(input: &str) -> IResult<&str, Statement> {
    map(
        (
            tag("GOAL"),
            ws(parse_identifier),
            many0(parse_statement),
            tag("END"),
        ),
        |(_, name, body, _)| Statement::Goal { name, body },
    )
    .parse(input)
}

/// Parse any statement.
fn parse_statement(input: &str) -> IResult<&str, Statement> {
    ws(alt((parse_set, parse_if, parse_use, parse_goal))).parse(input)
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
        assert_eq!(parse_value("true"), Ok(("", Value::Boolean(true))));
        assert_eq!(parse_value("false"), Ok(("", Value::Boolean(false))));
        assert_eq!(parse_value("42"), Ok(("", Value::Number(42.0))));
        assert_eq!(parse_value("3.14"), Ok(("", Value::Number(3.14))));
        assert_eq!(parse_value("\"hello\""), Ok(("", Value::Text("hello".to_string()))));
    }

    #[test]
    fn test_parse_expression() {
        assert_eq!(
            parse_expression("true"),
            Ok(("", Expression::Literal(Value::Boolean(true))))
        );
        assert_eq!(
            parse_expression("{my_var}"),
            Ok(("", Expression::VariableRef("my_var".to_string())))
        );
    }

    #[test]
    fn test_parse_set() {
        let input = "SET origin = \"London\"";
        let expected = Statement::Set {
            name: "origin".to_string(),
            value: Expression::Literal(Value::Text("London".to_string())),
        };
        assert_eq!(parse_set(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_goal() {
        let input = "GOAL my_goal SET x = 1 END";
        let expected = Statement::Goal {
            name: "my_goal".to_string(),
            body: vec![Statement::Set {
                name: "x".to_string(),
                value: Expression::Literal(Value::Number(1.0)),
            }],
        };
        assert_eq!(parse_goal(input), Ok(("", expected)));
    }

    #[test]
    fn test_parse_if() {
        let input = "IF true SET x = 1 ELSE SET x = 2 END";
        let expected = Statement::If {
            condition: Expression::Literal(Value::Boolean(true)),
            then_branch: vec![Statement::Set {
                name: "x".to_string(),
                value: Expression::Literal(Value::Number(1.0)),
            }],
            else_branch: Some(vec![Statement::Set {
                name: "x".to_string(),
                value: Expression::Literal(Value::Number(2.0)),
            }]),
        };
        assert_eq!(parse_if(input), Ok(("", expected)));
    }
}
