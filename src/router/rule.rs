use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleParseError {
    #[error("Invalid rule syntax: {0}")]
    InvalidSyntax(String),

    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("Unknown function: {0}")]
    UnknownFunction(String),
}

#[derive(Debug, Clone)]
pub enum Rule {
    Host(String),
    HostRegex(Regex),
    Path(String),
    PathPrefix(String),
    PathRegex(Regex),
    Header(String, String),
    HeaderRegex(String, Regex),
    Query(String, String),
    Method(String),
    And(Box<Rule>, Box<Rule>),
    Or(Box<Rule>, Box<Rule>),
    Not(Box<Rule>),
}

impl Rule {
    pub fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        headers: &hyper::HeaderMap,
    ) -> bool {
        match self {
            Rule::Host(expected) => {
                host.map(|h| h.eq_ignore_ascii_case(expected)).unwrap_or(false)
            }
            Rule::HostRegex(re) => {
                host.map(|h| re.is_match(h)).unwrap_or(false)
            }
            Rule::Path(expected) => path == expected,
            Rule::PathPrefix(prefix) => path.starts_with(prefix),
            Rule::PathRegex(re) => re.is_match(path),
            Rule::Header(name, value) => {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == value)
                    .unwrap_or(false)
            }
            Rule::HeaderRegex(name, re) => {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| re.is_match(v))
                    .unwrap_or(false)
            }
            Rule::Query(_, _) => {
                // Query matching would need the full URI
                // Simplified for now
                false
            }
            Rule::Method(_method) => {
                // Method matching would need the request method
                // Handled separately in the matcher
                false
            }
            Rule::And(a, b) => {
                a.matches(host, path, headers) && b.matches(host, path, headers)
            }
            Rule::Or(a, b) => {
                a.matches(host, path, headers) || b.matches(host, path, headers)
            }
            Rule::Not(r) => !r.matches(host, path, headers),
        }
    }
}

pub struct RuleParser;

impl RuleParser {
    pub fn parse(input: &str) -> Result<Rule, RuleParseError> {
        let input = input.trim();
        Self::parse_or(input)
    }

    fn parse_or(input: &str) -> Result<Rule, RuleParseError> {
        // Find || at the top level (not inside parentheses)
        if let Some(pos) = Self::find_operator(input, "||") {
            let left = Self::parse_or(&input[..pos])?;
            let right = Self::parse_or(&input[pos + 2..])?;
            return Ok(Rule::Or(Box::new(left), Box::new(right)));
        }
        Self::parse_and(input)
    }

    fn parse_and(input: &str) -> Result<Rule, RuleParseError> {
        // Find && at the top level
        if let Some(pos) = Self::find_operator(input, "&&") {
            let left = Self::parse_and(&input[..pos])?;
            let right = Self::parse_and(&input[pos + 2..])?;
            return Ok(Rule::And(Box::new(left), Box::new(right)));
        }
        Self::parse_unary(input)
    }

    fn parse_unary(input: &str) -> Result<Rule, RuleParseError> {
        let input = input.trim();

        if input.starts_with('!') {
            let inner = Self::parse_unary(&input[1..])?;
            return Ok(Rule::Not(Box::new(inner)));
        }

        Self::parse_primary(input)
    }

    fn parse_primary(input: &str) -> Result<Rule, RuleParseError> {
        let input = input.trim();

        // Handle parentheses
        if input.starts_with('(') && input.ends_with(')') {
            return Self::parse_or(&input[1..input.len() - 1]);
        }

        // Parse function calls
        Self::parse_function(input)
    }

    fn parse_function(input: &str) -> Result<Rule, RuleParseError> {
        let input = input.trim();

        // Match function pattern: FunctionName(`value`) or FunctionName(`key`, `value`)
        let paren_start = input
            .find('(')
            .ok_or_else(|| RuleParseError::InvalidSyntax(input.to_string()))?;

        let func_name = &input[..paren_start];

        if !input.ends_with(')') {
            return Err(RuleParseError::InvalidSyntax(input.to_string()));
        }

        let args_str = &input[paren_start + 1..input.len() - 1];
        let args = Self::parse_args(args_str)?;

        match func_name {
            "Host" => {
                let host = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("Host requires an argument".into()))?;
                Ok(Rule::Host(host.clone()))
            }
            "HostRegexp" => {
                let pattern = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("HostRegexp requires an argument".into()))?;
                let re = Regex::new(pattern)?;
                Ok(Rule::HostRegex(re))
            }
            "Path" => {
                let path = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("Path requires an argument".into()))?;
                Ok(Rule::Path(path.clone()))
            }
            "PathPrefix" => {
                let prefix = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("PathPrefix requires an argument".into()))?;
                Ok(Rule::PathPrefix(prefix.clone()))
            }
            "PathRegexp" => {
                let pattern = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("PathRegexp requires an argument".into()))?;
                let re = Regex::new(pattern)?;
                Ok(Rule::PathRegex(re))
            }
            "Header" => {
                if args.len() != 2 {
                    return Err(RuleParseError::InvalidSyntax(
                        "Header requires two arguments".into(),
                    ));
                }
                Ok(Rule::Header(args[0].clone(), args[1].clone()))
            }
            "HeaderRegexp" => {
                if args.len() != 2 {
                    return Err(RuleParseError::InvalidSyntax(
                        "HeaderRegexp requires two arguments".into(),
                    ));
                }
                let re = Regex::new(&args[1])?;
                Ok(Rule::HeaderRegex(args[0].clone(), re))
            }
            "Method" => {
                let method = args
                    .first()
                    .ok_or_else(|| RuleParseError::InvalidSyntax("Method requires an argument".into()))?;
                Ok(Rule::Method(method.clone()))
            }
            "Query" => {
                if args.len() != 2 {
                    return Err(RuleParseError::InvalidSyntax(
                        "Query requires two arguments".into(),
                    ));
                }
                Ok(Rule::Query(args[0].clone(), args[1].clone()))
            }
            _ => Err(RuleParseError::UnknownFunction(func_name.to_string())),
        }
    }

    fn parse_args(input: &str) -> Result<Vec<String>, RuleParseError> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_backtick = false;
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '`' => {
                    if in_backtick {
                        args.push(current.clone());
                        current.clear();
                    }
                    in_backtick = !in_backtick;
                }
                ',' if !in_backtick => {
                    // Skip comma and whitespace between args
                }
                ' ' if !in_backtick => {
                    // Skip whitespace outside backticks
                }
                _ if in_backtick => {
                    current.push(c);
                }
                _ => {
                    // Ignore characters outside backticks
                }
            }
        }

        Ok(args)
    }

    fn find_operator(input: &str, op: &str) -> Option<usize> {
        let mut depth = 0;
        let mut in_backtick = false;
        let chars: Vec<char> = input.chars().collect();

        for i in 0..chars.len() {
            match chars[i] {
                '`' => in_backtick = !in_backtick,
                '(' if !in_backtick => depth += 1,
                ')' if !in_backtick => depth -= 1,
                _ if !in_backtick && depth == 0 => {
                    if input[i..].starts_with(op) {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host() {
        let rule = RuleParser::parse("Host(`example.com`)").unwrap();
        assert!(matches!(rule, Rule::Host(h) if h == "example.com"));
    }

    #[test]
    fn test_parse_path_prefix() {
        let rule = RuleParser::parse("PathPrefix(`/api`)").unwrap();
        assert!(matches!(rule, Rule::PathPrefix(p) if p == "/api"));
    }

    #[test]
    fn test_parse_and() {
        let rule = RuleParser::parse("Host(`example.com`) && PathPrefix(`/api`)").unwrap();
        assert!(matches!(rule, Rule::And(_, _)));
    }

    #[test]
    fn test_parse_or() {
        let rule = RuleParser::parse("Host(`a.com`) || Host(`b.com`)").unwrap();
        assert!(matches!(rule, Rule::Or(_, _)));
    }
}
