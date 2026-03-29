//! Compiled route matcher that evaluates parsed rules against request attributes.

use super::rule::{Rule, RuleParseError, RuleParser};
use hyper::HeaderMap;

/// Compiled matcher that evaluates a parsed routing rule against request attributes.
#[derive(Debug)]
pub struct RouteMatcher {
    rule: Rule,
}

impl RouteMatcher {
    /// Parse a rule string into a compiled matcher.
    pub fn from_rule(rule_str: &str) -> Result<Self, RuleParseError> {
        let rule = RuleParser::parse(rule_str)?;
        Ok(Self { rule })
    }

    /// Test whether a request matches this route's rule.
    pub fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        query: Option<&str>,
        method: Option<&str>,
        headers: &HeaderMap,
    ) -> bool {
        self.rule.matches(host, path, query, method, headers)
    }

    /// Extract host names from the rule for indexing
    pub fn extract_hosts(&self) -> Vec<&str> {
        self.rule.extract_hosts()
    }
}
