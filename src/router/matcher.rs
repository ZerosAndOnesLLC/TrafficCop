use super::rule::{Rule, RuleParseError, RuleParser};
use hyper::HeaderMap;

#[derive(Debug)]
pub struct RouteMatcher {
    rule: Rule,
}

impl RouteMatcher {
    pub fn from_rule(rule_str: &str) -> Result<Self, RuleParseError> {
        let rule = RuleParser::parse(rule_str)?;
        Ok(Self { rule })
    }

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
