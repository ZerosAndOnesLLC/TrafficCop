use crate::config::ErrorsConfig;
use std::ops::RangeInclusive;

/// Errors middleware - intercepts error responses and serves custom error pages
pub struct ErrorsMiddleware {
    /// Parsed status code ranges to intercept
    status_ranges: Vec<StatusRange>,
    /// Service name to handle errors
    service: String,
    /// Query path template (supports {status} placeholder)
    query: String,
}

/// Represents either a single status code or a range
enum StatusRange {
    Single(u16),
    Range(RangeInclusive<u16>),
}

impl StatusRange {
    fn matches(&self, status: u16) -> bool {
        match self {
            StatusRange::Single(s) => *s == status,
            StatusRange::Range(r) => r.contains(&status),
        }
    }
}

impl ErrorsMiddleware {
    pub fn new(config: ErrorsConfig) -> Self {
        let status_ranges = config
            .status
            .iter()
            .filter_map(|s| Self::parse_status_range(s))
            .collect();

        Self {
            status_ranges,
            service: config.service,
            query: config.query,
        }
    }

    /// Parse a status range string like "500-599" or "404"
    fn parse_status_range(s: &str) -> Option<StatusRange> {
        let s = s.trim();
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].trim().parse::<u16>().ok()?;
                let end = parts[1].trim().parse::<u16>().ok()?;
                if start <= end && start >= 100 && end <= 599 {
                    return Some(StatusRange::Range(start..=end));
                }
            }
        } else {
            let code = s.parse::<u16>().ok()?;
            if (100..=599).contains(&code) {
                return Some(StatusRange::Single(code));
            }
        }
        None
    }

    /// Check if a status code should be intercepted
    #[inline]
    pub fn should_intercept(&self, status: u16) -> bool {
        self.status_ranges.iter().any(|r| r.matches(status))
    }

    /// Get the error service name
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Build the error page query path for a given status code
    #[inline]
    pub fn build_query(&self, status: u16) -> String {
        self.query.replace("{status}", &status.to_string())
    }

    /// Get the raw query template
    #[inline]
    pub fn query_template(&self) -> &str {
        &self.query
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(status: Vec<&str>, service: &str, query: &str) -> ErrorsConfig {
        ErrorsConfig {
            status: status.into_iter().map(String::from).collect(),
            service: service.to_string(),
            query: query.to_string(),
        }
    }

    #[test]
    fn test_single_status_code() {
        let config = make_config(vec!["404"], "error-service", "/{status}.html");
        let middleware = ErrorsMiddleware::new(config);

        assert!(middleware.should_intercept(404));
        assert!(!middleware.should_intercept(500));
        assert!(!middleware.should_intercept(200));
    }

    #[test]
    fn test_status_range() {
        let config = make_config(vec!["500-599"], "error-service", "/{status}.html");
        let middleware = ErrorsMiddleware::new(config);

        assert!(middleware.should_intercept(500));
        assert!(middleware.should_intercept(503));
        assert!(middleware.should_intercept(599));
        assert!(!middleware.should_intercept(499));
        assert!(!middleware.should_intercept(404));
    }

    #[test]
    fn test_multiple_ranges() {
        let config = make_config(vec!["404", "500-503"], "error-service", "/{status}.html");
        let middleware = ErrorsMiddleware::new(config);

        assert!(middleware.should_intercept(404));
        assert!(middleware.should_intercept(500));
        assert!(middleware.should_intercept(503));
        assert!(!middleware.should_intercept(504));
        assert!(!middleware.should_intercept(400));
    }

    #[test]
    fn test_query_template() {
        let config = make_config(vec!["500-599"], "error-service", "/errors/{status}.html");
        let middleware = ErrorsMiddleware::new(config);

        assert_eq!(middleware.build_query(500), "/errors/500.html");
        assert_eq!(middleware.build_query(503), "/errors/503.html");
    }

    #[test]
    fn test_invalid_range_ignored() {
        let config = make_config(vec!["invalid", "999", "404"], "error-service", "/{status}.html");
        let middleware = ErrorsMiddleware::new(config);

        // Only 404 should be valid
        assert!(middleware.should_intercept(404));
        assert!(!middleware.should_intercept(999)); // Out of valid range
    }

    #[test]
    fn test_service_name() {
        let config = make_config(vec!["500"], "my-error-handler", "/error");
        let middleware = ErrorsMiddleware::new(config);

        assert_eq!(middleware.service(), "my-error-handler");
    }
}
