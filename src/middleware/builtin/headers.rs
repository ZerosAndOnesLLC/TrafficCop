use crate::config::HeadersConfig;
use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;

/// Headers middleware for adding/removing request and response headers
pub struct HeadersMiddleware {
    #[allow(dead_code)]
    config: HeadersConfig,
    // Pre-parsed headers for performance
    request_headers: Vec<(HeaderName, HeaderValue)>,
    response_headers: Vec<(HeaderName, HeaderValue)>,
    remove_request: Vec<HeaderName>,
    remove_response: Vec<HeaderName>,
}

impl HeadersMiddleware {
    pub fn new(config: HeadersConfig) -> Self {
        let request_headers = config
            .request_headers
            .iter()
            .filter_map(|(k, v)| {
                let name = HeaderName::try_from(k.as_str()).ok()?;
                let value = HeaderValue::from_str(v).ok()?;
                Some((name, value))
            })
            .collect();

        let response_headers = config
            .response_headers
            .iter()
            .filter_map(|(k, v)| {
                let name = HeaderName::try_from(k.as_str()).ok()?;
                let value = HeaderValue::from_str(v).ok()?;
                Some((name, value))
            })
            .collect();

        let remove_request = config
            .remove_request_headers
            .iter()
            .filter_map(|k| HeaderName::try_from(k.as_str()).ok())
            .collect();

        let remove_response = config
            .remove_response_headers
            .iter()
            .filter_map(|k| HeaderName::try_from(k.as_str()).ok())
            .collect();

        Self {
            config,
            request_headers,
            response_headers,
            remove_request,
            remove_response,
        }
    }

    /// Modify request headers
    #[inline]
    pub fn apply_request(&self, headers: &mut HeaderMap) {
        // Remove headers first
        for name in &self.remove_request {
            headers.remove(name);
        }

        // Add headers
        for (name, value) in &self.request_headers {
            headers.insert(name.clone(), value.clone());
        }
    }

    /// Modify response headers
    #[inline]
    pub fn apply_response(&self, headers: &mut HeaderMap) {
        // Remove headers first
        for name in &self.remove_response {
            headers.remove(name);
        }

        // Add headers
        for (name, value) in &self.response_headers {
            headers.insert(name.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_add_headers() {
        let mut request_headers = HashMap::new();
        request_headers.insert("X-Custom".to_string(), "value".to_string());

        let config = HeadersConfig {
            request_headers,
            response_headers: HashMap::new(),
            remove_request_headers: vec![],
            remove_response_headers: vec![],
        };

        let middleware = HeadersMiddleware::new(config);
        let mut headers = HeaderMap::new();

        middleware.apply_request(&mut headers);

        assert_eq!(headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn test_remove_headers() {
        let config = HeadersConfig {
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            remove_request_headers: vec!["Server".to_string()],
            remove_response_headers: vec![],
        };

        let middleware = HeadersMiddleware::new(config);
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx"));

        middleware.apply_request(&mut headers);

        assert!(headers.get("server").is_none());
    }
}
