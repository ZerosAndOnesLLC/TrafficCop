use crate::config::HeadersConfig;
use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;

/// Headers middleware for adding/removing request and response headers
/// In Traefik, empty header values mean "remove this header"
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
        let mut request_headers = Vec::new();
        let mut remove_request = Vec::new();

        for (k, v) in &config.custom_request_headers {
            if let Ok(name) = HeaderName::try_from(k.as_str()) {
                if v.is_empty() {
                    // Empty value means remove the header (Traefik convention)
                    remove_request.push(name);
                } else if let Ok(value) = HeaderValue::from_str(v) {
                    request_headers.push((name, value));
                }
            }
        }

        let mut response_headers = Vec::new();
        let mut remove_response = Vec::new();

        for (k, v) in &config.custom_response_headers {
            if let Ok(name) = HeaderName::try_from(k.as_str()) {
                if v.is_empty() {
                    // Empty value means remove the header (Traefik convention)
                    remove_response.push(name);
                } else if let Ok(value) = HeaderValue::from_str(v) {
                    response_headers.push((name, value));
                }
            }
        }

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

    #[test]
    fn test_add_headers() {
        let mut config = HeadersConfig::default();
        config
            .custom_request_headers
            .insert("X-Custom".to_string(), "value".to_string());

        let middleware = HeadersMiddleware::new(config);
        let mut headers = HeaderMap::new();

        middleware.apply_request(&mut headers);

        assert_eq!(headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn test_remove_headers_with_empty_value() {
        let mut config = HeadersConfig::default();
        // Empty value means "remove"
        config
            .custom_request_headers
            .insert("Server".to_string(), "".to_string());

        let middleware = HeadersMiddleware::new(config);
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx"));

        middleware.apply_request(&mut headers);

        assert!(headers.get("server").is_none());
    }

    #[test]
    fn test_add_response_headers() {
        let mut config = HeadersConfig::default();
        config
            .custom_response_headers
            .insert("X-Frame-Options".to_string(), "DENY".to_string());

        let middleware = HeadersMiddleware::new(config);
        let mut headers = HeaderMap::new();

        middleware.apply_response(&mut headers);

        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    }
}
