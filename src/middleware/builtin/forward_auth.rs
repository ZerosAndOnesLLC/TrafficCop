use crate::config::ForwardAuthConfig;
use hyper::header::{HeaderMap, HeaderName, AUTHORIZATION, COOKIE};
use hyper::{Method, Request, StatusCode};
use regex::Regex;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

/// ForwardAuth middleware delegates authentication to an external service
pub struct ForwardAuthMiddleware {
    client: Client,
    address: String,
    trust_forward_header: bool,
    auth_response_headers: Vec<HeaderName>,
    auth_response_headers_regex: Option<Regex>,
    auth_request_headers: Vec<HeaderName>,
    add_auth_cookies_to_response: Vec<String>,
}

impl ForwardAuthMiddleware {
    pub fn new(config: ForwardAuthConfig) -> Option<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .ok()?;

        let auth_response_headers: Vec<HeaderName> = config
            .auth_response_headers
            .iter()
            .filter_map(|h| HeaderName::try_from(h.as_str()).ok())
            .collect();

        let auth_response_headers_regex = config
            .auth_response_headers_regex
            .as_ref()
            .and_then(|r| Regex::new(r).ok());

        let auth_request_headers: Vec<HeaderName> = config
            .auth_request_headers
            .iter()
            .filter_map(|h| HeaderName::try_from(h.as_str()).ok())
            .collect();

        Some(Self {
            client,
            address: config.address,
            trust_forward_header: config.trust_forward_header,
            auth_response_headers,
            auth_response_headers_regex,
            auth_request_headers,
            add_auth_cookies_to_response: config.add_auth_cookies_to_response,
        })
    }

    /// Check authentication by calling the external auth service
    /// Returns Ok with headers to forward, or Err with status code and body
    pub async fn authenticate<B>(
        &self,
        req: &Request<B>,
    ) -> Result<AuthResult, (StatusCode, String)> {
        // Build the auth request
        let mut auth_req = self
            .client
            .request(Method::GET, &self.address);

        // Forward specific headers
        let original_headers = req.headers();

        // Always forward these headers if present
        if let Some(auth) = original_headers.get(AUTHORIZATION) {
            if let Ok(v) = auth.to_str() {
                auth_req = auth_req.header(AUTHORIZATION.as_str(), v);
            }
        }

        if let Some(cookie) = original_headers.get(COOKIE) {
            if let Ok(v) = cookie.to_str() {
                auth_req = auth_req.header(COOKIE.as_str(), v);
            }
        }

        // Forward configured request headers
        for header_name in &self.auth_request_headers {
            if let Some(value) = original_headers.get(header_name) {
                if let Ok(v) = value.to_str() {
                    auth_req = auth_req.header(header_name.as_str(), v);
                }
            }
        }

        // Forward X-Forwarded-* headers if trusted
        if self.trust_forward_header {
            for (name, value) in original_headers.iter() {
                if name.as_str().starts_with("x-forwarded-") {
                    if let Ok(v) = value.to_str() {
                        auth_req = auth_req.header(name.as_str(), v);
                    }
                }
            }
        }

        // Add request info headers
        auth_req = auth_req
            .header("X-Forwarded-Method", req.method().as_str())
            .header("X-Forwarded-Uri", req.uri().to_string());

        if let Some(host) = original_headers.get("host") {
            if let Ok(v) = host.to_str() {
                auth_req = auth_req.header("X-Forwarded-Host", v);
            }
        }

        // Send the request
        let response = match auth_req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Forward auth request failed: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Auth service unavailable".to_string()));
            }
        };

        let status = response.status();

        if status.is_success() {
            // Auth succeeded - extract headers to forward
            let response_headers = response.headers();
            let mut forward_headers = HeaderMap::new();
            let mut cookies_to_add = Vec::new();

            // Copy explicitly configured headers
            for header_name in &self.auth_response_headers {
                if let Some(value) = response_headers.get(header_name) {
                    forward_headers.insert(header_name.clone(), value.clone());
                }
            }

            // Copy headers matching regex
            if let Some(ref regex) = self.auth_response_headers_regex {
                for (name, value) in response_headers.iter() {
                    if regex.is_match(name.as_str()) {
                        forward_headers.insert(name.clone(), value.clone());
                    }
                }
            }

            // Extract cookies to add to response
            for cookie_name in &self.add_auth_cookies_to_response {
                if let Some(set_cookie) = response_headers.get("set-cookie") {
                    if let Ok(v) = set_cookie.to_str() {
                        if v.starts_with(cookie_name) {
                            cookies_to_add.push(v.to_string());
                        }
                    }
                }
            }

            debug!("Forward auth succeeded, forwarding {} headers", forward_headers.len());

            Ok(AuthResult {
                headers_to_request: forward_headers,
                cookies_to_response: cookies_to_add,
            })
        } else {
            // Auth failed - return the error response
            let body = response.text().await.unwrap_or_default();
            debug!("Forward auth failed with status {}", status);
            Err((status, body))
        }
    }
}

/// Result of successful authentication
pub struct AuthResult {
    /// Headers to add to the request before forwarding to backend
    pub headers_to_request: HeaderMap,
    /// Cookies to add to the response
    pub cookies_to_response: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_auth_creation() {
        let config = ForwardAuthConfig {
            address: "http://auth.local/verify".to_string(),
            trust_forward_header: true,
            auth_response_headers: vec!["X-User-Id".to_string(), "X-User-Role".to_string()],
            auth_response_headers_regex: Some("^X-Auth-.*".to_string()),
            auth_request_headers: vec!["X-Custom-Header".to_string()],
            tls: None,
            add_auth_cookies_to_response: vec![],
        };

        let middleware = ForwardAuthMiddleware::new(config);
        assert!(middleware.is_some());
    }

    #[test]
    fn test_forward_auth_with_regex() {
        let config = ForwardAuthConfig {
            address: "http://auth.local/verify".to_string(),
            trust_forward_header: false,
            auth_response_headers: vec![],
            auth_response_headers_regex: Some("^X-Auth-.*".to_string()),
            auth_request_headers: vec![],
            tls: None,
            add_auth_cookies_to_response: vec![],
        };

        let middleware = ForwardAuthMiddleware::new(config).unwrap();
        assert!(middleware.auth_response_headers_regex.is_some());
    }
}
