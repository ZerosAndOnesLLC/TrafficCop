use crate::config::CorsConfig;
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
    VARY,
};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};

/// CORS middleware for handling Cross-Origin Resource Sharing
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
    allow_all_origins: bool,
    allowed_methods: String,
    allowed_headers: String,
    allowed_headers_set: Vec<String>,
    exposed_headers: Option<String>,
    allow_credentials: bool,
    max_age: Option<String>,
}

impl CorsMiddleware {
    pub fn new(config: CorsConfig) -> Self {
        let allow_all_origins = config.allowed_origins.iter().any(|o| o == "*");

        let allowed_methods = config.allowed_methods.join(", ");

        let allowed_headers_set: Vec<String> = config
            .allowed_headers
            .iter()
            .map(|h| h.to_lowercase())
            .collect();

        let allowed_headers = config.allowed_headers.join(", ");

        let exposed_headers = if config.exposed_headers.is_empty() {
            None
        } else {
            Some(config.exposed_headers.join(", "))
        };

        let max_age = if config.max_age_seconds > 0 {
            Some(config.max_age_seconds.to_string())
        } else {
            None
        };

        Self {
            allowed_origins: config.allowed_origins,
            allow_all_origins,
            allowed_methods,
            allowed_headers,
            allowed_headers_set,
            exposed_headers,
            allow_credentials: config.allow_credentials,
            max_age,
        }
    }

    /// Check if this is a preflight request (OPTIONS with CORS headers)
    #[inline]
    pub fn is_preflight<B>(&self, req: &Request<B>) -> bool {
        req.method() == Method::OPTIONS
            && req.headers().contains_key(ORIGIN)
            && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD)
    }

    /// Check if origin is allowed
    #[inline]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_all_origins {
            return true;
        }
        self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Validate preflight request headers
    fn validate_preflight<B>(&self, req: &Request<B>) -> bool {
        // Check requested method
        if let Some(method) = req.headers().get(ACCESS_CONTROL_REQUEST_METHOD) {
            if let Ok(method_str) = method.to_str() {
                if !self.allowed_methods.contains(method_str) {
                    return false;
                }
            }
        }

        // Check requested headers
        if let Some(headers) = req.headers().get(ACCESS_CONTROL_REQUEST_HEADERS) {
            if let Ok(headers_str) = headers.to_str() {
                for header in headers_str.split(',') {
                    let header = header.trim().to_lowercase();
                    if !self.allowed_headers_set.contains(&header) {
                        // Allow simple headers always
                        if !is_simple_header(&header) {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }

    /// Handle preflight request, returning a response
    pub fn handle_preflight<B>(&self, req: &Request<B>) -> Option<Response<()>> {
        let origin = req.headers().get(ORIGIN)?.to_str().ok()?;

        if !self.is_origin_allowed(origin) {
            return Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(())
                    .unwrap(),
            );
        }

        if !self.validate_preflight(req) {
            return Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(())
                    .unwrap(),
            );
        }

        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);

        // Set origin header
        let origin_value = if self.allow_all_origins && !self.allow_credentials {
            "*"
        } else {
            origin
        };

        builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);

        // Set methods
        builder = builder.header(ACCESS_CONTROL_ALLOW_METHODS, &self.allowed_methods);

        // Set headers
        builder = builder.header(ACCESS_CONTROL_ALLOW_HEADERS, &self.allowed_headers);

        // Set credentials if enabled
        if self.allow_credentials {
            builder = builder.header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }

        // Set max age
        if let Some(ref max_age) = self.max_age {
            builder = builder.header(ACCESS_CONTROL_MAX_AGE, max_age);
        }

        // Add Vary header for caching
        builder = builder.header(VARY, "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");

        Some(builder.body(()).unwrap())
    }

    /// Apply CORS headers to a response
    pub fn apply_headers(&self, origin: Option<&str>, headers: &mut HeaderMap) {
        let origin = match origin {
            Some(o) if self.is_origin_allowed(o) => o,
            _ => return,
        };

        // Set origin header
        let origin_value = if self.allow_all_origins && !self.allow_credentials {
            "*"
        } else {
            origin
        };

        if let Ok(val) = HeaderValue::from_str(origin_value) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, val);
        }

        // Set credentials if enabled
        if self.allow_credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }

        // Set exposed headers
        if let Some(ref exposed) = self.exposed_headers {
            if let Ok(val) = HeaderValue::from_str(exposed) {
                headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, val);
            }
        }

        // Add Vary header
        headers.insert(VARY, HeaderValue::from_static("Origin"));
    }

    /// Get origin from request headers
    pub fn get_origin<B>(req: &Request<B>) -> Option<String> {
        req.headers()
            .get(ORIGIN)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }
}

/// Check if a header is a CORS-safelisted header
fn is_simple_header(header: &str) -> bool {
    matches!(
        header,
        "accept"
            | "accept-language"
            | "content-language"
            | "content-type"
            | "range"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_seconds: 86400,
        }
    }

    #[test]
    fn test_origin_allowed() {
        let cors = CorsMiddleware::new(test_config());

        assert!(cors.is_origin_allowed("https://example.com"));
        assert!(!cors.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_wildcard_origin() {
        let mut config = test_config();
        config.allowed_origins = vec!["*".to_string()];
        let cors = CorsMiddleware::new(config);

        assert!(cors.is_origin_allowed("https://anything.com"));
    }

    #[test]
    fn test_preflight_detection() {
        let cors = CorsMiddleware::new(test_config());

        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://example.com")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(())
            .unwrap();

        assert!(cors.is_preflight(&req));

        let req = Request::builder()
            .method(Method::GET)
            .header(ORIGIN, "https://example.com")
            .body(())
            .unwrap();

        assert!(!cors.is_preflight(&req));
    }

    #[test]
    fn test_preflight_response() {
        let cors = CorsMiddleware::new(test_config());

        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://example.com")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(())
            .unwrap();

        let response = cors.handle_preflight(&req).unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_some());
    }

    #[test]
    fn test_credentials_with_specific_origin() {
        let mut config = test_config();
        config.allow_credentials = true;
        let cors = CorsMiddleware::new(config);

        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(ORIGIN, "https://example.com")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(())
            .unwrap();

        let response = cors.handle_preflight(&req).unwrap();

        // When credentials are enabled, origin must be specific, not wildcard
        let origin = response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap();
        assert_eq!(origin, "https://example.com");

        assert!(response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_some());
    }
}
