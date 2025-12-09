use crate::config::RedirectSchemeConfig;
use hyper::header::{HeaderValue, HOST, LOCATION};
use hyper::{Request, Response, StatusCode};

/// Middleware for redirecting between HTTP and HTTPS schemes
pub struct RedirectSchemeMiddleware {
    scheme: String,
    permanent: bool,
    port: Option<u16>,
}

impl RedirectSchemeMiddleware {
    pub fn new(config: RedirectSchemeConfig) -> Self {
        Self {
            scheme: config.scheme.to_lowercase(),
            permanent: config.permanent,
            port: config.port,
        }
    }

    /// Check if request needs redirect based on current TLS status
    #[inline]
    pub fn should_redirect(&self, is_tls: bool) -> bool {
        let current_scheme = if is_tls { "https" } else { "http" };
        current_scheme != self.scheme
    }

    /// Build redirect response
    pub fn build_redirect<B>(&self, req: &Request<B>) -> Response<()> {
        let status = if self.permanent {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::FOUND
        };

        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| {
                // Remove port from host if present
                h.split(':').next().unwrap_or(h)
            })
            .unwrap_or("localhost");

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let location = match self.port {
            Some(port) if !is_default_port(&self.scheme, port) => {
                format!("{}://{}:{}{}", self.scheme, host, port, path_and_query)
            }
            _ => {
                format!("{}://{}{}", self.scheme, host, path_and_query)
            }
        };

        let mut response = Response::builder().status(status);

        if let Ok(location_value) = HeaderValue::from_str(&location) {
            response = response.header(LOCATION, location_value);
        }

        response.body(()).unwrap()
    }

    /// Get the status code that will be used for redirects
    pub fn status_code(&self) -> StatusCode {
        if self.permanent {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::FOUND
        }
    }
}

/// Check if port is the default for the scheme
#[inline]
fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("http", 80) | ("https", 443))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_to_https_redirect() {
        let config = RedirectSchemeConfig {
            scheme: "https".to_string(),
            permanent: true,
            port: None,
        };
        let middleware = RedirectSchemeMiddleware::new(config);

        let req = Request::builder()
            .uri("http://example.com/path?query=1")
            .header(HOST, "example.com")
            .body(())
            .unwrap();

        assert!(middleware.should_redirect(false));

        let response = middleware.build_redirect(&req);
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);

        let location = response.headers().get(LOCATION).unwrap();
        assert_eq!(location, "https://example.com/path?query=1");
    }

    #[test]
    fn test_no_redirect_when_already_https() {
        let config = RedirectSchemeConfig {
            scheme: "https".to_string(),
            permanent: true,
            port: None,
        };
        let middleware = RedirectSchemeMiddleware::new(config);

        // is_tls = true means we're already on HTTPS
        assert!(!middleware.should_redirect(true));
    }

    #[test]
    fn test_redirect_with_custom_port() {
        let config = RedirectSchemeConfig {
            scheme: "https".to_string(),
            permanent: false,
            port: Some(8443),
        };
        let middleware = RedirectSchemeMiddleware::new(config);

        let req = Request::builder()
            .uri("http://example.com/path")
            .header(HOST, "example.com")
            .body(())
            .unwrap();

        let response = middleware.build_redirect(&req);
        assert_eq!(response.status(), StatusCode::FOUND);

        let location = response.headers().get(LOCATION).unwrap();
        assert_eq!(location, "https://example.com:8443/path");
    }

    #[test]
    fn test_redirect_preserves_host_without_port() {
        let config = RedirectSchemeConfig {
            scheme: "https".to_string(),
            permanent: true,
            port: None,
        };
        let middleware = RedirectSchemeMiddleware::new(config);

        let req = Request::builder()
            .uri("http://example.com:8080/path")
            .header(HOST, "example.com:8080")
            .body(())
            .unwrap();

        let response = middleware.build_redirect(&req);
        let location = response.headers().get(LOCATION).unwrap();
        // Should strip the old port and use default HTTPS port
        assert_eq!(location, "https://example.com/path");
    }

    #[test]
    fn test_default_port_not_included() {
        let config = RedirectSchemeConfig {
            scheme: "https".to_string(),
            permanent: true,
            port: Some(443),
        };
        let middleware = RedirectSchemeMiddleware::new(config);

        let req = Request::builder()
            .uri("http://example.com/")
            .header(HOST, "example.com")
            .body(())
            .unwrap();

        let response = middleware.build_redirect(&req);
        let location = response.headers().get(LOCATION).unwrap();
        // Port 443 should not be included for HTTPS
        assert_eq!(location, "https://example.com/");
    }
}
