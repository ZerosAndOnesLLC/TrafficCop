use crate::config::BasicAuthConfig;
use hyper::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;

/// Basic authentication middleware
/// Supports htpasswd-style password format: user:password (plaintext) or user:$apr1$... (hashed)
pub struct BasicAuthMiddleware {
    /// Map of username -> password (plaintext or hash)
    users: HashMap<String, String>,
    realm: String,
    www_authenticate: HeaderValue,
}

impl BasicAuthMiddleware {
    pub fn new(config: BasicAuthConfig) -> Self {
        let users: HashMap<String, String> = config
            .users
            .iter()
            .filter_map(|entry| {
                let mut parts = entry.splitn(2, ':');
                let user = parts.next()?.to_string();
                let pass = parts.next()?.to_string();
                Some((user, pass))
            })
            .collect();

        let realm = config.realm.unwrap_or_else(|| "Restricted".to_string());
        let www_authenticate =
            HeaderValue::from_str(&format!("Basic realm=\"{}\"", realm)).unwrap();

        Self {
            users,
            realm,
            www_authenticate,
        }
    }

    /// Check if request is authenticated
    pub fn is_authenticated<B>(&self, req: &Request<B>) -> bool {
        let auth_header = match req.headers().get(AUTHORIZATION) {
            Some(h) => h,
            None => return false,
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Check for "Basic " prefix
        if !auth_str.starts_with("Basic ") {
            return false;
        }

        let encoded = &auth_str[6..];

        // Decode base64
        let decoded = match base64_decode(encoded) {
            Some(d) => d,
            None => return false,
        };

        // Parse user:password
        let mut parts = decoded.splitn(2, ':');
        let username = match parts.next() {
            Some(u) => u,
            None => return false,
        };
        let password = match parts.next() {
            Some(p) => p,
            None => return false,
        };

        // Check credentials
        self.verify(username, password)
    }

    /// Verify username and password
    fn verify(&self, username: &str, password: &str) -> bool {
        match self.users.get(username) {
            Some(stored) => {
                // Check if it's a hash or plaintext
                if stored.starts_with("$apr1$") || stored.starts_with("$2") {
                    // Apache MD5 or bcrypt hash - for now just compare directly
                    // In production, you'd want proper hash verification
                    // This is a placeholder for the hash comparison
                    tracing::warn!(
                        "Hash-based password verification not fully implemented, using plaintext comparison"
                    );
                    stored == password
                } else {
                    // Plaintext comparison (constant-time would be better for production)
                    constant_time_compare(stored, password)
                }
            }
            None => false,
        }
    }

    /// Build 401 Unauthorized response
    pub fn unauthorized_response(&self) -> Response<()> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, self.www_authenticate.clone())
            .body(())
            .unwrap()
    }

    /// Get the realm
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Simple base64 decode (no external dependency)
fn base64_decode(input: &str) -> Option<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_val(c: u8) -> Option<u8> {
        ALPHABET.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let input = input.trim_end_matches('=');
    let bytes: Vec<u8> = input.bytes().collect();

    if bytes.is_empty() {
        return Some(String::new());
    }

    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for byte in bytes {
        let val = char_to_val(byte)?;
        buffer = (buffer << 6) | val as u32;
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            result.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    String::from_utf8(result).ok()
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BasicAuthConfig {
        BasicAuthConfig {
            users: vec![
                "admin:secret123".to_string(),
                "user:password".to_string(),
            ],
            users_file: None,
            realm: Some("Test Realm".to_string()),
            header_field: None,
            remove_header: false,
        }
    }

    #[test]
    fn test_valid_credentials() {
        let middleware = BasicAuthMiddleware::new(test_config());

        // admin:secret123 in base64 = YWRtaW46c2VjcmV0MTIz
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic YWRtaW46c2VjcmV0MTIz")
            .body(())
            .unwrap();

        assert!(middleware.is_authenticated(&req));
    }

    #[test]
    fn test_invalid_password() {
        let middleware = BasicAuthMiddleware::new(test_config());

        // admin:wrongpass in base64 = YWRtaW46d3JvbmdwYXNz
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic YWRtaW46d3JvbmdwYXNz")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_unknown_user() {
        let middleware = BasicAuthMiddleware::new(test_config());

        // unknown:password in base64 = dW5rbm93bjpwYXNzd29yZA==
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic dW5rbm93bjpwYXNzd29yZA==")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_no_auth_header() {
        let middleware = BasicAuthMiddleware::new(test_config());

        let req = Request::builder().body(()).unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_wrong_auth_type() {
        let middleware = BasicAuthMiddleware::new(test_config());

        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer token123")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_unauthorized_response() {
        let middleware = BasicAuthMiddleware::new(test_config());

        let response = middleware.unauthorized_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response.headers().get(WWW_AUTHENTICATE).unwrap();
        assert!(www_auth.to_str().unwrap().contains("Test Realm"));
    }

    #[test]
    fn test_base64_decode() {
        // "Hello" in base64
        assert_eq!(base64_decode("SGVsbG8="), Some("Hello".to_string()));

        // "admin:secret123" in base64
        assert_eq!(
            base64_decode("YWRtaW46c2VjcmV0MTIz"),
            Some("admin:secret123".to_string())
        );
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("test", "test"));
        assert!(!constant_time_compare("test", "Test"));
        assert!(!constant_time_compare("test", "test1"));
    }
}
