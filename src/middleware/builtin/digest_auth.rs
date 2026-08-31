use crate::config::DigestAuthConfig;
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// HTTP Digest authentication middleware (RFC 7616)
/// Uses MD5 algorithm for compatibility with most clients
pub struct DigestAuthMiddleware {
    /// Map of username -> HA1 (precomputed MD5(username:realm:password))
    users: HashMap<String, String>,
    realm: String,
    /// Nonce counter for uniqueness
    nonce_counter: AtomicU64,
    /// Opaque value (constant per server)
    opaque: String,
}

impl DigestAuthMiddleware {
    /// Create from config, precomputing HA1 hashes for each user.
    pub fn new(config: DigestAuthConfig) -> Self {
        let realm = config.realm.unwrap_or_else(|| "Restricted".to_string());

        // Parse users and precompute HA1 = MD5(username:realm:password)
        let users: HashMap<String, String> = config
            .users
            .iter()
            .filter_map(|entry| {
                let mut parts = entry.splitn(2, ':');
                let user = parts.next()?.to_string();
                let pass = parts.next()?.to_string();
                // HA1 = MD5(username:realm:password)
                let ha1 = md5_hex(&format!("{}:{}:{}", user, realm, pass));
                Some((user, ha1))
            })
            .collect();

        // Generate a random opaque value
        let opaque = md5_hex(&format!("opaque-{}", fast_random()));

        Self {
            users,
            realm,
            nonce_counter: AtomicU64::new(0),
            opaque,
        }
    }

    /// Generate a new nonce value
    fn generate_nonce(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let random = fast_random();

        // Nonce = base64(timestamp:counter:random:secret)
        let nonce_data = format!("{}:{}:{}:trafficcop", timestamp, counter, random);
        md5_hex(&nonce_data)
    }

    /// Check if request is authenticated
    pub fn authenticate<B>(&self, req: &Request<B>) -> AuthResult {
        let auth_header = match req.headers().get(AUTHORIZATION) {
            Some(h) => h,
            None => return AuthResult::NeedsAuth,
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return AuthResult::Invalid,
        };

        // Check for "Digest " prefix
        if !auth_str.starts_with("Digest ") {
            return AuthResult::Invalid;
        }

        // Parse the digest parameters
        let params = match parse_digest_params(&auth_str[7..]) {
            Some(p) => p,
            None => return AuthResult::Invalid,
        };

        // Extract required fields
        let username = match params.get("username") {
            Some(u) => u.as_str(),
            None => return AuthResult::Invalid,
        };

        let nonce = match params.get("nonce") {
            Some(n) => n.as_str(),
            None => return AuthResult::Invalid,
        };

        let uri = match params.get("uri") {
            Some(u) => u.as_str(),
            None => return AuthResult::Invalid,
        };

        let response = match params.get("response") {
            Some(r) => r.as_str(),
            None => return AuthResult::Invalid,
        };

        // Get optional qop-related fields
        let qop = params.get("qop").map(|s| s.as_str());
        let nc = params.get("nc").map(|s| s.as_str());
        let cnonce = params.get("cnonce").map(|s| s.as_str());

        // Verify the response
        if self.verify_response(username, nonce, uri, response, req.method().as_str(), qop, nc, cnonce) {
            AuthResult::Authenticated(username.to_string())
        } else {
            AuthResult::Invalid
        }
    }

    /// Verify the digest response
    #[allow(clippy::too_many_arguments)]
    fn verify_response(
        &self,
        username: &str,
        nonce: &str,
        uri: &str,
        response: &str,
        method: &str,
        qop: Option<&str>,
        nc: Option<&str>,
        cnonce: Option<&str>,
    ) -> bool {
        // Get HA1 for user
        let ha1 = match self.users.get(username) {
            Some(h) => h,
            None => return false,
        };

        // HA2 = MD5(method:uri)
        let ha2 = md5_hex(&format!("{}:{}", method, uri));

        // Calculate expected response based on qop
        let expected = match qop {
            Some("auth") | Some("auth-int") => {
                // With qop: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
                let nc = nc.unwrap_or("00000001");
                let cnonce = cnonce.unwrap_or("");
                let qop_val = qop.unwrap_or("auth");
                md5_hex(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop_val, ha2))
            }
            _ => {
                // Without qop: response = MD5(HA1:nonce:HA2)
                md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
            }
        };

        // Constant-time comparison
        constant_time_compare(&expected, response)
    }

    /// Build 401 Unauthorized response with WWW-Authenticate header
    pub fn unauthorized_response(&self) -> Response<String> {
        let nonce = self.generate_nonce();

        let www_auth = format!(
            "Digest realm=\"{}\", nonce=\"{}\", opaque=\"{}\", qop=\"auth\", algorithm=MD5",
            self.realm, nonce, self.opaque
        );

        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, www_auth)
            .body("Unauthorized".to_string())
            .unwrap()
    }

    /// Get the realm
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Result of digest authentication attempt
pub enum AuthResult {
    /// Successfully authenticated, contains username
    Authenticated(String),
    /// No Authorization header present
    NeedsAuth,
    /// Invalid credentials or malformed header
    Invalid,
}

/// Parse digest auth parameters from header value
fn parse_digest_params(input: &str) -> Option<HashMap<String, String>> {
    let mut params = HashMap::new();

    // Simple state machine parser for key="value" or key=value pairs
    let mut remaining = input.trim();

    while !remaining.is_empty() {
        // Skip whitespace and commas
        remaining = remaining.trim_start_matches(|c: char| c.is_whitespace() || c == ',');

        if remaining.is_empty() {
            break;
        }

        // Find the key
        let eq_pos = remaining.find('=')?;
        let key = remaining[..eq_pos].trim().to_lowercase();
        remaining = &remaining[eq_pos + 1..];

        // Get the value (quoted or unquoted)
        let value = if remaining.starts_with('"') {
            // Quoted value
            remaining = &remaining[1..];
            let end_quote = remaining.find('"')?;
            let val = &remaining[..end_quote];
            remaining = &remaining[end_quote + 1..];
            val.to_string()
        } else {
            // Unquoted value - ends at comma or end
            let end = remaining.find(',').unwrap_or(remaining.len());
            let val = remaining[..end].trim();
            remaining = &remaining[end..];
            val.to_string()
        };

        params.insert(key, value);
    }

    Some(params)
}

/// Compute MD5 hash and return as hex string.
/// MD5 is required by the Digest auth spec (RFC 7616); uses the audited
/// RustCrypto `md-5` crate rather than a hand-rolled implementation.
fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    let digest = Md5::digest(input.as_bytes());
    let mut out = String::with_capacity(32);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

fn fast_random() -> u32 {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 4];
    if rng.fill(&mut buf).is_err() {
        // OS RNG failure is effectively unreachable; degrade to a timestamp
        // rather than panicking (release builds abort on panic).
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
    }
    u32::from_ne_bytes(buf)
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

    fn test_config() -> DigestAuthConfig {
        DigestAuthConfig {
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
    fn test_md5_hash() {
        // Test vectors from RFC 1321
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    }

    #[test]
    fn test_digest_auth_creation() {
        let middleware = DigestAuthMiddleware::new(test_config());
        assert_eq!(middleware.realm(), "Test Realm");
        assert!(middleware.users.contains_key("admin"));
        assert!(middleware.users.contains_key("user"));
    }

    #[test]
    fn test_parse_digest_params() {
        let input = r#"username="admin", realm="Test", nonce="abc123", uri="/test", response="xyz""#;
        let params = parse_digest_params(input).unwrap();

        assert_eq!(params.get("username"), Some(&"admin".to_string()));
        assert_eq!(params.get("realm"), Some(&"Test".to_string()));
        assert_eq!(params.get("nonce"), Some(&"abc123".to_string()));
        assert_eq!(params.get("uri"), Some(&"/test".to_string()));
        assert_eq!(params.get("response"), Some(&"xyz".to_string()));
    }

    #[test]
    fn test_no_auth_header() {
        let middleware = DigestAuthMiddleware::new(test_config());
        let req = Request::builder().body(()).unwrap();

        assert!(matches!(middleware.authenticate(&req), AuthResult::NeedsAuth));
    }

    #[test]
    fn test_wrong_auth_type() {
        let middleware = DigestAuthMiddleware::new(test_config());
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic YWRtaW46c2VjcmV0MTIz")
            .body(())
            .unwrap();

        assert!(matches!(middleware.authenticate(&req), AuthResult::Invalid));
    }

    #[test]
    fn test_unauthorized_response() {
        let middleware = DigestAuthMiddleware::new(test_config());
        let response = middleware.unauthorized_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response.headers().get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(www_auth.contains("Digest"));
        assert!(www_auth.contains("Test Realm"));
        assert!(www_auth.contains("nonce="));
        assert!(www_auth.contains("qop=\"auth\""));
    }

    #[test]
    fn test_digest_response_calculation() {
        let middleware = DigestAuthMiddleware::new(test_config());

        // Manually compute what the response should be for a known request
        // HA1 = MD5(admin:Test Realm:secret123)
        let ha1 = md5_hex("admin:Test Realm:secret123");
        // HA2 = MD5(GET:/test)
        let ha2 = md5_hex("GET:/test");

        let nonce = "testnonce123";
        // Without qop: response = MD5(HA1:nonce:HA2)
        let expected_response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        // Verify using internal method
        assert!(middleware.verify_response(
            "admin",
            nonce,
            "/test",
            &expected_response,
            "GET",
            None,
            None,
            None
        ));
    }

    #[test]
    fn test_digest_response_with_qop() {
        let middleware = DigestAuthMiddleware::new(test_config());

        // HA1 = MD5(admin:Test Realm:secret123)
        let ha1 = md5_hex("admin:Test Realm:secret123");
        // HA2 = MD5(GET:/test)
        let ha2 = md5_hex("GET:/test");

        let nonce = "testnonce123";
        let nc = "00000001";
        let cnonce = "clientnonce";
        let qop = "auth";

        // With qop: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let expected_response = md5_hex(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2));

        assert!(middleware.verify_response(
            "admin",
            nonce,
            "/test",
            &expected_response,
            "GET",
            Some(qop),
            Some(nc),
            Some(cnonce)
        ));
    }
}
