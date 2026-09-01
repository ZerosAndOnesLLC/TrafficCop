use crate::config::JwtConfig;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, COOKIE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;

/// JWT validation middleware
/// Supports HS256, HS384, HS512 (HMAC) algorithms
/// Can extract JWT from header, query param, or cookie
pub struct JwtMiddleware {
    hmac_key: ring::hmac::Key,
    algorithm: JwtAlgorithm,
    issuer: Option<String>,
    audience: Option<String>,
    header_name: HeaderName,
    header_prefix: String,
    query_param: Option<String>,
    cookie_name: Option<String>,
    forward_claims: HashMap<String, String>,
    strip_authorization_header: bool,
}

/// Supported JWT signing algorithms.
/// The `none` algorithm is deliberately rejected: accepting it would disable
/// signature verification entirely (CVE-2015-9235 class of bypass).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JwtAlgorithm {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
}

impl JwtMiddleware {
    /// Create from config. Returns `None` if the algorithm is unsupported
    /// or no secret is configured.
    pub fn new(config: JwtConfig) -> Option<Self> {
        let algorithm = match config.algorithm.to_uppercase().as_str() {
            "HS256" => JwtAlgorithm::HS256,
            "HS384" => JwtAlgorithm::HS384,
            "HS512" => JwtAlgorithm::HS512,
            _ => {
                tracing::warn!("Unsupported JWT algorithm: {}. Only HMAC algorithms (HS256, HS384, HS512) are currently supported", config.algorithm);
                return None;
            }
        };

        let secret = match config.secret {
            Some(s) => s,
            None => {
                tracing::warn!("JWT middleware requires a secret for HMAC algorithms; middleware disabled");
                return None;
            }
        };

        let hmac_alg = match algorithm {
            JwtAlgorithm::HS256 => ring::hmac::HMAC_SHA256,
            JwtAlgorithm::HS384 => ring::hmac::HMAC_SHA384,
            JwtAlgorithm::HS512 => ring::hmac::HMAC_SHA512,
        };
        let hmac_key = ring::hmac::Key::new(hmac_alg, secret.as_bytes());

        let header_name = HeaderName::try_from(config.header_name.as_str()).ok()?;

        Some(Self {
            hmac_key,
            algorithm,
            issuer: config.issuer,
            audience: config.audience,
            header_name,
            header_prefix: config.header_prefix,
            query_param: config.query_param,
            cookie_name: config.cookie_name,
            forward_claims: config.forward_claims,
            strip_authorization_header: config.strip_authorization_header,
        })
    }

    /// Validate JWT from request
    /// Returns Ok with claims to forward as headers, or Err with status and message
    pub fn validate<B>(&self, req: &Request<B>) -> Result<JwtValidationResult, (StatusCode, String)> {
        // Try to extract token from various sources
        let token = self.extract_token(req)
            .ok_or((StatusCode::UNAUTHORIZED, "No JWT token found".to_string()))?;

        // Parse and validate the token
        let claims = self.validate_token(&token)?;

        // Build headers to forward
        let mut headers_to_add = HeaderMap::new();
        for (claim_name, header_name) in &self.forward_claims {
            if let Some(value) = claims.get(claim_name) {
                let value_str = match value {
                    ClaimValue::String(s) => s.clone(),
                    ClaimValue::Number(n) => n.to_string(),
                    ClaimValue::Bool(b) => b.to_string(),
                    ClaimValue::Array(arr) => arr.join(","),
                    ClaimValue::Null => continue,
                };

                if let Ok(header) = HeaderName::try_from(header_name.as_str())
                    && let Ok(val) = HeaderValue::from_str(&value_str) {
                        headers_to_add.insert(header, val);
                    }
            }
        }

        Ok(JwtValidationResult {
            claims,
            headers_to_add,
            strip_auth_header: self.strip_authorization_header,
        })
    }

    /// Extract token from request (header, query param, or cookie)
    fn extract_token<B>(&self, req: &Request<B>) -> Option<String> {
        // Try header first
        if let Some(auth) = req.headers().get(&self.header_name)
            && let Ok(auth_str) = auth.to_str()
                && auth_str.starts_with(&self.header_prefix) {
                    return Some(auth_str[self.header_prefix.len()..].to_string());
                }

        // Try query parameter
        if let Some(ref param) = self.query_param
            && let Some(query) = req.uri().query() {
                for pair in query.split('&') {
                    let mut parts = pair.splitn(2, '=');
                    if let (Some(key), Some(value)) = (parts.next(), parts.next())
                        && key == param {
                            return Some(value.to_string());
                        }
                }
            }

        // Try cookie
        if let Some(ref cookie_name) = self.cookie_name
            && let Some(cookie_header) = req.headers().get(COOKIE)
                && let Ok(cookies) = cookie_header.to_str() {
                    for cookie in cookies.split(';') {
                        let cookie = cookie.trim();
                        let mut parts = cookie.splitn(2, '=');
                        if let (Some(name), Some(value)) = (parts.next(), parts.next())
                            && name.trim() == cookie_name {
                                return Some(value.to_string());
                            }
                    }
                }

        None
    }

    /// Validate the JWT token
    fn validate_token(&self, token: &str) -> Result<HashMap<String, ClaimValue>, (StatusCode, String)> {
        // Split token into parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err((StatusCode::UNAUTHORIZED, "Invalid JWT format".to_string()));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // Decode header
        let header_json = base64_url_decode(header_b64)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT header encoding".to_string()))?;
        let header: JwtHeader = parse_json_object(&header_json)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT header".to_string()))?;

        // Verify algorithm matches. "none" is rejected here as an unsupported
        // algorithm — a token must never be able to opt out of verification.
        let token_alg = match header.alg.to_uppercase().as_str() {
            "HS256" => JwtAlgorithm::HS256,
            "HS384" => JwtAlgorithm::HS384,
            "HS512" => JwtAlgorithm::HS512,
            _ => return Err((StatusCode::UNAUTHORIZED, format!("Unsupported algorithm: {}", header.alg))),
        };

        if token_alg != self.algorithm {
            return Err((StatusCode::UNAUTHORIZED, "Algorithm mismatch".to_string()));
        }

        // Verify signature (ring's hmac::verify is constant-time)
        {
            let message = format!("{}.{}", header_b64, payload_b64);
            let actual_sig = base64_url_decode_bytes(signature_b64)
                .ok_or((StatusCode::UNAUTHORIZED, "Invalid signature encoding".to_string()))?;

            ring::hmac::verify(&self.hmac_key, message.as_bytes(), &actual_sig)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;
        }

        // Decode payload
        let payload_json = base64_url_decode(payload_b64)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT payload encoding".to_string()))?;
        let claims = parse_claims(&payload_json)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT claims".to_string()))?;

        // Validate standard claims. Compared as signed i64 — casting a
        // negative exp to u64 would wrap to a huge value and never expire.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Check expiration
        if let Some(ClaimValue::Number(exp)) = claims.get("exp")
            && *exp < now {
                return Err((StatusCode::UNAUTHORIZED, "Token expired".to_string()));
            }

        // Check not before
        if let Some(ClaimValue::Number(nbf)) = claims.get("nbf")
            && *nbf > now {
                return Err((StatusCode::UNAUTHORIZED, "Token not yet valid".to_string()));
            }

        // Check issuer
        if let Some(ref expected_iss) = self.issuer {
            match claims.get("iss") {
                Some(ClaimValue::String(iss)) if iss == expected_iss => {}
                _ => return Err((StatusCode::UNAUTHORIZED, "Invalid issuer".to_string())),
            }
        }

        // Check audience
        if let Some(ref expected_aud) = self.audience {
            let valid = match claims.get("aud") {
                Some(ClaimValue::String(aud)) => aud == expected_aud,
                Some(ClaimValue::Array(auds)) => auds.contains(expected_aud),
                _ => false,
            };
            if !valid {
                return Err((StatusCode::UNAUTHORIZED, "Invalid audience".to_string()));
            }
        }

        Ok(claims)
    }

    /// Build 401 Unauthorized response
    pub fn unauthorized_response(&self, message: &str) -> Response<String> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Bearer")
            .body(message.to_string())
            .unwrap()
    }
}

/// Result of successful JWT validation
#[derive(Debug)]
pub struct JwtValidationResult {
    /// Parsed claims from the token
    pub claims: HashMap<String, ClaimValue>,
    /// Headers to add to the request based on forward_claims config
    pub headers_to_add: HeaderMap,
    /// Whether to strip the Authorization header
    pub strip_auth_header: bool,
}

/// JWT claim value types
#[derive(Debug, Clone)]
pub enum ClaimValue {
    /// A string claim value.
    String(String),
    /// A numeric claim value.
    Number(i64),
    /// A boolean claim value.
    Bool(bool),
    /// An array of string claim values.
    Array(Vec<String>),
    /// A null claim value.
    Null,
}

#[derive(Debug)]
struct JwtHeader {
    alg: String,
    #[allow(dead_code)]
    typ: Option<String>,
}

/// Base64 URL decode to string
fn base64_url_decode(input: &str) -> Option<String> {
    let bytes = base64_url_decode_bytes(input)?;
    String::from_utf8(bytes).ok()
}

/// Base64 URL decode to bytes
fn base64_url_decode_bytes(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn char_to_val(c: u8) -> Option<u8> {
        ALPHABET.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return Some(Vec::new());
    }

    let bytes: Vec<u8> = input.bytes().collect();
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

    Some(result)
}

/// Parse the JWT header with a real JSON parser.
fn parse_json_object(json: &str) -> Option<JwtHeader> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = value.as_object()?;
    Some(JwtHeader {
        alg: obj.get("alg")?.as_str()?.to_string(),
        typ: obj.get("typ").and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}

/// Parse JWT claims from the JSON payload with a real JSON parser.
fn parse_claims(json: &str) -> Option<HashMap<String, ClaimValue>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = match value {
        serde_json::Value::Object(map) => map,
        _ => return None,
    };

    let mut claims = HashMap::with_capacity(obj.len());
    for (key, val) in obj {
        claims.insert(key, json_value_to_claim(val));
    }
    Some(claims)
}

fn json_value_to_claim(value: serde_json::Value) -> ClaimValue {
    match value {
        serde_json::Value::Null => ClaimValue::Null,
        serde_json::Value::Bool(b) => ClaimValue::Bool(b),
        serde_json::Value::Number(n) => {
            // Timestamps issued as floats (some libraries do) truncate to seconds.
            ClaimValue::Number(n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64))
        }
        serde_json::Value::String(s) => ClaimValue::String(s),
        serde_json::Value::Array(items) => ClaimValue::Array(
            items
                .into_iter()
                .map(|item| match item {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                })
                .collect(),
        ),
        // Nested objects keep their JSON form so forward_claims can pass them on.
        obj @ serde_json::Value::Object(_) => ClaimValue::String(obj.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::AUTHORIZATION;

    fn test_config() -> JwtConfig {
        JwtConfig {
            secret: Some("my-secret-key".to_string()),
            public_key: None,
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
            query_param: None,
            cookie_name: None,
            forward_claims: HashMap::new(),
            strip_authorization_header: false,
        }
    }

    #[test]
    fn test_jwt_middleware_creation() {
        let middleware = JwtMiddleware::new(test_config());
        assert!(middleware.is_some());
    }

    #[test]
    fn test_none_algorithm_config_rejected() {
        let mut config = test_config();
        config.algorithm = "none".to_string();
        assert!(JwtMiddleware::new(config).is_none());
    }

    #[test]
    fn test_missing_secret_rejected() {
        let mut config = test_config();
        config.secret = None;
        assert!(JwtMiddleware::new(config).is_none());
    }

    #[test]
    fn test_negative_exp_rejected() {
        let middleware = JwtMiddleware::new(test_config()).unwrap();

        // A negative exp previously wrapped via `as u64` and never expired
        let token = create_test_jwt("my-secret-key", r#"{"sub":"x","exp":-1}"#);
        let req = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().1.contains("expired"));
    }

    #[test]
    fn test_escaped_string_claims_parse() {
        let json = r#"{"name":"John \"JD\" Doe","path":"a,b}c","n":-5}"#;
        let claims = parse_claims(json).unwrap();
        assert!(matches!(claims.get("name"), Some(ClaimValue::String(s)) if s == r#"John "JD" Doe"#));
        assert!(matches!(claims.get("path"), Some(ClaimValue::String(s)) if s == "a,b}c"));
        assert!(matches!(claims.get("n"), Some(ClaimValue::Number(-5))));
    }

    #[test]
    fn test_none_algorithm_token_rejected() {
        let middleware = JwtMiddleware::new(test_config()).unwrap();

        // Forged token claiming alg:none with an empty signature
        let header_b64 = base64_url_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload_b64 = base64_url_encode(br#"{"sub":"attacker","exp":9999999999}"#);
        let token = format!("{}.{}.", header_b64, payload_b64);

        let req = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        assert!(middleware.validate(&req).is_err());
    }

    #[test]
    fn test_base64_url_decode() {
        // Standard JWT header
        let decoded = base64_url_decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert!(decoded.is_some());
        assert!(decoded.unwrap().contains("HS256"));
    }

    #[test]
    fn test_parse_claims() {
        let json = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;
        let claims = parse_claims(json).unwrap();

        assert!(matches!(claims.get("sub"), Some(ClaimValue::String(s)) if s == "1234567890"));
        assert!(matches!(claims.get("name"), Some(ClaimValue::String(s)) if s == "John Doe"));
        assert!(matches!(claims.get("iat"), Some(ClaimValue::Number(1516239022))));
    }

    #[test]
    fn test_no_token() {
        let middleware = JwtMiddleware::new(test_config()).unwrap();
        let req = Request::builder().body(()).unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_token_format() {
        let middleware = JwtMiddleware::new(test_config()).unwrap();
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer invalid-token")
            .body(())
            .unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_hs256_token() {
        let config = JwtConfig {
            secret: Some("your-256-bit-secret".to_string()),
            public_key: None,
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
            query_param: None,
            cookie_name: None,
            forward_claims: HashMap::new(),
            strip_authorization_header: false,
        };

        let middleware = JwtMiddleware::new(config).unwrap();

        // This is a valid JWT created with secret "your-256-bit-secret"
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":9999999999}
        // (exp far in future so test doesn't expire)
        let token = create_test_jwt(
            "your-256-bit-secret",
            r#"{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":9999999999}"#
        );

        let req = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_ok());

        let validation = result.unwrap();
        assert!(matches!(validation.claims.get("sub"), Some(ClaimValue::String(s)) if s == "1234567890"));
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig {
            secret: Some("your-256-bit-secret".to_string()),
            public_key: None,
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
            query_param: None,
            cookie_name: None,
            forward_claims: HashMap::new(),
            strip_authorization_header: false,
        };

        let middleware = JwtMiddleware::new(config).unwrap();

        // Token with expired exp claim
        let token = create_test_jwt(
            "your-256-bit-secret",
            r#"{"sub":"1234567890","exp":1000000000}"#
        );

        let req = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().1.contains("expired"));
    }

    #[test]
    fn test_wrong_signature() {
        let config = JwtConfig {
            secret: Some("correct-secret".to_string()),
            public_key: None,
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
            query_param: None,
            cookie_name: None,
            forward_claims: HashMap::new(),
            strip_authorization_header: false,
        };

        let middleware = JwtMiddleware::new(config).unwrap();

        // Token signed with different secret
        let token = create_test_jwt(
            "wrong-secret",
            r#"{"sub":"1234567890","exp":9999999999}"#
        );

        let req = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = middleware.validate(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().1.contains("signature"));
    }

    /// Helper to create a test JWT
    fn create_test_jwt(secret: &str, payload: &str) -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;

        let header_b64 = base64_url_encode(header.as_bytes());
        let payload_b64 = base64_url_encode(payload.as_bytes());

        let message = format!("{}.{}", header_b64, payload_b64);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let signature = ring::hmac::sign(&key, message.as_bytes());
        let sig_b64 = base64_url_encode(signature.as_ref());

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    /// Base64 URL encode
    fn base64_url_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut result = String::new();
        let mut buffer = 0u32;
        let mut bits = 0;

        for &byte in input {
            buffer = (buffer << 8) | byte as u32;
            bits += 8;

            while bits >= 6 {
                bits -= 6;
                result.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
            }
        }

        if bits > 0 {
            buffer <<= 6 - bits;
            result.push(ALPHABET[(buffer & 0x3F) as usize] as char);
        }

        result
    }
}
