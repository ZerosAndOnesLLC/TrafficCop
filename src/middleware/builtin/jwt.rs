use crate::config::JwtConfig;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, COOKIE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;

/// JWT validation middleware
/// Supports HS256, HS384, HS512 (HMAC) algorithms
/// Can extract JWT from header, query param, or cookie
pub struct JwtMiddleware {
    secret: Option<Vec<u8>>,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    // RS256/ES256 would require RSA/EC key handling - placeholder
    None,
}

impl JwtMiddleware {
    pub fn new(config: JwtConfig) -> Option<Self> {
        let algorithm = match config.algorithm.to_uppercase().as_str() {
            "HS256" => JwtAlgorithm::HS256,
            "HS384" => JwtAlgorithm::HS384,
            "HS512" => JwtAlgorithm::HS512,
            "NONE" => JwtAlgorithm::None,
            _ => {
                tracing::warn!("Unsupported JWT algorithm: {}. Only HMAC algorithms (HS256, HS384, HS512) are currently supported", config.algorithm);
                return None;
            }
        };

        let header_name = HeaderName::try_from(config.header_name.as_str()).ok()?;

        Some(Self {
            secret: config.secret.map(|s| s.into_bytes()),
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

                if let Ok(header) = HeaderName::try_from(header_name.as_str()) {
                    if let Ok(val) = HeaderValue::from_str(&value_str) {
                        headers_to_add.insert(header, val);
                    }
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
        if let Some(auth) = req.headers().get(&self.header_name) {
            if let Ok(auth_str) = auth.to_str() {
                if auth_str.starts_with(&self.header_prefix) {
                    return Some(auth_str[self.header_prefix.len()..].to_string());
                }
            }
        }

        // Try query parameter
        if let Some(ref param) = self.query_param {
            if let Some(query) = req.uri().query() {
                for pair in query.split('&') {
                    let mut parts = pair.splitn(2, '=');
                    if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                        if key == param {
                            return Some(value.to_string());
                        }
                    }
                }
            }
        }

        // Try cookie
        if let Some(ref cookie_name) = self.cookie_name {
            if let Some(cookie_header) = req.headers().get(COOKIE) {
                if let Ok(cookies) = cookie_header.to_str() {
                    for cookie in cookies.split(';') {
                        let cookie = cookie.trim();
                        let mut parts = cookie.splitn(2, '=');
                        if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                            if name.trim() == cookie_name {
                                return Some(value.to_string());
                            }
                        }
                    }
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

        // Verify algorithm matches
        let token_alg = match header.alg.to_uppercase().as_str() {
            "HS256" => JwtAlgorithm::HS256,
            "HS384" => JwtAlgorithm::HS384,
            "HS512" => JwtAlgorithm::HS512,
            "NONE" => JwtAlgorithm::None,
            _ => return Err((StatusCode::UNAUTHORIZED, format!("Unsupported algorithm: {}", header.alg))),
        };

        if token_alg != self.algorithm {
            return Err((StatusCode::UNAUTHORIZED, "Algorithm mismatch".to_string()));
        }

        // Verify signature
        if self.algorithm != JwtAlgorithm::None {
            let secret = self.secret.as_ref()
                .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "No secret configured".to_string()))?;

            let message = format!("{}.{}", header_b64, payload_b64);
            let expected_sig = match self.algorithm {
                JwtAlgorithm::HS256 => hmac_sha256(secret, message.as_bytes()),
                JwtAlgorithm::HS384 => hmac_sha384(secret, message.as_bytes()),
                JwtAlgorithm::HS512 => hmac_sha512(secret, message.as_bytes()),
                JwtAlgorithm::None => vec![],
            };

            let actual_sig = base64_url_decode_bytes(signature_b64)
                .ok_or((StatusCode::UNAUTHORIZED, "Invalid signature encoding".to_string()))?;

            if !constant_time_compare(&expected_sig, &actual_sig) {
                return Err((StatusCode::UNAUTHORIZED, "Invalid signature".to_string()));
            }
        }

        // Decode payload
        let payload_json = base64_url_decode(payload_b64)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT payload encoding".to_string()))?;
        let claims = parse_claims(&payload_json)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid JWT claims".to_string()))?;

        // Validate standard claims
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check expiration
        if let Some(ClaimValue::Number(exp)) = claims.get("exp") {
            if (*exp as u64) < now {
                return Err((StatusCode::UNAUTHORIZED, "Token expired".to_string()));
            }
        }

        // Check not before
        if let Some(ClaimValue::Number(nbf)) = claims.get("nbf") {
            if (*nbf as u64) > now {
                return Err((StatusCode::UNAUTHORIZED, "Token not yet valid".to_string()));
            }
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
    String(String),
    Number(i64),
    Bool(bool),
    Array(Vec<String>),
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

/// Simple JSON parser for JWT header
fn parse_json_object(json: &str) -> Option<JwtHeader> {
    let json = json.trim();
    if !json.starts_with('{') || !json.ends_with('}') {
        return None;
    }

    let mut alg = None;
    let mut typ = None;

    // Very simple JSON parsing for known fields
    for pair in json[1..json.len()-1].split(',') {
        let pair = pair.trim();
        let mut parts = pair.splitn(2, ':');
        let key = parts.next()?.trim().trim_matches('"');
        let value = parts.next()?.trim().trim_matches('"');

        match key {
            "alg" => alg = Some(value.to_string()),
            "typ" => typ = Some(value.to_string()),
            _ => {}
        }
    }

    Some(JwtHeader {
        alg: alg?,
        typ,
    })
}

/// Parse JWT claims from JSON payload
fn parse_claims(json: &str) -> Option<HashMap<String, ClaimValue>> {
    let json = json.trim();
    if !json.starts_with('{') || !json.ends_with('}') {
        return None;
    }

    let mut claims = HashMap::new();
    let content = &json[1..json.len()-1];

    // Simple state machine for parsing
    let mut remaining = content;
    while !remaining.is_empty() {
        remaining = remaining.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if remaining.is_empty() {
            break;
        }

        // Parse key
        if !remaining.starts_with('"') {
            break;
        }
        remaining = &remaining[1..];
        let key_end = remaining.find('"')?;
        let key = remaining[..key_end].to_string();
        remaining = &remaining[key_end + 1..];

        // Skip colon
        remaining = remaining.trim_start();
        if !remaining.starts_with(':') {
            break;
        }
        remaining = remaining[1..].trim_start();

        // Parse value
        let value = if remaining.starts_with('"') {
            remaining = &remaining[1..];
            let val_end = remaining.find('"')?;
            let val = remaining[..val_end].to_string();
            remaining = &remaining[val_end + 1..];
            ClaimValue::String(val)
        } else if remaining.starts_with('[') {
            // Array - simplified handling
            let arr_end = remaining.find(']')?;
            let arr_content = &remaining[1..arr_end];
            remaining = &remaining[arr_end + 1..];
            let items: Vec<String> = arr_content
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            ClaimValue::Array(items)
        } else if remaining.starts_with("true") {
            remaining = &remaining[4..];
            ClaimValue::Bool(true)
        } else if remaining.starts_with("false") {
            remaining = &remaining[5..];
            ClaimValue::Bool(false)
        } else if remaining.starts_with("null") {
            remaining = &remaining[4..];
            ClaimValue::Null
        } else {
            // Number
            let num_end = remaining.find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .unwrap_or(remaining.len());
            let num_str = &remaining[..num_end];
            remaining = &remaining[num_end..];
            let num: i64 = num_str.parse().ok()?;
            ClaimValue::Number(num)
        };

        claims.insert(key, value);
    }

    Some(claims)
}

/// HMAC-SHA256
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac(key, message, sha256, 64, 32)
}

/// HMAC-SHA384
fn hmac_sha384(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac(key, message, sha384, 128, 48)
}

/// HMAC-SHA512
fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac(key, message, sha512, 128, 64)
}

/// Generic HMAC implementation
fn hmac<F>(key: &[u8], message: &[u8], hash_fn: F, block_size: usize, hash_size: usize) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    // If key is longer than block size, hash it
    let key = if key.len() > block_size {
        hash_fn(key)
    } else {
        key.to_vec()
    };

    // Pad key to block size
    let mut key_padded = key.clone();
    key_padded.resize(block_size, 0);

    // Inner and outer padding
    let mut i_key_pad = vec![0x36u8; block_size];
    let mut o_key_pad = vec![0x5cu8; block_size];

    for i in 0..block_size {
        i_key_pad[i] ^= key_padded[i];
        o_key_pad[i] ^= key_padded[i];
    }

    // HMAC = H(o_key_pad || H(i_key_pad || message))
    let mut inner = i_key_pad;
    inner.extend_from_slice(message);
    let inner_hash = hash_fn(&inner);

    let mut outer = o_key_pad;
    outer.extend_from_slice(&inner_hash);

    let result = hash_fn(&outer);
    result[..hash_size].to_vec()
}

/// SHA-256 implementation
fn sha256(message: &[u8]) -> Vec<u8> {
    // Initial hash values
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Round constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Pre-processing: adding padding bits
    let orig_len = message.len();
    let mut padded = message.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((orig_len as u64 * 8).to_be_bytes()));

    // Process each 512-bit chunk
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];

        // Break chunk into sixteen 32-bit big-endian words
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }

        // Extend the sixteen 32-bit words into sixty-four 32-bit words
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        // Compression function main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce the final hash value (big-endian)
    h.iter().flat_map(|x| x.to_be_bytes()).collect()
}

/// SHA-384 implementation (truncated SHA-512)
fn sha384(message: &[u8]) -> Vec<u8> {
    sha512_family(message, true)
}

/// SHA-512 implementation
fn sha512(message: &[u8]) -> Vec<u8> {
    sha512_family(message, false)
}

/// SHA-512 family implementation
fn sha512_family(message: &[u8], is_384: bool) -> Vec<u8> {
    // Initial hash values (different for SHA-384 vs SHA-512)
    let mut h: [u64; 8] = if is_384 {
        [
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
            0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
        ]
    } else {
        [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        ]
    };

    // Round constants
    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    // Pre-processing: adding padding bits
    let orig_len = message.len();
    let mut padded = message.to_vec();
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&((orig_len as u128 * 8).to_be_bytes()));

    // Process each 1024-bit chunk
    for chunk in padded.chunks(128) {
        let mut w = [0u64; 80];

        // Break chunk into sixteen 64-bit big-endian words
        for (i, word) in chunk.chunks(8).enumerate() {
            w[i] = u64::from_be_bytes([
                word[0], word[1], word[2], word[3],
                word[4], word[5], word[6], word[7],
            ]);
        }

        // Extend the sixteen 64-bit words into eighty 64-bit words
        for i in 16..80 {
            let s0 = w[i-15].rotate_right(1) ^ w[i-15].rotate_right(8) ^ (w[i-15] >> 7);
            let s1 = w[i-2].rotate_right(19) ^ w[i-2].rotate_right(61) ^ (w[i-2] >> 6);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        // Compression function main loop
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce the final hash value
    let full: Vec<u8> = h.iter().flat_map(|x| x.to_be_bytes()).collect();

    if is_384 {
        full[..48].to_vec() // SHA-384 is truncated
    } else {
        full
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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
    fn test_sha256() {
        // Test vector: empty string
        let hash = sha256(b"");
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // Test vector: "abc"
        let hash = sha256(b"abc");
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_hmac_sha256() {
        // Test HMAC-SHA256 with known test vector
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let hmac = hmac_sha256(key, message);
        let hex: String = hmac.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
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
        let signature = hmac_sha256(secret.as_bytes(), message.as_bytes());
        let sig_b64 = base64_url_encode(&signature);

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
