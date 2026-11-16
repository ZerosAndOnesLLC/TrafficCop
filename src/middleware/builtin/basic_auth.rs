use crate::config::BasicAuthConfig;
use hyper::header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;

/// Basic authentication middleware (Traefik basicAuth).
/// Users are htpasswd entries `user:hash` with MD5-crypt (`$apr1$`, `$1$`),
/// SHA1 (`{SHA}`) or bcrypt (`$2a$`/`$2b$`/`$2y$`) hashes. Plaintext and
/// unknown formats are rejected at load (as in Traefik).
pub struct BasicAuthMiddleware {
    /// Map of username -> password hash
    users: HashMap<String, String>,
    realm: String,
    www_authenticate: HeaderValue,
}

impl BasicAuthMiddleware {
    /// Create from config. Malformed entries and unsupported hash formats are errors.
    pub fn new(config: BasicAuthConfig) -> Result<Self, String> {
        if config.users.is_empty() {
            return Err(if config.users_file.is_some() {
                "basicAuth: usersFile is not supported yet; use users".to_string()
            } else {
                "basicAuth: at least one user is required".to_string()
            });
        }
        let mut users = HashMap::new();
        for entry in &config.users {
            let Some((user, hash)) = entry.split_once(':') else {
                return Err("basicAuth: user entry must be 'user:hash'".to_string());
            };
            if user.is_empty() {
                return Err("basicAuth: empty username".to_string());
            }
            validate_hash(hash).map_err(|e| format!("basicAuth user '{user}': {e}"))?;
            users.insert(user.to_string(), hash.to_string());
        }

        let realm = config.realm.unwrap_or_else(|| "traefik".to_string());
        let www_authenticate = HeaderValue::from_str(&format!("Basic realm=\"{}\"", realm))
            .map_err(|_| format!("basicAuth: invalid realm '{realm}'"))?;

        Ok(Self {
            users,
            realm,
            www_authenticate,
        })
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
            Some(stored) => verify_password(stored, password),
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

/// Check an htpasswd hash is in a supported, well-formed format.
fn validate_hash(stored: &str) -> Result<(), String> {
    let md5 = |rest: &str| {
        matches!(rest.split_once('$'), Some((salt, hash))
            if !salt.is_empty() && salt.len() <= 8 && hash.len() == 22)
    };
    let ok = if let Some(rest) = stored.strip_prefix("$apr1$") {
        md5(rest)
    } else if let Some(rest) = stored.strip_prefix("$1$") {
        md5(rest)
    } else if stored.starts_with("$2") {
        stored.parse::<bcrypt::HashParts>().is_ok()
    } else if let Some(sha) = stored.strip_prefix("{SHA}") {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(sha)
            .is_ok_and(|d| d.len() == 20)
    } else {
        return Err(
            "unsupported password format (use htpasswd MD5 $apr1$/$1$, {SHA} or bcrypt; plaintext is not accepted)"
                .to_string(),
        );
    };
    if ok {
        Ok(())
    } else {
        Err("malformed password hash".to_string())
    }
}

/// Verify a password against an htpasswd hash. Unknown formats never match.
fn verify_password(stored: &str, password: &str) -> bool {
    let md5 = |rest: &str, magic: &[u8]| match rest.split_once('$') {
        Some((salt, hash)) if !salt.is_empty() && salt.len() <= 8 && !hash.is_empty() => {
            let computed = md5_crypt_encode(password.as_bytes(), salt.as_bytes(), magic);
            constant_time_compare(&computed, hash)
        }
        _ => false,
    };

    if let Some(rest) = stored.strip_prefix("$apr1$") {
        return md5(rest, b"$apr1$");
    }
    if let Some(rest) = stored.strip_prefix("$1$") {
        return md5(rest, b"$1$");
    }
    if stored.starts_with("$2") {
        // bcrypt::verify returns Err on malformed hashes — treat as no match
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    if let Some(sha_hash) = stored.strip_prefix("{SHA}") {
        use base64::Engine;
        let digest = sha1_smol::Sha1::from(password.as_bytes()).digest().bytes();
        let computed = base64::engine::general_purpose::STANDARD.encode(digest);
        return constant_time_compare(&computed, sha_hash);
    }
    false
}

/// MD5-crypt (`$1$`, and Apache's `$apr1$` variant which differs only in
/// the magic string): the standard key-stretching construction over the
/// audited RustCrypto `md-5` primitive (1000 iterations + crypt-alphabet
/// encoding), validated against openssl/htpasswd vectors in tests.
fn md5_crypt_encode(password: &[u8], salt: &[u8], magic: &[u8]) -> String {
    use md5::{Digest, Md5};

    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(magic);
    ctx.update(salt);

    let mut ctx1 = Md5::new();
    ctx1.update(password);
    ctx1.update(salt);
    ctx1.update(password);
    let digest1 = ctx1.finalize();

    let mut remaining = password.len();
    while remaining > 0 {
        let take = remaining.min(16);
        ctx.update(&digest1[..take]);
        remaining -= take;
    }

    let mut i = password.len();
    while i > 0 {
        if i & 1 == 1 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[..1]);
        }
        i >>= 1;
    }

    let mut fin: [u8; 16] = ctx.finalize().into();
    for r in 0..1000u32 {
        let mut c = Md5::new();
        if r & 1 == 1 {
            c.update(password);
        } else {
            c.update(fin);
        }
        if r % 3 != 0 {
            c.update(salt);
        }
        if r % 7 != 0 {
            c.update(password);
        }
        if r & 1 == 1 {
            c.update(fin);
        } else {
            c.update(password);
        }
        fin = c.finalize().into();
    }

    fn push_group(out: &mut String, mut v: u32, n: usize) {
        const CRYPT64: &[u8; 64] =
            b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for _ in 0..n {
            out.push(CRYPT64[(v & 0x3f) as usize] as char);
            v >>= 6;
        }
    }

    let mut out = String::with_capacity(22);
    for &(a, b, c) in &[
        (0usize, 6usize, 12usize),
        (1, 7, 13),
        (2, 8, 14),
        (3, 9, 15),
        (4, 10, 5),
    ] {
        let v = ((fin[a] as u32) << 16) | ((fin[b] as u32) << 8) | fin[c] as u32;
        push_group(&mut out, v, 4);
    }
    push_group(&mut out, fin[11] as u32, 2);
    out
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
                "admin:$apr1$Xy12Ab34$CMRwyEbD4qD9acmonDTWw.".to_string(),
                "user:$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/".to_string(),
            ],
            users_file: None,
            realm: Some("Test Realm".to_string()),
            header_field: None,
            remove_header: false,
        }
    }

    #[test]
    fn test_valid_credentials() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

        // admin:secret123 in base64 = YWRtaW46c2VjcmV0MTIz
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic YWRtaW46c2VjcmV0MTIz")
            .body(())
            .unwrap();

        assert!(middleware.is_authenticated(&req));
    }

    #[test]
    fn test_invalid_password() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

        // admin:wrongpass in base64 = YWRtaW46d3JvbmdwYXNz
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic YWRtaW46d3JvbmdwYXNz")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_unknown_user() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

        // unknown:password in base64 = dW5rbm93bjpwYXNzd29yZA==
        let req = Request::builder()
            .header(AUTHORIZATION, "Basic dW5rbm93bjpwYXNzd29yZA==")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_no_auth_header() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

        let req = Request::builder().body(()).unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_wrong_auth_type() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer token123")
            .body(())
            .unwrap();

        assert!(!middleware.is_authenticated(&req));
    }

    #[test]
    fn test_unauthorized_response() {
        let middleware = BasicAuthMiddleware::new(test_config()).unwrap();

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

    #[test]
    fn test_apr1_hash_verification() {
        let hash = "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
        assert!(verify_password(hash, "password"));
        assert!(!verify_password(hash, "wrong"));
        // The hash value itself must never work as the password
        assert!(!verify_password(hash, hash));
    }

    #[test]
    fn test_bcrypt_hash_verification() {
        let hash = "$2y$05$nC6nErr9XZJuMJ57WyCob.EuZEjylDt2KaHfbfOtyb.EgL1I2jCVa";
        assert!(verify_password(hash, "password"));
        assert!(!verify_password(hash, "wrong"));
        assert!(!verify_password(hash, hash));
    }

    #[test]
    fn test_sha1_hash_verification() {
        let hash = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        assert!(verify_password(hash, "password"));
        assert!(!verify_password(hash, "wrong"));
    }

    #[test]
    fn test_malformed_hashes_rejected_without_panic() {
        assert!(!verify_password("$apr1$", "password"));
        assert!(!verify_password("$apr1$short", "password"));
        assert!(!verify_password("$2y$05$tooshort", "password"));
        assert!(!verify_password(
            "$2z$05$nC6nErr9XZJuMJ57WyCob.EuZEjylDt2KaHfbfOtyb.EgL1I2jCVa",
            "password"
        ));
    }

    #[test]
    fn test_md5_crypt_variant() {
        let hash = "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/";
        assert!(verify_password(hash, "password"));
        assert!(!verify_password(hash, "wrong"));
    }

    #[test]
    fn plaintext_and_unknown_formats_are_rejected() {
        // Unknown formats never verify, even when the "password" equals the stored value.
        for stored in ["secret", "$6$salt$abc", "$5$x$y"] {
            assert!(!verify_password(stored, stored));
        }
        let mk = |u: &str| {
            BasicAuthMiddleware::new(BasicAuthConfig {
                users: vec![u.to_string()],
                users_file: None,
                realm: None,
                header_field: None,
                remove_header: false,
            })
        };
        assert!(mk("admin:secret123").is_err());
        assert!(mk("admin:$6$rounds=5000$salt$hash").is_err());
        assert!(mk("admin:$apr1$short").is_err());
        assert!(mk("admin:{SHA}notbase64!").is_err());
        assert!(mk("nocolon").is_err());
        assert!(mk("admin:$apr1$Xy12Ab34$CMRwyEbD4qD9acmonDTWw.").is_ok());
    }
}
