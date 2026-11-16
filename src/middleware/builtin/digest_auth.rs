use crate::config::DigestAuthConfig;
use dashmap::DashMap;
use hyper::header::{AUTHORIZATION, HeaderName, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds a server nonce stays valid before the client is told it is stale.
const NONCE_TTL_SECS: u64 = 300;
/// Upper bound on tracked nonces; expired entries are purged past this.
const MAX_TRACKED_NONCES: usize = 100_000;

/// HTTP Digest authentication middleware (RFC 7616, MD5, qop=auth), matching
/// Traefik's digestAuth: users are htdigest entries `user:realm:HA1`.
///
/// Nonces are stateless (timestamp + random, HMAC-signed with a per-process
/// key) and expire after [`NONCE_TTL_SECS`]. The nonce count is tracked per
/// nonce so a captured `Authorization` header cannot be replayed.
pub struct DigestAuthMiddleware {
    /// `user:realm` -> HA1
    users: HashMap<String, String>,
    realm: String,
    opaque: String,
    nonce_key: hmac::Key,
    rng: SystemRandom,
    /// nonce -> highest nonce-count seen
    seen: DashMap<String, u32>,
    header_field: Option<HeaderName>,
    remove_header: bool,
}

/// Result of a digest authentication attempt.
pub enum AuthResult {
    /// Successfully authenticated; contains the username.
    Authenticated(String),
    /// No Authorization header present.
    NeedsAuth,
    /// Credentials valid but the nonce expired; client should retry with a fresh one.
    Stale,
    /// Invalid credentials or malformed header.
    Invalid,
}

impl DigestAuthMiddleware {
    /// Create from config. Malformed user entries are configuration errors.
    pub fn new(config: DigestAuthConfig) -> Result<Self, String> {
        let realm = config.realm.unwrap_or_else(|| "traefik".to_string());

        let mut lines: Vec<String> = config.users.clone();
        if let Some(path) = &config.users_file {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("digestAuth usersFile '{path}' unreadable: {e}"))?;
            lines.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string),
            );
        }
        if lines.is_empty() {
            return Err("digestAuth requires at least one user".to_string());
        }

        let mut users = HashMap::new();
        for line in &lines {
            let parts: Vec<&str> = line.split(':').collect();
            let [user, user_realm, ha1] = parts[..] else {
                return Err(format!(
                    "digestAuth user entry must be 'user:realm:md5hash' (htdigest), got '{}'",
                    redact(line)
                ));
            };
            if user.is_empty() || ha1.len() != 32 || !ha1.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "digestAuth user entry must be 'user:realm:md5hash' (htdigest), got '{}'",
                    redact(line)
                ));
            }
            users.insert(format!("{user}:{user_realm}"), ha1.to_ascii_lowercase());
        }

        let header_field = match &config.header_field {
            Some(h) => Some(
                HeaderName::try_from(h.as_str())
                    .map_err(|_| format!("digestAuth headerField '{h}' is invalid"))?,
            ),
            None => None,
        };

        let rng = SystemRandom::new();
        let key_bytes = random_bytes::<32>(&rng)?;
        let opaque = hex(&random_bytes::<16>(&rng)?);

        Ok(Self {
            users,
            realm,
            opaque,
            nonce_key: hmac::Key::new(hmac::HMAC_SHA256, &key_bytes),
            rng,
            seen: DashMap::new(),
            header_field,
            remove_header: config.remove_header,
        })
    }

    /// Header to receive the authenticated username, if configured.
    pub fn header_field(&self) -> Option<&HeaderName> {
        self.header_field.as_ref()
    }

    /// Whether to strip `Authorization` before forwarding.
    pub fn remove_header(&self) -> bool {
        self.remove_header
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// nonce = hex(ts[8] || rand[16]) || hex(hmac[..16])
    fn generate_nonce(&self) -> String {
        let mut raw = [0u8; 24];
        raw[..8].copy_from_slice(&Self::now().to_be_bytes());
        // RNG failure leaves zeroes; the HMAC still binds the nonce to this process.
        let _ = self.rng.fill(&mut raw[8..]);
        let tag = hmac::sign(&self.nonce_key, &raw);
        format!("{}{}", hex(&raw), hex(&tag.as_ref()[..16]))
    }

    /// Returns the nonce timestamp if the nonce was issued by this instance.
    fn verify_nonce(&self, nonce: &str) -> Option<u64> {
        if nonce.len() != 80 {
            return None;
        }
        let raw = unhex(&nonce[..48])?;
        let tag = unhex(&nonce[48..])?;
        let expected = hmac::sign(&self.nonce_key, &raw);
        if !constant_time_eq(&expected.as_ref()[..16], &tag) {
            return None;
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[..8]);
        Some(u64::from_be_bytes(ts))
    }

    /// Check if request is authenticated.
    pub fn authenticate<B>(&self, req: &Request<B>) -> AuthResult {
        let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
            return AuthResult::NeedsAuth;
        };
        let Ok(auth_str) = auth_header.to_str() else {
            return AuthResult::Invalid;
        };
        let Some(rest) = auth_str.strip_prefix("Digest ") else {
            return AuthResult::Invalid;
        };
        let Some(params) = parse_digest_params(rest) else {
            return AuthResult::Invalid;
        };

        let get = |k: &str| params.get(k).map(String::as_str);
        let (Some(username), Some(nonce), Some(uri), Some(response), Some(nc), Some(cnonce)) = (
            get("username"),
            get("nonce"),
            get("uri"),
            get("response"),
            get("nc"),
            get("cnonce"),
        ) else {
            return AuthResult::Invalid;
        };
        // Only qop=auth is offered; anything else (incl. RFC 2069 no-qop) is refused.
        if get("qop") != Some("auth") {
            return AuthResult::Invalid;
        }
        if get("realm").is_some_and(|r| r != self.realm) {
            return AuthResult::Invalid;
        }
        if get("opaque").is_some_and(|o| o != self.opaque) {
            return AuthResult::Invalid;
        }

        // The digested URI must be the URI actually requested.
        let request_uri = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        if uri != request_uri {
            return AuthResult::Invalid;
        }

        let Ok(nc_val) = u32::from_str_radix(nc, 16) else {
            return AuthResult::Invalid;
        };
        if nc.len() != 8 || nc_val == 0 {
            return AuthResult::Invalid;
        }

        let Some(issued) = self.verify_nonce(nonce) else {
            return AuthResult::Invalid;
        };

        let Some(ha1) = self.users.get(&format!("{username}:{}", self.realm)) else {
            return AuthResult::Invalid;
        };
        let ha2 = md5_hex(&format!("{}:{}", req.method().as_str(), uri));
        let expected = md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"));
        if !constant_time_eq(expected.as_bytes(), response.as_bytes()) {
            return AuthResult::Invalid;
        }

        if Self::now().saturating_sub(issued) > NONCE_TTL_SECS {
            return AuthResult::Stale;
        }

        // Replay protection: nonce-count must strictly increase per nonce.
        let mut fresh = false;
        self.seen
            .entry(nonce.to_string())
            .and_modify(|last| {
                if nc_val > *last {
                    *last = nc_val;
                    fresh = true;
                }
            })
            .or_insert_with(|| {
                fresh = true;
                nc_val
            });
        if !fresh {
            return AuthResult::Invalid;
        }
        self.purge_expired();

        AuthResult::Authenticated(username.to_string())
    }

    fn purge_expired(&self) {
        if self.seen.len() <= MAX_TRACKED_NONCES {
            return;
        }
        let now = Self::now();
        self.seen.retain(|nonce, _| {
            self.verify_nonce(nonce)
                .is_some_and(|ts| now.saturating_sub(ts) <= NONCE_TTL_SECS)
        });
    }

    /// Build 401 Unauthorized response with a fresh challenge.
    pub fn unauthorized_response(&self, stale: bool) -> Response<String> {
        let www_auth = format!(
            "Digest realm=\"{}\", nonce=\"{}\", opaque=\"{}\", qop=\"auth\", algorithm=MD5{}",
            self.realm,
            self.generate_nonce(),
            self.opaque,
            if stale { ", stale=true" } else { "" }
        );
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, www_auth)
            .body("401 Unauthorized\n".to_string())
            .unwrap_or_default()
    }

    /// Get the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

fn redact(line: &str) -> String {
    line.split(':').next().unwrap_or("").to_string() + ":…"
}

fn random_bytes<const N: usize>(rng: &SystemRandom) -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    rng.fill(&mut b)
        .map_err(|_| "system RNG unavailable".to_string())?;
    Ok(b)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Parse digest auth parameters from header value.
fn parse_digest_params(input: &str) -> Option<HashMap<String, String>> {
    let mut params = HashMap::new();
    let mut remaining = input.trim();

    while !remaining.is_empty() {
        remaining = remaining.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if remaining.is_empty() {
            break;
        }

        let eq_pos = remaining.find('=')?;
        let key = remaining[..eq_pos].trim().to_lowercase();
        remaining = &remaining[eq_pos + 1..];

        let value = if let Some(quoted) = remaining.strip_prefix('"') {
            let end_quote = quoted.find('"')?;
            let val = &quoted[..end_quote];
            remaining = &quoted[end_quote + 1..];
            val.to_string()
        } else {
            let end = remaining.find(',').unwrap_or(remaining.len());
            let val = remaining[..end].trim();
            remaining = &remaining[end..];
            val.to_string()
        };

        // Duplicate parameters are ambiguous; reject the header.
        if params.insert(key, value).is_some() {
            return None;
        }
    }

    Some(params)
}

/// MD5 hex digest. MD5 is mandated by Digest auth (RFC 7616 MD5 variant).
fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    hex(&Md5::digest(input.as_bytes()))
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "traefik";

    fn ha1(user: &str, pass: &str) -> String {
        md5_hex(&format!("{user}:{REALM}:{pass}"))
    }

    fn mw() -> DigestAuthMiddleware {
        DigestAuthMiddleware::new(DigestAuthConfig {
            users: vec![
                format!("admin:{REALM}:{}", ha1("admin", "secret123")),
                format!("other:elsewhere:{}", ha1("other", "pw")),
            ],
            users_file: None,
            realm: None,
            header_field: None,
            remove_header: false,
        })
        .unwrap()
    }

    fn nonce_of(m: &DigestAuthMiddleware) -> String {
        let r = m.unauthorized_response(false);
        let h = r.headers()[WWW_AUTHENTICATE].to_str().unwrap().to_string();
        let start = h.find("nonce=\"").unwrap() + 7;
        h[start..start + 80].to_string()
    }

    fn header(user: &str, pass: &str, nonce: &str, uri: &str, nc: &str) -> String {
        let ha2 = md5_hex(&format!("GET:{uri}"));
        let resp = md5_hex(&format!("{}:{nonce}:{nc}:cn:auth:{ha2}", ha1(user, pass)));
        format!(
            "Digest username=\"{user}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", qop=auth, nc={nc}, cnonce=\"cn\", response=\"{resp}\""
        )
    }

    fn req(uri: &str, auth: &str) -> Request<()> {
        Request::builder()
            .uri(uri)
            .header(AUTHORIZATION, auth)
            .body(())
            .unwrap()
    }

    #[test]
    fn md5_vectors() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn rejects_non_htdigest_entries() {
        let bad = |u: &str| {
            DigestAuthMiddleware::new(DigestAuthConfig {
                users: vec![u.to_string()],
                users_file: None,
                realm: None,
                header_field: None,
                remove_header: false,
            })
            .is_err()
        };
        assert!(bad("admin:plaintext"));
        assert!(bad("admin:traefik:nothex"));
        assert!(!bad("test:traefik:a2688e031edb4be6a3797f3882655c05"));
    }

    #[test]
    fn valid_login() {
        let m = mw();
        let n = nonce_of(&m);
        let r = req(
            "/a?b=1",
            &header("admin", "secret123", &n, "/a?b=1", "00000001"),
        );
        assert!(matches!(m.authenticate(&r), AuthResult::Authenticated(u) if u == "admin"));
    }

    #[test]
    fn wrong_password_and_wrong_realm_user() {
        let m = mw();
        let n = nonce_of(&m);
        let r = req("/", &header("admin", "nope", &n, "/", "00000001"));
        assert!(matches!(m.authenticate(&r), AuthResult::Invalid));
        // "other" exists only for a different realm
        let r = req("/", &header("other", "pw", &n, "/", "00000001"));
        assert!(matches!(m.authenticate(&r), AuthResult::Invalid));
    }

    #[test]
    fn replay_is_rejected() {
        let m = mw();
        let n = nonce_of(&m);
        let h = header("admin", "secret123", &n, "/", "00000001");
        assert!(matches!(
            m.authenticate(&req("/", &h)),
            AuthResult::Authenticated(_)
        ));
        assert!(matches!(m.authenticate(&req("/", &h)), AuthResult::Invalid));
        let h2 = header("admin", "secret123", &n, "/", "00000002");
        assert!(matches!(
            m.authenticate(&req("/", &h2)),
            AuthResult::Authenticated(_)
        ));
    }

    #[test]
    fn forged_nonce_is_rejected() {
        let m = mw();
        let n = "0".repeat(80);
        let r = req("/", &header("admin", "secret123", &n, "/", "00000001"));
        assert!(matches!(m.authenticate(&r), AuthResult::Invalid));
        // a nonce from another instance (different key) is also rejected
        let other = nonce_of(&mw());
        let r = req("/", &header("admin", "secret123", &other, "/", "00000001"));
        assert!(matches!(m.authenticate(&r), AuthResult::Invalid));
    }

    #[test]
    fn uri_must_match_request() {
        let m = mw();
        let n = nonce_of(&m);
        let r = req(
            "/admin",
            &header("admin", "secret123", &n, "/public", "00000001"),
        );
        assert!(matches!(m.authenticate(&r), AuthResult::Invalid));
    }

    #[test]
    fn missing_header_and_wrong_scheme() {
        let m = mw();
        let r = Request::builder().uri("/").body(()).unwrap();
        assert!(matches!(m.authenticate(&r), AuthResult::NeedsAuth));
        assert!(matches!(
            m.authenticate(&req("/", "Basic YWRtaW46c2VjcmV0MTIz")),
            AuthResult::Invalid
        ));
    }

    #[test]
    fn challenge_format() {
        let r = mw().unauthorized_response(true);
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers()[WWW_AUTHENTICATE].to_str().unwrap();
        assert!(h.starts_with("Digest realm=\"traefik\""));
        assert!(h.contains("qop=\"auth\"") && h.contains("stale=true"));
    }

    #[test]
    fn duplicate_params_rejected() {
        assert!(parse_digest_params("a=1, a=2").is_none());
    }
}
