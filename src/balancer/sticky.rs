use crate::config::{Server, Sticky, StickyCookie};
use dashmap::DashMap;
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::{Request, Response};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sticky session manager for session affinity
/// Maps session cookies to specific backend servers
pub struct StickySessionManager {
    /// Session cookie configuration
    cookie_config: StickyCookie,
    /// Map of session ID -> (server index, last access time)
    sessions: DashMap<String, SessionEntry>,
    /// Server list for validation
    servers: Arc<Vec<Server>>,
    /// Session cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: std::sync::Mutex<Instant>,
}

struct SessionEntry {
    server_index: usize,
    last_access: Instant,
}

impl StickySessionManager {
    pub fn new(sticky: &Sticky, servers: Arc<Vec<Server>>) -> Option<Self> {
        let cookie_config = sticky.cookie.clone()?;

        // Default max age to 24 hours if not specified
        let max_age_secs = cookie_config.max_age.unwrap_or(86400);

        Some(Self {
            cookie_config,
            sessions: DashMap::new(),
            servers,
            cleanup_interval: Duration::from_secs(max_age_secs as u64 / 10), // Cleanup at 10% of max age
            last_cleanup: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Get the sticky server for a request, if one exists
    pub fn get_sticky_server<B>(&self, req: &Request<B>) -> Option<usize> {
        // Extract session ID from cookie
        let session_id = self.extract_session_cookie(req)?;

        // Look up session
        let entry = self.sessions.get(&session_id)?;

        // Validate server index is still valid
        if entry.server_index < self.servers.len() {
            // Update last access time
            drop(entry);
            if let Some(mut entry) = self.sessions.get_mut(&session_id) {
                entry.last_access = Instant::now();
            }
            Some(self.sessions.get(&session_id)?.server_index)
        } else {
            // Server no longer exists, remove stale session
            self.sessions.remove(&session_id);
            None
        }
    }

    /// Create a new sticky session for a server
    pub fn create_session(&self, server_index: usize) -> String {
        // Generate a unique session ID
        let session_id = generate_session_id();

        // Store the session
        self.sessions.insert(
            session_id.clone(),
            SessionEntry {
                server_index,
                last_access: Instant::now(),
            },
        );

        // Maybe do cleanup
        self.maybe_cleanup();

        session_id
    }

    /// Get the Set-Cookie header value for a new session
    pub fn set_cookie_header(&self, session_id: &str) -> String {
        let mut cookie = format!("{}={}", self.cookie_config.name, session_id);

        if let Some(ref path) = self.cookie_config.path {
            cookie.push_str(&format!("; Path={}", path));
        } else {
            cookie.push_str("; Path=/");
        }

        if let Some(max_age) = self.cookie_config.max_age {
            cookie.push_str(&format!("; Max-Age={}", max_age));
        }

        if self.cookie_config.http_only {
            cookie.push_str("; HttpOnly");
        }

        if self.cookie_config.secure {
            cookie.push_str("; Secure");
        }

        if let Some(ref same_site) = self.cookie_config.same_site {
            cookie.push_str(&format!("; SameSite={}", same_site));
        }

        cookie
    }

    /// Add sticky session cookie to response if needed
    pub fn add_cookie_to_response<B>(&self, response: &mut Response<B>, session_id: &str) {
        let cookie_header = self.set_cookie_header(session_id);
        if let Ok(value) = cookie_header.parse() {
            response.headers_mut().insert(SET_COOKIE, value);
        }
    }

    /// Extract session cookie from request
    fn extract_session_cookie<B>(&self, req: &Request<B>) -> Option<String> {
        let cookie_header = req.headers().get(COOKIE)?;
        let cookies = cookie_header.to_str().ok()?;

        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            let mut parts = cookie.splitn(2, '=');
            let name = parts.next()?;
            let value = parts.next()?;

            if name.trim() == self.cookie_config.name {
                return Some(value.to_string());
            }
        }

        None
    }

    /// Periodically clean up expired sessions
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        if last_cleanup.elapsed() < self.cleanup_interval {
            return;
        }

        *last_cleanup = Instant::now();
        drop(last_cleanup);

        let max_age = Duration::from_secs(
            self.cookie_config.max_age.unwrap_or(86400) as u64
        );

        // Remove expired sessions
        self.sessions.retain(|_, entry| entry.last_access.elapsed() < max_age);
    }

    /// Get session count (for metrics)
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get cookie name
    pub fn cookie_name(&self) -> &str {
        &self.cookie_config.name
    }
}

/// Generate a random session ID
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let random1 = fast_random();
    let random2 = fast_random();

    // Create a base64-like string from the combined values
    let combined = timestamp ^ ((random1 as u128) << 32) ^ (random2 as u128);

    // Simple hex encoding (could use base64 for shorter IDs)
    format!("{:032x}", combined)
}

/// Fast xorshift random - no allocation, no syscall
#[inline]
fn fast_random() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = Cell::new(0xBEEFCAFE);
    }
    STATE.with(|state| {
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state.set(x);
        x
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sticky_config() -> Sticky {
        Sticky {
            cookie: Some(StickyCookie {
                name: "SERVERID".to_string(),
                secure: false,
                http_only: true,
                same_site: Some("Lax".to_string()),
                max_age: Some(3600),
                path: Some("/".to_string()),
            }),
        }
    }

    fn test_servers() -> Arc<Vec<Server>> {
        Arc::new(vec![
            Server {
                url: "http://server1:8080".to_string(),
                weight: 1,
                preserve_path: false,
            },
            Server {
                url: "http://server2:8080".to_string(),
                weight: 1,
                preserve_path: false,
            },
        ])
    }

    #[test]
    fn test_sticky_session_creation() {
        let manager = StickySessionManager::new(&test_sticky_config(), test_servers()).unwrap();

        let session_id = manager.create_session(0);
        assert!(!session_id.is_empty());
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_sticky_session_lookup() {
        let manager = StickySessionManager::new(&test_sticky_config(), test_servers()).unwrap();

        let session_id = manager.create_session(1);

        // Create a request with the session cookie
        let req = Request::builder()
            .header(COOKIE, format!("SERVERID={}", session_id))
            .body(())
            .unwrap();

        let server_idx = manager.get_sticky_server(&req);
        assert_eq!(server_idx, Some(1));
    }

    #[test]
    fn test_sticky_session_no_cookie() {
        let manager = StickySessionManager::new(&test_sticky_config(), test_servers()).unwrap();

        let req = Request::builder().body(()).unwrap();

        let server_idx = manager.get_sticky_server(&req);
        assert_eq!(server_idx, None);
    }

    #[test]
    fn test_set_cookie_header() {
        let manager = StickySessionManager::new(&test_sticky_config(), test_servers()).unwrap();

        let session_id = "test-session-123";
        let cookie = manager.set_cookie_header(session_id);

        assert!(cookie.contains("SERVERID=test-session-123"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn test_extract_session_cookie() {
        let manager = StickySessionManager::new(&test_sticky_config(), test_servers()).unwrap();

        // Multiple cookies
        let req = Request::builder()
            .header(COOKIE, "other=value; SERVERID=abc123; another=test")
            .body(())
            .unwrap();

        let session_id = manager.extract_session_cookie(&req);
        assert_eq!(session_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 32); // 128 bits in hex = 32 chars
    }
}
