use crate::config::{Server, Sticky, StickyCookie};
use crate::store::Store;
use dashmap::DashMap;
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::{Request, Response};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Sticky session manager for session affinity
/// Supports both local-only and distributed (Valkey/Redis) modes
pub struct StickySessionManager {
    /// Session cookie configuration
    cookie_config: StickyCookie,
    /// Local cache of session ID -> server URL
    local_cache: DashMap<String, LocalCacheEntry>,
    /// Server list for validation
    servers: Arc<Vec<Server>>,
    /// Service name (for distributed key prefix)
    service_name: String,
    /// Distributed store (optional)
    store: Option<Arc<dyn Store>>,
    /// Session TTL
    session_ttl: Duration,
    /// Local cache TTL (shorter than session TTL for freshness)
    local_cache_ttl: Duration,
    /// Last cleanup time
    last_cleanup: std::sync::Mutex<Instant>,
}

struct LocalCacheEntry {
    server_url: String,
    cached_at: Instant,
}

impl StickySessionManager {
    /// Create a new local-only sticky session manager
    pub fn new(sticky: &Sticky, servers: Arc<Vec<Server>>, service_name: &str) -> Option<Self> {
        let cookie_config = sticky.cookie.clone()?;
        let max_age_secs = cookie_config.max_age.unwrap_or(86400) as u64;

        Some(Self {
            cookie_config,
            local_cache: DashMap::new(),
            servers,
            service_name: service_name.to_string(),
            store: None,
            session_ttl: Duration::from_secs(max_age_secs),
            local_cache_ttl: Duration::from_secs(max_age_secs.min(300)), // Max 5 min local cache
            last_cleanup: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Create with distributed store backing
    pub fn with_store(
        sticky: &Sticky,
        servers: Arc<Vec<Server>>,
        service_name: &str,
        store: Arc<dyn Store>,
    ) -> Option<Self> {
        let cookie_config = sticky.cookie.clone()?;
        let max_age_secs = cookie_config.max_age.unwrap_or(86400) as u64;

        Some(Self {
            cookie_config,
            local_cache: DashMap::new(),
            servers,
            service_name: service_name.to_string(),
            store: Some(store),
            session_ttl: Duration::from_secs(max_age_secs),
            local_cache_ttl: Duration::from_secs(max_age_secs.min(300)),
            last_cleanup: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Get the sticky server for a request (sync, local cache only)
    /// Use this for hot path when eventual consistency is acceptable
    pub fn get_sticky_server<B>(&self, req: &Request<B>) -> Option<usize> {
        let session_id = self.extract_session_cookie(req)?;

        // Check local cache first
        if let Some(entry) = self.local_cache.get(&session_id) {
            if entry.cached_at.elapsed() < self.local_cache_ttl {
                return self.find_server_index(&entry.server_url);
            }
        }

        None
    }

    /// Get the sticky server (async, checks distributed store)
    pub async fn get_sticky_server_distributed<B>(&self, req: &Request<B>) -> Option<usize> {
        let session_id = self.extract_session_cookie(req)?;

        // Check local cache first
        if let Some(entry) = self.local_cache.get(&session_id) {
            if entry.cached_at.elapsed() < self.local_cache_ttl {
                return self.find_server_index(&entry.server_url);
            }
        }

        // Check distributed store
        if let Some(store) = &self.store {
            match store.sticky_session_get(&self.service_name, &session_id).await {
                Ok(Some(server_url)) => {
                    // Update local cache
                    self.local_cache.insert(
                        session_id.clone(),
                        LocalCacheEntry {
                            server_url: server_url.clone(),
                            cached_at: Instant::now(),
                        },
                    );

                    return self.find_server_index(&server_url);
                }
                Ok(None) => {
                    debug!("Session {} not found in distributed store", session_id);
                }
                Err(e) => {
                    warn!("Failed to get session from store: {}", e);
                }
            }
        }

        None
    }

    /// Create a new sticky session for a server
    pub fn create_session(&self, server_index: usize) -> Option<String> {
        let server = self.servers.get(server_index)?;
        let session_id = generate_session_id();

        // Store in local cache
        self.local_cache.insert(
            session_id.clone(),
            LocalCacheEntry {
                server_url: server.url.clone(),
                cached_at: Instant::now(),
            },
        );

        // Store in distributed store (async, non-blocking)
        if let Some(store) = self.store.clone() {
            let service_name = self.service_name.clone();
            let session_id_clone = session_id.clone();
            let server_url = server.url.clone();
            let ttl = self.session_ttl;

            tokio::spawn(async move {
                if let Err(e) = store
                    .sticky_session_set(&service_name, &session_id_clone, &server_url, ttl)
                    .await
                {
                    warn!("Failed to store session in distributed store: {}", e);
                }
            });
        }

        // Maybe cleanup
        self.maybe_cleanup();

        Some(session_id)
    }

    /// Create a session and store it synchronously (for when you need to wait)
    pub async fn create_session_sync(&self, server_index: usize) -> Option<String> {
        let server = self.servers.get(server_index)?;
        let session_id = generate_session_id();

        // Store in local cache
        self.local_cache.insert(
            session_id.clone(),
            LocalCacheEntry {
                server_url: server.url.clone(),
                cached_at: Instant::now(),
            },
        );

        // Store in distributed store
        if let Some(store) = &self.store {
            if let Err(e) = store
                .sticky_session_set(&self.service_name, &session_id, &server.url, self.session_ttl)
                .await
            {
                warn!("Failed to store session in distributed store: {}", e);
            }
        }

        Some(session_id)
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

    /// Find server index by URL
    fn find_server_index(&self, server_url: &str) -> Option<usize> {
        self.servers.iter().position(|s| s.url == server_url)
    }

    /// Periodically clean up expired local cache entries
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        let cleanup_interval = self.local_cache_ttl / 10;

        if last_cleanup.elapsed() < cleanup_interval {
            return;
        }

        *last_cleanup = Instant::now();
        drop(last_cleanup);

        let now = Instant::now();
        self.local_cache
            .retain(|_, entry| now.duration_since(entry.cached_at) < self.local_cache_ttl);
    }

    /// Delete a session (e.g., on logout)
    pub async fn delete_session(&self, session_id: &str) {
        self.local_cache.remove(session_id);

        if let Some(store) = &self.store {
            if let Err(e) = store
                .sticky_session_delete(&self.service_name, session_id)
                .await
            {
                warn!("Failed to delete session from distributed store: {}", e);
            }
        }
    }

    /// Get session count (for metrics)
    pub fn local_session_count(&self) -> usize {
        self.local_cache.len()
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
        let manager =
            StickySessionManager::new(&test_sticky_config(), test_servers(), "test-service")
                .unwrap();

        let session_id = manager.create_session(0);
        assert!(session_id.is_some());
        assert_eq!(manager.local_session_count(), 1);
    }

    #[test]
    fn test_sticky_session_lookup() {
        let manager =
            StickySessionManager::new(&test_sticky_config(), test_servers(), "test-service")
                .unwrap();

        let session_id = manager.create_session(1).unwrap();

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
        let manager =
            StickySessionManager::new(&test_sticky_config(), test_servers(), "test-service")
                .unwrap();

        let req = Request::builder().body(()).unwrap();

        let server_idx = manager.get_sticky_server(&req);
        assert_eq!(server_idx, None);
    }

    #[test]
    fn test_set_cookie_header() {
        let manager =
            StickySessionManager::new(&test_sticky_config(), test_servers(), "test-service")
                .unwrap();

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
        let manager =
            StickySessionManager::new(&test_sticky_config(), test_servers(), "test-service")
                .unwrap();

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
