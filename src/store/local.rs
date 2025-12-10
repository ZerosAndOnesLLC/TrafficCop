use super::{
    HealthStatus, NodeInfo, NodeStatus, Store, StoreResult,
};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Local in-memory store for single-node deployments
/// All state is local to this process
pub struct LocalStore {
    // Rate limiting: key -> (count, window_start)
    rate_limits: DashMap<String, RateLimitEntry>,

    // Sticky sessions: service:session_id -> (server_url, expires_at)
    sticky_sessions: DashMap<String, StickyEntry>,

    // Health state: service:server_url -> HealthStatus
    health_state: DashMap<String, HealthStatus>,

    // Circuit breaker: service -> failure_count
    circuit_breakers: DashMap<String, CircuitBreakerEntry>,

    // Node registry (for local mode, just this node)
    nodes: DashMap<String, NodeInfo>,

    // Config storage
    config_content: RwLock<Option<String>>,
    config_version: AtomicU64,

    // ACME challenges
    acme_challenges: DashMap<String, AcmeEntry>,

    // Leader state (in local mode, this node is always leader)
    leaders: DashMap<String, LeaderEntry>,

    // Pub/sub channels
    config_tx: broadcast::Sender<()>,
    health_tx: broadcast::Sender<(String, String, HealthStatus)>,
    drain_tx: broadcast::Sender<String>,
}

struct RateLimitEntry {
    count: AtomicU64,
    window_start: Instant,
}

struct StickyEntry {
    server_url: String,
    expires_at: Instant,
}

struct CircuitBreakerEntry {
    failures: AtomicU64,
    window_start: Instant,
}

struct AcmeEntry {
    auth: String,
    expires_at: Instant,
}

struct LeaderEntry {
    node_id: String,
    expires_at: Instant,
}

impl LocalStore {
    pub fn new() -> Self {
        let (config_tx, _) = broadcast::channel(16);
        let (health_tx, _) = broadcast::channel(256);
        let (drain_tx, _) = broadcast::channel(16);

        Self {
            rate_limits: DashMap::new(),
            sticky_sessions: DashMap::new(),
            health_state: DashMap::new(),
            circuit_breakers: DashMap::new(),
            nodes: DashMap::new(),
            config_content: RwLock::new(None),
            config_version: AtomicU64::new(0),
            acme_challenges: DashMap::new(),
            leaders: DashMap::new(),
            config_tx,
            health_tx,
            drain_tx,
        }
    }

    fn current_time_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Cleanup expired entries (should be called periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean rate limits (older than 2 minutes)
        self.rate_limits
            .retain(|_, entry| now.duration_since(entry.window_start) < Duration::from_secs(120));

        // Clean sticky sessions
        self.sticky_sessions
            .retain(|_, entry| entry.expires_at > now);

        // Clean circuit breakers (older than 5 minutes)
        self.circuit_breakers
            .retain(|_, entry| now.duration_since(entry.window_start) < Duration::from_secs(300));

        // Clean ACME challenges
        self.acme_challenges
            .retain(|_, entry| entry.expires_at > now);

        // Clean expired leaders
        self.leaders.retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Store for LocalStore {
    // =========================================================================
    // Rate Limiting
    // =========================================================================

    async fn rate_limit_check(
        &self,
        key: &str,
        limit: u64,
        window_secs: u64,
    ) -> StoreResult<(bool, u64, u64)> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(window_secs);

        let entry = self
            .rate_limits
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry {
                count: AtomicU64::new(0),
                window_start: now,
            });

        // Check if we're in a new window
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= window_duration {
            // Reset for new window
            entry.count.store(1, Ordering::Relaxed);
            // Note: Can't update window_start through DashMap entry
            // This is a limitation of local store, but works for single-threaded access
            let reset_time = Self::current_time_millis() + (window_secs * 1000);
            return Ok((true, limit.saturating_sub(1), reset_time));
        }

        let current = entry.count.fetch_add(1, Ordering::Relaxed);
        let reset_time =
            Self::current_time_millis() + (window_duration - elapsed).as_millis() as u64;

        if current < limit {
            Ok((true, limit.saturating_sub(current + 1), reset_time))
        } else {
            // Undo the increment since we're rejecting
            entry.count.fetch_sub(1, Ordering::Relaxed);
            Ok((false, 0, reset_time))
        }
    }

    async fn rate_limit_remaining(&self, key: &str, limit: u64) -> StoreResult<u64> {
        match self.rate_limits.get(key) {
            Some(entry) => {
                let count = entry.count.load(Ordering::Relaxed);
                Ok(limit.saturating_sub(count))
            }
            None => Ok(limit),
        }
    }

    // =========================================================================
    // Sticky Sessions
    // =========================================================================

    async fn sticky_session_get(
        &self,
        service: &str,
        session_id: &str,
    ) -> StoreResult<Option<String>> {
        let key = format!("{}:{}", service, session_id);
        match self.sticky_sessions.get(&key) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.server_url.clone())),
            _ => Ok(None),
        }
    }

    async fn sticky_session_set(
        &self,
        service: &str,
        session_id: &str,
        server_url: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        let key = format!("{}:{}", service, session_id);
        self.sticky_sessions.insert(
            key,
            StickyEntry {
                server_url: server_url.to_string(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn sticky_session_delete(&self, service: &str, session_id: &str) -> StoreResult<()> {
        let key = format!("{}:{}", service, session_id);
        self.sticky_sessions.remove(&key);
        Ok(())
    }

    // =========================================================================
    // Health Check State
    // =========================================================================

    async fn health_get(
        &self,
        service: &str,
        server_url: &str,
    ) -> StoreResult<Option<HealthStatus>> {
        let key = format!("{}:{}", service, server_url);
        Ok(self.health_state.get(&key).map(|e| e.clone()))
    }

    async fn health_set(
        &self,
        service: &str,
        server_url: &str,
        status: &HealthStatus,
    ) -> StoreResult<()> {
        let key = format!("{}:{}", service, server_url);
        self.health_state.insert(key, status.clone());

        // Notify subscribers
        let _ = self
            .health_tx
            .send((service.to_string(), server_url.to_string(), status.clone()));

        Ok(())
    }

    async fn health_get_all(&self, service: &str) -> StoreResult<HashMap<String, HealthStatus>> {
        let prefix = format!("{}:", service);
        let mut result = HashMap::new();

        for entry in self.health_state.iter() {
            if entry.key().starts_with(&prefix) {
                let server_url = entry.key().strip_prefix(&prefix).unwrap_or(entry.key());
                result.insert(server_url.to_string(), entry.value().clone());
            }
        }

        Ok(result)
    }

    // =========================================================================
    // Circuit Breaker
    // =========================================================================

    async fn circuit_breaker_fail(&self, service: &str, window_secs: u64) -> StoreResult<u64> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(window_secs);

        let entry = self
            .circuit_breakers
            .entry(service.to_string())
            .or_insert_with(|| CircuitBreakerEntry {
                failures: AtomicU64::new(0),
                window_start: now,
            });

        // Check if we're in a new window
        if now.duration_since(entry.window_start) >= window_duration {
            entry.failures.store(1, Ordering::Relaxed);
            return Ok(1);
        }

        let new_count = entry.failures.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(new_count)
    }

    async fn circuit_breaker_success(&self, service: &str) -> StoreResult<()> {
        self.circuit_breakers.remove(service);
        Ok(())
    }

    async fn circuit_breaker_failures(&self, service: &str) -> StoreResult<u64> {
        match self.circuit_breakers.get(service) {
            Some(entry) => Ok(entry.failures.load(Ordering::Relaxed)),
            None => Ok(0),
        }
    }

    // =========================================================================
    // Node Registry
    // =========================================================================

    async fn node_register(&self, info: &NodeInfo) -> StoreResult<()> {
        self.nodes.insert(info.node_id.clone(), info.clone());
        Ok(())
    }

    async fn node_heartbeat(&self, node_id: &str, connections: u64) -> StoreResult<()> {
        if let Some(mut entry) = self.nodes.get_mut(node_id) {
            entry.last_heartbeat = Self::current_time_millis();
            entry.active_connections = connections;
        }
        Ok(())
    }

    async fn node_set_status(&self, node_id: &str, status: NodeStatus) -> StoreResult<()> {
        if let Some(mut entry) = self.nodes.get_mut(node_id) {
            entry.status = status;

            // Notify about drain events
            if status == NodeStatus::Draining {
                let _ = self.drain_tx.send(node_id.to_string());
            }
        }
        Ok(())
    }

    async fn node_get(&self, node_id: &str) -> StoreResult<Option<NodeInfo>> {
        Ok(self.nodes.get(node_id).map(|e| e.clone()))
    }

    async fn node_list(&self) -> StoreResult<Vec<NodeInfo>> {
        Ok(self.nodes.iter().map(|e| e.value().clone()).collect())
    }

    async fn node_deregister(&self, node_id: &str) -> StoreResult<()> {
        self.nodes.remove(node_id);
        Ok(())
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    async fn config_version(&self) -> StoreResult<u64> {
        Ok(self.config_version.load(Ordering::Relaxed))
    }

    async fn config_get(&self) -> StoreResult<Option<String>> {
        Ok(self.config_content.read().clone())
    }

    async fn config_set(&self, content: &str) -> StoreResult<u64> {
        let new_version = self.config_version.fetch_add(1, Ordering::Relaxed) + 1;
        *self.config_content.write() = Some(content.to_string());

        // Notify subscribers
        let _ = self.config_tx.send(());

        Ok(new_version)
    }

    // =========================================================================
    // Pub/Sub
    // =========================================================================

    async fn subscribe_config_changes(&self) -> StoreResult<broadcast::Receiver<()>> {
        Ok(self.config_tx.subscribe())
    }

    async fn subscribe_health_changes(
        &self,
    ) -> StoreResult<broadcast::Receiver<(String, String, HealthStatus)>> {
        Ok(self.health_tx.subscribe())
    }

    async fn subscribe_drain_events(&self) -> StoreResult<broadcast::Receiver<String>> {
        Ok(self.drain_tx.subscribe())
    }

    // =========================================================================
    // ACME Challenges
    // =========================================================================

    async fn acme_challenge_set(&self, token: &str, auth: &str, ttl: Duration) -> StoreResult<()> {
        self.acme_challenges.insert(
            token.to_string(),
            AcmeEntry {
                auth: auth.to_string(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn acme_challenge_get(&self, token: &str) -> StoreResult<Option<String>> {
        match self.acme_challenges.get(token) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.auth.clone())),
            _ => Ok(None),
        }
    }

    async fn acme_challenge_delete(&self, token: &str) -> StoreResult<()> {
        self.acme_challenges.remove(token);
        Ok(())
    }

    // =========================================================================
    // Leader Election
    // =========================================================================

    async fn leader_acquire(&self, task: &str, node_id: &str, ttl: Duration) -> StoreResult<bool> {
        let now = Instant::now();

        // Check if there's an existing leader
        if let Some(entry) = self.leaders.get(task) {
            if entry.expires_at > now && entry.node_id != node_id {
                return Ok(false); // Someone else is leader
            }
        }

        // Acquire leadership
        self.leaders.insert(
            task.to_string(),
            LeaderEntry {
                node_id: node_id.to_string(),
                expires_at: now + ttl,
            },
        );

        Ok(true)
    }

    async fn leader_release(&self, task: &str, node_id: &str) -> StoreResult<()> {
        if let Some(entry) = self.leaders.get(task) {
            if entry.node_id == node_id {
                drop(entry);
                self.leaders.remove(task);
            }
        }
        Ok(())
    }

    async fn leader_get(&self, task: &str) -> StoreResult<Option<String>> {
        match self.leaders.get(task) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.node_id.clone())),
            _ => Ok(None),
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    async fn health_check(&self) -> StoreResult<()> {
        // Local store is always healthy
        Ok(())
    }

    fn store_type(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit() {
        let store = LocalStore::new();

        // First request should be allowed
        let (allowed, remaining, _) = store.rate_limit_check("test_ip", 5, 60).await.unwrap();
        assert!(allowed);
        assert_eq!(remaining, 4);

        // Use up the limit
        for _ in 0..4 {
            store.rate_limit_check("test_ip", 5, 60).await.unwrap();
        }

        // Should be blocked
        let (allowed, remaining, _) = store.rate_limit_check("test_ip", 5, 60).await.unwrap();
        assert!(!allowed);
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn test_sticky_session() {
        let store = LocalStore::new();

        // No session initially
        let result = store.sticky_session_get("api", "session123").await.unwrap();
        assert!(result.is_none());

        // Set session
        store
            .sticky_session_set("api", "session123", "http://server1:8080", Duration::from_secs(3600))
            .await
            .unwrap();

        // Should get it back
        let result = store.sticky_session_get("api", "session123").await.unwrap();
        assert_eq!(result, Some("http://server1:8080".to_string()));
    }

    #[tokio::test]
    async fn test_health_state() {
        let store = LocalStore::new();

        let status = HealthStatus {
            healthy: true,
            last_check: LocalStore::current_time_millis(),
            consecutive_failures: 0,
            last_error: None,
        };

        store
            .health_set("api", "http://server1:8080", &status)
            .await
            .unwrap();

        let result = store
            .health_get("api", "http://server1:8080")
            .await
            .unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().healthy);
    }

    #[tokio::test]
    async fn test_leader_election() {
        let store = LocalStore::new();

        // Node 1 acquires leadership
        let acquired = store
            .leader_acquire("health_check", "node1", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(acquired);

        // Node 2 cannot acquire
        let acquired = store
            .leader_acquire("health_check", "node2", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(!acquired);

        // Node 1 releases
        store.leader_release("health_check", "node1").await.unwrap();

        // Now node 2 can acquire
        let acquired = store
            .leader_acquire("health_check", "node2", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(acquired);
    }
}
