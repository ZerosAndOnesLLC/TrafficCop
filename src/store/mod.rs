mod local;
mod valkey;

pub use local::LocalStore;
pub use valkey::ValkeyStore;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Result type for store operations
pub type StoreResult<T> = Result<T, StoreError>;

/// Store errors
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Operation timeout")]
    Timeout,

    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Store unavailable")]
    Unavailable,
}

/// Health status for a backend server
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: u64, // Unix timestamp millis
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true,
            last_check: 0,
            consecutive_failures: 0,
            last_error: None,
        }
    }
}

/// Node information for cluster membership
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub address: String,
    pub status: NodeStatus,
    pub active_connections: u64,
    pub last_heartbeat: u64, // Unix timestamp millis
    pub started_at: u64,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Active,
    Draining,
    Unhealthy,
}

/// Abstraction for distributed state storage
/// Implementations can be local (single-node) or distributed (Valkey/Redis)
#[async_trait]
pub trait Store: Send + Sync {
    // =========================================================================
    // Rate Limiting
    // =========================================================================

    /// Check if a request is allowed under rate limits
    /// Returns (allowed, remaining_tokens, reset_time_millis)
    async fn rate_limit_check(
        &self,
        key: &str,
        limit: u64,
        window_secs: u64,
    ) -> StoreResult<(bool, u64, u64)>;

    /// Get current rate limit state for an IP
    async fn rate_limit_remaining(&self, key: &str, limit: u64) -> StoreResult<u64>;

    // =========================================================================
    // Sticky Sessions
    // =========================================================================

    /// Get the server URL for a sticky session
    async fn sticky_session_get(&self, service: &str, session_id: &str) -> StoreResult<Option<String>>;

    /// Set a sticky session mapping
    async fn sticky_session_set(
        &self,
        service: &str,
        session_id: &str,
        server_url: &str,
        ttl: Duration,
    ) -> StoreResult<()>;

    /// Delete a sticky session
    async fn sticky_session_delete(&self, service: &str, session_id: &str) -> StoreResult<()>;

    // =========================================================================
    // Health Check State
    // =========================================================================

    /// Get health status for a backend server
    async fn health_get(&self, service: &str, server_url: &str) -> StoreResult<Option<HealthStatus>>;

    /// Set health status for a backend server
    async fn health_set(
        &self,
        service: &str,
        server_url: &str,
        status: &HealthStatus,
    ) -> StoreResult<()>;

    /// Get all health statuses for a service
    async fn health_get_all(&self, service: &str) -> StoreResult<HashMap<String, HealthStatus>>;

    // =========================================================================
    // Circuit Breaker
    // =========================================================================

    /// Increment failure count, returns new count
    async fn circuit_breaker_fail(&self, service: &str, window_secs: u64) -> StoreResult<u64>;

    /// Record a success (resets failures)
    async fn circuit_breaker_success(&self, service: &str) -> StoreResult<()>;

    /// Get current failure count
    async fn circuit_breaker_failures(&self, service: &str) -> StoreResult<u64>;

    // =========================================================================
    // Node Registry (Cluster Membership)
    // =========================================================================

    /// Register this node in the cluster
    async fn node_register(&self, info: &NodeInfo) -> StoreResult<()>;

    /// Update node heartbeat
    async fn node_heartbeat(&self, node_id: &str, connections: u64) -> StoreResult<()>;

    /// Set node status (e.g., for draining)
    async fn node_set_status(&self, node_id: &str, status: NodeStatus) -> StoreResult<()>;

    /// Get node info
    async fn node_get(&self, node_id: &str) -> StoreResult<Option<NodeInfo>>;

    /// Get all active nodes
    async fn node_list(&self) -> StoreResult<Vec<NodeInfo>>;

    /// Remove a node from the registry
    async fn node_deregister(&self, node_id: &str) -> StoreResult<()>;

    // =========================================================================
    // Configuration
    // =========================================================================

    /// Get current config version
    async fn config_version(&self) -> StoreResult<u64>;

    /// Get config content
    async fn config_get(&self) -> StoreResult<Option<String>>;

    /// Set config content (returns new version)
    async fn config_set(&self, content: &str) -> StoreResult<u64>;

    // =========================================================================
    // Pub/Sub for real-time updates
    // =========================================================================

    /// Subscribe to configuration changes
    /// Returns a channel that receives notifications
    async fn subscribe_config_changes(&self) -> StoreResult<tokio::sync::broadcast::Receiver<()>>;

    /// Subscribe to health status changes
    async fn subscribe_health_changes(&self) -> StoreResult<tokio::sync::broadcast::Receiver<(String, String, HealthStatus)>>;

    /// Subscribe to node drain events
    async fn subscribe_drain_events(&self) -> StoreResult<tokio::sync::broadcast::Receiver<String>>;

    // =========================================================================
    // ACME Challenges
    // =========================================================================

    /// Store an ACME challenge token
    async fn acme_challenge_set(&self, token: &str, auth: &str, ttl: Duration) -> StoreResult<()>;

    /// Get an ACME challenge response
    async fn acme_challenge_get(&self, token: &str) -> StoreResult<Option<String>>;

    /// Delete an ACME challenge
    async fn acme_challenge_delete(&self, token: &str) -> StoreResult<()>;

    // =========================================================================
    // Leader Election (for health check coordination)
    // =========================================================================

    /// Try to acquire leadership for a given task
    /// Returns true if this node is now the leader
    async fn leader_acquire(&self, task: &str, node_id: &str, ttl: Duration) -> StoreResult<bool>;

    /// Release leadership
    async fn leader_release(&self, task: &str, node_id: &str) -> StoreResult<()>;

    /// Check who is the current leader
    async fn leader_get(&self, task: &str) -> StoreResult<Option<String>>;

    // =========================================================================
    // Utilities
    // =========================================================================

    /// Check if the store is healthy/connected
    async fn health_check(&self) -> StoreResult<()>;

    /// Get store type name
    fn store_type(&self) -> &'static str;
}

/// Create a store from configuration
pub async fn create_store(config: &StoreConfig) -> StoreResult<Arc<dyn Store>> {
    match config {
        StoreConfig::Local => Ok(Arc::new(LocalStore::new())),
        StoreConfig::Valkey(valkey_config) => {
            let store = ValkeyStore::new(valkey_config).await?;
            Ok(Arc::new(store))
        }
    }
}

/// Store configuration (Traefik-compatible)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreConfig {
    Local,
    Valkey(ValkeyConfig),
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig::Local
    }
}

/// Valkey/Redis configuration (Traefik redis provider compatible)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValkeyConfig {
    /// Redis/Valkey endpoints (supports cluster mode)
    /// Format: "redis://host:port" or "rediss://host:port" for TLS
    pub endpoints: Vec<String>,

    /// Password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Username for authentication (Redis 6+ ACL)
    #[serde(default)]
    pub username: Option<String>,

    /// Database number (default 0)
    #[serde(default)]
    pub db: i64,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<ValkeyTlsConfig>,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// Key prefix for all keys
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,

    /// Connection timeout
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: crate::config::Duration,

    /// Operation timeout
    #[serde(default = "default_operation_timeout")]
    pub operation_timeout: crate::config::Duration,

    /// Sentinel configuration (optional)
    #[serde(default)]
    pub sentinel: Option<SentinelConfig>,
}

fn default_pool_size() -> u32 {
    10
}

fn default_key_prefix() -> String {
    "trafficcop".to_string()
}

fn default_connect_timeout() -> crate::config::Duration {
    crate::config::Duration::from_secs(5)
}

fn default_operation_timeout() -> crate::config::Duration {
    crate::config::Duration::from_secs(1)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ValkeyTlsConfig {
    #[serde(default)]
    pub ca: Option<String>,

    #[serde(default)]
    pub cert: Option<String>,

    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentinelConfig {
    /// Sentinel master name
    pub master_name: String,

    /// Sentinel endpoints
    pub endpoints: Vec<String>,

    /// Sentinel password
    #[serde(default)]
    pub password: Option<String>,
}

// Async trait is needed for async methods in traits
#[async_trait]
pub trait AsyncTrait: Send + Sync {}
