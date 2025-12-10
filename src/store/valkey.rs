use super::{
    HealthStatus, NodeInfo, NodeStatus, Store, StoreError, StoreResult,
    ValkeyConfig,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client, Script};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Lua script for sliding window rate limiting
const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Remove old entries outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window * 1000)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add new entry
    redis.call('ZADD', key, now, now .. '-' .. math.random(1000000))
    redis.call('PEXPIRE', key, window * 1000)
    return {1, limit - count - 1, now + window * 1000}
else
    return {0, 0, now + window * 1000}
end
"#;

/// Lua script for leader election with SET NX EX
const LEADER_ACQUIRE_SCRIPT: &str = r#"
local key = KEYS[1]
local node_id = ARGV[1]
local ttl = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current == false or current == node_id then
    redis.call('SET', key, node_id, 'EX', ttl)
    return 1
else
    return 0
end
"#;

/// Lua script for leader release (only if we're the leader)
const LEADER_RELEASE_SCRIPT: &str = r#"
local key = KEYS[1]
local node_id = ARGV[1]

local current = redis.call('GET', key)
if current == node_id then
    redis.call('DEL', key)
    return 1
else
    return 0
end
"#;

/// Distributed store using Valkey/Redis
pub struct ValkeyStore {
    conn: ConnectionManager,
    key_prefix: String,
    #[allow(dead_code)]
    config: ValkeyConfig,

    // Pub/sub channels
    config_tx: broadcast::Sender<()>,
    health_tx: broadcast::Sender<(String, String, HealthStatus)>,
    drain_tx: broadcast::Sender<String>,

    // Lua scripts (precompiled)
    rate_limit_script: Script,
    leader_acquire_script: Script,
    leader_release_script: Script,

    // Background task handles
    subscriber_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
}

impl ValkeyStore {
    /// Create a new Valkey store
    pub async fn new(config: &ValkeyConfig) -> StoreResult<Self> {
        let client = Self::create_client(config)?;

        // Create connection manager (handles reconnection automatically)
        let conn = ConnectionManager::new(client.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        let (config_tx, _) = broadcast::channel(16);
        let (health_tx, _) = broadcast::channel(256);
        let (drain_tx, _) = broadcast::channel(16);

        let store = Self {
            conn,
            key_prefix: config.key_prefix.clone(),
            config: config.clone(),
            config_tx,
            health_tx,
            drain_tx,
            rate_limit_script: Script::new(RATE_LIMIT_SCRIPT),
            leader_acquire_script: Script::new(LEADER_ACQUIRE_SCRIPT),
            leader_release_script: Script::new(LEADER_RELEASE_SCRIPT),
            subscriber_handle: RwLock::new(None),
        };

        // Start pub/sub listener
        store.start_pubsub_listener(client).await?;

        info!(
            "Connected to Valkey at {:?} with prefix '{}'",
            config.endpoints, config.key_prefix
        );

        Ok(store)
    }

    /// Create Redis client with appropriate configuration (including TLS)
    fn create_client(config: &ValkeyConfig) -> StoreResult<Client> {
        let endpoint = config
            .endpoints
            .first()
            .ok_or_else(|| StoreError::Connection("No endpoints provided".to_string()))?;

        // Build connection URL with authentication
        let mut url = endpoint.clone();

        // Handle authentication in URL if not already present
        if !url.contains('@') {
            if let (Some(user), Some(pass)) = (&config.username, &config.password) {
                // Insert auth into URL: redis://user:pass@host:port
                if let Some(pos) = url.find("://") {
                    let (scheme, rest) = url.split_at(pos + 3);
                    url = format!("{}{}:{}@{}", scheme, user, pass, rest);
                }
            } else if let Some(pass) = &config.password {
                // Just password, no username
                if let Some(pos) = url.find("://") {
                    let (scheme, rest) = url.split_at(pos + 3);
                    url = format!("{}:{}@{}", scheme, pass, rest);
                }
            }
        }

        // Add database number if not 0
        if config.db != 0 && !url.contains('/') {
            url = format!("{}/{}", url, config.db);
        }

        // Parse and build client
        let client = Client::open(url.as_str())
            .map_err(|e| StoreError::Connection(format!("Failed to create client: {}", e)))?;

        Ok(client)
    }

    /// Start the pub/sub listener for real-time updates
    async fn start_pubsub_listener(&self, client: Client) -> StoreResult<()> {
        let config_tx = self.config_tx.clone();
        let health_tx = self.health_tx.clone();
        let drain_tx = self.drain_tx.clone();
        let key_prefix = self.key_prefix.clone();

        let handle = tokio::spawn(async move {
            loop {
                match Self::run_pubsub_loop(
                    &client,
                    &key_prefix,
                    &config_tx,
                    &health_tx,
                    &drain_tx,
                )
                .await
                {
                    Ok(()) => {
                        debug!("Pub/sub loop ended normally");
                        break;
                    }
                    Err(e) => {
                        error!("Pub/sub error: {}, reconnecting in 1s", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        *self.subscriber_handle.write() = Some(handle);
        Ok(())
    }

    async fn run_pubsub_loop(
        client: &Client,
        key_prefix: &str,
        config_tx: &broadcast::Sender<()>,
        health_tx: &broadcast::Sender<(String, String, HealthStatus)>,
        drain_tx: &broadcast::Sender<String>,
    ) -> StoreResult<()> {
        let mut pubsub = client
            .get_async_pubsub()
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Subscribe to channels
        let config_channel = format!("{}:events:config_change", key_prefix);
        let health_channel = format!("{}:events:health_change", key_prefix);
        let drain_channel = format!("{}:events:node_drain", key_prefix);

        pubsub
            .subscribe(&config_channel)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;
        pubsub
            .subscribe(&health_channel)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;
        pubsub
            .subscribe(&drain_channel)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        debug!(
            "Subscribed to channels: {}, {}, {}",
            config_channel, health_channel, drain_channel
        );

        // Process messages
        let mut msg_stream = pubsub.into_on_message();

        use futures::StreamExt;
        while let Some(msg) = msg_stream.next().await {
            let channel: String = msg.get_channel_name().to_string();
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to get message payload: {}", e);
                    continue;
                }
            };

            if channel == config_channel {
                debug!("Config change notification received");
                let _ = config_tx.send(());
            } else if channel == health_channel {
                // Parse health change: "service:server_url:json"
                if let Some((service, rest)) = payload.split_once(':') {
                    if let Some((server_url, json)) = rest.split_once(':') {
                        if let Ok(status) = serde_json::from_str::<HealthStatus>(json) {
                            let _ = health_tx.send((
                                service.to_string(),
                                server_url.to_string(),
                                status,
                            ));
                        }
                    }
                }
            } else if channel == drain_channel {
                debug!("Drain event received for node: {}", payload);
                let _ = drain_tx.send(payload);
            }
        }

        Ok(())
    }

    /// Build a key with the prefix
    #[inline]
    fn key(&self, parts: &[&str]) -> String {
        let mut key = self.key_prefix.clone();
        for part in parts {
            key.push(':');
            key.push_str(part);
        }
        key
    }

    /// Get current time in milliseconds
    fn current_time_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[async_trait]
impl Store for ValkeyStore {
    // =========================================================================
    // Rate Limiting (Sliding Window with Lua)
    // =========================================================================

    async fn rate_limit_check(
        &self,
        key: &str,
        limit: u64,
        window_secs: u64,
    ) -> StoreResult<(bool, u64, u64)> {
        let full_key = self.key(&["ratelimit", key]);
        let now = Self::current_time_millis();

        let result: Vec<i64> = self
            .rate_limit_script
            .key(&full_key)
            .arg(limit)
            .arg(window_secs)
            .arg(now)
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        if result.len() >= 3 {
            let allowed = result[0] == 1;
            let remaining = result[1] as u64;
            let reset_time = result[2] as u64;
            Ok((allowed, remaining, reset_time))
        } else {
            Err(StoreError::Serialization(
                "Invalid rate limit response".to_string(),
            ))
        }
    }

    async fn rate_limit_remaining(&self, key: &str, limit: u64) -> StoreResult<u64> {
        let full_key = self.key(&["ratelimit", key]);

        let count: u64 = self
            .conn
            .clone()
            .zcard(&full_key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(limit.saturating_sub(count))
    }

    // =========================================================================
    // Sticky Sessions (Hash with TTL)
    // =========================================================================

    async fn sticky_session_get(
        &self,
        service: &str,
        session_id: &str,
    ) -> StoreResult<Option<String>> {
        let key = self.key(&["sticky", service, session_id]);

        let result: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(result)
    }

    async fn sticky_session_set(
        &self,
        service: &str,
        session_id: &str,
        server_url: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        let key = self.key(&["sticky", service, session_id]);

        self.conn
            .clone()
            .set_ex::<_, _, ()>(&key, server_url, ttl.as_secs())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn sticky_session_delete(&self, service: &str, session_id: &str) -> StoreResult<()> {
        let key = self.key(&["sticky", service, session_id]);

        self.conn
            .clone()
            .del::<_, ()>(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

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
        let key = self.key(&["health", service, server_url]);

        let result: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        match result {
            Some(json) => {
                let status: HealthStatus = serde_json::from_str(&json)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    async fn health_set(
        &self,
        service: &str,
        server_url: &str,
        status: &HealthStatus,
    ) -> StoreResult<()> {
        let key = self.key(&["health", service, server_url]);
        let json = serde_json::to_string(status)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        // Set with 5 minute TTL (health checks should refresh)
        self.conn
            .clone()
            .set_ex::<_, _, ()>(&key, &json, 300)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Publish health change event
        let channel = self.key(&["events", "health_change"]);
        let payload = format!("{}:{}:{}", service, server_url, json);
        let _: () = self
            .conn
            .clone()
            .publish(&channel, &payload)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn health_get_all(&self, service: &str) -> StoreResult<HashMap<String, HealthStatus>> {
        let pattern = self.key(&["health", service, "*"]);

        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut self.conn.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        let mut result = HashMap::new();

        for key in keys {
            let json: Option<String> = self
                .conn
                .clone()
                .get(&key)
                .await
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            if let Some(json) = json {
                if let Ok(status) = serde_json::from_str::<HealthStatus>(&json) {
                    // Extract server_url from key
                    let prefix = self.key(&["health", service, ""]);
                    if let Some(server_url) = key.strip_prefix(&prefix) {
                        result.insert(server_url.to_string(), status);
                    }
                }
            }
        }

        Ok(result)
    }

    // =========================================================================
    // Circuit Breaker
    // =========================================================================

    async fn circuit_breaker_fail(&self, service: &str, window_secs: u64) -> StoreResult<u64> {
        let key = self.key(&["circuit", service]);

        // Increment and set expiry
        let count: u64 = self
            .conn
            .clone()
            .incr(&key, 1u64)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Set expiry on first failure
        if count == 1 {
            self.conn
                .clone()
                .expire::<_, ()>(&key, window_secs as i64)
                .await
                .map_err(|e| StoreError::Connection(e.to_string()))?;
        }

        Ok(count)
    }

    async fn circuit_breaker_success(&self, service: &str) -> StoreResult<()> {
        let key = self.key(&["circuit", service]);

        self.conn
            .clone()
            .del::<_, ()>(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn circuit_breaker_failures(&self, service: &str) -> StoreResult<u64> {
        let key = self.key(&["circuit", service]);

        let count: Option<u64> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(count.unwrap_or(0))
    }

    // =========================================================================
    // Node Registry
    // =========================================================================

    async fn node_register(&self, info: &NodeInfo) -> StoreResult<()> {
        let key = self.key(&["nodes", &info.node_id]);
        let json =
            serde_json::to_string(info).map_err(|e| StoreError::Serialization(e.to_string()))?;

        // Set with 60 second TTL (heartbeat should refresh)
        self.conn
            .clone()
            .set_ex::<_, _, ()>(&key, &json, 60)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Add to nodes set
        let set_key = self.key(&["nodes_set"]);
        self.conn
            .clone()
            .sadd::<_, _, ()>(&set_key, &info.node_id)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn node_heartbeat(&self, node_id: &str, connections: u64) -> StoreResult<()> {
        let key = self.key(&["nodes", node_id]);

        // Get existing node info
        let json: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        if let Some(json) = json {
            let mut info: NodeInfo = serde_json::from_str(&json)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            info.last_heartbeat = Self::current_time_millis();
            info.active_connections = connections;

            let new_json = serde_json::to_string(&info)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            self.conn
                .clone()
                .set_ex::<_, _, ()>(&key, &new_json, 60)
                .await
                .map_err(|e| StoreError::Connection(e.to_string()))?;
        }

        Ok(())
    }

    async fn node_set_status(&self, node_id: &str, status: NodeStatus) -> StoreResult<()> {
        let key = self.key(&["nodes", node_id]);

        let json: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        if let Some(json) = json {
            let mut info: NodeInfo = serde_json::from_str(&json)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            info.status = status;
            info.last_heartbeat = Self::current_time_millis();

            let new_json = serde_json::to_string(&info)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            self.conn
                .clone()
                .set_ex::<_, _, ()>(&key, &new_json, 60)
                .await
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            // Publish drain event if draining
            if status == NodeStatus::Draining {
                let channel = self.key(&["events", "node_drain"]);
                let _: () = self
                    .conn
                    .clone()
                    .publish(&channel, node_id)
                    .await
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn node_get(&self, node_id: &str) -> StoreResult<Option<NodeInfo>> {
        let key = self.key(&["nodes", node_id]);

        let json: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        match json {
            Some(json) => {
                let info: NodeInfo = serde_json::from_str(&json)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    async fn node_list(&self) -> StoreResult<Vec<NodeInfo>> {
        let set_key = self.key(&["nodes_set"]);

        let node_ids: Vec<String> = self
            .conn
            .clone()
            .smembers(&set_key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        let mut nodes = Vec::new();

        for node_id in node_ids {
            if let Some(info) = self.node_get(&node_id).await? {
                nodes.push(info);
            } else {
                // Remove stale node from set
                self.conn
                    .clone()
                    .srem::<_, _, ()>(&set_key, &node_id)
                    .await
                    .ok();
            }
        }

        Ok(nodes)
    }

    async fn node_deregister(&self, node_id: &str) -> StoreResult<()> {
        let key = self.key(&["nodes", node_id]);
        let set_key = self.key(&["nodes_set"]);

        self.conn
            .clone()
            .del::<_, ()>(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        self.conn
            .clone()
            .srem::<_, _, ()>(&set_key, node_id)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    async fn config_version(&self) -> StoreResult<u64> {
        let key = self.key(&["config", "version"]);

        let version: Option<u64> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(version.unwrap_or(0))
    }

    async fn config_get(&self) -> StoreResult<Option<String>> {
        let key = self.key(&["config", "current"]);

        let content: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(content)
    }

    async fn config_set(&self, content: &str) -> StoreResult<u64> {
        let version_key = self.key(&["config", "version"]);
        let content_key = self.key(&["config", "current"]);

        // Increment version
        let new_version: u64 = self
            .conn
            .clone()
            .incr(&version_key, 1u64)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Set content
        self.conn
            .clone()
            .set::<_, _, ()>(&content_key, content)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Publish change notification
        let channel = self.key(&["events", "config_change"]);
        let _: () = self
            .conn
            .clone()
            .publish(&channel, new_version.to_string())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

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
        let key = self.key(&["acme", token]);

        self.conn
            .clone()
            .set_ex::<_, _, ()>(&key, auth, ttl.as_secs())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn acme_challenge_get(&self, token: &str) -> StoreResult<Option<String>> {
        let key = self.key(&["acme", token]);

        let auth: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(auth)
    }

    async fn acme_challenge_delete(&self, token: &str) -> StoreResult<()> {
        let key = self.key(&["acme", token]);

        self.conn
            .clone()
            .del::<_, ()>(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    // =========================================================================
    // Leader Election
    // =========================================================================

    async fn leader_acquire(&self, task: &str, node_id: &str, ttl: Duration) -> StoreResult<bool> {
        let key = self.key(&["leader", task]);

        let result: i64 = self
            .leader_acquire_script
            .key(&key)
            .arg(node_id)
            .arg(ttl.as_secs())
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(result == 1)
    }

    async fn leader_release(&self, task: &str, node_id: &str) -> StoreResult<()> {
        let key = self.key(&["leader", task]);

        let _: i64 = self
            .leader_release_script
            .key(&key)
            .arg(node_id)
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    async fn leader_get(&self, task: &str) -> StoreResult<Option<String>> {
        let key = self.key(&["leader", task]);

        let leader: Option<String> = self
            .conn
            .clone()
            .get(&key)
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(leader)
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    async fn health_check(&self) -> StoreResult<()> {
        let _: String = redis::cmd("PING")
            .query_async(&mut self.conn.clone())
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(())
    }

    fn store_type(&self) -> &'static str {
        "valkey"
    }
}

impl Drop for ValkeyStore {
    fn drop(&mut self) {
        if let Some(handle) = self.subscriber_handle.write().take() {
            handle.abort();
        }
    }
}
