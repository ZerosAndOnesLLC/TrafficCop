use crate::config::ClusterConfig;
use crate::store::{NodeInfo, NodeStatus, Store};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Cluster manager handles node registration, heartbeats, and coordination
pub struct ClusterManager {
    node_id: String,
    advertise_address: String,
    store: Arc<dyn Store>,
    config: ClusterConfig,
    is_leader: AtomicBool,
    is_draining: AtomicBool,
    active_connections: RwLock<u64>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl ClusterManager {
    /// Create a new cluster manager
    pub async fn new(
        config: ClusterConfig,
        store: Arc<dyn Store>,
    ) -> anyhow::Result<Arc<Self>> {
        // Generate or use provided node ID
        let node_id = config.node_id.clone().unwrap_or_else(|| {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let uuid = uuid::Uuid::new_v4();
            format!("{}-{}", hostname, &uuid.to_string()[..8])
        });

        // Get advertise address
        let advertise_address = config.advertise_address.clone().unwrap_or_else(|| {
            format!("{}:8080", hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "127.0.0.1".to_string()))
        });

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        let manager = Arc::new(Self {
            node_id,
            advertise_address,
            store,
            config,
            is_leader: AtomicBool::new(false),
            is_draining: AtomicBool::new(false),
            active_connections: RwLock::new(0),
            shutdown_tx,
        });

        // Register this node
        manager.register_node().await?;

        // Start background tasks
        manager.clone().start_heartbeat_task();
        manager.clone().start_leader_election_task();
        manager.clone().start_drain_listener();

        info!(
            "Cluster manager started: node_id={}, advertise={}",
            manager.node_id, manager.advertise_address
        );

        Ok(manager)
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Check if this node is the leader for health checks
    pub fn is_health_check_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// Check if this node is draining
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::Relaxed)
    }

    /// Get the store
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Update active connection count
    pub async fn update_connections(&self, count: u64) {
        *self.active_connections.write().await = count;
    }

    /// Start draining this node
    pub async fn start_drain(&self) -> anyhow::Result<()> {
        info!("Starting node drain: {}", self.node_id);
        self.is_draining.store(true, Ordering::Release);

        // Update status in store
        self.store
            .node_set_status(&self.node_id, NodeStatus::Draining)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to set drain status: {}", e))?;

        Ok(())
    }

    /// Shutdown the cluster manager
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        info!("Shutting down cluster manager: {}", self.node_id);

        // Signal shutdown
        let _ = self.shutdown_tx.send(());

        // Release leadership if held
        if self.is_leader.load(Ordering::Relaxed) {
            self.store
                .leader_release("health_check", &self.node_id)
                .await
                .ok();
        }

        // Deregister node
        self.store.node_deregister(&self.node_id).await.ok();

        Ok(())
    }

    /// Register this node in the cluster
    async fn register_node(&self) -> anyhow::Result<()> {
        let info = NodeInfo {
            node_id: self.node_id.clone(),
            address: self.advertise_address.clone(),
            status: NodeStatus::Active,
            active_connections: 0,
            last_heartbeat: current_time_millis(),
            started_at: current_time_millis(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        self.store
            .node_register(&info)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to register node: {}", e))?;

        Ok(())
    }

    /// Start the heartbeat task
    fn start_heartbeat_task(self: Arc<Self>) {
        let interval = self.config.heartbeat_interval.as_std();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let connections = *self.active_connections.read().await;
                        if let Err(e) = self.store.node_heartbeat(&self.node_id, connections).await {
                            warn!("Failed to send heartbeat: {}", e);
                        } else {
                            debug!("Heartbeat sent: connections={}", connections);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Start the leader election task
    fn start_leader_election_task(self: Arc<Self>) {
        let ttl = self.config.leader_ttl.as_std();
        let election_interval = ttl / 3; // Try to acquire/renew at 1/3 of TTL
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(election_interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        match self.store.leader_acquire("health_check", &self.node_id, ttl).await {
                            Ok(acquired) => {
                                let was_leader = self.is_leader.swap(acquired, Ordering::Relaxed);
                                if acquired && !was_leader {
                                    info!("Acquired health check leadership");
                                } else if !acquired && was_leader {
                                    info!("Lost health check leadership");
                                }
                            }
                            Err(e) => {
                                warn!("Leader election failed: {}", e);
                                self.is_leader.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Leader election task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Start listening for drain events from other nodes
    fn start_drain_listener(self: Arc<Self>) {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let drain_rx = match self.store.subscribe_drain_events().await {
                Ok(rx) => rx,
                Err(e) => {
                    error!("Failed to subscribe to drain events: {}", e);
                    return;
                }
            };

            let mut drain_rx = drain_rx;

            loop {
                tokio::select! {
                    result = drain_rx.recv() => {
                        match result {
                            Ok(node_id) => {
                                if node_id != self.node_id {
                                    info!("Node {} is draining", node_id);
                                    // Could trigger re-balancing or other actions here
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                // Missed some messages, continue
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Drain listener task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Get list of active nodes in the cluster
    pub async fn get_active_nodes(&self) -> anyhow::Result<Vec<NodeInfo>> {
        let nodes = self
            .store
            .node_list()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list nodes: {}", e))?;

        let now = current_time_millis();
        let timeout_ms = self.config.node_timeout.as_std().as_millis() as u64;

        // Filter out stale nodes
        Ok(nodes
            .into_iter()
            .filter(|n| {
                n.status != NodeStatus::Unhealthy
                    && (now - n.last_heartbeat) < timeout_ms
            })
            .collect())
    }

    /// Get cluster statistics
    pub async fn get_cluster_stats(&self) -> ClusterStats {
        let nodes = self.get_active_nodes().await.unwrap_or_default();

        let total_connections: u64 = nodes.iter().map(|n| n.active_connections).sum();
        let active_count = nodes.iter().filter(|n| n.status == NodeStatus::Active).count();
        let draining_count = nodes.iter().filter(|n| n.status == NodeStatus::Draining).count();

        ClusterStats {
            node_count: nodes.len(),
            active_nodes: active_count,
            draining_nodes: draining_count,
            total_connections,
            this_node_id: self.node_id.clone(),
            this_node_is_leader: self.is_leader.load(Ordering::Relaxed),
            this_node_is_draining: self.is_draining.load(Ordering::Relaxed),
        }
    }
}

/// Cluster statistics
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterStats {
    pub node_count: usize,
    pub active_nodes: usize,
    pub draining_nodes: usize,
    pub total_connections: u64,
    pub this_node_id: String,
    pub this_node_is_leader: bool,
    pub this_node_is_draining: bool,
}

fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
