use crate::config::HealthCheck;
use crate::store::{HealthStatus as StoreHealthStatus, Store};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

/// Distributed health checker that coordinates health checks across the cluster
///
/// When in HA mode:
/// - Only the leader node performs active health checks
/// - Health status is stored in the distributed store
/// - All nodes read health status from the store
/// - Leader election ensures only one node is checking at a time
pub struct DistributedHealthChecker {
    service_name: String,
    server_url: String,
    config: HealthCheck,
    store: Arc<dyn Store>,
    is_leader: Arc<AtomicBool>,
    #[allow(dead_code)]
    node_id: String,
    client: Client<HttpConnector, http_body_util::Empty<Bytes>>,
}

impl DistributedHealthChecker {
    /// Create a new distributed health checker
    pub fn new(
        service_name: String,
        server_url: String,
        config: HealthCheck,
        store: Arc<dyn Store>,
        is_leader: Arc<AtomicBool>,
        node_id: String,
    ) -> Self {
        let connector = HttpConnector::new();
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .build(connector);

        Self {
            service_name,
            server_url,
            config,
            store,
            is_leader,
            node_id,
            client,
        }
    }

    /// Start the health check loop
    pub async fn start(self) {
        let interval_duration = self.config.interval.as_std();
        let check_timeout = self.config.timeout.as_std();
        let healthy_threshold = 2u32;
        let unhealthy_threshold = 3u32;

        let mut ticker = interval(interval_duration);
        let mut local_consecutive_successes = 0u32;
        let mut local_consecutive_failures = 0u32;
        let mut current_health = true;

        loop {
            ticker.tick().await;

            // Only perform health check if we're the leader
            if !self.is_leader.load(Ordering::Relaxed) {
                // Not leader, just read health status from store
                match self.store.health_get(&self.service_name, &self.server_url).await {
                    Ok(Some(status)) => {
                        current_health = status.healthy;
                        debug!(
                            "Read health status for {} from store: healthy={}",
                            self.server_url, status.healthy
                        );
                    }
                    Ok(None) => {
                        // No status in store, assume healthy
                        current_health = true;
                    }
                    Err(e) => {
                        warn!("Failed to read health status from store: {}", e);
                    }
                }
                continue;
            }

            // We're the leader, perform the health check
            let result = timeout(check_timeout, self.perform_http_check()).await;

            match result {
                Ok(Ok(())) => {
                    local_consecutive_successes += 1;
                    local_consecutive_failures = 0;

                    if !current_health && local_consecutive_successes >= healthy_threshold {
                        current_health = true;
                        info!("Server {} is now healthy", self.server_url);
                    }
                }
                Ok(Err(e)) => {
                    local_consecutive_failures += 1;
                    local_consecutive_successes = 0;

                    if current_health && local_consecutive_failures >= unhealthy_threshold {
                        current_health = false;
                        warn!("Server {} is now unhealthy: {}", self.server_url, e);
                    }
                }
                Err(_) => {
                    local_consecutive_failures += 1;
                    local_consecutive_successes = 0;

                    if current_health && local_consecutive_failures >= unhealthy_threshold {
                        current_health = false;
                        warn!("Server {} is now unhealthy: timeout", self.server_url);
                    }
                }
            }

            // Update distributed store
            let status = StoreHealthStatus {
                healthy: current_health,
                last_check: current_time_millis(),
                consecutive_failures: local_consecutive_failures,
                last_error: if current_health {
                    None
                } else {
                    Some("Health check failed".to_string())
                },
            };

            if let Err(e) = self.store.health_set(&self.service_name, &self.server_url, &status).await {
                warn!("Failed to update health status in store: {}", e);
            }
        }
    }

    async fn perform_http_check(&self) -> Result<(), String> {
        let scheme = self.config.scheme.as_deref().unwrap_or("http");
        let check_url = format!(
            "{}://{}{}",
            scheme,
            self.server_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('/'),
            self.config.path
        );

        let uri: hyper::Uri = check_url
            .parse()
            .map_err(|e| format!("Invalid URL: {}", e))?;

        let method = self
            .config
            .method
            .as_ref()
            .map(|m| m.parse().unwrap_or(Method::GET))
            .unwrap_or(Method::GET);

        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("user-agent", "traffic-management-health-checker/1.0")
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| format!("Failed to build request: {}", e))?;

        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = response.status();

        if let Some(expected) = self.config.status {
            if status.as_u16() != expected {
                return Err(format!("Expected status {}, got {}", expected, status));
            }
            return Ok(());
        }

        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else if status.is_server_error() {
            Err(format!("Server error: {}", status))
        } else {
            Ok(())
        }
    }
}

/// Manager for distributed health checks across multiple servers
pub struct DistributedHealthManager {
    store: Arc<dyn Store>,
    is_leader: Arc<AtomicBool>,
    node_id: String,
}

impl DistributedHealthManager {
    pub fn new(store: Arc<dyn Store>, is_leader: Arc<AtomicBool>, node_id: String) -> Self {
        Self {
            store,
            is_leader,
            node_id,
        }
    }

    /// Start health checks for a service
    pub fn start_health_checks(
        &self,
        service_name: &str,
        servers: &[String],
        config: &HealthCheck,
    ) {
        for server_url in servers {
            let checker = DistributedHealthChecker::new(
                service_name.to_string(),
                server_url.clone(),
                config.clone(),
                Arc::clone(&self.store),
                Arc::clone(&self.is_leader),
                self.node_id.clone(),
            );

            tokio::spawn(async move {
                checker.start().await;
            });
        }
    }

    /// Get health status for all servers in a service
    pub async fn get_health_status(&self, service_name: &str) -> Vec<(String, bool)> {
        match self.store.health_get_all(service_name).await {
            Ok(statuses) => statuses
                .into_iter()
                .map(|(url, status)| (url, status.healthy))
                .collect(),
            Err(e) => {
                warn!("Failed to get health statuses: {}", e);
                Vec::new()
            }
        }
    }

    /// Check if a specific server is healthy
    pub async fn is_server_healthy(&self, service_name: &str, server_url: &str) -> bool {
        match self.store.health_get(service_name, server_url).await {
            Ok(Some(status)) => status.healthy,
            Ok(None) => true, // No status means assume healthy
            Err(_) => true,   // On error, assume healthy
        }
    }
}

fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalStore;

    #[tokio::test]
    async fn test_health_manager_creation() {
        let store = Arc::new(LocalStore::new());
        let is_leader = Arc::new(AtomicBool::new(true));
        let node_id = "test-node".to_string();

        let manager = DistributedHealthManager::new(store, is_leader, node_id);

        // Should return empty initially
        let statuses = manager.get_health_status("test-service").await;
        assert!(statuses.is_empty());
    }

    #[tokio::test]
    async fn test_server_health_check() {
        let store = Arc::new(LocalStore::new());
        let is_leader = Arc::new(AtomicBool::new(true));
        let node_id = "test-node".to_string();

        let manager = DistributedHealthManager::new(store.clone(), is_leader, node_id);

        // Set health status directly
        let status = StoreHealthStatus {
            healthy: true,
            last_check: current_time_millis(),
            consecutive_failures: 0,
            last_error: None,
        };
        store
            .health_set("test-service", "http://server1:8080", &status)
            .await
            .unwrap();

        // Check health
        let is_healthy = manager
            .is_server_healthy("test-service", "http://server1:8080")
            .await;
        assert!(is_healthy);
    }
}
