use crate::config::Config;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Manages TCP services and load balancing
pub struct TcpServiceManager {
    services: HashMap<String, Arc<TcpService>>,
}

/// A TCP service with load balancing
pub struct TcpService {
    name: String,
    servers: Vec<TcpBackendServer>,
    /// Round-robin counter
    rr_counter: AtomicUsize,
    /// Health status
    healthy: RwLock<Vec<bool>>,
}

/// A TCP backend server
#[derive(Clone)]
pub struct TcpBackendServer {
    /// Server address (host:port)
    pub address: String,
    /// Weight for load balancing
    pub weight: u32,
    /// Enable TLS to backend
    pub use_tls: bool,
}

impl TcpServiceManager {
    /// Create a new service manager from configuration
    pub fn new(config: &Config) -> Self {
        let mut services = HashMap::new();

        for (name, service_config) in config.tcp_services() {
            if let Some(lb) = &service_config.load_balancer {
                let servers: Vec<TcpBackendServer> = lb
                    .servers
                    .iter()
                    .map(|s| TcpBackendServer {
                        address: s.address.clone(),
                        weight: s.weight,
                        use_tls: s.tls,
                    })
                    .collect();

                let healthy = vec![true; servers.len()];

                let service = TcpService {
                    name: name.clone(),
                    servers,
                    rr_counter: AtomicUsize::new(0),
                    healthy: RwLock::new(healthy),
                };

                services.insert(name.clone(), Arc::new(service));
            }
            // TODO: Handle weighted services
        }

        Self { services }
    }

    /// Get a service by name
    pub fn get_service(&self, name: &str) -> Option<Arc<TcpService>> {
        self.services.get(name).cloned()
    }
}

impl TcpService {
    /// Get the next healthy backend server (round-robin)
    pub fn next_server(&self) -> Option<&TcpBackendServer> {
        if self.servers.is_empty() {
            return None;
        }

        let healthy = self.healthy.read();
        let healthy_count = healthy.iter().filter(|&&h| h).count();

        if healthy_count == 0 {
            warn!("TCP service '{}': No healthy backends available", self.name);
            // Fall back to first server even if unhealthy
            return self.servers.first();
        }

        // Round-robin through healthy servers
        let mut attempts = 0;
        loop {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % self.servers.len();
            if healthy[idx] {
                return Some(&self.servers[idx]);
            }
            attempts += 1;
            if attempts >= self.servers.len() {
                // All servers checked, return first available
                return self.servers.first();
            }
        }
    }

    /// Mark a server as unhealthy
    pub fn mark_unhealthy(&self, index: usize) {
        if index < self.servers.len() {
            let mut healthy = self.healthy.write();
            healthy[index] = false;
            debug!(
                "TCP service '{}': Marked server {} as unhealthy",
                self.name, self.servers[index].address
            );
        }
    }

    /// Mark a server as healthy
    pub fn mark_healthy(&self, index: usize) {
        if index < self.servers.len() {
            let mut healthy = self.healthy.write();
            healthy[index] = true;
            debug!(
                "TCP service '{}': Marked server {} as healthy",
                self.name, self.servers[index].address
            );
        }
    }

    /// Get all backend servers
    pub fn servers(&self) -> &[TcpBackendServer] {
        &self.servers
    }

    /// Get server count
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Get healthy server count
    pub fn healthy_count(&self) -> usize {
        self.healthy.read().iter().filter(|&&h| h).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let service = TcpService {
            name: "test".to_string(),
            servers: vec![
                TcpBackendServer {
                    address: "localhost:8001".to_string(),
                    weight: 1,
                    use_tls: false,
                },
                TcpBackendServer {
                    address: "localhost:8002".to_string(),
                    weight: 1,
                    use_tls: false,
                },
            ],
            rr_counter: AtomicUsize::new(0),
            healthy: RwLock::new(vec![true, true]),
        };

        let s1 = service.next_server().unwrap();
        let s2 = service.next_server().unwrap();
        let s3 = service.next_server().unwrap();

        assert_eq!(s1.address, "localhost:8001");
        assert_eq!(s2.address, "localhost:8002");
        assert_eq!(s3.address, "localhost:8001");
    }

    #[test]
    fn test_skip_unhealthy() {
        let service = TcpService {
            name: "test".to_string(),
            servers: vec![
                TcpBackendServer {
                    address: "localhost:8001".to_string(),
                    weight: 1,
                    use_tls: false,
                },
                TcpBackendServer {
                    address: "localhost:8002".to_string(),
                    weight: 1,
                    use_tls: false,
                },
            ],
            rr_counter: AtomicUsize::new(0),
            healthy: RwLock::new(vec![false, true]),
        };

        // Should always return the healthy server
        for _ in 0..5 {
            let s = service.next_server().unwrap();
            assert_eq!(s.address, "localhost:8002");
        }
    }
}
