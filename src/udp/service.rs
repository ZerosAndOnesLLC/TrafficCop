use crate::config::Config;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Manages UDP services and load balancing
pub struct UdpServiceManager {
    services: HashMap<String, Arc<UdpService>>,
}

/// A UDP service with load balancing
pub struct UdpService {
    name: String,
    servers: Vec<UdpBackendServer>,
    /// Round-robin counter
    rr_counter: AtomicUsize,
    /// Health status
    healthy: RwLock<Vec<bool>>,
}

/// A UDP backend server
#[derive(Clone)]
pub struct UdpBackendServer {
    /// Server address (host:port)
    pub address: String,
    /// Weight for load balancing
    pub weight: u32,
}

impl UdpServiceManager {
    /// Create a new service manager from configuration
    pub fn new(config: &Config) -> Self {
        let mut services = HashMap::new();

        for (name, service_config) in config.udp_services() {
            if let Some(lb) = &service_config.load_balancer {
                let servers: Vec<UdpBackendServer> = lb
                    .servers
                    .iter()
                    .map(|s| UdpBackendServer {
                        address: s.address.clone(),
                        weight: s.weight,
                    })
                    .collect();

                let healthy = vec![true; servers.len()];

                let service = UdpService {
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
    pub fn get_service(&self, name: &str) -> Option<Arc<UdpService>> {
        self.services.get(name).cloned()
    }

    /// Get all service names
    pub fn service_names(&self) -> impl Iterator<Item = &String> {
        self.services.keys()
    }
}

impl UdpService {
    /// Get the next healthy backend server (round-robin)
    pub fn next_server(&self) -> Option<&UdpBackendServer> {
        if self.servers.is_empty() {
            return None;
        }

        let healthy = self.healthy.read();
        let healthy_count = healthy.iter().filter(|&&h| h).count();

        if healthy_count == 0 {
            warn!("UDP service '{}': No healthy backends available", self.name);
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

    /// Get server by index (for consistent hashing based on source IP)
    pub fn get_server_by_hash(&self, hash: usize) -> Option<&UdpBackendServer> {
        if self.servers.is_empty() {
            return None;
        }

        let healthy = self.healthy.read();
        let idx = hash % self.servers.len();

        // Try the hashed server first
        if healthy[idx] {
            return Some(&self.servers[idx]);
        }

        // Fall back to round-robin if hashed server is unhealthy
        self.next_server()
    }

    /// Mark a server as unhealthy
    pub fn mark_unhealthy(&self, index: usize) {
        if index < self.servers.len() {
            let mut healthy = self.healthy.write();
            healthy[index] = false;
            debug!(
                "UDP service '{}': Marked server {} as unhealthy",
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
                "UDP service '{}': Marked server {} as healthy",
                self.name, self.servers[index].address
            );
        }
    }

    /// Get all backend servers
    pub fn servers(&self) -> &[UdpBackendServer] {
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

    /// Get service name
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let service = UdpService {
            name: "test".to_string(),
            servers: vec![
                UdpBackendServer {
                    address: "localhost:5001".to_string(),
                    weight: 1,
                },
                UdpBackendServer {
                    address: "localhost:5002".to_string(),
                    weight: 1,
                },
            ],
            rr_counter: AtomicUsize::new(0),
            healthy: RwLock::new(vec![true, true]),
        };

        let s1 = service.next_server().unwrap();
        let s2 = service.next_server().unwrap();
        let s3 = service.next_server().unwrap();

        assert_eq!(s1.address, "localhost:5001");
        assert_eq!(s2.address, "localhost:5002");
        assert_eq!(s3.address, "localhost:5001");
    }

    #[test]
    fn test_skip_unhealthy() {
        let service = UdpService {
            name: "test".to_string(),
            servers: vec![
                UdpBackendServer {
                    address: "localhost:5001".to_string(),
                    weight: 1,
                },
                UdpBackendServer {
                    address: "localhost:5002".to_string(),
                    weight: 1,
                },
            ],
            rr_counter: AtomicUsize::new(0),
            healthy: RwLock::new(vec![false, true]),
        };

        // Should always return the healthy server
        for _ in 0..5 {
            let s = service.next_server().unwrap();
            assert_eq!(s.address, "localhost:5002");
        }
    }

    #[test]
    fn test_hash_based_selection() {
        let service = UdpService {
            name: "test".to_string(),
            servers: vec![
                UdpBackendServer {
                    address: "localhost:5001".to_string(),
                    weight: 1,
                },
                UdpBackendServer {
                    address: "localhost:5002".to_string(),
                    weight: 1,
                },
                UdpBackendServer {
                    address: "localhost:5003".to_string(),
                    weight: 1,
                },
            ],
            rr_counter: AtomicUsize::new(0),
            healthy: RwLock::new(vec![true, true, true]),
        };

        // Same hash should always return same server
        let s1 = service.get_server_by_hash(42).unwrap();
        let s2 = service.get_server_by_hash(42).unwrap();
        assert_eq!(s1.address, s2.address);
    }
}
