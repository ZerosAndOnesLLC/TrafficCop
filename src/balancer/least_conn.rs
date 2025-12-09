use super::Balancer;
use crate::config::ServerConfig;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Least connections load balancer
/// Selects the server with the fewest active connections
pub struct LeastConnBalancer {
    servers: Vec<LeastConnServer>,
}

struct LeastConnServer {
    config: ServerConfig,
    healthy: AtomicBool,
    active_connections: AtomicUsize,
}

impl LeastConnBalancer {
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        let servers = servers
            .into_iter()
            .map(|config| LeastConnServer {
                config,
                healthy: AtomicBool::new(true),
                active_connections: AtomicUsize::new(0),
            })
            .collect();

        Self { servers }
    }

    /// Increment connection count for a server (call when starting a request)
    pub fn acquire(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.active_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement connection count for a server (call when request completes)
    pub fn release(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Balancer for LeastConnBalancer {
    fn next_server(&self) -> Option<&ServerConfig> {
        if self.servers.is_empty() {
            return None;
        }

        let mut best_idx = None;
        let mut min_conns = usize::MAX;

        for (idx, server) in self.servers.iter().enumerate() {
            if !server.healthy.load(Ordering::Relaxed) {
                continue;
            }

            let conns = server.active_connections.load(Ordering::Relaxed);

            // Weighted least connections: divide by weight
            let weighted_conns = if server.config.weight > 0 {
                conns * 100 / server.config.weight as usize
            } else {
                conns * 100
            };

            if weighted_conns < min_conns {
                min_conns = weighted_conns;
                best_idx = Some(idx);
            }
        }

        best_idx.map(|idx| &self.servers[idx].config)
    }

    fn mark_healthy(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.healthy.store(true, Ordering::Relaxed);
        }
    }

    fn mark_unhealthy(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.healthy.store(false, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_servers(count: usize) -> Vec<ServerConfig> {
        (0..count)
            .map(|i| ServerConfig {
                url: format!("http://server{}:8080", i),
                weight: 1,
            })
            .collect()
    }

    #[test]
    fn test_least_conn_selects_least_loaded() {
        let balancer = LeastConnBalancer::new(make_servers(3));

        // Simulate some connections
        balancer.acquire(0);
        balancer.acquire(0);
        balancer.acquire(1);

        // Server 2 has 0 connections, should be selected
        let server = balancer.next_server().unwrap();
        assert!(server.url.contains("server2"));
    }
}
