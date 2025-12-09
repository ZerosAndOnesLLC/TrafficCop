use super::Balancer;
use crate::config::ServerConfig;
use std::sync::atomic::{AtomicBool, Ordering};

/// Random load balancer with optional weighting
pub struct RandomBalancer {
    servers: Vec<RandomServer>,
    total_weight: u32,
}

struct RandomServer {
    config: ServerConfig,
    healthy: AtomicBool,
}

impl RandomBalancer {
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        let total_weight: u32 = servers.iter().map(|s| s.weight).sum();
        let servers: Vec<RandomServer> = servers
            .into_iter()
            .map(|config| RandomServer {
                config,
                healthy: AtomicBool::new(true),
            })
            .collect();

        Self {
            total_weight,
            servers,
        }
    }

    #[inline]
    fn fast_random() -> u32 {
        // Fast xorshift random - no allocation, no syscall
        use std::cell::Cell;
        thread_local! {
            static STATE: Cell<u32> = Cell::new(0xDEADBEEF);
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
}

impl Balancer for RandomBalancer {
    fn next_server(&self) -> Option<&ServerConfig> {
        if self.servers.is_empty() || self.total_weight == 0 {
            return self.servers.first().map(|s| &s.config);
        }

        // Calculate healthy total weight
        let healthy_weight: u32 = self
            .servers
            .iter()
            .filter(|s| s.healthy.load(Ordering::Relaxed))
            .map(|s| s.config.weight)
            .sum();

        if healthy_weight == 0 {
            return self.servers.first().map(|s| &s.config);
        }

        let rand = Self::fast_random() % healthy_weight;

        let mut cumulative = 0u32;
        for server in &self.servers {
            if !server.healthy.load(Ordering::Relaxed) {
                continue;
            }
            cumulative += server.config.weight;
            if rand < cumulative {
                return Some(&server.config);
            }
        }

        // Fallback
        self.servers.first().map(|s| &s.config)
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

    fn make_servers() -> Vec<ServerConfig> {
        vec![
            ServerConfig {
                url: "http://server0:8080".to_string(),
                weight: 1,
            },
            ServerConfig {
                url: "http://server1:8080".to_string(),
                weight: 1,
            },
        ]
    }

    #[test]
    fn test_random_returns_server() {
        let balancer = RandomBalancer::new(make_servers());

        for _ in 0..100 {
            let server = balancer.next_server();
            assert!(server.is_some());
        }
    }
}
