use super::Balancer;
use crate::config::ServerConfig;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Weighted round-robin load balancer using smooth weighted round-robin algorithm
/// This provides better distribution than simple weighted selection
pub struct WeightedBalancer {
    servers: Vec<WeightedServer>,
}

struct WeightedServer {
    config: ServerConfig,
    healthy: AtomicBool,
    current_weight: AtomicI64, // Use signed to handle subtraction properly
    effective_weight: AtomicU64,
}

impl WeightedBalancer {
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        let servers = servers
            .into_iter()
            .map(|config| {
                let weight = config.weight as u64;
                WeightedServer {
                    config,
                    healthy: AtomicBool::new(true),
                    current_weight: AtomicI64::new(0),
                    effective_weight: AtomicU64::new(weight),
                }
            })
            .collect();

        Self { servers }
    }

    fn total_weight(&self) -> i64 {
        self.servers
            .iter()
            .filter(|s| s.healthy.load(Ordering::Relaxed))
            .map(|s| s.effective_weight.load(Ordering::Relaxed) as i64)
            .sum()
    }
}

impl Balancer for WeightedBalancer {
    fn next_server(&self) -> Option<&ServerConfig> {
        if self.servers.is_empty() {
            return None;
        }

        let total = self.total_weight();
        if total == 0 {
            // All servers have zero weight or are unhealthy, return first
            return self.servers.first().map(|s| &s.config);
        }

        let mut best_idx = None;
        let mut best_weight = i64::MIN;

        // Smooth weighted round-robin
        for (idx, server) in self.servers.iter().enumerate() {
            if !server.healthy.load(Ordering::Relaxed) {
                continue;
            }

            let ew = server.effective_weight.load(Ordering::Relaxed) as i64;
            let cw = server.current_weight.fetch_add(ew, Ordering::Relaxed) + ew;

            if best_idx.is_none() || cw > best_weight {
                best_weight = cw;
                best_idx = Some(idx);
            }
        }

        if let Some(idx) = best_idx {
            // Subtract total weight from selected server
            self.servers[idx]
                .current_weight
                .fetch_sub(total, Ordering::Relaxed);
            return Some(&self.servers[idx].config);
        }

        // Fallback
        self.servers.first().map(|s| &s.config)
    }

    fn mark_healthy(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.healthy.store(true, Ordering::Relaxed);
            // Restore effective weight
            server
                .effective_weight
                .store(server.config.weight as u64, Ordering::Relaxed);
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

    fn make_weighted_servers() -> Vec<ServerConfig> {
        vec![
            ServerConfig {
                url: "http://server0:8080".to_string(),
                weight: 5,
            },
            ServerConfig {
                url: "http://server1:8080".to_string(),
                weight: 3,
            },
            ServerConfig {
                url: "http://server2:8080".to_string(),
                weight: 2,
            },
        ]
    }

    #[test]
    fn test_weighted_distribution() {
        let balancer = WeightedBalancer::new(make_weighted_servers());

        let mut counts = [0u32; 3];
        for _ in 0..100 {
            let server = balancer.next_server().unwrap();
            if server.url.contains("server0") {
                counts[0] += 1;
            } else if server.url.contains("server1") {
                counts[1] += 1;
            } else {
                counts[2] += 1;
            }
        }

        // Weight ratio is 5:3:2, so expect roughly 50:30:20
        assert!(counts[0] > counts[1]);
        assert!(counts[1] > counts[2]);
    }
}
