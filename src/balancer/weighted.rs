use super::Balancer;
use crate::config::Server;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Weighted round-robin load balancer using smooth weighted round-robin algorithm
/// This provides better distribution than simple weighted selection
pub struct WeightedBalancer {
    servers: Vec<WeightedServer>,
    cached_total_weight: AtomicI64,
}

struct WeightedServer {
    config: Server,
    healthy: AtomicBool,
    current_weight: AtomicI64, // Use signed to handle subtraction properly
    effective_weight: AtomicU64,
}

impl WeightedBalancer {
    /// Create a weighted balancer from servers with their configured weights.
    pub fn new(servers: Vec<Server>) -> Self {
        let servers: Vec<WeightedServer> = servers
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

        let total: i64 = servers
            .iter()
            .map(|s| s.effective_weight.load(Ordering::Relaxed) as i64)
            .sum();

        Self {
            servers,
            cached_total_weight: AtomicI64::new(total),
        }
    }

    fn recompute_total_weight(&self) {
        let total: i64 = self
            .servers
            .iter()
            .filter(|s| s.healthy.load(Ordering::Relaxed))
            .map(|s| s.effective_weight.load(Ordering::Relaxed) as i64)
            .sum();
        self.cached_total_weight.store(total, Ordering::Relaxed);
    }
}

impl Balancer for WeightedBalancer {
    fn next_server(&self) -> Option<&Server> {
        if self.servers.is_empty() {
            return None;
        }

        let total = self.cached_total_weight.load(Ordering::Relaxed);
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
            server
                .effective_weight
                .store(server.config.weight as u64, Ordering::Relaxed);
            self.recompute_total_weight();
        }
    }

    fn mark_unhealthy(&self, index: usize) {
        if let Some(server) = self.servers.get(index) {
            server.healthy.store(false, Ordering::Relaxed);
            self.recompute_total_weight();
        }
    }

    fn find_server_index(&self, url: &str) -> Option<usize> {
        self.servers.iter().position(|s| s.config.url == url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_weighted_servers() -> Vec<Server> {
        vec![
            Server {
                url: "http://server0:8080".to_string(),
                weight: 5,
                preserve_path: false,
                parsed_uri: None,
                url_arc: None,
            },
            Server {
                url: "http://server1:8080".to_string(),
                weight: 3,
                preserve_path: false,
                parsed_uri: None,
                url_arc: None,
            },
            Server {
                url: "http://server2:8080".to_string(),
                weight: 2,
                preserve_path: false,
                parsed_uri: None,
                url_arc: None,
            },
        ]
    }

    #[test]
    fn test_weighted_distribution_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let balancer = Arc::new(WeightedBalancer::new(make_weighted_servers()));
        let counts: [Arc<std::sync::atomic::AtomicU32>; 3] = [
            Arc::new(std::sync::atomic::AtomicU32::new(0)),
            Arc::new(std::sync::atomic::AtomicU32::new(0)),
            Arc::new(std::sync::atomic::AtomicU32::new(0)),
        ];

        let mut handles = vec![];
        for _ in 0..10 {
            let b = Arc::clone(&balancer);
            let c = counts.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let server = b.next_server().unwrap();
                    if server.url.contains("server0") {
                        c[0].fetch_add(1, Ordering::Relaxed);
                    } else if server.url.contains("server1") {
                        c[1].fetch_add(1, Ordering::Relaxed);
                    } else {
                        c[2].fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let c0 = counts[0].load(Ordering::Relaxed);
        let c1 = counts[1].load(Ordering::Relaxed);
        let c2 = counts[2].load(Ordering::Relaxed);

        // Weight ratio is 5:3:2. Under concurrency, expect ordering preserved
        assert!(c0 > c1, "server0({c0}) should get more than server1({c1})");
        assert!(c1 > c2, "server1({c1}) should get more than server2({c2})");
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
