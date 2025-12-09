use super::Balancer;
use crate::config::Server;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct RoundRobinBalancer {
    servers: Vec<Server>,
    healthy: Vec<AtomicBool>,
    counter: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new(servers: Vec<Server>) -> Self {
        let healthy = servers.iter().map(|_| AtomicBool::new(true)).collect();
        Self {
            servers,
            healthy,
            counter: AtomicUsize::new(0),
        }
    }
}

impl Balancer for RoundRobinBalancer {
    fn next_server(&self) -> Option<&Server> {
        if self.servers.is_empty() {
            return None;
        }

        let len = self.servers.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed);

        // Try to find a healthy server, wrapping around if needed
        for i in 0..len {
            let idx = (start + i) % len;
            if self.healthy[idx].load(Ordering::Relaxed) {
                return Some(&self.servers[idx]);
            }
        }

        // All servers unhealthy, return first one anyway
        // (the health checker will eventually mark them healthy)
        Some(&self.servers[start % len])
    }

    fn mark_healthy(&self, index: usize) {
        if index < self.healthy.len() {
            self.healthy[index].store(true, Ordering::Relaxed);
        }
    }

    fn mark_unhealthy(&self, index: usize) {
        if index < self.healthy.len() {
            self.healthy[index].store(false, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_servers(count: usize) -> Vec<Server> {
        (0..count)
            .map(|i| Server {
                url: format!("http://server{}:8080", i),
                weight: 1,
                preserve_path: false,
            })
            .collect()
    }

    #[test]
    fn test_round_robin() {
        let balancer = RoundRobinBalancer::new(make_servers(3));

        let s1 = balancer.next_server().unwrap();
        let s2 = balancer.next_server().unwrap();
        let s3 = balancer.next_server().unwrap();
        let s4 = balancer.next_server().unwrap();

        assert!(s1.url.contains("server0"));
        assert!(s2.url.contains("server1"));
        assert!(s3.url.contains("server2"));
        assert!(s4.url.contains("server0")); // wraps around
    }

    #[test]
    fn test_skip_unhealthy() {
        let balancer = RoundRobinBalancer::new(make_servers(3));
        balancer.mark_unhealthy(1);

        let s1 = balancer.next_server().unwrap();
        let s2 = balancer.next_server().unwrap();
        let s3 = balancer.next_server().unwrap();
        let s4 = balancer.next_server().unwrap();

        // Should skip server1: sequence is 0->2->2->0->2->2...
        assert!(s1.url.contains("server0")); // start=0, returns 0
        assert!(s2.url.contains("server2")); // start=1, skips 1, returns 2
        assert!(s3.url.contains("server2")); // start=2, returns 2
        assert!(s4.url.contains("server0")); // start=3%3=0, returns 0
    }
}
