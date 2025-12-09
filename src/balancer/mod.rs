mod least_conn;
mod random;
mod round_robin;
mod weighted;

pub use least_conn::LeastConnBalancer;
pub use random::RandomBalancer;
pub use round_robin::RoundRobinBalancer;
pub use weighted::WeightedBalancer;

use crate::config::{LoadBalancerService, Server, Service};

pub trait Balancer: Send + Sync {
    fn next_server(&self) -> Option<&Server>;
    fn mark_healthy(&self, index: usize);
    fn mark_unhealthy(&self, index: usize);
}

pub struct LoadBalancer {
    strategy: Box<dyn Balancer>,
}

impl LoadBalancer {
    pub fn new(service: &Service) -> Option<Self> {
        if let Some(lb) = &service.load_balancer {
            Some(Self::from_load_balancer(lb))
        } else {
            // Weighted and mirroring services are not load balancers
            None
        }
    }

    pub fn from_load_balancer(lb: &LoadBalancerService) -> Self {
        // Determine strategy based on server weights
        // If all weights are equal, use round robin; otherwise use weighted
        let all_equal_weights = lb.servers.windows(2).all(|w| w[0].weight == w[1].weight);
        let has_weights = lb.servers.iter().any(|s| s.weight > 1);

        let strategy: Box<dyn Balancer> = if has_weights && !all_equal_weights {
            Box::new(WeightedBalancer::new(lb.servers.clone()))
        } else {
            // Default to round robin
            Box::new(RoundRobinBalancer::new(lb.servers.clone()))
        };

        Self { strategy }
    }

    /// Create a load balancer with a specific strategy
    pub fn with_strategy(servers: Vec<Server>, strategy: &str) -> Self {
        let strategy: Box<dyn Balancer> = match strategy {
            "round_robin" | "roundRobin" => Box::new(RoundRobinBalancer::new(servers)),
            "weighted" => Box::new(WeightedBalancer::new(servers)),
            "least_conn" | "leastConn" => Box::new(LeastConnBalancer::new(servers)),
            "random" => Box::new(RandomBalancer::new(servers)),
            _ => Box::new(RoundRobinBalancer::new(servers)), // Default
        };

        Self { strategy }
    }

    #[inline]
    pub fn next_server(&self) -> Option<&Server> {
        self.strategy.next_server()
    }

    pub fn mark_healthy(&self, index: usize) {
        self.strategy.mark_healthy(index);
    }

    pub fn mark_unhealthy(&self, index: usize) {
        self.strategy.mark_unhealthy(index);
    }
}
