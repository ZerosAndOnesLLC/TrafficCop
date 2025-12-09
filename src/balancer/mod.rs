mod least_conn;
mod random;
mod round_robin;
mod weighted;

pub use least_conn::LeastConnBalancer;
pub use random::RandomBalancer;
pub use round_robin::RoundRobinBalancer;
pub use weighted::WeightedBalancer;

use crate::config::{LoadBalancerStrategy, ServerConfig, Service};

pub trait Balancer: Send + Sync {
    fn next_server(&self) -> Option<&ServerConfig>;
    fn mark_healthy(&self, index: usize);
    fn mark_unhealthy(&self, index: usize);
}

pub struct LoadBalancer {
    strategy: Box<dyn Balancer>,
}

impl LoadBalancer {
    pub fn new(service: &Service) -> Self {
        let strategy: Box<dyn Balancer> = match service.load_balancer.strategy {
            LoadBalancerStrategy::RoundRobin => {
                Box::new(RoundRobinBalancer::new(service.servers.clone()))
            }
            LoadBalancerStrategy::Weighted => {
                Box::new(WeightedBalancer::new(service.servers.clone()))
            }
            LoadBalancerStrategy::LeastConn => {
                Box::new(LeastConnBalancer::new(service.servers.clone()))
            }
            LoadBalancerStrategy::Random => {
                Box::new(RandomBalancer::new(service.servers.clone()))
            }
        };

        Self { strategy }
    }

    #[inline]
    pub fn next_server(&self) -> Option<&ServerConfig> {
        self.strategy.next_server()
    }

    pub fn mark_healthy(&self, index: usize) {
        self.strategy.mark_healthy(index);
    }

    pub fn mark_unhealthy(&self, index: usize) {
        self.strategy.mark_unhealthy(index);
    }
}
