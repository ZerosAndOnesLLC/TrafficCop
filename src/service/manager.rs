use crate::balancer::LoadBalancer;
use crate::config::{Config, LoadBalancerService, Service};
use crate::health::{HealthChecker, HealthStatus};
use crate::pool::ConnectionPool;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub struct ServiceManager {
    services: DashMap<String, ServiceState>,
    pool: Arc<ConnectionPool>,
}

pub struct ServiceState {
    pub config: Service,
    pub balancer: Option<LoadBalancer>,
    pub health_statuses: Vec<Arc<HealthStatus>>,
}

impl ServiceManager {
    pub fn new(config: &Config) -> Self {
        let pool = Arc::new(ConnectionPool::new(100, Duration::from_secs(90)));
        let services = DashMap::new();

        for (name, service_config) in config.services() {
            let (balancer, health_statuses, server_count) = if let Some(lb) = &service_config.load_balancer {
                let balancer = Some(LoadBalancer::from_load_balancer(lb));
                let statuses: Vec<Arc<HealthStatus>> = lb
                    .servers
                    .iter()
                    .map(|_| Arc::new(HealthStatus::new()))
                    .collect();
                (balancer, statuses, lb.servers.len())
            } else if let Some(w) = &service_config.weighted {
                // TODO: Implement weighted service routing
                (None, Vec::new(), w.services.len())
            } else if service_config.mirroring.is_some() {
                // Mirroring service - references other services
                (None, Vec::new(), 1)
            } else if let Some(f) = &service_config.failover {
                // Failover service - references primary and fallback services
                info!(
                    "Failover service '{}' configured: primary='{}', fallback='{}'",
                    name, f.service, f.fallback
                );
                (None, Vec::new(), 2)
            } else {
                (None, Vec::new(), 0)
            };

            services.insert(
                name.clone(),
                ServiceState {
                    config: service_config.clone(),
                    balancer,
                    health_statuses,
                },
            );

            info!("Registered service '{}' with {} servers", name, server_count);
        }

        Self { services, pool }
    }

    pub fn get_service(
        &self,
        name: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, ServiceState>> {
        self.services.get(name)
    }

    pub fn get_pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    pub fn start_health_checks(&self) {
        for entry in self.services.iter() {
            let service_name = entry.key().clone();
            let service = entry.value();

            if let Some(lb) = &service.config.load_balancer {
                if let Some(health_config) = &lb.health_check {
                    for (idx, server) in lb.servers.iter().enumerate() {
                        let checker = HealthChecker::new(
                            health_config.clone(),
                            server.url.clone(),
                            Arc::clone(&service.health_statuses[idx]),
                        );

                        info!(
                            "Starting health checker for service '{}' server '{}'",
                            service_name, server.url
                        );

                        tokio::spawn(async move {
                            checker.start().await;
                        });
                    }
                }
            }
        }
    }

    /// Get the load balancer service config for a service (if it's a load balancer)
    pub fn get_load_balancer_config(&self, name: &str) -> Option<LoadBalancerService> {
        let service = self.services.get(name)?;
        service.config.load_balancer.clone()
    }
}
