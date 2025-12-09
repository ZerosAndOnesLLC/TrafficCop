use crate::balancer::LoadBalancer;
use crate::config::{Config, Service, TimeoutConfig};
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
    pub balancer: LoadBalancer,
    pub health_statuses: Vec<Arc<HealthStatus>>,
    pub timeouts: TimeoutConfig,
}

impl ServiceManager {
    pub fn new(config: &Config) -> Self {
        let pool = Arc::new(ConnectionPool::new(100, Duration::from_secs(90)));
        let services = DashMap::new();

        for (name, service_config) in &config.services {
            let balancer = LoadBalancer::new(service_config);
            let health_statuses: Vec<Arc<HealthStatus>> = service_config
                .servers
                .iter()
                .map(|_| Arc::new(HealthStatus::new()))
                .collect();

            services.insert(
                name.clone(),
                ServiceState {
                    config: service_config.clone(),
                    balancer,
                    health_statuses,
                    timeouts: service_config.timeouts.clone(),
                },
            );

            info!("Registered service '{}' with {} servers", name, service_config.servers.len());
        }

        Self { services, pool }
    }

    pub fn get_service(&self, name: &str) -> Option<dashmap::mapref::one::Ref<'_, String, ServiceState>> {
        self.services.get(name)
    }

    pub fn get_pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    pub fn start_health_checks(&self) {
        for entry in self.services.iter() {
            let service_name = entry.key().clone();
            let service = entry.value();

            if let Some(health_config) = &service.config.health_check {
                for (idx, server) in service.config.servers.iter().enumerate() {
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
