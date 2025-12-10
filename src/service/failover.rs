use crate::config::FailoverService;
use crate::health::HealthStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Failover service router - routes to primary service unless it's unhealthy
pub struct FailoverServiceRouter {
    /// Primary service name
    primary: String,
    /// Fallback service name
    fallback: String,
    /// Whether the primary service is currently healthy
    primary_healthy: AtomicBool,
    /// Health status for tracking (if health check is configured)
    health_status: Option<Arc<HealthStatus>>,
}

impl FailoverServiceRouter {
    pub fn new(config: &FailoverService) -> Self {
        Self {
            primary: config.service.clone(),
            fallback: config.fallback.clone(),
            primary_healthy: AtomicBool::new(true),
            health_status: None,
        }
    }

    /// Create with external health status monitoring
    pub fn with_health_status(config: &FailoverService, health_status: Arc<HealthStatus>) -> Self {
        Self {
            primary: config.service.clone(),
            fallback: config.fallback.clone(),
            primary_healthy: AtomicBool::new(true),
            health_status: Some(health_status),
        }
    }

    /// Get the current active service name
    /// Returns primary if healthy, fallback otherwise
    pub fn active_service(&self) -> &str {
        // If we have an external health status, use that
        if let Some(ref status) = self.health_status {
            if status.is_healthy() {
                return &self.primary;
            } else {
                return &self.fallback;
            }
        }

        // Otherwise use our internal tracking
        if self.primary_healthy.load(Ordering::Relaxed) {
            &self.primary
        } else {
            &self.fallback
        }
    }

    /// Mark the primary service as healthy
    pub fn mark_primary_healthy(&self) {
        self.primary_healthy.store(true, Ordering::Relaxed);
    }

    /// Mark the primary service as unhealthy (triggers failover)
    pub fn mark_primary_unhealthy(&self) {
        self.primary_healthy.store(false, Ordering::Relaxed);
    }

    /// Check if currently using the primary service
    pub fn is_using_primary(&self) -> bool {
        if let Some(ref status) = self.health_status {
            return status.is_healthy();
        }
        self.primary_healthy.load(Ordering::Relaxed)
    }

    /// Get the primary service name
    pub fn primary(&self) -> &str {
        &self.primary
    }

    /// Get the fallback service name
    pub fn fallback(&self) -> &str {
        &self.fallback
    }

    /// Get both service names
    pub fn service_names(&self) -> (&str, &str) {
        (&self.primary, &self.fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FailoverService;

    fn make_config() -> FailoverService {
        FailoverService {
            service: "primary-service".to_string(),
            fallback: "fallback-service".to_string(),
            health_check: None,
        }
    }

    #[test]
    fn test_default_uses_primary() {
        let config = make_config();
        let router = FailoverServiceRouter::new(&config);

        assert_eq!(router.active_service(), "primary-service");
        assert!(router.is_using_primary());
    }

    #[test]
    fn test_failover_to_fallback() {
        let config = make_config();
        let router = FailoverServiceRouter::new(&config);

        // Initially healthy
        assert_eq!(router.active_service(), "primary-service");

        // Mark unhealthy
        router.mark_primary_unhealthy();
        assert_eq!(router.active_service(), "fallback-service");
        assert!(!router.is_using_primary());
    }

    #[test]
    fn test_recovery_to_primary() {
        let config = make_config();
        let router = FailoverServiceRouter::new(&config);

        // Fail over
        router.mark_primary_unhealthy();
        assert_eq!(router.active_service(), "fallback-service");

        // Recover
        router.mark_primary_healthy();
        assert_eq!(router.active_service(), "primary-service");
        assert!(router.is_using_primary());
    }

    #[test]
    fn test_service_names() {
        let config = make_config();
        let router = FailoverServiceRouter::new(&config);

        assert_eq!(router.primary(), "primary-service");
        assert_eq!(router.fallback(), "fallback-service");

        let (primary, fallback) = router.service_names();
        assert_eq!(primary, "primary-service");
        assert_eq!(fallback, "fallback-service");
    }

    #[test]
    fn test_with_health_status() {
        let config = make_config();
        let health_status = Arc::new(HealthStatus::new());

        let router = FailoverServiceRouter::with_health_status(&config, health_status.clone());

        // Initially healthy
        assert_eq!(router.active_service(), "primary-service");

        // Mark unhealthy via health status
        health_status.mark_unhealthy();
        assert_eq!(router.active_service(), "fallback-service");

        // Recover
        health_status.mark_healthy();
        assert_eq!(router.active_service(), "primary-service");
    }
}
