//! Health checking subsystem: active polling, passive monitoring, circuit breaking, and distributed coordination.

mod checker;
mod circuit_breaker;
mod distributed;
mod passive;

/// Active HTTP health checker that polls backends on a schedule.
pub use checker::HealthChecker;
/// Circuit breaker with closed/open/half-open state transitions.
pub use circuit_breaker::{CircuitBreaker, CircuitState};
/// Cluster-aware health checker coordinated via distributed store.
pub use distributed::{DistributedHealthChecker, DistributedHealthManager};
/// Passive health monitoring based on response codes and latencies.
pub use passive::{
    BackendStats, HealthChange, PassiveHealthChecker, PassiveHealthConfig,
    PassiveHealthConfigBuilder,
};

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

/// Atomic health status tracker for a single backend server.
#[derive(Debug)]
pub struct HealthStatus {
    /// Whether the backend is currently healthy.
    pub healthy: AtomicBool,
    /// Number of consecutive successful health checks.
    pub consecutive_successes: AtomicU32,
    /// Number of consecutive failed health checks.
    pub consecutive_failures: AtomicU32,
    /// Timestamp of the most recent health check.
    pub last_check: RwLock<Option<Instant>>,
    /// Error message from the most recent failure, if any.
    pub last_error: RwLock<Option<String>>,
}

impl HealthStatus {
    /// Create a new health status, initially healthy.
    pub fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            last_check: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }

    /// Returns true if the backend is currently marked healthy.
    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Record a successful health check, resetting the failure counter.
    pub fn record_success(&self) {
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_check.write() = Some(Instant::now());
        *self.last_error.write() = None;
    }

    /// Record a failed health check with the given error message.
    pub fn record_failure(&self, error: String) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        *self.last_check.write() = Some(Instant::now());
        *self.last_error.write() = Some(error);
    }

    /// Force-mark this backend as healthy.
    pub fn mark_healthy(&self) {
        self.healthy.store(true, Ordering::Relaxed);
    }

    /// Force-mark this backend as unhealthy.
    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}
