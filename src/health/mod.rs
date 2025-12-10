mod checker;
mod circuit_breaker;
mod passive;

pub use checker::HealthChecker;
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use passive::{
    BackendStats, HealthChange, PassiveHealthChecker, PassiveHealthConfig,
    PassiveHealthConfigBuilder,
};

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct HealthStatus {
    pub healthy: AtomicBool,
    pub consecutive_successes: AtomicU32,
    pub consecutive_failures: AtomicU32,
    pub last_check: RwLock<Option<Instant>>,
    pub last_error: RwLock<Option<String>>,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            last_check: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }

    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_check.write() = Some(Instant::now());
        *self.last_error.write() = None;
    }

    pub fn record_failure(&self, error: String) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        *self.last_check.write() = Some(Instant::now());
        *self.last_error.write() = Some(error);
    }

    pub fn mark_healthy(&self) {
        self.healthy.store(true, Ordering::Relaxed);
    }

    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}
