use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, reject requests
    HalfOpen, // Testing if service recovered
}

/// High-performance circuit breaker using atomics
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout_ms: u64,

    // Atomic state
    failures: AtomicU32,
    successes: AtomicU32,
    state: AtomicU32, // 0=Closed, 1=Open, 2=HalfOpen
    opened_at: AtomicU64,
    epoch: Instant,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout_ms: recovery_timeout.as_millis() as u64,
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            state: AtomicU32::new(0), // Closed
            opened_at: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    #[inline]
    pub fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Relaxed) {
            0 => CircuitState::Closed,
            1 => {
                // Check if recovery timeout has passed
                let opened = self.opened_at.load(Ordering::Relaxed);
                let now = self.epoch.elapsed().as_millis() as u64;
                if now - opened >= self.recovery_timeout_ms {
                    // Transition to half-open
                    self.state.store(2, Ordering::Relaxed);
                    self.successes.store(0, Ordering::Relaxed);
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Open
                }
            }
            _ => CircuitState::HalfOpen,
        }
    }

    /// Check if request should be allowed
    #[inline]
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                true
            }
        }
    }

    /// Record a successful request
    #[inline]
    pub fn record_success(&self) {
        match self.state() {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failures.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
                // After a few successes in half-open, close the circuit
                if successes >= 3 {
                    self.state.store(0, Ordering::Relaxed);
                    self.failures.store(0, Ordering::Relaxed);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed request
    #[inline]
    pub fn record_failure(&self) {
        match self.state() {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= self.failure_threshold {
                    // Open the circuit
                    self.state.store(1, Ordering::Relaxed);
                    self.opened_at
                        .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                self.state.store(1, Ordering::Relaxed);
                self.opened_at
                    .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    /// Reset the circuit breaker
    pub fn reset(&self) {
        self.state.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.successes.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_opens_after_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));

        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        // Record failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_success_resets_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));

        cb.record_failure();
        cb.record_failure();
        cb.record_success();

        // Failures should be reset
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
