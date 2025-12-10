use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Passive health checker that monitors response codes and latencies
/// to detect unhealthy backends without active probing
pub struct PassiveHealthChecker {
    /// Configuration
    config: PassiveHealthConfig,
    /// State per backend
    backends: RwLock<std::collections::HashMap<String, BackendState>>,
}

/// Configuration for passive health checks
#[derive(Debug, Clone)]
pub struct PassiveHealthConfig {
    /// Number of consecutive failures before marking unhealthy
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking healthy again
    pub success_threshold: u32,
    /// Response status codes that count as failures (default: 500-599)
    pub failure_status_codes: Vec<u16>,
    /// Response time threshold in ms - responses slower than this count as failure
    pub response_time_threshold_ms: Option<u64>,
    /// Time window to track failures (sliding window)
    pub window_duration: Duration,
    /// Recovery interval - time to wait before retrying an unhealthy backend
    pub recovery_interval: Duration,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            failure_status_codes: (500..=599).collect(),
            response_time_threshold_ms: None,
            window_duration: Duration::from_secs(30),
            recovery_interval: Duration::from_secs(10),
        }
    }
}

/// Tracking state for a single backend
struct BackendState {
    /// Whether backend is considered healthy
    healthy: bool,
    /// Consecutive failures
    consecutive_failures: u32,
    /// Consecutive successes (after being marked unhealthy)
    consecutive_successes: u32,
    /// Time when backend was marked unhealthy
    unhealthy_since: Option<Instant>,
    /// Rolling window of request results
    window: SlidingWindow,
    /// Total requests
    total_requests: AtomicU64,
    /// Total failures
    total_failures: AtomicU64,
    /// Average response time in microseconds
    avg_response_time_us: AtomicU64,
}

impl BackendState {
    fn new(window_duration: Duration) -> Self {
        Self {
            healthy: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            unhealthy_since: None,
            window: SlidingWindow::new(window_duration),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
        }
    }
}

/// Sliding window for tracking recent requests
struct SlidingWindow {
    /// Duration of the window
    duration: Duration,
    /// Recent request outcomes (timestamp, is_failure)
    entries: Vec<(Instant, bool)>,
}

impl SlidingWindow {
    fn new(duration: Duration) -> Self {
        Self {
            duration,
            entries: Vec::new(),
        }
    }

    /// Add an entry and return (failure_count, total_count) in window
    fn add(&mut self, is_failure: bool) -> (usize, usize) {
        let now = Instant::now();
        let cutoff = now - self.duration;

        // Remove old entries
        self.entries.retain(|(ts, _)| *ts > cutoff);

        // Add new entry
        self.entries.push((now, is_failure));

        // Count failures
        let failure_count = self.entries.iter().filter(|(_, f)| *f).count();
        (failure_count, self.entries.len())
    }

    fn failure_count(&self) -> usize {
        let now = Instant::now();
        let cutoff = now - self.duration;
        self.entries
            .iter()
            .filter(|(ts, f)| *ts > cutoff && *f)
            .count()
    }
}

impl PassiveHealthChecker {
    pub fn new(config: PassiveHealthConfig) -> Self {
        Self {
            config,
            backends: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Check if a backend is healthy
    pub fn is_healthy(&self, backend_url: &str) -> bool {
        let backends = self.backends.read();
        backends
            .get(backend_url)
            .map(|s| s.healthy)
            .unwrap_or(true)
    }

    /// Check if a backend can be tried (healthy or past recovery interval)
    pub fn can_try(&self, backend_url: &str) -> bool {
        let backends = self.backends.read();
        backends
            .get(backend_url)
            .map(|s| {
                if s.healthy {
                    return true;
                }
                // Check if recovery interval has passed
                if let Some(unhealthy_since) = s.unhealthy_since {
                    unhealthy_since.elapsed() >= self.config.recovery_interval
                } else {
                    false
                }
            })
            .unwrap_or(true)
    }

    /// Record a response from a backend
    pub fn record_response(
        &self,
        backend_url: &str,
        status_code: u16,
        response_time: Duration,
    ) -> HealthChange {
        let is_failure = self.is_failure(status_code, response_time);

        let mut backends = self.backends.write();
        let state = backends
            .entry(backend_url.to_string())
            .or_insert_with(|| BackendState::new(self.config.window_duration));

        // Update stats
        state.total_requests.fetch_add(1, Ordering::Relaxed);
        if is_failure {
            state.total_failures.fetch_add(1, Ordering::Relaxed);
        }

        // Update average response time (exponential moving average)
        let response_us = response_time.as_micros() as u64;
        let prev_avg = state.avg_response_time_us.load(Ordering::Relaxed);
        let new_avg = if prev_avg == 0 {
            response_us
        } else {
            // EMA with alpha = 0.1
            (prev_avg * 9 + response_us) / 10
        };
        state.avg_response_time_us.store(new_avg, Ordering::Relaxed);

        // Update sliding window
        let (failure_count, _total_count) = state.window.add(is_failure);

        // Update consecutive counts
        if is_failure {
            state.consecutive_failures += 1;
            state.consecutive_successes = 0;
        } else {
            state.consecutive_successes += 1;
            state.consecutive_failures = 0;
        }

        // Determine health state change
        let was_healthy = state.healthy;

        if state.healthy {
            // Check if should mark unhealthy
            if state.consecutive_failures >= self.config.failure_threshold
                || failure_count >= self.config.failure_threshold as usize
            {
                state.healthy = false;
                state.unhealthy_since = Some(Instant::now());
                state.consecutive_successes = 0;
                return HealthChange::BecameUnhealthy;
            }
        } else {
            // Check if should mark healthy again
            if state.consecutive_successes >= self.config.success_threshold {
                state.healthy = true;
                state.unhealthy_since = None;
                state.consecutive_failures = 0;
                return HealthChange::BecameHealthy;
            }
        }

        if was_healthy == state.healthy {
            HealthChange::NoChange
        } else if state.healthy {
            HealthChange::BecameHealthy
        } else {
            HealthChange::BecameUnhealthy
        }
    }

    /// Check if a response should be counted as a failure
    fn is_failure(&self, status_code: u16, response_time: Duration) -> bool {
        // Check status code
        if self.config.failure_status_codes.contains(&status_code) {
            return true;
        }

        // Check response time threshold
        if let Some(threshold_ms) = self.config.response_time_threshold_ms {
            if response_time.as_millis() as u64 > threshold_ms {
                return true;
            }
        }

        false
    }

    /// Get statistics for a backend
    pub fn get_stats(&self, backend_url: &str) -> Option<BackendStats> {
        let backends = self.backends.read();
        backends.get(backend_url).map(|s| BackendStats {
            healthy: s.healthy,
            total_requests: s.total_requests.load(Ordering::Relaxed),
            total_failures: s.total_failures.load(Ordering::Relaxed),
            avg_response_time_us: s.avg_response_time_us.load(Ordering::Relaxed),
            consecutive_failures: s.consecutive_failures,
            consecutive_successes: s.consecutive_successes,
            recent_failure_count: s.window.failure_count(),
        })
    }

    /// Get all backend statistics
    pub fn all_stats(&self) -> Vec<(String, BackendStats)> {
        let backends = self.backends.read();
        backends
            .iter()
            .map(|(url, s)| {
                (
                    url.clone(),
                    BackendStats {
                        healthy: s.healthy,
                        total_requests: s.total_requests.load(Ordering::Relaxed),
                        total_failures: s.total_failures.load(Ordering::Relaxed),
                        avg_response_time_us: s.avg_response_time_us.load(Ordering::Relaxed),
                        consecutive_failures: s.consecutive_failures,
                        consecutive_successes: s.consecutive_successes,
                        recent_failure_count: s.window.failure_count(),
                    },
                )
            })
            .collect()
    }
}

/// Result of recording a response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthChange {
    NoChange,
    BecameHealthy,
    BecameUnhealthy,
}

/// Statistics for a backend
#[derive(Debug, Clone)]
pub struct BackendStats {
    pub healthy: bool,
    pub total_requests: u64,
    pub total_failures: u64,
    pub avg_response_time_us: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub recent_failure_count: usize,
}

/// Builder for PassiveHealthConfig
pub struct PassiveHealthConfigBuilder {
    config: PassiveHealthConfig,
}

impl PassiveHealthConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: PassiveHealthConfig::default(),
        }
    }

    pub fn failure_threshold(mut self, threshold: u32) -> Self {
        self.config.failure_threshold = threshold;
        self
    }

    pub fn success_threshold(mut self, threshold: u32) -> Self {
        self.config.success_threshold = threshold;
        self
    }

    pub fn failure_status_codes(mut self, codes: Vec<u16>) -> Self {
        self.config.failure_status_codes = codes;
        self
    }

    pub fn response_time_threshold_ms(mut self, threshold_ms: u64) -> Self {
        self.config.response_time_threshold_ms = Some(threshold_ms);
        self
    }

    pub fn window_duration(mut self, duration: Duration) -> Self {
        self.config.window_duration = duration;
        self
    }

    pub fn recovery_interval(mut self, duration: Duration) -> Self {
        self.config.recovery_interval = duration;
        self
    }

    pub fn build(self) -> PassiveHealthConfig {
        self.config
    }
}

impl Default for PassiveHealthConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_health_default_healthy() {
        let checker = PassiveHealthChecker::new(PassiveHealthConfig::default());
        assert!(checker.is_healthy("http://backend:8080"));
    }

    #[test]
    fn test_passive_health_becomes_unhealthy() {
        let config = PassiveHealthConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let checker = PassiveHealthChecker::new(config);
        let backend = "http://backend:8080";

        // First two failures - still healthy
        checker.record_response(backend, 500, Duration::from_millis(100));
        checker.record_response(backend, 500, Duration::from_millis(100));
        assert!(checker.is_healthy(backend));

        // Third failure - becomes unhealthy
        let change = checker.record_response(backend, 500, Duration::from_millis(100));
        assert_eq!(change, HealthChange::BecameUnhealthy);
        assert!(!checker.is_healthy(backend));
    }

    #[test]
    fn test_passive_health_recovery() {
        let config = PassiveHealthConfig {
            failure_threshold: 2,
            success_threshold: 2,
            recovery_interval: Duration::from_millis(0), // Allow immediate retry
            ..Default::default()
        };
        let checker = PassiveHealthChecker::new(config);
        let backend = "http://backend:8080";

        // Make unhealthy
        checker.record_response(backend, 500, Duration::from_millis(100));
        checker.record_response(backend, 500, Duration::from_millis(100));
        assert!(!checker.is_healthy(backend));

        // First success
        checker.record_response(backend, 200, Duration::from_millis(100));
        assert!(!checker.is_healthy(backend)); // Still unhealthy

        // Second success - should become healthy
        let change = checker.record_response(backend, 200, Duration::from_millis(100));
        assert_eq!(change, HealthChange::BecameHealthy);
        assert!(checker.is_healthy(backend));
    }

    #[test]
    fn test_response_time_threshold() {
        let config = PassiveHealthConfig {
            failure_threshold: 2,
            response_time_threshold_ms: Some(100),
            ..Default::default()
        };
        let checker = PassiveHealthChecker::new(config);
        let backend = "http://backend:8080";

        // Slow responses count as failures
        checker.record_response(backend, 200, Duration::from_millis(150));
        checker.record_response(backend, 200, Duration::from_millis(150));
        assert!(!checker.is_healthy(backend));
    }

    #[test]
    fn test_custom_failure_codes() {
        let config = PassiveHealthConfig {
            failure_threshold: 2,
            failure_status_codes: vec![502, 503, 504],
            ..Default::default()
        };
        let checker = PassiveHealthChecker::new(config);
        let backend = "http://backend:8080";

        // 500 is not in the list, should not count as failure
        checker.record_response(backend, 500, Duration::from_millis(100));
        checker.record_response(backend, 500, Duration::from_millis(100));
        assert!(checker.is_healthy(backend));

        // 502 is in the list
        checker.record_response(backend, 502, Duration::from_millis(100));
        checker.record_response(backend, 502, Duration::from_millis(100));
        assert!(!checker.is_healthy(backend));
    }

    #[test]
    fn test_stats_tracking() {
        let checker = PassiveHealthChecker::new(PassiveHealthConfig::default());
        let backend = "http://backend:8080";

        checker.record_response(backend, 200, Duration::from_millis(50));
        checker.record_response(backend, 500, Duration::from_millis(100));
        checker.record_response(backend, 200, Duration::from_millis(75));

        let stats = checker.get_stats(backend).unwrap();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.total_failures, 1);
        assert!(stats.healthy);
    }

    #[test]
    fn test_config_builder() {
        let config = PassiveHealthConfigBuilder::new()
            .failure_threshold(10)
            .success_threshold(5)
            .response_time_threshold_ms(500)
            .build();

        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.success_threshold, 5);
        assert_eq!(config.response_time_threshold_ms, Some(500));
    }

    #[test]
    fn test_success_resets_consecutive_failures() {
        let config = PassiveHealthConfig {
            failure_threshold: 3,
            window_duration: Duration::from_secs(1), // Short window
            ..Default::default()
        };
        let checker = PassiveHealthChecker::new(config);
        let backend = "http://backend:8080";

        // Two failures
        checker.record_response(backend, 500, Duration::from_millis(100));
        checker.record_response(backend, 500, Duration::from_millis(100));
        assert!(checker.is_healthy(backend)); // Still healthy (2 < 3)

        // Success resets the consecutive count
        checker.record_response(backend, 200, Duration::from_millis(100));
        assert!(checker.is_healthy(backend));

        let stats = checker.get_stats(backend).unwrap();
        assert_eq!(stats.consecutive_failures, 0);
        assert_eq!(stats.consecutive_successes, 1);
    }
}
