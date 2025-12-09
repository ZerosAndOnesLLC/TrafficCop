use crate::config::RetryConfig;
use std::time::Duration;

/// Retry middleware with exponential backoff
pub struct RetryMiddleware {
    max_attempts: u32,
    initial_interval: Duration,
    max_interval: Duration,
    multiplier: f64,
}

impl RetryMiddleware {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            max_attempts: config.attempts.max(1),
            initial_interval: Duration::from_millis(config.initial_interval_ms),
            max_interval: Duration::from_secs(30), // Cap at 30 seconds
            multiplier: 2.0,
        }
    }

    /// Get the number of retry attempts allowed
    #[inline]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Calculate delay for a given attempt (0-indexed)
    #[inline]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let delay_ms = self.initial_interval.as_millis() as f64
            * self.multiplier.powi(attempt.saturating_sub(1) as i32);

        let delay = Duration::from_millis(delay_ms as u64);
        delay.min(self.max_interval)
    }

    /// Check if a status code is retryable
    #[inline]
    pub fn is_retryable_status(status: u16) -> bool {
        matches!(status, 502 | 503 | 504 | 408 | 429)
    }

    /// Check if an error is retryable (connection errors, timeouts)
    #[inline]
    pub fn is_retryable_error(error: &str) -> bool {
        let error_lower = error.to_lowercase();
        error_lower.contains("connection")
            || error_lower.contains("timeout")
            || error_lower.contains("reset")
            || error_lower.contains("refused")
            || error_lower.contains("broken pipe")
    }

    /// Check if a request method is safe to retry (idempotent)
    #[inline]
    pub fn is_idempotent_method(method: &str) -> bool {
        matches!(
            method.to_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE"
        )
    }

    /// Should retry based on attempt number, status, and method
    #[inline]
    pub fn should_retry(&self, attempt: u32, status: u16, method: &str) -> bool {
        attempt < self.max_attempts
            && Self::is_retryable_status(status)
            && Self::is_idempotent_method(method)
    }

    /// Should retry based on error and method
    #[inline]
    pub fn should_retry_error(&self, attempt: u32, error: &str, method: &str) -> bool {
        attempt < self.max_attempts
            && Self::is_retryable_error(error)
            && Self::is_idempotent_method(method)
    }
}

/// Iterator that yields delays for retry attempts
pub struct RetryIterator {
    middleware: RetryMiddleware,
    current_attempt: u32,
}

impl RetryIterator {
    pub fn new(middleware: RetryMiddleware) -> Self {
        Self {
            middleware,
            current_attempt: 0,
        }
    }
}

impl Iterator for RetryIterator {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_attempt >= self.middleware.max_attempts {
            return None;
        }

        let delay = self.middleware.delay_for_attempt(self.current_attempt);
        self.current_attempt += 1;
        Some(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> RetryConfig {
        RetryConfig {
            attempts: 3,
            initial_interval_ms: 100,
        }
    }

    #[test]
    fn test_delay_calculation() {
        let middleware = RetryMiddleware::new(make_config());

        // First attempt has no delay
        assert_eq!(middleware.delay_for_attempt(0), Duration::ZERO);

        // Second attempt: 100ms
        assert_eq!(middleware.delay_for_attempt(1), Duration::from_millis(100));

        // Third attempt: 200ms (100 * 2)
        assert_eq!(middleware.delay_for_attempt(2), Duration::from_millis(200));

        // Fourth attempt: 400ms (100 * 4)
        assert_eq!(middleware.delay_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_delay_capped_at_max() {
        let config = RetryConfig {
            attempts: 20,
            initial_interval_ms: 1000,
        };
        let middleware = RetryMiddleware::new(config);

        // Very high attempt should be capped at 30 seconds
        let delay = middleware.delay_for_attempt(15);
        assert!(delay <= Duration::from_secs(30));
    }

    #[test]
    fn test_retryable_status_codes() {
        assert!(RetryMiddleware::is_retryable_status(502));
        assert!(RetryMiddleware::is_retryable_status(503));
        assert!(RetryMiddleware::is_retryable_status(504));
        assert!(RetryMiddleware::is_retryable_status(429));
        assert!(RetryMiddleware::is_retryable_status(408));

        assert!(!RetryMiddleware::is_retryable_status(200));
        assert!(!RetryMiddleware::is_retryable_status(404));
        assert!(!RetryMiddleware::is_retryable_status(500));
    }

    #[test]
    fn test_idempotent_methods() {
        assert!(RetryMiddleware::is_idempotent_method("GET"));
        assert!(RetryMiddleware::is_idempotent_method("HEAD"));
        assert!(RetryMiddleware::is_idempotent_method("PUT"));
        assert!(RetryMiddleware::is_idempotent_method("DELETE"));
        assert!(RetryMiddleware::is_idempotent_method("OPTIONS"));

        assert!(!RetryMiddleware::is_idempotent_method("POST"));
        assert!(!RetryMiddleware::is_idempotent_method("PATCH"));
    }

    #[test]
    fn test_should_retry() {
        let middleware = RetryMiddleware::new(make_config());

        // Should retry: retryable status, idempotent method, within attempts
        assert!(middleware.should_retry(0, 503, "GET"));
        assert!(middleware.should_retry(1, 502, "PUT"));

        // Should not retry: max attempts reached
        assert!(!middleware.should_retry(3, 503, "GET"));

        // Should not retry: non-retryable status
        assert!(!middleware.should_retry(0, 500, "GET"));

        // Should not retry: non-idempotent method
        assert!(!middleware.should_retry(0, 503, "POST"));
    }

    #[test]
    fn test_retry_iterator() {
        let middleware = RetryMiddleware::new(make_config());
        let iter = RetryIterator::new(middleware);

        let delays: Vec<Duration> = iter.collect();
        assert_eq!(delays.len(), 3);
        assert_eq!(delays[0], Duration::ZERO);
        assert_eq!(delays[1], Duration::from_millis(100));
        assert_eq!(delays[2], Duration::from_millis(200));
    }
}
