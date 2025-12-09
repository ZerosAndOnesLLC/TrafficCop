use crate::config::RateLimitConfig;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// High-performance token bucket rate limiter
/// Uses lock-free atomic operations for the hot path
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    buckets: DashMap<IpAddr, TokenBucket>,
    #[allow(dead_code)]
    cleanup_interval: Duration,
}

struct TokenBucket {
    tokens: AtomicU64,
    last_update: AtomicU64, // Stored as nanos since some epoch
    epoch: Instant,
}

impl TokenBucket {
    fn new(initial_tokens: u64) -> Self {
        Self {
            tokens: AtomicU64::new(initial_tokens * 1000), // Store as millis for precision
            last_update: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    #[inline]
    fn try_acquire(&self, tokens_per_sec: u64, burst: u64) -> bool {
        let now_nanos = self.epoch.elapsed().as_nanos() as u64;
        let last = self.last_update.swap(now_nanos, Ordering::Relaxed);

        // Calculate tokens to add based on time elapsed
        let elapsed_millis = (now_nanos.saturating_sub(last)) / 1_000_000;
        let tokens_to_add = (elapsed_millis * tokens_per_sec) / 1000;

        let max_tokens = burst * 1000;

        // Add tokens (capped at burst)
        let current = self.tokens.load(Ordering::Relaxed);
        let new_tokens = (current + tokens_to_add).min(max_tokens);

        // Try to take one token
        if new_tokens >= 1000 {
            // Try compare-and-swap
            if self
                .tokens
                .compare_exchange(
                    current,
                    new_tokens - 1000,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
            // CAS failed, try again with updated value
            let current = self.tokens.load(Ordering::Relaxed);
            if current >= 1000 {
                self.tokens.fetch_sub(1000, Ordering::Relaxed);
                return true;
            }
        }

        false
    }
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: DashMap::with_capacity(10000),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Check if request from IP is allowed
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let bucket = self.buckets.entry(ip).or_insert_with(|| {
            TokenBucket::new(self.config.burst.max(self.config.average))
        });

        bucket.try_acquire(self.config.average, self.config.burst.max(1))
    }

    /// Get remaining tokens for an IP (for headers)
    pub fn remaining(&self, ip: IpAddr) -> u64 {
        self.buckets
            .get(&ip)
            .map(|b| b.tokens.load(Ordering::Relaxed) / 1000)
            .unwrap_or(self.config.burst)
    }

    /// Clean up old buckets to prevent memory growth
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            let last_nanos = bucket.last_update.load(Ordering::Relaxed);
            let last_instant = bucket.epoch + Duration::from_nanos(last_nanos);
            now.duration_since(last_instant) < max_age
        });
    }

    /// Get current bucket count (for metrics)
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Duration as ConfigDuration;

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let config = RateLimitConfig {
            average: 10,
            burst: 10,
            period: ConfigDuration::from_secs(1),
            source_criterion: None,
        };
        let limiter = RateLimitMiddleware::new(config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should allow burst requests
        for _ in 0..10 {
            assert!(limiter.is_allowed(ip));
        }
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let config = RateLimitConfig {
            average: 1,
            burst: 2,
            period: ConfigDuration::from_secs(1),
            source_criterion: None,
        };
        let limiter = RateLimitMiddleware::new(config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Exhaust burst
        assert!(limiter.is_allowed(ip));
        assert!(limiter.is_allowed(ip));

        // Should be blocked
        assert!(!limiter.is_allowed(ip));
    }
}
