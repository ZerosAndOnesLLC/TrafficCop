use crate::config::RateLimitConfig;
use crate::store::Store;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// High-performance token bucket rate limiter with optional distributed backing
///
/// In local mode: Pure in-memory, lock-free atomic operations
/// In distributed mode: Local cache with async sync to Valkey/Redis
///
/// Design: Eventual consistency for performance
/// - Local cache handles most requests (sub-microsecond)
/// - Background sync to distributed store every ~100ms
/// - ~1-5% variance in rate limits across cluster (acceptable tradeoff)
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    /// Local token buckets for fast path
    buckets: DashMap<String, TokenBucket>,
    /// Distributed store (optional)
    store: Option<Arc<dyn Store>>,
    /// Sync interval for distributed mode
    sync_interval: Duration,
    /// Last sync time per key
    last_sync: DashMap<String, Instant>,
    /// Cleanup interval
    cleanup_interval: Duration,
}

struct TokenBucket {
    tokens: AtomicU64,
    last_update: AtomicU64, // Stored as nanos since some epoch
    epoch: Instant,
    /// Track requests since last sync (for distributed mode)
    requests_since_sync: AtomicU64,
}

impl TokenBucket {
    fn new(initial_tokens: u64) -> Self {
        Self {
            tokens: AtomicU64::new(initial_tokens * 1000), // Store as millis for precision
            last_update: AtomicU64::new(0),
            epoch: Instant::now(),
            requests_since_sync: AtomicU64::new(0),
        }
    }

    #[inline]
    fn try_acquire(&self, tokens_per_sec: u64, burst: u64) -> bool {
        let now_nanos = self.epoch.elapsed().as_nanos() as u64;
        let max_tokens = burst * 1000;

        // CAS loop with retry limit to prevent livelock
        for _ in 0..8 {
            let last = self.last_update.load(Ordering::Relaxed);

            // Calculate tokens to add based on time elapsed
            let elapsed_millis = (now_nanos.saturating_sub(last)) / 1_000_000;
            let tokens_to_add = (elapsed_millis * tokens_per_sec) / 1000;

            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(max_tokens);

            // Not enough tokens
            if new_tokens < 1000 {
                return false;
            }

            // Try to atomically consume one token
            if self
                .tokens
                .compare_exchange_weak(
                    current,
                    new_tokens - 1000,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // Update timestamp via CAS (best-effort, avoids stealing other threads' elapsed time)
                let _ = self.last_update.compare_exchange(
                    last,
                    now_nanos,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                self.requests_since_sync.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            // CAS failed — another thread modified tokens; retry with fresh values
        }

        // All retries exhausted — reject to prevent livelock
        false
    }

    fn remaining(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed) / 1000
    }

    #[allow(dead_code)]
    fn reset_sync_counter(&self) -> u64 {
        self.requests_since_sync.swap(0, Ordering::Relaxed)
    }
}

impl RateLimitMiddleware {
    /// Create a local-only rate limiter from config.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: DashMap::with_capacity(10000),
            store: None,
            sync_interval: Duration::from_millis(100),
            last_sync: DashMap::new(),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Create with distributed store backing
    pub fn with_store(config: RateLimitConfig, store: Arc<dyn Store>) -> Self {
        Self {
            config,
            buckets: DashMap::with_capacity(10000),
            store: Some(store),
            sync_interval: Duration::from_millis(100),
            last_sync: DashMap::new(),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Check if request is allowed (fast path - local only)
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let key = ip.to_string();
        self.is_allowed_by_key(&key)
    }

    /// Check if request is allowed by arbitrary key
    #[inline]
    pub fn is_allowed_by_key(&self, key: &str) -> bool {
        let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(self.config.burst.max(self.config.average))
        });

        let allowed = bucket.try_acquire(self.config.average, self.config.burst.max(1));

        // Schedule async sync if we have a distributed store
        if self.store.is_some() {
            self.maybe_schedule_sync(key);
        }

        allowed
    }

    /// Check if request is allowed (async version with distributed check)
    /// Use this for strict rate limiting where cluster-wide accuracy matters
    pub async fn is_allowed_distributed(&self, ip: IpAddr) -> bool {
        let key = ip.to_string();
        self.is_allowed_distributed_by_key(&key).await
    }

    /// Check if request is allowed by key (async with distributed check)
    pub async fn is_allowed_distributed_by_key(&self, key: &str) -> bool {
        // First check local cache
        let local_allowed = self.is_allowed_by_key(key);

        // If local says no, trust it (fail fast)
        if !local_allowed {
            return false;
        }

        // If we have a distributed store, also check there
        if let Some(store) = &self.store {
            let window_secs = self.config.period.as_std().as_secs().max(1);

            match store.rate_limit_check(key, self.config.average, window_secs).await {
                Ok((allowed, _remaining, _reset)) => {
                    if !allowed {
                        debug!("Distributed rate limit exceeded for key: {}", key);
                    }
                    allowed
                }
                Err(e) => {
                    // If store is unavailable, fall back to local decision
                    warn!("Distributed rate limit check failed: {}, using local result", e);
                    local_allowed
                }
            }
        } else {
            local_allowed
        }
    }

    /// Get remaining tokens for an IP (for headers)
    pub fn remaining(&self, ip: IpAddr) -> u64 {
        let key = ip.to_string();
        self.remaining_by_key(&key)
    }

    /// Get remaining tokens by key
    pub fn remaining_by_key(&self, key: &str) -> u64 {
        self.buckets
            .get(key)
            .map(|b| b.remaining())
            .unwrap_or(self.config.burst)
    }

    /// Get remaining tokens from distributed store
    pub async fn remaining_distributed(&self, ip: IpAddr) -> u64 {
        let key = ip.to_string();

        if let Some(store) = &self.store {
            match store.rate_limit_remaining(&key, self.config.average).await {
                Ok(remaining) => remaining,
                Err(_) => self.remaining_by_key(&key),
            }
        } else {
            self.remaining_by_key(&key)
        }
    }

    /// Clean up old buckets to prevent memory growth
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            let last_nanos = bucket.last_update.load(Ordering::Relaxed);
            let last_instant = bucket.epoch + Duration::from_nanos(last_nanos);
            now.duration_since(last_instant) < max_age
        });

        self.last_sync.retain(|_, last| {
            now.duration_since(*last) < max_age
        });
    }

    /// Get current bucket count (for metrics)
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Check if we should sync to distributed store
    fn maybe_schedule_sync(&self, key: &str) {
        let now = Instant::now();
        let should_sync = self.last_sync
            .get(key)
            .map(|last| now.duration_since(*last) >= self.sync_interval)
            .unwrap_or(true);

        if should_sync {
            self.last_sync.insert(key.to_string(), now);

            // Spawn async sync task
            if let Some(store) = self.store.clone() {
                let key = key.to_string();
                let limit = self.config.average;
                let window_secs = self.config.period.as_std().as_secs().max(1);

                tokio::spawn(async move {
                    // Just record the request in distributed store
                    // We don't block on the result
                    let _ = store.rate_limit_check(&key, limit, window_secs).await;
                });
            }
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;
                self.cleanup(Duration::from_secs(120));
            }
        });
    }
}

/// Distributed rate limiter that uses the store directly
/// Use this when you need strict cluster-wide rate limiting
#[allow(dead_code)]
pub struct DistributedRateLimiter {
    store: Arc<dyn Store>,
    limit: u64,
    window_secs: u64,
}

#[allow(dead_code)]
impl DistributedRateLimiter {
    /// Create a distributed rate limiter backed by the given store.
    pub fn new(store: Arc<dyn Store>, limit: u64, window_secs: u64) -> Self {
        Self {
            store,
            limit,
            window_secs,
        }
    }

    /// Check if request is allowed (hits store every time)
    pub async fn is_allowed(&self, key: &str) -> Result<RateLimitResult, crate::store::StoreError> {
        let (allowed, remaining, reset_time) = self.store
            .rate_limit_check(key, self.limit, self.window_secs)
            .await?;

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_time,
            limit: self.limit,
        })
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub reset_time: u64,
    pub limit: u64,
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

    #[test]
    fn test_rate_limit_by_key() {
        let config = RateLimitConfig {
            average: 5,
            burst: 5,
            period: ConfigDuration::from_secs(1),
            source_criterion: None,
        };
        let limiter = RateLimitMiddleware::new(config);

        // Different keys should have separate buckets
        for _ in 0..5 {
            assert!(limiter.is_allowed_by_key("user:1"));
            assert!(limiter.is_allowed_by_key("user:2"));
        }

        // Both should now be exhausted
        assert!(!limiter.is_allowed_by_key("user:1"));
        assert!(!limiter.is_allowed_by_key("user:2"));
    }

    #[test]
    fn test_concurrent_cas_no_underflow() {
        use std::sync::Arc;
        use std::thread;

        let config = RateLimitConfig {
            average: 100,
            burst: 100,
            period: ConfigDuration::from_secs(1),
            source_criterion: None,
        };
        let limiter = Arc::new(RateLimitMiddleware::new(config));

        let mut handles = vec![];
        let allowed_count = Arc::new(AtomicU64::new(0));

        for _ in 0..100 {
            let limiter = Arc::clone(&limiter);
            let allowed_count = Arc::clone(&allowed_count);
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    if limiter.is_allowed_by_key("stress-test") {
                        allowed_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let total_allowed = allowed_count.load(Ordering::Relaxed);
        // Should never exceed burst (100) by more than a small margin from token refill
        assert!(total_allowed <= 110, "allowed {} requests, expected <= 110", total_allowed);

        // Verify no underflow: remaining tokens should be reasonable (not quintillions)
        let remaining = limiter.remaining_by_key("stress-test");
        assert!(remaining <= 100, "remaining {} tokens, suspected underflow", remaining);
    }

    #[test]
    fn test_remaining_tokens() {
        let config = RateLimitConfig {
            average: 10,
            burst: 10,
            period: ConfigDuration::from_secs(1),
            source_criterion: None,
        };
        let limiter = RateLimitMiddleware::new(config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert_eq!(limiter.remaining(ip), 10);

        limiter.is_allowed(ip);
        assert_eq!(limiter.remaining(ip), 9);

        for _ in 0..9 {
            limiter.is_allowed(ip);
        }
        assert_eq!(limiter.remaining(ip), 0);
    }
}
