use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hyper::HeaderMap;
use std::collections::HashMap;

// Re-implement minimal versions for benchmarking without full crate dependency
// This allows isolated benchmarking of core algorithms

mod rule_bench {
    use regex::Regex;

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub enum Rule {
        Host(String),
        HostRegex(Regex),
        PathPrefix(String),
        PathRegex(Regex),
        And(Box<Rule>, Box<Rule>),
        Or(Box<Rule>, Box<Rule>),
    }

    impl Rule {
        pub fn matches(&self, host: Option<&str>, path: &str) -> bool {
            match self {
                Rule::Host(expected) => {
                    host.map(|h| h.eq_ignore_ascii_case(expected))
                        .unwrap_or(false)
                }
                Rule::HostRegex(re) => host.map(|h| re.is_match(h)).unwrap_or(false),
                Rule::PathPrefix(prefix) => path.starts_with(prefix),
                Rule::PathRegex(re) => re.is_match(path),
                Rule::And(a, b) => a.matches(host, path) && b.matches(host, path),
                Rule::Or(a, b) => a.matches(host, path) || b.matches(host, path),
            }
        }
    }
}

fn router_matching_benchmark(c: &mut Criterion) {
    use rule_bench::Rule;

    let mut group = c.benchmark_group("router_matching");

    // Simple host match
    let host_rule = Rule::Host("example.com".to_string());

    group.bench_function("host_match_hit", |b| {
        b.iter(|| {
            black_box(host_rule.matches(Some("example.com"), "/"))
        })
    });

    group.bench_function("host_match_miss", |b| {
        b.iter(|| {
            black_box(host_rule.matches(Some("other.com"), "/"))
        })
    });

    // Path prefix match
    let path_rule = Rule::PathPrefix("/api/v1".to_string());

    group.bench_function("path_prefix_hit", |b| {
        b.iter(|| {
            black_box(path_rule.matches(None, "/api/v1/users"))
        })
    });

    group.bench_function("path_prefix_miss", |b| {
        b.iter(|| {
            black_box(path_rule.matches(None, "/web/page"))
        })
    });

    // Regex path match
    let regex_rule = Rule::PathRegex(regex::Regex::new(r"^/api/v\d+/users/\d+$").unwrap());

    group.bench_function("path_regex_hit", |b| {
        b.iter(|| {
            black_box(regex_rule.matches(None, "/api/v1/users/12345"))
        })
    });

    group.bench_function("path_regex_miss", |b| {
        b.iter(|| {
            black_box(regex_rule.matches(None, "/api/v1/posts/abc"))
        })
    });

    // Complex combined rule: Host && PathPrefix
    let combined = Rule::And(
        Box::new(Rule::Host("api.example.com".to_string())),
        Box::new(Rule::PathPrefix("/v2".to_string())),
    );

    group.bench_function("combined_and_hit", |b| {
        b.iter(|| {
            black_box(combined.matches(Some("api.example.com"), "/v2/endpoint"))
        })
    });

    group.bench_function("combined_and_miss", |b| {
        b.iter(|| {
            black_box(combined.matches(Some("api.example.com"), "/v1/endpoint"))
        })
    });

    // Or rule with multiple hosts
    let or_rule = Rule::Or(
        Box::new(Rule::Host("a.example.com".to_string())),
        Box::new(Rule::Or(
            Box::new(Rule::Host("b.example.com".to_string())),
            Box::new(Rule::Host("c.example.com".to_string())),
        )),
    );

    group.bench_function("multi_host_or_first", |b| {
        b.iter(|| {
            black_box(or_rule.matches(Some("a.example.com"), "/"))
        })
    });

    group.bench_function("multi_host_or_last", |b| {
        b.iter(|| {
            black_box(or_rule.matches(Some("c.example.com"), "/"))
        })
    });

    group.bench_function("multi_host_or_miss", |b| {
        b.iter(|| {
            black_box(or_rule.matches(Some("d.example.com"), "/"))
        })
    });

    group.finish();
}

fn load_balancer_benchmark(c: &mut Criterion) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut group = c.benchmark_group("load_balancer");

    // Simulate round-robin selection
    let counter = AtomicUsize::new(0);
    let backends = vec!["backend1", "backend2", "backend3", "backend4"];

    group.bench_function("round_robin_4_backends", |b| {
        b.iter(|| {
            let idx = counter.fetch_add(1, Ordering::Relaxed) % backends.len();
            black_box(backends[idx])
        })
    });

    // Simulate weighted selection (smooth weighted round-robin)
    struct WeightedBackend {
        addr: &'static str,
        weight: i32,
        current_weight: std::cell::Cell<i32>,
    }

    let weighted_backends = vec![
        WeightedBackend {
            addr: "backend1",
            weight: 5,
            current_weight: std::cell::Cell::new(0),
        },
        WeightedBackend {
            addr: "backend2",
            weight: 3,
            current_weight: std::cell::Cell::new(0),
        },
        WeightedBackend {
            addr: "backend3",
            weight: 2,
            current_weight: std::cell::Cell::new(0),
        },
    ];
    let total_weight: i32 = weighted_backends.iter().map(|b| b.weight).sum();

    group.bench_function("smooth_weighted_rr", |b| {
        b.iter(|| {
            // Smooth weighted round-robin algorithm
            let mut best_idx = 0;
            let mut best_weight = i32::MIN;

            for (idx, backend) in weighted_backends.iter().enumerate() {
                let new_weight = backend.current_weight.get() + backend.weight;
                backend.current_weight.set(new_weight);

                if new_weight > best_weight {
                    best_weight = new_weight;
                    best_idx = idx;
                }
            }

            weighted_backends[best_idx]
                .current_weight
                .set(weighted_backends[best_idx].current_weight.get() - total_weight);

            black_box(weighted_backends[best_idx].addr)
        })
    });

    // Simulate least connections (using atomic counters)
    let conn_counts: Vec<AtomicUsize> = (0..4).map(|_| AtomicUsize::new(0)).collect();

    group.bench_function("least_connections", |b| {
        b.iter(|| {
            let (idx, _) = conn_counts
                .iter()
                .enumerate()
                .min_by_key(|(_, count)| count.load(Ordering::Relaxed))
                .unwrap();
            conn_counts[idx].fetch_add(1, Ordering::Relaxed);
            black_box(idx)
        })
    });

    group.finish();
}

fn connection_pool_benchmark(c: &mut Criterion) {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    let mut group = c.benchmark_group("connection_pool");

    // Simulate connection pool operations
    struct MockPool {
        connections: Mutex<VecDeque<usize>>,
    }

    impl MockPool {
        fn new(size: usize) -> Self {
            let connections = (0..size).collect();
            Self {
                connections: Mutex::new(connections),
            }
        }

        fn acquire(&self) -> Option<usize> {
            self.connections.lock().unwrap().pop_front()
        }

        fn release(&self, conn: usize) {
            self.connections.lock().unwrap().push_back(conn);
        }
    }

    let pool = MockPool::new(100);

    group.bench_function("pool_acquire_release", |b| {
        b.iter(|| {
            let conn = pool.acquire();
            black_box(&conn);
            if let Some(c) = conn {
                pool.release(c);
            }
        })
    });

    group.finish();
}

fn rate_limiter_benchmark(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut group = c.benchmark_group("rate_limiter");

    // Token bucket simulation
    struct TokenBucket {
        tokens: AtomicU64,
        max_tokens: u64,
    }

    impl TokenBucket {
        fn new(max_tokens: u64) -> Self {
            Self {
                tokens: AtomicU64::new(max_tokens),
                max_tokens,
            }
        }

        fn try_acquire(&self) -> bool {
            // Simplified - just check and decrement
            loop {
                let current = self.tokens.load(Ordering::Relaxed);
                if current == 0 {
                    return false;
                }
                if self
                    .tokens
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            }
        }

        fn refill(&self) {
            self.tokens.store(self.max_tokens, Ordering::Relaxed);
        }
    }

    let limiter = TokenBucket::new(1000);

    group.bench_function("token_bucket_acquire", |b| {
        b.iter(|| {
            let result = limiter.try_acquire();
            black_box(result)
        });
        limiter.refill(); // Reset after bench
    });

    // IP-based rate limiting with HashMap lookup
    let mut ip_limits: HashMap<&str, AtomicU64> = HashMap::new();
    for i in 0..1000 {
        let ip = Box::leak(format!("192.168.1.{}", i % 256).into_boxed_str());
        ip_limits.insert(ip, AtomicU64::new(100));
    }

    let test_ip = "192.168.1.50";

    group.bench_function("ip_rate_limit_lookup", |b| {
        b.iter(|| {
            if let Some(limit) = ip_limits.get(test_ip) {
                let current = limit.load(Ordering::Relaxed);
                if current > 0 {
                    limit.fetch_sub(1, Ordering::Relaxed);
                    black_box(true)
                } else {
                    black_box(false)
                }
            } else {
                black_box(true)
            }
        })
    });

    group.finish();
}

fn header_manipulation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_manipulation");

    group.bench_function("header_map_insert", |b| {
        b.iter(|| {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", "192.168.1.1".parse().unwrap());
            headers.insert("x-request-id", "abc123".parse().unwrap());
            headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());
            black_box(headers)
        })
    });

    let mut base_headers = HeaderMap::new();
    base_headers.insert("content-type", "application/json".parse().unwrap());
    base_headers.insert("authorization", "Bearer token123".parse().unwrap());
    base_headers.insert("accept", "*/*".parse().unwrap());
    base_headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

    group.bench_function("header_map_get", |b| {
        b.iter(|| {
            let ct = base_headers.get("content-type");
            let auth = base_headers.get("authorization");
            black_box((ct, auth))
        })
    });

    group.bench_function("header_map_contains", |b| {
        b.iter(|| {
            let has_auth = base_headers.contains_key("authorization");
            let has_missing = base_headers.contains_key("x-custom-header");
            black_box((has_auth, has_missing))
        })
    });

    group.finish();
}

fn circuit_breaker_benchmark(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

    let mut group = c.benchmark_group("circuit_breaker");

    // Circuit breaker state machine
    const CLOSED: u8 = 0;
    const OPEN: u8 = 1;
    #[allow(dead_code)]
    const HALF_OPEN: u8 = 2;

    struct CircuitBreaker {
        state: AtomicU8,
        failure_count: AtomicU32,
        failure_threshold: u32,
    }

    impl CircuitBreaker {
        fn new(threshold: u32) -> Self {
            Self {
                state: AtomicU8::new(CLOSED),
                failure_count: AtomicU32::new(0),
                failure_threshold: threshold,
            }
        }

        fn can_execute(&self) -> bool {
            self.state.load(Ordering::Relaxed) != OPEN
        }

        fn record_success(&self) {
            self.failure_count.store(0, Ordering::Relaxed);
            self.state.store(CLOSED, Ordering::Relaxed);
        }

        fn record_failure(&self) {
            let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
            if failures >= self.failure_threshold {
                self.state.store(OPEN, Ordering::Relaxed);
            }
        }
    }

    let cb = CircuitBreaker::new(5);

    group.bench_function("circuit_breaker_check", |b| {
        b.iter(|| {
            black_box(cb.can_execute())
        })
    });

    group.bench_function("circuit_breaker_record_success", |b| {
        b.iter(|| {
            cb.record_success();
            black_box(())
        })
    });

    group.bench_function("circuit_breaker_record_failure", |b| {
        b.iter(|| {
            cb.record_failure();
        });
        // Reset
        cb.failure_count.store(0, Ordering::Relaxed);
        cb.state.store(CLOSED, Ordering::Relaxed);
    });

    group.finish();
}

fn throughput_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_simulation");

    // Simulate the core request path without actual network I/O
    // This measures the proxy's internal overhead

    #[allow(dead_code)]
    struct RequestContext {
        host: String,
        path: String,
        method: String,
    }

    let contexts: Vec<RequestContext> = (0..1000)
        .map(|i| RequestContext {
            host: format!("service{}.example.com", i % 10),
            path: format!("/api/v1/resource/{}", i),
            method: "GET".to_string(),
        })
        .collect();

    // Simple router simulation
    let routes: Vec<(&str, &str)> = vec![
        ("service0.example.com", "backend-0"),
        ("service1.example.com", "backend-1"),
        ("service2.example.com", "backend-2"),
        ("service3.example.com", "backend-3"),
        ("service4.example.com", "backend-4"),
        ("service5.example.com", "backend-5"),
        ("service6.example.com", "backend-6"),
        ("service7.example.com", "backend-7"),
        ("service8.example.com", "backend-8"),
        ("service9.example.com", "backend-9"),
    ];

    group.throughput(Throughput::Elements(1));

    group.bench_function("request_routing_overhead", |b| {
        let mut idx = 0;
        b.iter(|| {
            let ctx = &contexts[idx % contexts.len()];
            idx += 1;

            // Route lookup
            let backend = routes
                .iter()
                .find(|(host, _)| *host == ctx.host)
                .map(|(_, backend)| *backend);

            black_box(backend)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    router_matching_benchmark,
    load_balancer_benchmark,
    connection_pool_benchmark,
    rate_limiter_benchmark,
    header_manipulation_benchmark,
    circuit_breaker_benchmark,
    throughput_simulation,
);

criterion_main!(benches);
