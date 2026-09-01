//! Prometheus metrics collection for HTTP requests, backend health, and connection tracking.

use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram, SharedString};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Duration;

/// Allocation-free label for an HTTP method (all standard methods are static).
fn method_label(method: &str) -> SharedString {
    match method {
        "GET" => SharedString::const_str("GET"),
        "POST" => SharedString::const_str("POST"),
        "PUT" => SharedString::const_str("PUT"),
        "DELETE" => SharedString::const_str("DELETE"),
        "HEAD" => SharedString::const_str("HEAD"),
        "OPTIONS" => SharedString::const_str("OPTIONS"),
        "PATCH" => SharedString::const_str("PATCH"),
        "TRACE" => SharedString::const_str("TRACE"),
        "CONNECT" => SharedString::const_str("CONNECT"),
        other => SharedString::from_owned(other.to_string()),
    }
}

/// Allocation-free label for a status code, backed by a lazily built table.
fn status_label(status: u16) -> SharedString {
    static TABLE: OnceLock<Vec<String>> = OnceLock::new();
    let table = TABLE.get_or_init(|| (0u16..600).map(|s| s.to_string()).collect());
    match table.get(status as usize) {
        Some(s) => SharedString::const_str(s.as_str()),
        None => SharedString::from_owned(status.to_string()),
    }
}

/// Register all metric descriptions with the global recorder.
pub fn init_metrics() {
    describe_counter!(
        "http_requests_total",
        "Total number of HTTP requests processed"
    );
    describe_histogram!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds"
    );
    describe_counter!(
        "backend_requests_total",
        "Total number of requests sent to backends"
    );
    describe_histogram!(
        "backend_request_duration_seconds",
        "Backend request duration in seconds"
    );
    describe_gauge!("backend_health", "Backend health status (1=healthy, 0=unhealthy)");
    describe_gauge!("active_connections", "Number of active connections");
    describe_gauge!("connection_pool_size", "Size of connection pool");
}

/// Start a Prometheus HTTP scrape endpoint on the given address.
pub fn start_metrics_server(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = addr.parse()?;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    init_metrics();

    Ok(())
}

/// Install the Prometheus recorder and return a handle for manual metric rendering.
pub fn get_prometheus_handle() -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    init_metrics();
    Ok(handle)
}

/// Static helper for recording proxy metrics (requests, backends, connections).
pub struct Metrics;

impl Metrics {
    /// Record an incoming HTTP request
    #[inline]
    pub fn record_request(
        entrypoint: &str,
        router: &str,
        service: &str,
        method: &str,
        status: u16,
        duration: Duration,
    ) {
        let labels = [
            ("entrypoint", SharedString::from_owned(entrypoint.to_string())),
            ("router", SharedString::from_owned(router.to_string())),
            ("service", SharedString::from_owned(service.to_string())),
            ("method", method_label(method)),
            ("status", status_label(status)),
        ];

        counter!("http_requests_total", &labels).increment(1);
        histogram!("http_request_duration_seconds", &labels).record(duration.as_secs_f64());
    }

    /// Record a backend request
    #[inline]
    pub fn record_backend_request(service: &str, server: &str, status: u16, duration: Duration) {
        let labels = [
            ("service", SharedString::from_owned(service.to_string())),
            ("server", SharedString::from_owned(server.to_string())),
            ("status", status_label(status)),
        ];

        counter!("backend_requests_total", &labels).increment(1);
        histogram!("backend_request_duration_seconds", &labels).record(duration.as_secs_f64());
    }

    /// Set backend health status
    #[inline]
    pub fn set_backend_health(service: &str, server: &str, healthy: bool) {
        let labels = [
            ("service", service.to_string()),
            ("server", server.to_string()),
        ];

        gauge!("backend_health", &labels).set(if healthy { 1.0 } else { 0.0 });
    }

    /// Record connection pool size
    #[inline]
    pub fn record_connection_pool_size(service: &str, size: usize) {
        let labels = [("service", service.to_string())];
        gauge!("connection_pool_size", &labels).set(size as f64);
    }

    /// Record active connections
    #[inline]
    pub fn record_active_connections(entrypoint: &str, count: usize) {
        let labels = [("entrypoint", entrypoint.to_string())];
        gauge!("active_connections", &labels).set(count as f64);
    }
}

/// Convenience timer that records request duration on drop via `finish()`.
pub struct RequestTimer {
    start: std::time::Instant,
    entrypoint: String,
    router: String,
    service: String,
    method: String,
}

impl RequestTimer {
    /// Start a new request timer with the given labels.
    pub fn new(entrypoint: &str, router: &str, service: &str, method: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            entrypoint: entrypoint.to_string(),
            router: router.to_string(),
            service: service.to_string(),
            method: method.to_string(),
        }
    }

    /// Stop the timer and record the request duration with the given HTTP status.
    pub fn finish(self, status: u16) {
        let duration = self.start.elapsed();
        Metrics::record_request(
            &self.entrypoint,
            &self.router,
            &self.service,
            &self.method,
            status,
            duration,
        );
    }
}
