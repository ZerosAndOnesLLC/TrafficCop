use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Duration;

/// Initialize metrics with descriptions
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

/// Start Prometheus metrics server on given address
pub fn start_metrics_server(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = addr.parse()?;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    init_metrics();

    Ok(())
}

/// Get a Prometheus handle for manual scraping
pub fn get_prometheus_handle() -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    init_metrics();
    Ok(handle)
}

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
            ("entrypoint", entrypoint.to_string()),
            ("router", router.to_string()),
            ("service", service.to_string()),
            ("method", method.to_string()),
            ("status", status.to_string()),
        ];

        counter!("http_requests_total", &labels).increment(1);
        histogram!("http_request_duration_seconds", &labels).record(duration.as_secs_f64());
    }

    /// Record a backend request
    #[inline]
    pub fn record_backend_request(service: &str, server: &str, status: u16, duration: Duration) {
        let labels = [
            ("service", service.to_string()),
            ("server", server.to_string()),
            ("status", status.to_string()),
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

/// Timer for request duration tracking
pub struct RequestTimer {
    start: std::time::Instant,
    entrypoint: String,
    router: String,
    service: String,
    method: String,
}

impl RequestTimer {
    pub fn new(entrypoint: &str, router: &str, service: &str, method: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            entrypoint: entrypoint.to_string(),
            router: router.to_string(),
            service: service.to_string(),
            method: method.to_string(),
        }
    }

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
