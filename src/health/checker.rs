use super::HealthStatus;
use crate::config::HealthCheck;
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, timeout};
use tracing::{debug, warn};

pub struct HealthChecker {
    config: HealthCheck,
    server_url: String,
    status: Arc<HealthStatus>,
    client: Client<HttpConnector, http_body_util::Empty<Bytes>>,
}

impl HealthChecker {
    pub fn new(config: HealthCheck, server_url: String, status: Arc<HealthStatus>) -> Self {
        let connector = HttpConnector::new();
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .build(connector);

        Self {
            config,
            server_url,
            status,
            client,
        }
    }

    pub async fn start(self) {
        let interval_duration = self.config.interval.as_std();
        let check_timeout = self.config.timeout.as_std();
        // Traefik doesn't have threshold concepts, so we use sensible defaults
        let healthy_threshold = 2u32;
        let unhealthy_threshold = 3u32;

        let mut ticker = interval(interval_duration);

        loop {
            ticker.tick().await;

            let result = timeout(check_timeout, self.perform_http_check()).await;

            match result {
                Ok(Ok(())) => {
                    self.status.record_success();
                    let successes = self
                        .status
                        .consecutive_successes
                        .load(Ordering::Relaxed);

                    if !self.status.is_healthy() && successes >= healthy_threshold {
                        self.status.mark_healthy();
                        debug!("Server {} is now healthy", self.server_url);
                    }
                }
                Ok(Err(e)) => {
                    self.status.record_failure(e.clone());
                    let failures = self.status.consecutive_failures.load(Ordering::Relaxed);

                    if self.status.is_healthy() && failures >= unhealthy_threshold {
                        self.status.mark_unhealthy();
                        warn!("Server {} is now unhealthy: {}", self.server_url, e);
                    }
                }
                Err(_) => {
                    self.status.record_failure("Timeout".to_string());
                    let failures = self.status.consecutive_failures.load(Ordering::Relaxed);

                    if self.status.is_healthy() && failures >= unhealthy_threshold {
                        self.status.mark_unhealthy();
                        warn!("Server {} is now unhealthy: timeout", self.server_url);
                    }
                }
            }
        }
    }

    async fn perform_http_check(&self) -> Result<(), String> {
        let scheme = self.config.scheme.as_deref().unwrap_or("http");
        let check_url = format!(
            "{}://{}{}",
            scheme,
            self.server_url.trim_start_matches("http://").trim_start_matches("https://").trim_end_matches('/'),
            self.config.path
        );

        let uri: hyper::Uri = check_url
            .parse()
            .map_err(|e| format!("Invalid URL: {}", e))?;

        let method = self
            .config
            .method
            .as_ref()
            .map(|m| m.parse().unwrap_or(Method::GET))
            .unwrap_or(Method::GET);

        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("user-agent", "traffic-management-health-checker/1.0")
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| format!("Failed to build request: {}", e))?;

        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = response.status();

        // Check against expected status if specified
        if let Some(expected) = self.config.status {
            if status.as_u16() != expected {
                return Err(format!("Expected status {}, got {}", expected, status));
            }
            return Ok(());
        }

        // Default: success or 404 is considered healthy
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else if status.is_server_error() {
            Err(format!("Server error: {}", status))
        } else {
            // 4xx other than 404 might still mean the service is up
            Ok(())
        }
    }
}
