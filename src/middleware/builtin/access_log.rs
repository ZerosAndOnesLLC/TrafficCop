use serde::Serialize;
use std::net::SocketAddr;
use std::time::Instant;
use tracing::info;

/// Structured access log entry
#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    /// Timestamp (RFC3339)
    pub timestamp: String,
    /// Remote client address
    pub remote_addr: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Query string (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Host header value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP status code
    pub status: u16,
    /// Response body size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<u64>,
    /// Request duration in milliseconds
    pub duration_ms: f64,
    /// User agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Referer header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    /// X-Forwarded-For (original client IP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_for: Option<String>,
    /// Request ID (if set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Matched route name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Backend service name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Backend server URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// TLS protocol version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// HTTP protocol version
    pub protocol: String,
}

impl AccessLogEntry {
    /// Log the entry using tracing
    pub fn log(&self) {
        // Use structured logging with tracing
        info!(
            remote_addr = %self.remote_addr,
            method = %self.method,
            path = %self.path,
            status = self.status,
            duration_ms = self.duration_ms,
            route = self.route.as_deref().unwrap_or("-"),
            service = self.service.as_deref().unwrap_or("-"),
            "access"
        );
    }

    /// Log as JSON string
    pub fn log_json(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            info!(target: "access_log", "{}", json);
        }
    }
}

/// Builder for creating access log entries
pub struct AccessLogBuilder {
    start: Instant,
    remote_addr: SocketAddr,
    method: String,
    path: String,
    query: Option<String>,
    host: Option<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    forwarded_for: Option<String>,
    request_id: Option<String>,
    protocol: String,
    is_tls: bool,
}

impl AccessLogBuilder {
    pub fn new(remote_addr: SocketAddr, method: &str, path: &str, protocol: &str) -> Self {
        Self {
            start: Instant::now(),
            remote_addr,
            method: method.to_string(),
            path: path.to_string(),
            query: None,
            host: None,
            user_agent: None,
            referer: None,
            forwarded_for: None,
            request_id: None,
            protocol: protocol.to_string(),
            is_tls: false,
        }
    }

    pub fn query(mut self, query: Option<&str>) -> Self {
        self.query = query.map(|s| s.to_string());
        self
    }

    pub fn host(mut self, host: Option<&str>) -> Self {
        self.host = host.map(|s| s.to_string());
        self
    }

    pub fn user_agent(mut self, ua: Option<&str>) -> Self {
        self.user_agent = ua.map(|s| s.to_string());
        self
    }

    pub fn referer(mut self, referer: Option<&str>) -> Self {
        self.referer = referer.map(|s| s.to_string());
        self
    }

    pub fn forwarded_for(mut self, xff: Option<&str>) -> Self {
        self.forwarded_for = xff.map(|s| s.to_string());
        self
    }

    pub fn request_id(mut self, id: Option<&str>) -> Self {
        self.request_id = id.map(|s| s.to_string());
        self
    }

    pub fn tls(mut self, is_tls: bool) -> Self {
        self.is_tls = is_tls;
        self
    }

    /// Finish building and create the log entry
    pub fn finish(
        self,
        status: u16,
        body_bytes: Option<u64>,
        route: Option<&str>,
        service: Option<&str>,
        backend: Option<&str>,
    ) -> AccessLogEntry {
        let duration = self.start.elapsed();

        AccessLogEntry {
            timestamp: chrono_lite_now(),
            remote_addr: self.remote_addr.to_string(),
            method: self.method,
            path: self.path,
            query: self.query,
            host: self.host,
            status,
            body_bytes,
            duration_ms: duration.as_secs_f64() * 1000.0,
            user_agent: self.user_agent,
            referer: self.referer,
            forwarded_for: self.forwarded_for,
            request_id: self.request_id,
            route: route.map(|s| s.to_string()),
            service: service.map(|s| s.to_string()),
            backend: backend.map(|s| s.to_string()),
            tls_version: if self.is_tls {
                Some("TLSv1.3".to_string())
            } else {
                None
            },
            protocol: self.protocol,
        }
    }
}

/// Simple timestamp function (avoiding chrono dependency)
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Convert to rough ISO 8601 format
    // This is simplified - for production, use chrono
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;
    let hours = secs_today / 3600;
    let mins = (secs_today % 3600) / 60;
    let secs_remaining = secs_today % 60;

    // Approximate year/month/day calculation (not accounting for leap years perfectly)
    let years_approx = days_since_epoch / 365;
    let year = 1970 + years_approx;
    let day_of_year = days_since_epoch % 365;
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, mins, secs_remaining, millis
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_log_builder() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let entry = AccessLogBuilder::new(addr, "GET", "/api/test", "HTTP/1.1")
            .host(Some("example.com"))
            .user_agent(Some("test-agent"))
            .finish(200, Some(1234), Some("api-route"), Some("api-service"), Some("http://backend:8080"));

        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/api/test");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, Some(1234));
        assert_eq!(entry.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_timestamp_format() {
        let ts = chrono_lite_now();
        // Should be roughly ISO 8601 format
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
    }
}
