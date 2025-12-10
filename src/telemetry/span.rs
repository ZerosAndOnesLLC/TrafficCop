use std::net::SocketAddr;
use std::time::Instant;

use super::TraceContext;

/// Span kind following OpenTelemetry conventions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// Server span - handles incoming request
    Server,
    /// Client span - makes outgoing request
    Client,
    /// Internal span - internal operation
    Internal,
}

impl std::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpanKind::Server => write!(f, "server"),
            SpanKind::Client => write!(f, "client"),
            SpanKind::Internal => write!(f, "internal"),
        }
    }
}

/// Request span for tracing HTTP requests
#[derive(Debug)]
pub struct RequestSpan {
    /// Trace context
    pub context: TraceContext,
    /// Span ID for this specific span
    pub span_id: String,
    /// Span kind
    pub kind: SpanKind,
    /// Operation name
    pub name: String,
    /// Start time
    pub start: Instant,
    /// HTTP method
    pub http_method: Option<String>,
    /// HTTP URL
    pub http_url: Option<String>,
    /// HTTP status code (set when span ends)
    pub http_status: Option<u16>,
    /// Target service name
    pub service_name: Option<String>,
    /// Remote address
    pub remote_addr: Option<SocketAddr>,
    /// Error message if any
    pub error: Option<String>,
    /// Additional attributes
    attributes: Vec<(String, String)>,
}

impl RequestSpan {
    /// Create a new server span for handling incoming requests
    pub fn server(context: TraceContext, name: impl Into<String>) -> Self {
        Self {
            span_id: context.parent_id.clone(),
            context,
            kind: SpanKind::Server,
            name: name.into(),
            start: Instant::now(),
            http_method: None,
            http_url: None,
            http_status: None,
            service_name: None,
            remote_addr: None,
            error: None,
            attributes: Vec::new(),
        }
    }

    /// Create a new client span for making outgoing requests
    pub fn client(parent: &TraceContext, name: impl Into<String>) -> Self {
        let child_ctx = parent.child();
        Self {
            span_id: child_ctx.parent_id.clone(),
            context: child_ctx,
            kind: SpanKind::Client,
            name: name.into(),
            start: Instant::now(),
            http_method: None,
            http_url: None,
            http_status: None,
            service_name: None,
            remote_addr: None,
            error: None,
            attributes: Vec::new(),
        }
    }

    /// Create an internal span
    pub fn internal(parent: &TraceContext, name: impl Into<String>) -> Self {
        let child_ctx = parent.child();
        Self {
            span_id: child_ctx.parent_id.clone(),
            context: child_ctx,
            kind: SpanKind::Internal,
            name: name.into(),
            start: Instant::now(),
            http_method: None,
            http_url: None,
            http_status: None,
            service_name: None,
            remote_addr: None,
            error: None,
            attributes: Vec::new(),
        }
    }

    /// Set HTTP method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.http_method = Some(method.into());
        self
    }

    /// Set HTTP URL
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.http_url = Some(url.into());
        self
    }

    /// Set service name
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service_name = Some(service.into());
        self
    }

    /// Set remote address
    pub fn with_remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Add a custom attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Record HTTP status code
    pub fn record_status(&mut self, status: u16) {
        self.http_status = Some(status);
    }

    /// Record an error
    pub fn record_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    /// Get elapsed duration
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    /// Check if span has error
    pub fn has_error(&self) -> bool {
        self.error.is_some() || self.http_status.map(|s| s >= 500).unwrap_or(false)
    }

    /// Log the span using tracing
    pub fn log(&self) {
        let duration_ms = self.elapsed().as_secs_f64() * 1000.0;
        let status = self.http_status.map(|s| s.to_string()).unwrap_or_default();

        if self.has_error() {
            tracing::error!(
                trace_id = %self.context.trace_id,
                span_id = %self.span_id,
                parent_id = %self.context.parent_id,
                span_kind = %self.kind,
                name = %self.name,
                http.method = ?self.http_method,
                http.url = ?self.http_url,
                http.status_code = %status,
                service = ?self.service_name,
                remote_addr = ?self.remote_addr,
                duration_ms = %duration_ms,
                error = ?self.error,
                "request completed with error"
            );
        } else {
            tracing::info!(
                trace_id = %self.context.trace_id,
                span_id = %self.span_id,
                parent_id = %self.context.parent_id,
                span_kind = %self.kind,
                name = %self.name,
                http.method = ?self.http_method,
                http.url = ?self.http_url,
                http.status_code = %status,
                service = ?self.service_name,
                remote_addr = ?self.remote_addr,
                duration_ms = %duration_ms,
                "request completed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_span() {
        let ctx = TraceContext::default();
        let span = RequestSpan::server(ctx.clone(), "handle_request")
            .with_method("GET")
            .with_url("/api/users");

        assert_eq!(span.kind, SpanKind::Server);
        assert_eq!(span.name, "handle_request");
        assert_eq!(span.http_method, Some("GET".to_string()));
    }

    #[test]
    fn test_client_span() {
        let parent = TraceContext::default();
        let span = RequestSpan::client(&parent, "upstream_request")
            .with_service("backend-api");

        assert_eq!(span.kind, SpanKind::Client);
        assert_eq!(span.context.trace_id, parent.trace_id);
        assert_ne!(span.span_id, parent.parent_id);
    }

    #[test]
    fn test_span_error() {
        let ctx = TraceContext::default();
        let mut span = RequestSpan::server(ctx, "test");

        assert!(!span.has_error());

        span.record_error("connection refused");
        assert!(span.has_error());
    }

    #[test]
    fn test_span_status_error() {
        let ctx = TraceContext::default();
        let mut span = RequestSpan::server(ctx, "test");

        span.record_status(200);
        assert!(!span.has_error());

        span.record_status(500);
        assert!(span.has_error());
    }

    #[test]
    fn test_span_attributes() {
        let ctx = TraceContext::default();
        let span = RequestSpan::server(ctx, "test")
            .with_attribute("custom.key", "custom.value")
            .with_attribute("another.key", "another.value");

        assert_eq!(span.attributes.len(), 2);
    }
}
