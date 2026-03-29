//! Distributed tracing: W3C/B3/Jaeger context propagation and request span tracking.

mod propagation;
mod span;

/// Extract trace context from incoming headers, inject into outgoing headers.
pub use propagation::{extract_context, inject_context, TraceContext};
/// Request span for structured tracing of HTTP requests through the proxy.
pub use span::{RequestSpan, SpanKind};
