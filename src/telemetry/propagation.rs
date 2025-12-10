use hyper::header::HeaderValue;
use hyper::HeaderMap;

/// W3C Trace Context for distributed tracing
/// See: https://www.w3.org/TR/trace-context/
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID - 32 hex characters (16 bytes)
    pub trace_id: String,
    /// Parent Span ID - 16 hex characters (8 bytes)
    pub parent_id: String,
    /// Trace flags (sampled, etc.)
    pub trace_flags: u8,
    /// Optional trace state from vendors
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// Create a new trace context with random IDs
    pub fn new() -> Self {
        Self {
            trace_id: Self::generate_trace_id(),
            parent_id: Self::generate_span_id(),
            trace_flags: 0x01, // Sampled
            trace_state: None,
        }
    }

    /// Create a child context (same trace_id, new parent_id)
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_id: Self::generate_span_id(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }

    /// Generate a random trace ID (32 hex chars)
    fn generate_trace_id() -> String {
        let mut bytes = [0u8; 16];
        Self::fill_random(&mut bytes);
        Self::to_hex(&bytes)
    }

    /// Generate a random span ID (16 hex chars)
    fn generate_span_id() -> String {
        let mut bytes = [0u8; 8];
        Self::fill_random(&mut bytes);
        Self::to_hex(&bytes)
    }

    fn fill_random(bytes: &mut [u8]) {
        // Simple xorshift-based random
        static mut STATE: u64 = 0;
        unsafe {
            if STATE == 0 {
                STATE = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
            }
            for byte in bytes.iter_mut() {
                STATE ^= STATE << 13;
                STATE ^= STATE >> 7;
                STATE ^= STATE << 17;
                *byte = STATE as u8;
            }
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }

    /// Parse traceparent header value
    /// Format: version-trace_id-parent_id-trace_flags
    /// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    fn parse_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        let trace_id = parts[1];
        let parent_id = parts[2];
        let flags = parts[3];

        // Validate version (only 00 supported)
        if version != "00" {
            return None;
        }

        // Validate trace_id (32 hex chars, not all zeros)
        if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if trace_id == "00000000000000000000000000000000" {
            return None;
        }

        // Validate parent_id (16 hex chars, not all zeros)
        if parent_id.len() != 16 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if parent_id == "0000000000000000" {
            return None;
        }

        // Parse trace flags
        let trace_flags = u8::from_str_radix(flags, 16).ok()?;

        Some(Self {
            trace_id: trace_id.to_lowercase(),
            parent_id: parent_id.to_lowercase(),
            trace_flags,
            trace_state: None,
        })
    }

    /// Format as traceparent header value
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.parent_id, self.trace_flags
        )
    }

    /// Check if trace is sampled
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract trace context from incoming request headers
pub fn extract_context(headers: &HeaderMap) -> TraceContext {
    // Try W3C traceparent header first
    if let Some(traceparent) = headers.get("traceparent") {
        if let Ok(value) = traceparent.to_str() {
            if let Some(mut ctx) = TraceContext::parse_traceparent(value) {
                // Also extract tracestate if present
                if let Some(tracestate) = headers.get("tracestate") {
                    if let Ok(state) = tracestate.to_str() {
                        ctx.trace_state = Some(state.to_string());
                    }
                }
                return ctx;
            }
        }
    }

    // Try B3 propagation format (used by Zipkin)
    if let (Some(trace_id), Some(span_id)) = (
        headers.get("x-b3-traceid"),
        headers.get("x-b3-spanid"),
    ) {
        if let (Ok(tid), Ok(sid)) = (trace_id.to_str(), span_id.to_str()) {
            let sampled = headers
                .get("x-b3-sampled")
                .and_then(|v| v.to_str().ok())
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true);

            // Normalize trace_id to 32 chars (pad if necessary)
            let normalized_trace_id = if tid.len() == 16 {
                format!("0000000000000000{}", tid)
            } else {
                tid.to_string()
            };

            return TraceContext {
                trace_id: normalized_trace_id.to_lowercase(),
                parent_id: sid.to_lowercase(),
                trace_flags: if sampled { 0x01 } else { 0x00 },
                trace_state: None,
            };
        }
    }

    // Try Jaeger format
    if let Some(uber_ctx) = headers.get("uber-trace-id") {
        if let Ok(value) = uber_ctx.to_str() {
            // Format: trace_id:span_id:parent_id:flags
            let parts: Vec<&str> = value.split(':').collect();
            if parts.len() >= 4 {
                let trace_id = parts[0];
                let span_id = parts[1];
                let flags = u8::from_str_radix(parts[3], 16).unwrap_or(1);

                // Normalize trace_id to 32 chars
                let normalized_trace_id = if trace_id.len() == 16 {
                    format!("0000000000000000{}", trace_id)
                } else {
                    trace_id.to_string()
                };

                return TraceContext {
                    trace_id: normalized_trace_id.to_lowercase(),
                    parent_id: span_id.to_lowercase(),
                    trace_flags: flags,
                    trace_state: None,
                };
            }
        }
    }

    // No trace context found, create new one
    TraceContext::new()
}

/// Inject trace context into outgoing request headers
pub fn inject_context(headers: &mut HeaderMap, ctx: &TraceContext) {
    // Always inject W3C traceparent
    if let Ok(value) = HeaderValue::from_str(&ctx.to_traceparent()) {
        headers.insert("traceparent", value);
    }

    // Inject tracestate if present
    if let Some(ref state) = ctx.trace_state {
        if let Ok(value) = HeaderValue::from_str(state) {
            headers.insert("tracestate", value);
        }
    }

    // Also inject B3 headers for compatibility
    if let Ok(value) = HeaderValue::from_str(&ctx.trace_id) {
        headers.insert("x-b3-traceid", value);
    }
    if let Ok(value) = HeaderValue::from_str(&ctx.parent_id) {
        headers.insert("x-b3-spanid", value);
    }
    let sampled = if ctx.is_sampled() {
        HeaderValue::from_static("1")
    } else {
        HeaderValue::from_static("0")
    };
    headers.insert("x-b3-sampled", sampled);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_creation() {
        let ctx = TraceContext::new();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.parent_id.len(), 16);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_traceparent_parsing() {
        let ctx = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .unwrap();

        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_id, "00f067aa0ba902b7");
        assert_eq!(ctx.trace_flags, 0x01);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let original = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse_traceparent(original).unwrap();
        assert_eq!(ctx.to_traceparent(), original);
    }

    #[test]
    fn test_extract_w3c_context() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert("tracestate", HeaderValue::from_static("vendor=value"));

        let ctx = extract_context(&headers);
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.trace_state, Some("vendor=value".to_string()));
    }

    #[test]
    fn test_extract_b3_context() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-b3-traceid",
            HeaderValue::from_static("463ac35c9f6413ad48485a3953bb6124"),
        );
        headers.insert("x-b3-spanid", HeaderValue::from_static("0020000000000001"));
        headers.insert("x-b3-sampled", HeaderValue::from_static("1"));

        let ctx = extract_context(&headers);
        assert_eq!(ctx.trace_id, "463ac35c9f6413ad48485a3953bb6124");
        assert_eq!(ctx.parent_id, "0020000000000001");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_extract_jaeger_context() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "uber-trace-id",
            HeaderValue::from_static("6f6f6d646e6f6873:1:0:1"),
        );

        let ctx = extract_context(&headers);
        assert_eq!(ctx.trace_id, "00000000000000006f6f6d646e6f6873");
        assert_eq!(ctx.parent_id, "1");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_inject_context() {
        let ctx = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            parent_id: "00f067aa0ba902b7".to_string(),
            trace_flags: 0x01,
            trace_state: Some("vendor=value".to_string()),
        };

        let mut headers = HeaderMap::new();
        inject_context(&mut headers, &ctx);

        assert!(headers.contains_key("traceparent"));
        assert!(headers.contains_key("tracestate"));
        assert!(headers.contains_key("x-b3-traceid"));
        assert!(headers.contains_key("x-b3-spanid"));
        assert!(headers.contains_key("x-b3-sampled"));
    }

    #[test]
    fn test_child_context() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.parent_id, child.parent_id);
        assert_eq!(parent.trace_flags, child.trace_flags);
    }

    #[test]
    fn test_invalid_traceparent() {
        // Wrong version
        assert!(TraceContext::parse_traceparent(
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        )
        .is_none());

        // All zero trace_id
        assert!(TraceContext::parse_traceparent(
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        )
        .is_none());

        // All zero span_id
        assert!(TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
        )
        .is_none());

        // Wrong format
        assert!(TraceContext::parse_traceparent("invalid").is_none());
    }
}
