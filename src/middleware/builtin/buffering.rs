use crate::config::BufferingConfig;

/// Buffering middleware configuration for request/response body buffering
/// This allows retrying requests by buffering the body in memory
pub struct BufferingMiddleware {
    /// Maximum size of request body to buffer (0 = no limit)
    pub max_request_body_bytes: i64,
    /// Size of memory buffer for request body before spooling to disk
    pub mem_request_body_bytes: i64,
    /// Maximum size of response body to buffer (0 = no limit)
    pub max_response_body_bytes: i64,
    /// Size of memory buffer for response body before spooling to disk
    pub mem_response_body_bytes: i64,
    /// Expression to determine when to retry (e.g., "IsNetworkError() && Attempts() < 2")
    pub retry_expression: Option<String>,
}

impl BufferingMiddleware {
    pub fn new(config: BufferingConfig) -> Self {
        Self {
            max_request_body_bytes: config.max_request_body_bytes,
            mem_request_body_bytes: config.mem_request_body_bytes,
            max_response_body_bytes: config.max_response_body_bytes,
            mem_response_body_bytes: config.mem_response_body_bytes,
            retry_expression: config.retry_expression,
        }
    }

    /// Check if request body buffering is enabled
    pub fn buffer_request(&self) -> bool {
        self.max_request_body_bytes != 0 || self.mem_request_body_bytes > 0
    }

    /// Check if response body buffering is enabled
    pub fn buffer_response(&self) -> bool {
        self.max_response_body_bytes != 0 || self.mem_response_body_bytes > 0
    }

    /// Check if request body size is within limits
    pub fn request_within_limit(&self, size: i64) -> bool {
        self.max_request_body_bytes == 0 || size <= self.max_request_body_bytes
    }

    /// Check if response body size is within limits
    pub fn response_within_limit(&self, size: i64) -> bool {
        self.max_response_body_bytes == 0 || size <= self.max_response_body_bytes
    }

    /// Check if request should use memory buffer (vs spool to disk)
    pub fn request_fits_in_memory(&self, size: i64) -> bool {
        self.mem_request_body_bytes == 0 || size <= self.mem_request_body_bytes
    }

    /// Check if response should use memory buffer (vs spool to disk)
    pub fn response_fits_in_memory(&self, size: i64) -> bool {
        self.mem_response_body_bytes == 0 || size <= self.mem_response_body_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffering_defaults() {
        let config = BufferingConfig {
            max_request_body_bytes: 0,
            mem_request_body_bytes: 0,
            max_response_body_bytes: 0,
            mem_response_body_bytes: 0,
            retry_expression: None,
        };

        let middleware = BufferingMiddleware::new(config);

        // 0 means no limit
        assert!(middleware.request_within_limit(i64::MAX));
        assert!(middleware.response_within_limit(i64::MAX));
    }

    #[test]
    fn test_buffering_limits() {
        let config = BufferingConfig {
            max_request_body_bytes: 1024 * 1024, // 1MB
            mem_request_body_bytes: 64 * 1024,   // 64KB
            max_response_body_bytes: 10 * 1024 * 1024, // 10MB
            mem_response_body_bytes: 1024 * 1024, // 1MB
            retry_expression: Some("IsNetworkError()".to_string()),
        };

        let middleware = BufferingMiddleware::new(config);

        assert!(middleware.buffer_request());
        assert!(middleware.buffer_response());

        // 512KB fits in 1MB limit
        assert!(middleware.request_within_limit(512 * 1024));
        // 512KB doesn't fit in 64KB memory buffer
        assert!(!middleware.request_fits_in_memory(512 * 1024));
        // 32KB fits in 64KB memory buffer
        assert!(middleware.request_fits_in_memory(32 * 1024));

        // 2MB doesn't fit in 1MB limit
        assert!(!middleware.request_within_limit(2 * 1024 * 1024));
    }

    #[test]
    fn test_buffering_disabled() {
        let config = BufferingConfig {
            max_request_body_bytes: 0,
            mem_request_body_bytes: 0,
            max_response_body_bytes: 0,
            mem_response_body_bytes: 0,
            retry_expression: None,
        };

        let middleware = BufferingMiddleware::new(config);

        // With 0 values, buffering is technically disabled
        assert!(!middleware.buffer_request());
        assert!(!middleware.buffer_response());
    }
}
