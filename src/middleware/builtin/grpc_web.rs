use crate::config::GrpcWebConfig;
use bytes::{BufMut, Bytes, BytesMut};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{HeaderMap, Request, Response};
use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

const GRPC_WEB_CONTENT_TYPE: &str = "application/grpc-web";
const GRPC_WEB_TEXT_CONTENT_TYPE: &str = "application/grpc-web-text";
const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// gRPC-Web middleware that translates between gRPC-Web and gRPC protocols
///
/// This middleware allows browser-based clients to communicate with gRPC services
/// by translating the gRPC-Web protocol to native gRPC.
///
/// Features:
/// - Translates application/grpc-web to application/grpc
/// - Handles base64-encoded payloads (grpc-web-text)
/// - Converts trailers to trailer-prefixed messages for browser consumption
/// - Supports CORS preflight for cross-origin requests
pub struct GrpcWebMiddleware {
    allow_origins: Vec<Regex>,
}

impl GrpcWebMiddleware {
    pub fn new(config: GrpcWebConfig) -> Self {
        let allow_origins = config
            .allow_origins
            .iter()
            .filter_map(|pattern| {
                // Convert glob-like patterns to regex
                let regex_pattern = pattern
                    .replace('.', "\\.")
                    .replace('*', ".*");
                Regex::new(&format!("^{}$", regex_pattern)).ok()
            })
            .collect();

        Self { allow_origins }
    }

    /// Check if the origin is allowed
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_origins.is_empty() {
            return true; // Allow all origins if none specified
        }
        self.allow_origins.iter().any(|re| re.is_match(origin))
    }

    /// Check if this is a gRPC-Web request
    pub fn is_grpc_web_request<B>(req: &Request<B>) -> bool {
        req.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with(GRPC_WEB_CONTENT_TYPE) || v.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE))
            .unwrap_or(false)
    }

    /// Check if this is a base64-encoded gRPC-Web request
    pub fn is_grpc_web_text<B>(req: &Request<B>) -> bool {
        req.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE))
            .unwrap_or(false)
    }

    /// Transform request headers for gRPC-Web to gRPC
    pub fn transform_request_headers(&self, headers: &mut HeaderMap) -> TransformResult {
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let is_text = content_type
            .as_ref()
            .map(|ct| ct.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE))
            .unwrap_or(false);

        let is_grpc_web = content_type
            .as_ref()
            .map(|ct| ct.starts_with(GRPC_WEB_CONTENT_TYPE) || ct.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE))
            .unwrap_or(false);

        if !is_grpc_web {
            return TransformResult {
                is_grpc_web: false,
                is_text: false,
            };
        }

        debug!("gRPC-Web request detected, translating to gRPC");

        // Change content-type to application/grpc
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(GRPC_CONTENT_TYPE));

        TransformResult {
            is_grpc_web: true,
            is_text,
        }
    }

    /// Transform response headers from gRPC to gRPC-Web
    pub fn transform_response_headers(&self, headers: &mut HeaderMap, is_text: bool) {
        // Change content-type back to grpc-web
        let new_content_type = if is_text {
            GRPC_WEB_TEXT_CONTENT_TYPE
        } else {
            GRPC_WEB_CONTENT_TYPE
        };

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(new_content_type).unwrap_or(HeaderValue::from_static(GRPC_WEB_CONTENT_TYPE)),
        );

        // Add CORS headers for browser compatibility
        headers.insert(
            HeaderName::from_static("access-control-expose-headers"),
            HeaderValue::from_static("grpc-status,grpc-message"),
        );
    }

    /// Decode base64 content (for grpc-web-text)
    pub fn decode_base64(data: &[u8]) -> Option<Vec<u8>> {
        base64_decode(data)
    }

    /// Encode to base64 (for grpc-web-text response)
    pub fn encode_base64(data: &[u8]) -> String {
        base64_encode(data)
    }

    /// Convert gRPC trailers to trailer-prefixed message
    /// In gRPC-Web, trailers are sent as a length-prefixed message with a trailer flag
    pub fn encode_trailers(trailers: &[(String, String)]) -> Bytes {
        let mut trailer_data = BytesMut::new();

        for (key, value) in trailers {
            trailer_data.extend_from_slice(key.as_bytes());
            trailer_data.extend_from_slice(b": ");
            trailer_data.extend_from_slice(value.as_bytes());
            trailer_data.extend_from_slice(b"\r\n");
        }

        // Create trailer frame: 1 byte flags (0x80 for trailer), 4 bytes length, data
        let len = trailer_data.len() as u32;
        let mut frame = BytesMut::with_capacity(5 + trailer_data.len());
        frame.put_u8(0x80); // Trailer flag
        frame.put_u32(len);
        frame.extend_from_slice(&trailer_data);

        frame.freeze()
    }

    /// Extract trailers from response headers (for Trailers-Only response)
    pub fn extract_grpc_trailers<B>(response: &Response<B>) -> Vec<(String, String)> {
        let mut trailers = Vec::new();

        // gRPC status and message from headers (Trailers-Only response)
        if let Some(status) = response.headers().get("grpc-status") {
            if let Ok(s) = status.to_str() {
                trailers.push(("grpc-status".to_string(), s.to_string()));
            }
        }

        if let Some(message) = response.headers().get("grpc-message") {
            if let Ok(s) = message.to_str() {
                trailers.push(("grpc-message".to_string(), s.to_string()));
            }
        }

        trailers
    }
}

/// Result of request transformation
pub struct TransformResult {
    /// Whether this was a gRPC-Web request
    pub is_grpc_web: bool,
    /// Whether this was a grpc-web-text (base64) request
    pub is_text: bool,
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Simple base64 decoding
fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    static DECODE_TABLE: OnceLock<[i8; 256]> = OnceLock::new();
    let table = DECODE_TABLE.get_or_init(|| {
        let mut table = [-1i8; 256];
        for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
            table[c as usize] = i as i8;
        }
        table
    });

    let mut result = Vec::with_capacity(data.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &byte in data {
        if byte == b'=' {
            break;
        }
        if byte == b'\n' || byte == b'\r' || byte == b' ' {
            continue;
        }
        let val = table[byte as usize];
        if val < 0 {
            return None;
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, gRPC-Web!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(encoded.as_bytes()).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_encode_trailers() {
        let trailers = vec![
            ("grpc-status".to_string(), "0".to_string()),
            ("grpc-message".to_string(), "OK".to_string()),
        ];
        let frame = GrpcWebMiddleware::encode_trailers(&trailers);

        // First byte should be trailer flag (0x80)
        assert_eq!(frame[0], 0x80);

        // Next 4 bytes are length
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(len as usize + 5, frame.len());
    }

    #[test]
    fn test_origin_matching() {
        let config = GrpcWebConfig {
            allow_origins: vec![
                "https://example.com".to_string(),
                "https://*.example.org".to_string(),
            ],
        };
        let middleware = GrpcWebMiddleware::new(config);

        assert!(middleware.is_origin_allowed("https://example.com"));
        assert!(middleware.is_origin_allowed("https://sub.example.org"));
        assert!(middleware.is_origin_allowed("https://deep.sub.example.org"));
        assert!(!middleware.is_origin_allowed("https://other.com"));
    }

    #[test]
    fn test_allow_all_origins_when_empty() {
        let config = GrpcWebConfig {
            allow_origins: vec![],
        };
        let middleware = GrpcWebMiddleware::new(config);

        assert!(middleware.is_origin_allowed("https://any.domain.com"));
    }
}
