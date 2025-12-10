use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{body::Incoming, Request, Response, StatusCode};
use tracing::debug;

/// gRPC content type prefix
const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// gRPC-Web content types
const GRPC_WEB_CONTENT_TYPE: &str = "application/grpc-web";
const GRPC_WEB_TEXT_CONTENT_TYPE: &str = "application/grpc-web-text";

/// Check if request is a gRPC request
#[inline]
pub fn is_grpc_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with(GRPC_CONTENT_TYPE))
        .unwrap_or(false)
}

/// Check if request is a gRPC-Web request
#[inline]
pub fn is_grpc_web_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with(GRPC_WEB_CONTENT_TYPE) || v.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE))
        .unwrap_or(false)
}

/// gRPC status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "OK",
            GrpcStatus::Cancelled => "CANCELLED",
            GrpcStatus::Unknown => "UNKNOWN",
            GrpcStatus::InvalidArgument => "INVALID_ARGUMENT",
            GrpcStatus::DeadlineExceeded => "DEADLINE_EXCEEDED",
            GrpcStatus::NotFound => "NOT_FOUND",
            GrpcStatus::AlreadyExists => "ALREADY_EXISTS",
            GrpcStatus::PermissionDenied => "PERMISSION_DENIED",
            GrpcStatus::ResourceExhausted => "RESOURCE_EXHAUSTED",
            GrpcStatus::FailedPrecondition => "FAILED_PRECONDITION",
            GrpcStatus::Aborted => "ABORTED",
            GrpcStatus::OutOfRange => "OUT_OF_RANGE",
            GrpcStatus::Unimplemented => "UNIMPLEMENTED",
            GrpcStatus::Internal => "INTERNAL",
            GrpcStatus::Unavailable => "UNAVAILABLE",
            GrpcStatus::DataLoss => "DATA_LOSS",
            GrpcStatus::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// Convert HTTP status to gRPC status
    pub fn from_http_status(status: StatusCode) -> Self {
        match status.as_u16() {
            200 => GrpcStatus::Ok,
            400 => GrpcStatus::InvalidArgument,
            401 => GrpcStatus::Unauthenticated,
            403 => GrpcStatus::PermissionDenied,
            404 => GrpcStatus::NotFound,
            408 => GrpcStatus::DeadlineExceeded,
            409 => GrpcStatus::Aborted,
            429 => GrpcStatus::ResourceExhausted,
            499 => GrpcStatus::Cancelled,
            500 => GrpcStatus::Internal,
            501 => GrpcStatus::Unimplemented,
            502 | 503 => GrpcStatus::Unavailable,
            504 => GrpcStatus::DeadlineExceeded,
            _ => GrpcStatus::Unknown,
        }
    }
}

/// Build a gRPC error response with proper trailers
pub fn grpc_error_response(
    status: GrpcStatus,
    message: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    debug!("gRPC error response: {:?} - {}", status, message);

    // For gRPC, we return HTTP 200 with grpc-status in trailers
    // But for proxy errors, we can return the error in headers (Trailers-Only response)
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/grpc")
        .header("grpc-status", (status as i32).to_string())
        .header("grpc-message", percent_encode(message))
        .body(empty_body())
        .unwrap()
}

/// Build a gRPC error response for gateway errors
/// These use HTTP error codes which gRPC clients will interpret
pub fn grpc_gateway_error(
    http_status: StatusCode,
    message: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let grpc_status = GrpcStatus::from_http_status(http_status);

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/grpc")
        .header("grpc-status", (grpc_status as i32).to_string())
        .header("grpc-message", percent_encode(message))
        .body(empty_body())
        .unwrap()
}

/// Percent-encode a string for grpc-message header
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => result.push_str("%25"),
            ' ' => result.push_str("%20"),
            '\n' => result.push_str("%0A"),
            '\r' => result.push_str("%0D"),
            c if c.is_ascii_alphanumeric() || "-_.~".contains(c) => result.push(c),
            c => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

/// Ensure gRPC-specific headers are properly forwarded
pub fn prepare_grpc_request<B>(req: &mut Request<B>) {
    // Ensure TE: trailers is set (required for gRPC over HTTP/2)
    if !req.headers().contains_key("te") {
        req.headers_mut()
            .insert(HeaderName::from_static("te"), HeaderValue::from_static("trailers"));
    }
}

/// Copy gRPC trailers to response headers (for Trailers-Only responses)
pub fn copy_grpc_trailers(
    response: &mut Response<BoxBody<Bytes, hyper::Error>>,
    grpc_status: Option<&str>,
    grpc_message: Option<&str>,
) {
    if let Some(status) = grpc_status {
        if let Ok(val) = HeaderValue::from_str(status) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("grpc-status"), val);
        }
    }

    if let Some(message) = grpc_message {
        if let Ok(val) = HeaderValue::from_str(message) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("grpc-message"), val);
        }
    }
}

#[inline]
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_status_from_http() {
        assert_eq!(GrpcStatus::from_http_status(StatusCode::OK), GrpcStatus::Ok);
        assert_eq!(
            GrpcStatus::from_http_status(StatusCode::NOT_FOUND),
            GrpcStatus::NotFound
        );
        assert_eq!(
            GrpcStatus::from_http_status(StatusCode::SERVICE_UNAVAILABLE),
            GrpcStatus::Unavailable
        );
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello"), "hello");
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("100%"), "100%25");
    }
}
