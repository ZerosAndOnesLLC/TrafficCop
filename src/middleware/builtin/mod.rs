//! Built-in middleware implementations (auth, rate limiting, headers, path manipulation, etc.).

mod access_log;
mod basic_auth;
mod buffering;
mod chain;
mod compress;
mod cors;
mod digest_auth;
mod errors;
mod forward_auth;
mod grpc_web;
mod headers;
mod jwt;
mod ip_filter;
mod path;
mod rate_limit;
mod redirect_scheme;
mod retry;

/// Structured access log entry builder and output.
pub use access_log::{AccessLogBuilder, AccessLogEntry};
/// HTTP Basic authentication middleware.
pub use basic_auth::BasicAuthMiddleware;
/// Request/response body buffering for retry support.
pub use buffering::BufferingMiddleware;
/// Custom error page middleware.
pub use errors::ErrorsMiddleware;
/// HTTP Digest authentication (RFC 7616).
pub use digest_auth::{AuthResult as DigestAuthResult, DigestAuthMiddleware};
/// Compose multiple named middleware into a single reference.
pub use chain::ChainMiddleware;
/// Response body compression (gzip/brotli).
pub use compress::{CompressMiddleware, CompressionAlgorithm};
/// Cross-Origin Resource Sharing (CORS) middleware.
pub use cors::CorsMiddleware;
/// Delegate authentication to an external HTTP service.
pub use forward_auth::{AuthResult, ForwardAuthMiddleware};
/// gRPC-Web to native gRPC protocol translation.
pub use grpc_web::GrpcWebMiddleware;
/// Add, remove, or override request/response headers.
pub use headers::HeadersMiddleware;
/// JWT token validation and claim forwarding.
pub use jwt::{ClaimValue, JwtAlgorithm, JwtMiddleware, JwtValidationResult};
/// IP-based allow/deny list filtering.
pub use ip_filter::{IpAllowListMiddleware, IpDenyListMiddleware};
/// URL path manipulation (strip, add, replace with literal or regex).
pub use path::{
    AddPrefixMiddleware, ReplacePathMiddleware, ReplacePathRegexMiddleware,
    StripPrefixMiddleware, StripPrefixRegexMiddleware,
};
/// Token-bucket rate limiting with optional distributed backing store.
pub use rate_limit::RateLimitMiddleware;
/// HTTP-to-HTTPS (or reverse) scheme redirect.
pub use redirect_scheme::RedirectSchemeMiddleware;
/// Retry failed requests with exponential backoff.
pub use retry::{RetryIterator, RetryMiddleware};
