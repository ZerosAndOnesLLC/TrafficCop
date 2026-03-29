//! Reverse proxy engine for forwarding HTTP, gRPC, and WebSocket traffic to backends.

/// gRPC request detection and error response utilities.
pub mod grpc;
mod handler;
/// HTTP/2 connection pooling for upstream backends.
pub mod http2_client;
/// WebSocket upgrade detection and bidirectional proxying.
pub mod websocket;

pub use grpc::{is_grpc_request, is_grpc_web_request, grpc_error_response, grpc_gateway_error, GrpcStatus};
pub use handler::ProxyHandler;
pub use http2_client::{Http2ConnectionPool, Http2Error, Http2PoolStats};
pub use websocket::{handle_websocket_upgrade, is_websocket_upgrade};
