//! TCP proxying: SNI-based routing, bidirectional stream copying, and backend load balancing.

mod middleware;
mod proxy;
mod router;
pub mod rule;
mod service;

/// TCP middlewares (ipAllowList, ipDenyList, inFlightConn).
pub use middleware::{ConnGuard, TcpMiddlewares};
/// Handles incoming TCP connections, extracts SNI, and proxies to backends.
pub use proxy::TcpProxy;
/// Matches TCP connections to routes by SNI hostname or client IP.
pub use router::TcpRouter;
/// Manages TCP backend services and round-robin load balancing.
pub use service::TcpServiceManager;
