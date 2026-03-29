//! UDP proxying: session-aware datagram forwarding with client IP routing and load balancing.

mod proxy;
mod router;
mod service;

/// Session-aware UDP proxy that forwards datagrams and tracks client sessions.
pub use proxy::UdpProxy;
/// Matches UDP datagrams to routes by client IP.
pub use router::UdpRouter;
/// Manages UDP backend services and round-robin load balancing.
pub use service::UdpServiceManager;
