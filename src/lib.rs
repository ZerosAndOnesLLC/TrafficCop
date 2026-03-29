//! TrafficCop - a high-performance reverse proxy and load balancer.
//!
//! Supports HTTP/HTTPS/gRPC routing, TCP/UDP proxying, TLS termination,
//! middleware chains, health checking, and hot config reloading.
//!
//! # Quick start
//! ```no_run
//! use trafficcop::Config;
//! let config = Config::load(std::path::Path::new("trafficcop.yml")).unwrap();
//! ```

/// Admin API for runtime introspection and dashboard.
pub mod admin;
/// Load balancing algorithms (round-robin, weighted, least-connections, etc.).
pub mod balancer;
/// Cluster coordination and high-availability support.
pub mod cluster;
/// Configuration loading, parsing, validation, and hot-reloading.
pub mod config;
/// Active and passive health checking for backends.
pub mod health;
/// Prometheus metrics collection and export.
pub mod metrics;
/// HTTP middleware implementations (rate limiting, auth, headers, etc.).
pub mod middleware;
/// HTTP/HTTPS/gRPC reverse proxy engine.
pub mod proxy;
/// Request routing and rule matching.
pub mod router;
/// Server lifecycle management and entrypoint binding.
pub mod server;
/// Backend service abstractions (load balancer, weighted, mirroring, failover).
pub mod service;
/// Distributed state store for cluster coordination.
pub mod store;
/// TCP proxy and routing.
pub mod tcp;
/// OpenTelemetry tracing integration.
pub mod telemetry;
/// TLS certificate management and termination.
pub mod tls;
/// UDP proxy and routing.
pub mod udp;

/// Re-exported root configuration type.
pub use config::Config;
/// Re-exported store types for cluster setup.
pub use store::{Store, StoreConfig};
