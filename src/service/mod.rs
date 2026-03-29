//! Service routing and management for load balancing, failover, mirroring, and weighted traffic splitting.

mod failover;
mod manager;
mod mirroring;
mod weighted;

/// Failover router that switches between primary and fallback services.
pub use failover::FailoverServiceRouter;
/// Central registry of all configured services and their backends.
pub use manager::ServiceManager;
/// Traffic mirroring router that shadows requests to secondary services.
pub use mirroring::MirroringServiceRouter;
/// Weighted traffic splitter using smooth round-robin distribution.
pub use weighted::WeightedServiceRouter;
