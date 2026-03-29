//! Admin API and dashboard for runtime inspection, health status, and cluster management.

mod api;
mod server;

/// REST API handler for inspecting routers, services, health, and cluster state.
pub use api::AdminApi;
/// HTTP server that hosts the admin API and dashboard.
pub use server::AdminServer;
