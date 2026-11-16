use crate::config::EntryPoint;
use crate::udp::{UdpMiddlewares, UdpProxy, UdpRouter, UdpServiceManager};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

/// UDP listener for a specific entrypoint
pub struct UdpListener {
    name: String,
    entrypoint: EntryPoint,
    router: Arc<UdpRouter>,
    services: Arc<UdpServiceManager>,
    middlewares: Arc<UdpMiddlewares>,
}

impl UdpListener {
    /// Create a UDP listener for the given entrypoint with its router and service manager.
    pub fn new(
        name: String,
        entrypoint: EntryPoint,
        router: Arc<UdpRouter>,
        services: Arc<UdpServiceManager>,
        middlewares: Arc<UdpMiddlewares>,
    ) -> Self {
        Self {
            name,
            entrypoint,
            router,
            services,
            middlewares,
        }
    }

    /// Start serving UDP traffic
    pub async fn serve(self, shutdown: mpsc::Receiver<()>) -> Result<()> {
        let addr: SocketAddr = self
            .entrypoint
            .address
            .parse()
            .with_context(|| format!("Invalid address: {}", self.entrypoint.address))?;

        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket to {}", addr))?;

        info!("UDP entrypoint '{}' listening on {}", self.name, addr);

        let proxy = Arc::new(UdpProxy::new(
            Arc::clone(&self.router),
            Arc::clone(&self.services),
            Arc::clone(&self.middlewares),
        ));

        proxy.run(Arc::new(socket), &self.name, shutdown).await;

        Ok(())
    }
}
