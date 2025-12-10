use crate::config::EntryPoint;
use crate::udp::{UdpProxy, UdpRouter, UdpServiceManager};
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
}

impl UdpListener {
    pub fn new(
        name: String,
        entrypoint: EntryPoint,
        router: Arc<UdpRouter>,
        services: Arc<UdpServiceManager>,
    ) -> Self {
        Self {
            name,
            entrypoint,
            router,
            services,
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
        ));

        proxy.run(Arc::new(socket), &self.name, shutdown).await;

        Ok(())
    }
}
