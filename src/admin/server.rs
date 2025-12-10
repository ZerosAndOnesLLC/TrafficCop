use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::AdminApi;

/// Admin server for serving the admin API
pub struct AdminServer {
    api: Arc<AdminApi>,
    address: SocketAddr,
}

impl AdminServer {
    pub fn new(api: AdminApi, address: SocketAddr) -> Self {
        Self {
            api: Arc::new(api),
            address,
        }
    }

    /// Start the admin server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.address).await?;
        info!("Admin API listening on http://{}", self.address);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let api = Arc::clone(&self.api);

            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let api = Arc::clone(&api);
                    async move {
                        debug!("Admin request: {} {}", req.method(), req.uri().path());
                        Ok::<_, hyper::Error>(api.handle(req).await)
                    }
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    error!("Admin connection error from {}: {}", remote_addr, e);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::router::Router;
    use crate::service::ServiceManager;

    #[test]
    fn test_admin_server_creation() {
        let config = Arc::new(Config::default());
        let router = Arc::new(Router::from_config(&config));
        let services = Arc::new(ServiceManager::new(&config));
        let api = AdminApi::new(config, router, services);

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let _server = AdminServer::new(api, addr);
    }
}
