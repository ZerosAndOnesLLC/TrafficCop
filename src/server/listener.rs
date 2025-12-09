use crate::config::Entrypoint;
use crate::proxy::ProxyHandler;
use crate::server::SharedState;
use crate::tls::{try_handle_challenge, TlsAcceptor};
use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::server::ResolvesServerCert;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{debug, error, info};

pub struct Listener {
    name: String,
    entrypoint: Entrypoint,
    state: Arc<SharedState>,
    proxy: Arc<ProxyHandler>,
    tls_acceptor: Option<TokioTlsAcceptor>,
}

impl Listener {
    pub fn new(
        name: String,
        entrypoint: Entrypoint,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
    ) -> Self {
        // Build TLS acceptor
        let tls_acceptor = Self::build_tls_acceptor(&name, &entrypoint, &state);

        Self {
            name,
            entrypoint,
            state,
            proxy,
            tls_acceptor,
        }
    }

    fn build_tls_acceptor(
        name: &str,
        entrypoint: &Entrypoint,
        state: &SharedState,
    ) -> Option<TokioTlsAcceptor> {
        let tls_config = entrypoint.tls.as_ref()?;

        // Check if we should use ACME/SNI resolver
        if tls_config.cert_resolver.is_some() {
            // Use SNI-based certificate resolver from shared state
            if let Some(ref resolver) = state.cert_resolver {
                match TlsAcceptor::from_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>) {
                    Ok(acceptor) => {
                        info!("TLS enabled for entrypoint '{}' (SNI resolver)", name);
                        return Some(TokioTlsAcceptor::from(acceptor.get_config()));
                    }
                    Err(e) => {
                        error!("Failed to configure SNI TLS for '{}': {}", name, e);
                    }
                }
            } else {
                error!(
                    "Entrypoint '{}' requests cert_resolver but ACME is not configured",
                    name
                );
            }
        }

        // Fall back to static cert files
        if tls_config.cert_file.is_some() && tls_config.key_file.is_some() {
            match TlsAcceptor::from_entrypoint_tls(tls_config) {
                Ok(acceptor) => {
                    info!("TLS enabled for entrypoint '{}' (static cert)", name);
                    return Some(TokioTlsAcceptor::from(acceptor.get_config()));
                }
                Err(e) => {
                    error!("Failed to configure TLS for '{}': {}", name, e);
                }
            }
        }

        None
    }

    pub async fn serve(&self) -> Result<()> {
        let addr: SocketAddr = self
            .entrypoint
            .address
            .parse()
            .with_context(|| format!("Invalid address: {}", self.entrypoint.address))?;

        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        let protocol = if self.tls_acceptor.is_some() {
            "https"
        } else {
            "http"
        };
        info!(
            "Entrypoint '{}' listening on {} ({})",
            self.name, addr, protocol
        );

        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let state = Arc::clone(&self.state);
            let proxy = Arc::clone(&self.proxy);
            let entrypoint_name = self.name.clone();
            let tls_acceptor = self.tls_acceptor.clone();
            let connection_is_tls = tls_acceptor.is_some();

            tokio::spawn(async move {
                // Check if draining - reject new connections
                if !state.connections.connection_start() {
                    debug!("Rejecting connection from {} - server draining", remote_addr);
                    return;
                }

                if let Some(acceptor) = tls_acceptor {
                    // TLS connection
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            Self::serve_connection(
                                io,
                                remote_addr,
                                &entrypoint_name,
                                Arc::clone(&state),
                                proxy,
                                connection_is_tls,
                            )
                            .await;
                        }
                        Err(e) => {
                            debug!("TLS handshake failed from {}: {}", remote_addr, e);
                        }
                    }
                } else {
                    // Plain HTTP connection
                    let io = TokioIo::new(stream);
                    Self::serve_connection(
                        io,
                        remote_addr,
                        &entrypoint_name,
                        Arc::clone(&state),
                        proxy,
                        connection_is_tls,
                    )
                    .await;
                }

                // Mark connection as done
                state.connections.connection_end();
            });
        }
    }

    async fn serve_connection<I>(
        io: I,
        remote_addr: SocketAddr,
        entrypoint_name: &str,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
        is_tls: bool,
    ) where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let ep_name = entrypoint_name.to_string();

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let state = Arc::clone(&state);
            let proxy = Arc::clone(&proxy);
            let ep = ep_name.clone();

            async move {
                // Check for ACME HTTP-01 challenges first (on non-TLS connections)
                if !is_tls {
                    if let Some(response) =
                        try_handle_challenge(&req, &state.acme_challenges).await
                    {
                        // Convert Full<Bytes> to BoxBody
                        let boxed = response.map(|body| {
                            body.map_err(|_: std::convert::Infallible| {
                                unreachable!("Infallible error")
                            })
                            .boxed()
                        });
                        return Ok(boxed);
                    }
                }

                // Load current router and services (supports hot reload)
                let router = state.router.load();
                let services = state.services.load();

                proxy
                    .handle(req, remote_addr, &ep, &router, &services, is_tls)
                    .await
            }
        });

        // Auto-detect HTTP/1 or HTTP/2 (including h2c and ALPN negotiated h2)
        let builder = AutoBuilder::new(TokioExecutor::new());
        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            debug!("Connection error from {}: {}", remote_addr, e);
        }
    }
}
