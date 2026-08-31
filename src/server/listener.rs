use crate::config::EntryPoint;
use crate::middleware::{AccessLogWriter, RequestContext};
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
use tracing::{debug, error, info, warn};

/// Forwarded headers stripped from requests arriving from untrusted peers,
/// preventing client IP spoofing and forwarded-header injection.
const FORWARDED_HEADERS: [&str; 6] = [
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-real-ip",
];

/// Precomputed forwarded-headers trust policy for an entrypoint
/// (Traefik `forwardedHeaders.trustedIPs` / `forwardedHeaders.insecure`).
/// Default with no configuration: no peer is trusted.
pub struct ForwardedTrust {
    insecure: bool,
    trusted: Vec<ipnetwork::IpNetwork>,
}

impl ForwardedTrust {
    fn from_entrypoint(name: &str, entrypoint: &EntryPoint) -> Self {
        let (insecure, trusted) = match &entrypoint.forwarded_headers {
            Some(fh) => {
                let trusted = fh
                    .trusted_ips
                    .iter()
                    .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                        Ok(net) => Some(net),
                        Err(_) => match s.parse::<std::net::IpAddr>() {
                            Ok(ip) => Some(ipnetwork::IpNetwork::from(ip)),
                            Err(_) => {
                                warn!(
                                    "Entrypoint '{}': invalid forwardedHeaders.trustedIPs entry '{}' ignored",
                                    name, s
                                );
                                None
                            }
                        },
                    })
                    .collect();
                (fh.insecure, trusted)
            }
            None => (false, Vec::new()),
        };
        Self { insecure, trusted }
    }

    fn is_trusted(&self, ip: std::net::IpAddr) -> bool {
        self.insecure || self.trusted.iter().any(|net| net.contains(ip))
    }
}

/// TCP/TLS listener for a single entrypoint, handling HTTP/1.1 and HTTP/2 connections.
pub struct Listener {
    name: Arc<str>,
    entrypoint: EntryPoint,
    state: Arc<SharedState>,
    proxy: Arc<ProxyHandler>,
    tls_acceptor: Option<TokioTlsAcceptor>,
    forwarded_trust: Arc<ForwardedTrust>,
    max_request_body_bytes: Option<u64>,
}

impl Listener {
    /// Create a listener for the given entrypoint, optionally with TLS.
    pub fn new(
        name: String,
        entrypoint: EntryPoint,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
    ) -> Self {
        // Build TLS acceptor
        let tls_acceptor = Self::build_tls_acceptor(&name, &entrypoint, &state);
        let forwarded_trust = Arc::new(ForwardedTrust::from_entrypoint(&name, &entrypoint));
        let max_request_body_bytes = entrypoint
            .transport
            .as_ref()
            .and_then(|t| t.max_request_body_bytes);

        Self {
            name: Arc::from(name),
            entrypoint,
            state,
            proxy,
            tls_acceptor,
            forwarded_trust,
            max_request_body_bytes,
        }
    }

    fn build_tls_acceptor(
        name: &str,
        entrypoint: &EntryPoint,
        state: &SharedState,
    ) -> Option<TokioTlsAcceptor> {
        // TLS can be configured at entrypoint level (http.tls)
        let tls_config = entrypoint.http.as_ref()?.tls.as_ref()?;

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

        // If TLS is enabled but no cert resolver, try to use certificates from global TLS config
        // This will be resolved by the router/server when loading the full config
        // For now, just enable TLS mode (the actual certs come from tls.certificates)
        info!("TLS enabled for entrypoint '{}' (via http.tls)", name);

        // Use shared cert resolver if available
        if let Some(ref resolver) = state.cert_resolver {
            match TlsAcceptor::from_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>) {
                Ok(acceptor) => {
                    return Some(TokioTlsAcceptor::from(acceptor.get_config()));
                }
                Err(e) => {
                    error!("Failed to configure TLS for '{}': {}", name, e);
                }
            }
        }

        None
    }

    /// Bind and accept connections in a loop until the server drains.
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
            let entrypoint_name = Arc::clone(&self.name);
            let tls_acceptor = self.tls_acceptor.clone();
            let connection_is_tls = tls_acceptor.is_some();
            let access_log = state.access_log.clone();
            let forwarded_trust = Arc::clone(&self.forwarded_trust);
            let max_body = self.max_request_body_bytes;

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
                                Arc::clone(&entrypoint_name),
                                Arc::clone(&state),
                                proxy,
                                connection_is_tls,
                                access_log,
                                forwarded_trust,
                                max_body,
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
                        entrypoint_name,
                        Arc::clone(&state),
                        proxy,
                        connection_is_tls,
                        access_log,
                        forwarded_trust,
                        max_body,
                    )
                    .await;
                }

                // Mark connection as done
                state.connections.connection_end();
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_connection<I>(
        io: I,
        remote_addr: SocketAddr,
        entrypoint_name: Arc<str>,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
        is_tls: bool,
        access_log: AccessLogWriter,
        forwarded_trust: Arc<ForwardedTrust>,
        max_body: Option<u64>,
    ) where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let service = service_fn(move |mut req: Request<hyper::body::Incoming>| {
            let state = Arc::clone(&state);
            let proxy = Arc::clone(&proxy);
            let ep = Arc::clone(&entrypoint_name);
            let access_log = access_log.clone();
            let forwarded_trust = Arc::clone(&forwarded_trust);

            async move {
                // Strip forwarded headers from untrusted peers so downstream
                // consumers (IP filters, access logs, backends) never see
                // client-spoofed values. Trust is granted via the entrypoint's
                // forwardedHeaders.trustedIPs / insecure settings.
                if !forwarded_trust.is_trusted(remote_addr.ip()) {
                    let headers = req.headers_mut();
                    for header in FORWARDED_HEADERS {
                        headers.remove(header);
                    }
                }

                // Reject oversized request bodies up front (transport.maxRequestBodyBytes).
                // Bodies stream through the proxy, so Content-Length is the
                // enforcement point; chunked uploads are bounded by backends.
                if let Some(limit) = max_body
                    && let Some(len) = req
                        .headers()
                        .get(hyper::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                    && len > limit
                {
                    let body = http_body_util::Full::new(bytes::Bytes::from_static(
                        b"Request Entity Too Large",
                    ))
                    .map_err(|_: std::convert::Infallible| unreachable!("Infallible error"))
                    .boxed();
                    return Ok(hyper::Response::builder()
                        .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                        .body(body)
                        .unwrap());
                }
                // Check for ACME HTTP-01 challenges first (on non-TLS connections)
                if !is_tls
                    && let Some(response) =
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

                // Inject request context for middleware (remote_addr, is_tls)
                req.extensions_mut().insert(RequestContext {
                    remote_addr,
                    is_tls,
                });

                // Load current router, services, and middlewares (supports hot reload)
                let router = state.router.load();
                let services = state.services.load();
                let middlewares = state.middlewares.load();
                let passive_health = Arc::clone(&state.passive_health);

                proxy
                    .handle(req, remote_addr, &ep, &router, &services, &middlewares, &passive_health, is_tls, &access_log)
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
