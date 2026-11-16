use crate::config::EntryPoint;
use crate::middleware::{AccessLogWriter, RequestContext};
use crate::proxy::ProxyHandler;
use crate::server::SharedState;
use crate::server::ep_redirect::EntryPointRedirect;
use crate::tls::try_handle_challenge;
use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::Request;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;
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

/// Per-connection TLS facts carried into request handling.
#[derive(Clone)]
struct TlsConnInfo {
    client_certs: Option<Arc<Vec<rustls::pki_types::CertificateDer<'static>>>>,
    /// TLS option selected from the SNI.
    option: Arc<str>,
}

/// TCP/TLS listener for a single entrypoint, handling HTTP/1.1 and HTTP/2 connections.
pub struct Listener {
    name: Arc<str>,
    entrypoint: EntryPoint,
    state: Arc<SharedState>,
    proxy: Arc<ProxyHandler>,
    /// Whether this entrypoint terminates TLS (http.tls).
    tls: bool,
    /// http.redirections.entryPoint, if configured.
    redirect: Option<Arc<EntryPointRedirect>>,
    forwarded_trust: Arc<ForwardedTrust>,
    max_request_body_bytes: Option<u64>,
}

impl Listener {
    /// Create a listener for the given entrypoint, optionally with TLS.
    /// TLS configs come from [`SharedState::tls_options`] per connection.
    pub fn new(
        name: String,
        entrypoint: EntryPoint,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
        redirect: Option<EntryPointRedirect>,
    ) -> Self {
        let tls = state.tls_options.load().is_tls(&name);
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
            tls,
            redirect: redirect.map(Arc::new),
            forwarded_trust,
            max_request_body_bytes,
        }
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

        let protocol = if self.tls { "https" } else { "http" };
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
            let connection_is_tls = self.tls;
            let access_log = state.access_log.clone();
            let forwarded_trust = Arc::clone(&self.forwarded_trust);
            let max_body = self.max_request_body_bytes;
            let redirect = self.redirect.clone();

            tokio::spawn(async move {
                // Check if draining - reject new connections
                if !state.connections.connection_start() {
                    debug!(
                        "Rejecting connection from {} - server draining",
                        remote_addr
                    );
                    return;
                }

                if connection_is_tls {
                    // Read the ClientHello first so the TLS option (versions,
                    // ciphers, client auth, sniStrict) can be chosen per SNI.
                    let start =
                        match LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                debug!("TLS ClientHello from {} failed: {}", remote_addr, e);
                                state.connections.connection_end();
                                return;
                            }
                        };
                    let sni = start.client_hello().server_name().map(str::to_string);
                    let Some((option, cfg)) = state
                        .tls_options
                        .load()
                        .select(&entrypoint_name, sni.as_deref())
                    else {
                        debug!("No TLS config for entrypoint '{}'", entrypoint_name);
                        state.connections.connection_end();
                        return;
                    };
                    match start.into_stream(cfg).await {
                        Ok(tls_stream) => {
                            let client_certs = tls_stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .filter(|c| !c.is_empty())
                                .map(|c| {
                                    Arc::new(c.iter().map(|d| d.clone().into_owned()).collect())
                                });
                            let io = TokioIo::new(tls_stream);
                            Self::serve_connection(
                                io,
                                remote_addr,
                                Some(TlsConnInfo {
                                    client_certs,
                                    option,
                                }),
                                Arc::clone(&entrypoint_name),
                                Arc::clone(&state),
                                proxy,
                                connection_is_tls,
                                access_log,
                                forwarded_trust,
                                max_body,
                                redirect,
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
                        None,
                        entrypoint_name,
                        Arc::clone(&state),
                        proxy,
                        connection_is_tls,
                        access_log,
                        forwarded_trust,
                        max_body,
                        redirect,
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
        tls_info: Option<TlsConnInfo>,
        entrypoint_name: Arc<str>,
        state: Arc<SharedState>,
        proxy: Arc<ProxyHandler>,
        is_tls: bool,
        access_log: AccessLogWriter,
        forwarded_trust: Arc<ForwardedTrust>,
        max_body: Option<u64>,
        redirect: Option<Arc<EntryPointRedirect>>,
    ) where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let service = service_fn(move |mut req: Request<hyper::body::Incoming>| {
            let state = Arc::clone(&state);
            let proxy = Arc::clone(&proxy);
            let ep = Arc::clone(&entrypoint_name);
            let access_log = access_log.clone();
            let forwarded_trust = Arc::clone(&forwarded_trust);
            let tls_info = tls_info.clone();
            let redirect = redirect.clone();

            async move {
                // TLS options are chosen from the SNI; the Host must map to the
                // same option or an mTLS/sniStrict/version policy could be
                // bypassed by fronting with another SNI (Traefik answers 421).
                if let Some(info) = &tls_info {
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .map(|h| h.rsplit_once(':').map(|(h, _)| h).unwrap_or(h).to_string())
                        .or_else(|| req.uri().host().map(str::to_string));
                    let expected = state
                        .tls_options
                        .load()
                        .option_for(&ep, host.as_deref())
                        .map(str::to_string);
                    if expected.as_deref() != Some(&*info.option) {
                        debug!(
                            "421: host {:?} TLS option {:?} != connection option '{}'",
                            host, expected, info.option
                        );
                        let body = http_body_util::Full::new(bytes::Bytes::from_static(
                            b"Misdirected Request",
                        ))
                        .map_err(|_: std::convert::Infallible| unreachable!("Infallible error"))
                        .boxed();
                        return Ok(hyper::Response::builder()
                            .status(hyper::StatusCode::MISDIRECTED_REQUEST)
                            .body(body)
                            .unwrap());
                    }
                }

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
                    && let Some(response) = try_handle_challenge(&req, &state.acme_challenges).await
                {
                    // Convert Full<Bytes> to BoxBody
                    let boxed = response.map(|body| {
                        body.map_err(|_: std::convert::Infallible| unreachable!("Infallible error"))
                            .boxed()
                    });
                    return Ok(boxed);
                }

                // Entrypoint-wide redirection (e.g. HTTP -> HTTPS).
                if let Some(r) = &redirect {
                    return Ok(r.respond(&req));
                }

                // Inject request context for middleware (remote_addr, is_tls)
                req.extensions_mut().insert(RequestContext {
                    remote_addr,
                    is_tls,
                    client_certs: tls_info.as_ref().and_then(|t| t.client_certs.clone()),
                });

                // Load current router, services, and middlewares (supports hot reload)
                let router = state.router.load();
                let services = state.services.load();
                let middlewares = state.middlewares.load();
                let transports = state.transports.load();
                let passive_health = Arc::clone(&state.passive_health);

                proxy
                    .handle(
                        req,
                        remote_addr,
                        &ep,
                        &router,
                        &services,
                        &middlewares,
                        &transports,
                        &passive_health,
                        is_tls,
                        &access_log,
                    )
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
