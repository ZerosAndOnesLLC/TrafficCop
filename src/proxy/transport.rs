//! Backend (upstream) transports: one HTTP/1 + HTTP/2 client pair per Traefik
//! `serversTransport`, plus a default. Backend certificates are verified
//! against the system trust store unless `insecureSkipVerify` is set.

use crate::config::{Config, ServersTransport};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_rustls::{FixedServerNameResolver, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_rustls::TlsConnector;
use tracing::warn;

/// HTTPS-capable connector used by backend clients.
pub type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;
/// Backend client type.
pub type BackendClient = Client<HttpsConnector, BoxBody<Bytes, hyper::Error>>;

/// Name of the transport used when a service names none (Traefik `default`).
const DEFAULT_NAME: &str = "default";
const DEFAULT_IDLE_PER_HOST: usize = 256;

/// Client pair and TLS settings for one transport.
pub struct BackendClients {
    /// HTTP/1.1 (ALPN may negotiate h2 unless disableHTTP2) client.
    pub http1: BackendClient,
    /// HTTP/2-only client (gRPC, h2c).
    pub h2: BackendClient,
    /// TLS connector for raw dials (WebSocket upgrades).
    pub tls: TlsConnector,
    /// SNI / verification name override (`serverName`).
    pub server_name: Option<ServerName<'static>>,
    /// Response-header timeout; `None` keeps the proxy default.
    pub response_header_timeout: Option<Duration>,
    /// Serialized config, used to reuse pools across reloads.
    fingerprint: String,
}

/// All transports for the current config, keyed for per-service lookup.
pub struct TransportRegistry {
    default: Arc<BackendClients>,
    by_service: HashMap<String, Arc<BackendClients>>,
}

impl TransportRegistry {
    /// Build from config. Transports whose settings are unchanged from
    /// `previous` are reused so connection pools survive reloads.
    pub fn from_config(config: &Config, previous: Option<&TransportRegistry>) -> Result<Self> {
        let defined = config
            .http
            .as_ref()
            .map(|h| &h.servers_transports)
            .cloned()
            .unwrap_or_default();

        let reuse = |fp: &str| -> Option<Arc<BackendClients>> {
            let prev = previous?;
            std::iter::once(&prev.default)
                .chain(prev.by_service.values())
                .find(|c| c.fingerprint == fp)
                .cloned()
        };

        let mut built: HashMap<String, Arc<BackendClients>> = HashMap::new();
        for (name, t) in &defined {
            let fp = fingerprint(t);
            let clients = match reuse(&fp) {
                Some(c) => c,
                None => {
                    Arc::new(build(t, fp).with_context(|| format!("serversTransport '{name}'"))?)
                }
            };
            built.insert(name.clone(), clients);
        }

        let default = match built.get(DEFAULT_NAME) {
            Some(d) => Arc::clone(d),
            None => {
                let t = default_transport();
                let fp = fingerprint(&t);
                match reuse(&fp) {
                    Some(c) => c,
                    None => Arc::new(build(&t, fp)?),
                }
            }
        };

        let mut by_service = HashMap::new();
        for (svc, s) in config.services() {
            if let Some(name) = s
                .load_balancer
                .as_ref()
                .and_then(|lb| lb.servers_transport.as_ref())
            {
                let clients = built.get(name).with_context(|| {
                    format!("service '{svc}' references unknown serversTransport '{name}'")
                })?;
                by_service.insert(svc.clone(), Arc::clone(clients));
            }
        }

        Ok(Self {
            default,
            by_service,
        })
    }

    /// Transport for a service (its `serversTransport`, else the default).
    pub fn for_service(&self, service: &str) -> &Arc<BackendClients> {
        self.by_service.get(service).unwrap_or(&self.default)
    }
}

fn default_transport() -> ServersTransport {
    serde_norway::from_str("{}").unwrap_or_else(|_| ServersTransport {
        server_name: None,
        insecure_skip_verify: false,
        root_cas: Vec::new(),
        certificates: Vec::new(),
        max_idle_conns_per_host: 0,
        forwarding_timeouts: None,
        disable_http2: false,
        peer_cert_uri: None,
    })
}

fn fingerprint(t: &ServersTransport) -> String {
    serde_json::to_string(t).unwrap_or_default()
}

/// System trust store, falling back to the bundled Mozilla roots when the
/// host has none (e.g. scratch/distroless images).
fn system_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    Arc::clone(ROOTS.get_or_init(|| {
        let mut store = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            warn!("loading system root certificates: {}", e);
        }
        let (added, _) = store.add_parsable_certificates(native.certs);
        if added == 0 {
            warn!("no system root certificates found; using bundled Mozilla roots");
            store.add_parsable_certificates(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
            );
        }
        Arc::new(store)
    }))
}

fn read_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading certificates from '{path}'"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in '{path}'"))?;
    if certs.is_empty() {
        bail!("no certificates found in '{path}'");
    }
    Ok(certs)
}

/// Explicit crypto provider so behaviour never depends on process-global state.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_config(t: &ServersTransport) -> Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?;

    let builder = if t.insecure_skip_verify {
        warn!("serversTransport with insecureSkipVerify: backend certificates are NOT verified");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
    } else {
        // Traefik: rootCAs, when set, replace the system pool.
        let roots = if t.root_cas.is_empty() {
            system_roots()
        } else {
            let mut store = RootCertStore::empty();
            for path in &t.root_cas {
                for c in read_pem_certs(path)? {
                    store
                        .add(c)
                        .with_context(|| format!("invalid CA certificate in '{path}'"))?;
                }
            }
            Arc::new(store)
        };
        let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider())
            .build()
            .context("building certificate verifier")?;
        let verifier: Arc<dyn ServerCertVerifier> = match &t.peer_cert_uri {
            Some(uri) => Arc::new(PeerUriVerifier {
                inner: webpki,
                uri: uri.clone(),
            }),
            None => webpki,
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
    };

    let mut cfg = match t.certificates.as_slice() {
        [] => builder.with_no_client_auth(),
        [c] => {
            let chain = read_pem_certs(&c.cert_file)?;
            let key = PrivateKeyDer::from_pem_file(&c.key_file)
                .with_context(|| format!("reading private key '{}'", c.key_file))?;
            builder
                .with_client_auth_cert(chain, key)
                .context("invalid client certificate/key")?
        }
        _ => bail!("only one client certificate per serversTransport is supported"),
    };
    cfg.alpn_protocols = Vec::new();
    Ok(cfg)
}

fn build(t: &ServersTransport, fingerprint: String) -> Result<BackendClients> {
    let tls = tls_config(t)?;
    let timeouts = t.forwarding_timeouts.clone().unwrap_or_default();

    let server_name = match &t.server_name {
        Some(n) if !n.is_empty() => Some(
            ServerName::try_from(n.clone()).with_context(|| format!("invalid serverName '{n}'"))?,
        ),
        _ => None,
    };

    let idle_per_host = match t.max_idle_conns_per_host {
        n if n > 0 => n as usize,
        n if n < 0 => 0,
        _ => DEFAULT_IDLE_PER_HOST,
    };
    let idle_timeout = Some(timeouts.idle_conn_timeout.as_std()).filter(|d| !d.is_zero());
    let dial_timeout = Some(timeouts.dial_timeout.as_std()).filter(|d| !d.is_zero());

    let make = |h2_only: bool| -> BackendClient {
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.set_reuse_address(true);
        http.enforce_http(false);
        http.set_connect_timeout(dial_timeout);

        let b = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http();
        let b = match &server_name {
            Some(n) => b.with_server_name_resolver(FixedServerNameResolver::new(n.clone())),
            None => b,
        };
        let connector = if h2_only {
            b.enable_http2().wrap_connector(http)
        } else if t.disable_http2 {
            b.enable_http1().wrap_connector(http)
        } else {
            b.enable_all_versions().wrap_connector(http)
        };

        let mut cb = Client::builder(TokioExecutor::new());
        cb.pool_idle_timeout(idle_timeout)
            .pool_max_idle_per_host(idle_per_host)
            .retry_canceled_requests(true)
            .set_host(true);
        if h2_only {
            cb.http2_only(true);
        }
        cb.build(connector)
    };

    let mut raw = tls.clone();
    raw.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(BackendClients {
        http1: make(false),
        h2: make(true),
        tls: TlsConnector::from(Arc::new(raw)),
        server_name,
        response_header_timeout: Some(timeouts.response_header_timeout.as_std())
            .filter(|d| !d.is_zero()),
        fingerprint,
    })
}

/// Accept-all verifier for `insecureSkipVerify: true` only.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Standard verification plus a required URI SAN on the leaf (`peerCertURI`).
#[derive(Debug)]
struct PeerUriVerifier {
    inner: Arc<WebPkiServerVerifier>,
    uri: String,
}

impl ServerCertVerifier for PeerUriVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ok =
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        use x509_parser::prelude::*;
        let matches = X509Certificate::from_der(end_entity.as_ref())
            .ok()
            .and_then(|(_, c)| {
                c.subject_alternative_name()
                    .ok()
                    .flatten()
                    .map(|e| e.value.clone())
            })
            .is_some_and(|san| {
                san.general_names
                    .iter()
                    .any(|n| matches!(n, GeneralName::URI(u) if *u == self.uri))
            });
        if matches {
            Ok(ok)
        } else {
            Err(rustls::Error::General(format!(
                "backend certificate lacks URI SAN '{}'",
                self.uri
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

    /// TLS backend presenting the fixture leaf (SAN backend.test).
    async fn tls_backend() -> u16 {
        let certs = read_pem_certs(&format!("{FIX}/backend.pem")).unwrap();
        let key = PrivateKeyDer::from_pem_file(format!("{FIX}/backend.key")).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(|_r: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from_static(b"ok"),
                        )))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        port
    }

    fn registry(transport_yaml: &str) -> TransportRegistry {
        let yaml = format!(
            "entryPoints:\n  web: {{address: \"127.0.0.1:1\"}}\nhttp:\n  serversTransports:\n    t:\n{transport_yaml}\n  services:\n    plain:\n      loadBalancer: {{servers: [{{url: \"https://127.0.0.1:1\"}}]}}\n    custom:\n      loadBalancer:\n        serversTransport: t\n        servers: [{{url: \"https://127.0.0.1:1\"}}]\n"
        );
        let cfg = Config::from_yaml_str(&yaml).unwrap();
        TransportRegistry::from_config(&cfg, None).unwrap()
    }

    async fn get(c: &BackendClients, url: &str) -> Result<String, String> {
        let req = hyper::Request::get(url)
            .body(Empty::<Bytes>::new().map_err(|n| match n {}).boxed())
            .unwrap();
        let resp = c.http1.request(req).await.map_err(|e| format!("{e:?}"))?;
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&body.to_bytes()).into_owned())
    }

    #[tokio::test]
    async fn default_transport_rejects_untrusted_backend() {
        let port = tls_backend().await;
        let r = registry("      maxIdleConnsPerHost: 1");
        let res = get(
            r.for_service("plain"),
            &format!("https://127.0.0.1:{port}/"),
        )
        .await;
        assert!(
            res.is_err(),
            "self-signed backend must not be trusted by default"
        );
    }

    #[tokio::test]
    async fn root_cas_and_server_name() {
        let port = tls_backend().await;
        let r = registry(&format!(
            "      rootCAs: [\"{FIX}/ca.pem\"]\n      serverName: backend.test"
        ));
        let c = r.for_service("custom");
        assert_eq!(
            get(c, &format!("https://127.0.0.1:{port}/")).await.unwrap(),
            "ok"
        );
        // service without the transport still uses the default (untrusted)
        assert!(
            get(
                r.for_service("plain"),
                &format!("https://127.0.0.1:{port}/")
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn wrong_server_name_fails() {
        let port = tls_backend().await;
        let r = registry(&format!(
            "      rootCAs: [\"{FIX}/ca.pem\"]\n      serverName: other.test"
        ));
        assert!(
            get(
                r.for_service("custom"),
                &format!("https://127.0.0.1:{port}/")
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn peer_cert_uri_enforced() {
        let port = tls_backend().await;
        let ok = registry(&format!(
            "      rootCAs: [\"{FIX}/ca.pem\"]\n      serverName: backend.test\n      peerCertURI: spiffe://test/backend"
        ));
        assert!(
            get(
                ok.for_service("custom"),
                &format!("https://127.0.0.1:{port}/")
            )
            .await
            .is_ok()
        );
        let bad = registry(&format!(
            "      rootCAs: [\"{FIX}/ca.pem\"]\n      serverName: backend.test\n      peerCertURI: spiffe://test/other"
        ));
        assert!(
            get(
                bad.for_service("custom"),
                &format!("https://127.0.0.1:{port}/")
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn insecure_skip_verify_is_explicit_opt_in() {
        let port = tls_backend().await;
        let r = registry("      insecureSkipVerify: true");
        assert!(
            get(
                r.for_service("custom"),
                &format!("https://127.0.0.1:{port}/")
            )
            .await
            .is_ok()
        );
    }

    #[test]
    fn unknown_transport_and_bad_files_rejected() {
        let yaml = "entryPoints:\n  web: {address: \"127.0.0.1:1\"}\nhttp:\n  services:\n    s:\n      loadBalancer:\n        serversTransport: nope\n        servers: [{url: \"http://127.0.0.1:1\"}]\n";
        let cfg: Config = serde_norway::from_str(yaml).unwrap();
        assert!(TransportRegistry::from_config(&cfg, None).is_err());

        let yaml = "entryPoints:\n  web: {address: \"127.0.0.1:1\"}\nhttp:\n  serversTransports:\n    t: {rootCAs: [/nonexistent.pem]}\n";
        let cfg: Config = serde_norway::from_str(yaml).unwrap();
        assert!(TransportRegistry::from_config(&cfg, None).is_err());
    }

    #[test]
    fn unchanged_transports_are_reused_on_reload() {
        let r1 = registry("      maxIdleConnsPerHost: 5");
        let yaml = "entryPoints:\n  web: {address: \"127.0.0.1:1\"}\nhttp:\n  serversTransports:\n    t:\n      maxIdleConnsPerHost: 5\n  services:\n    custom:\n      loadBalancer:\n        serversTransport: t\n        servers: [{url: \"https://127.0.0.1:1\"}]\n";
        let r2 = TransportRegistry::from_config(&Config::from_yaml_str(yaml).unwrap(), Some(&r1))
            .unwrap();
        assert!(Arc::ptr_eq(
            r1.for_service("custom"),
            r2.for_service("custom")
        ));
        assert!(Arc::ptr_eq(&r1.default, &r2.default));
    }
}
