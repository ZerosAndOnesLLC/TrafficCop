//! Traefik TLS options (`tls.options`) applied per connection.
//!
//! One `ServerConfig` is built per TLS option. The option for a connection is
//! chosen from the SNI: routers on the entrypoint map their `Host()` domains
//! to their `tls.options` (or the entrypoint's, or `default`). After the
//! handshake, the HTTP Host must map to the same option, otherwise the request
//! is answered 421 (prevents bypassing e.g. mTLS via a different SNI).

use super::resolver::CertificateResolver;
use crate::config::{ClientAuth, Config, TlsOptions};
use crate::router::RuleParser;
use anyhow::{Context, Result, bail};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme,
    SupportedProtocolVersion,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, warn};

/// Name of the implicit option used when nothing else applies.
pub const DEFAULT_OPTION: &str = "default";

/// Built TLS options and the host -> option mapping per TLS entrypoint.
pub struct TlsOptionSet {
    configs: HashMap<String, Arc<ServerConfig>>,
    /// entrypoint -> lowercase host -> option name
    hosts: HashMap<String, HashMap<String, String>>,
    /// entrypoint -> option used for unknown hosts / no SNI
    ep_default: HashMap<String, String>,
}

impl TlsOptionSet {
    /// Build for every entrypoint with `http.tls`. A TLS entrypoint without a
    /// certificate source is an error (never fall back to plaintext).
    pub fn build(config: &Config, resolver: Option<Arc<CertificateResolver>>) -> Result<Self> {
        let defined = config
            .tls
            .as_ref()
            .map(|t| t.options.clone())
            .unwrap_or_default();

        let tls_eps: Vec<(&String, Option<String>)> = config
            .entry_points
            .iter()
            .filter_map(|(name, ep)| {
                ep.http
                    .as_ref()
                    .and_then(|h| h.tls.as_ref())
                    .map(|t| (name, t.options.clone()))
            })
            .collect();

        let mut set = Self {
            configs: HashMap::new(),
            hosts: HashMap::new(),
            ep_default: HashMap::new(),
        };
        if tls_eps.is_empty() {
            return Ok(set);
        }
        let Some(resolver) = resolver else {
            bail!(
                "entryPoint '{}' has http.tls but no certificate is configured (tls.certificates or a certificate resolver)",
                tls_eps[0].0
            );
        };

        let mut used: Vec<String> = vec![DEFAULT_OPTION.to_string()];
        for (ep, ep_opt) in &tls_eps {
            let ep_option = ep_opt.clone().unwrap_or_else(|| DEFAULT_OPTION.to_string());
            used.push(ep_option.clone());
            let mut host_map: HashMap<String, String> = HashMap::new();
            let mut conflicts: Vec<String> = Vec::new();

            for (rname, r) in config.routers() {
                let on_ep = r.entry_points.is_empty() || r.entry_points.iter().any(|e| e == *ep);
                if !on_ep {
                    continue;
                }
                let option = r
                    .tls
                    .as_ref()
                    .and_then(|t| t.options.clone())
                    .unwrap_or_else(|| ep_option.clone());
                used.push(option.clone());
                let Ok(rule) = RuleParser::parse(&r.rule) else {
                    continue;
                };
                for host in rule.all_hosts() {
                    let host = host.to_ascii_lowercase();
                    match host_map.get(&host) {
                        Some(existing) if *existing != option => {
                            error!(
                                "router '{}': host '{}' has conflicting TLS options ('{}' vs '{}'); using '{}'",
                                rname, host, existing, option, DEFAULT_OPTION
                            );
                            conflicts.push(host);
                        }
                        Some(_) => {}
                        None => {
                            host_map.insert(host, option.clone());
                        }
                    }
                }
            }
            for h in conflicts {
                host_map.insert(h, DEFAULT_OPTION.to_string());
            }
            set.hosts.insert((*ep).clone(), host_map);
            set.ep_default.insert((*ep).clone(), ep_option);
        }

        used.sort();
        used.dedup();
        for name in used {
            let opts = match defined.get(&name) {
                Some(o) => o.clone(),
                None if name == DEFAULT_OPTION => TlsOptions::default(),
                None => bail!("unknown TLS option '{name}'"),
            };
            let cfg = build_server_config(&opts, Arc::clone(&resolver))
                .with_context(|| format!("tls.options.{name}"))?;
            set.configs.insert(name, Arc::new(cfg));
        }
        Ok(set)
    }

    /// Whether the entrypoint terminates TLS.
    pub fn is_tls(&self, entrypoint: &str) -> bool {
        self.ep_default.contains_key(entrypoint)
    }

    /// TLS option name for a host on an entrypoint.
    pub fn option_for(&self, entrypoint: &str, host: Option<&str>) -> Option<&str> {
        let default = self.ep_default.get(entrypoint)?;
        let opt = host
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .and_then(|h| self.hosts.get(entrypoint)?.get(&h))
            .unwrap_or(default);
        Some(opt.as_str())
    }

    /// Server config to use for a ClientHello with this SNI.
    pub fn select(
        &self,
        entrypoint: &str,
        sni: Option<&str>,
    ) -> Option<(Arc<str>, Arc<ServerConfig>)> {
        let name = self.option_for(entrypoint, sni)?;
        let cfg = self.configs.get(name)?;
        Some((Arc::from(name), Arc::clone(cfg)))
    }
}

fn crypto(opts: &TlsOptions) -> Result<CryptoProvider> {
    let base = rustls::crypto::ring::default_provider();
    let mut provider = base.clone();

    if !opts.cipher_suites.is_empty() {
        let mut wanted = Vec::new();
        for name in &opts.cipher_suites {
            match rustls_suite_name(name) {
                Some(n) => wanted.push(n),
                None if is_known_weak_suite(name) => {
                    warn!("cipher suite '{}' is not supported (weak); skipped", name)
                }
                None => bail!("unknown cipher suite '{name}'"),
            }
        }
        // TLS 1.3 suites are not configurable (same as Go/Traefik).
        provider.cipher_suites = base
            .cipher_suites
            .iter()
            .filter(|s| {
                s.version() == &rustls::version::TLS13
                    || wanted.contains(&format!("{:?}", s.suite()).as_str())
            })
            .copied()
            .collect();
        if !provider
            .cipher_suites
            .iter()
            .any(|s| s.version() == &rustls::version::TLS12)
            && max_is_12(opts)
        {
            bail!("cipherSuites leaves no usable TLS 1.2 suite");
        }
    }

    if !opts.curve_preferences.is_empty() {
        let mut groups = Vec::new();
        for c in &opts.curve_preferences {
            let found = match c.as_str() {
                "X25519" => Some("X25519"),
                "CurveP256" | "secp256r1" | "P256" => Some("secp256r1"),
                "CurveP384" | "secp384r1" | "P384" => Some("secp384r1"),
                "CurveP521" | "secp521r1" | "P521" | "X25519MLKEM768" => {
                    warn!("curve '{}' is not supported; skipped", c);
                    None
                }
                other => bail!("unknown curve '{other}'"),
            };
            if let Some(n) = found
                && let Some(g) = base
                    .kx_groups
                    .iter()
                    .find(|g| format!("{:?}", g.name()).eq_ignore_ascii_case(n))
            {
                groups.push(*g);
            }
        }
        if groups.is_empty() {
            bail!("curvePreferences leaves no supported curve");
        }
        provider.kx_groups = groups;
    }
    Ok(provider)
}

fn max_is_12(opts: &TlsOptions) -> bool {
    opts.max_version.as_deref() == Some("VersionTLS12")
}

/// Go cipher-suite name -> rustls `CipherSuite` Debug name.
fn rustls_suite_name(go: &str) -> Option<&'static str> {
    Some(match go {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
        | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305" | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        // TLS 1.3 names are accepted and ignored (always enabled).
        "TLS_AES_128_GCM_SHA256" => "TLS13_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384" => "TLS13_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256" => "TLS13_CHACHA20_POLY1305_SHA256",
        _ => return None,
    })
}

fn is_known_weak_suite(go: &str) -> bool {
    go.starts_with("TLS_") && (go.contains("_CBC_") || go.contains("RC4") || go.contains("3DES"))
}

fn versions(opts: &TlsOptions) -> Result<Vec<&'static SupportedProtocolVersion>> {
    let rank = |v: &str| -> Result<u8> {
        Ok(match v {
            "VersionTLS10" | "VersionTLS11" => {
                warn!("{} is not supported; using VersionTLS12 as the minimum", v);
                12
            }
            "VersionTLS12" => 12,
            "VersionTLS13" => 13,
            other => bail!("unknown TLS version '{other}'"),
        })
    };
    let min = opts
        .min_version
        .as_deref()
        .map(rank)
        .transpose()?
        .unwrap_or(12);
    let max = opts
        .max_version
        .as_deref()
        .map(rank)
        .transpose()?
        .unwrap_or(13);
    if min > max {
        bail!("minVersion is greater than maxVersion");
    }
    let mut v = Vec::new();
    if min <= 13 && max >= 13 {
        v.push(&rustls::version::TLS13);
    }
    if min <= 12 && max >= 12 {
        v.push(&rustls::version::TLS12);
    }
    Ok(v)
}

fn load_ca(entry: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = if entry.contains("-----BEGIN") {
        CertificateDer::pem_slice_iter(entry.as_bytes())
            .collect::<Result<_, _>>()
            .context("parsing inline CA")?
    } else {
        CertificateDer::pem_file_iter(entry)
            .with_context(|| format!("reading CA file '{entry}'"))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("parsing CA file '{entry}'"))?
    };
    if certs.is_empty() {
        bail!("no certificates in CA '{entry}'");
    }
    Ok(certs)
}

fn client_verifier(
    ca: Option<&ClientAuth>,
    provider: &Arc<CryptoProvider>,
) -> Result<Option<Arc<dyn ClientCertVerifier>>> {
    let Some(ca) = ca else {
        return Ok(None);
    };
    let mut roots = RootCertStore::empty();
    for f in &ca.ca_files {
        for c in load_ca(f)? {
            roots.add(c).context("invalid client CA certificate")?;
        }
    }
    let has_cas = !ca.ca_files.is_empty();
    // Traefik: caFiles without an explicit type means RequireAndVerifyClientCert.
    let mode = match ca.client_auth_type.as_deref() {
        None | Some("") if has_cas => "RequireAndVerifyClientCert",
        None | Some("") => "NoClientCert",
        Some(m) => m,
    };
    let webpki = |allow_unauth: bool| -> Result<Arc<dyn ClientCertVerifier>> {
        if !has_cas {
            bail!("clientAuthType {mode} requires caFiles");
        }
        let b = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            Arc::clone(provider),
        );
        let b = if allow_unauth {
            b.allow_unauthenticated()
        } else {
            b
        };
        let v: Arc<dyn ClientCertVerifier> = b.build().context("building client verifier")?;
        Ok(v)
    };
    Ok(match mode {
        "NoClientCert" => None,
        "RequestClientCert" => Some(Arc::new(AnyClientCert::new(false, provider))),
        "RequireAnyClientCert" => Some(Arc::new(AnyClientCert::new(true, provider))),
        "VerifyClientCertIfGiven" => Some(webpki(true)?),
        "RequireAndVerifyClientCert" => Some(webpki(false)?),
        other => bail!("unknown clientAuthType '{other}'"),
    })
}

/// Build the rustls config for one TLS option.
pub fn build_server_config(
    opts: &TlsOptions,
    resolver: Arc<CertificateResolver>,
) -> Result<ServerConfig> {
    let provider = Arc::new(crypto(opts)?);
    let versions = versions(opts)?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&versions)
        .context("incompatible TLS versions / cipher suites")?;
    let builder = match client_verifier(opts.client_auth.as_ref(), &provider)? {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    };
    let cert_resolver: Arc<dyn ResolvesServerCert> = if opts.sni_strict {
        Arc::new(StrictResolver(resolver))
    } else {
        resolver
    };
    let mut cfg = builder.with_cert_resolver(cert_resolver);
    cfg.alpn_protocols = if opts.alpn_protocols.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        opts.alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect()
    };
    cfg.ignore_client_order = opts.prefer_server_cipher_suites;
    Ok(cfg)
}

/// `sniStrict`: refuse handshakes without SNI or without a matching certificate.
#[derive(Debug)]
struct StrictResolver(Arc<CertificateResolver>);

impl ResolvesServerCert for StrictResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello
            .server_name()
            .and_then(|sni| self.0.find_cert_exact(sni))
    }
}

/// RequestClientCert / RequireAnyClientCert: accept any client certificate
/// without chain validation, but still verify the handshake signature.
#[derive(Debug)]
struct AnyClientCert {
    mandatory: bool,
    algs: WebPkiSupportedAlgorithms,
}

impl AnyClientCert {
    fn new(mandatory: bool, provider: &Arc<CryptoProvider>) -> Self {
        Self {
            mandatory,
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConfig;
    use rustls::pki_types::{PrivateKeyDer, ServerName};

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

    fn set(extra_tls: &str, routers: &str) -> Result<TlsOptionSet> {
        let yaml = format!(
            r#"
entryPoints:
  websecure:
    address: "127.0.0.1:1"
    http: {{tls: {{}}}}
tls:
  certificates:
    - {{certFile: "{FIX}/backend.pem", keyFile: "{FIX}/backend.key"}}
{extra_tls}
http:
  routers:
{routers}
  services:
    s:
      loadBalancer: {{servers: [{{url: "http://127.0.0.1:9"}}]}}
"#
        );
        let cfg = Config::from_yaml_str(&yaml)?;
        let resolver = Arc::new(CertificateResolver::from_static_certs(
            &cfg.tls.as_ref().unwrap().certificates,
        )?);
        TlsOptionSet::build(&cfg, Some(resolver))
    }

    const MTLS: &str = r#"  options:
    mtls:
      clientAuth:
        caFiles: ["FIX/client-ca.pem"]
        clientAuthType: RequireAndVerifyClientCert
    modern:
      minVersion: VersionTLS13
    strict:
      sniStrict: true"#;

    fn opts() -> String {
        MTLS.replace("FIX", FIX)
    }

    const ROUTERS: &str = r#"    admin: {rule: "Host(`backend.test`)", service: s, tls: {options: mtls}}
    pub: {rule: "Host(`public.test`) || Host(`www.public.test`)", service: s}"#;

    /// Handshake over an in-memory pipe; returns the negotiated option name.
    async fn handshake(
        set: &TlsOptionSet,
        sni: Option<&str>,
        client_cert: bool,
        tls12_only: bool,
    ) -> Result<String, String> {
        let mut roots = RootCertStore::empty();
        for c in load_ca(&format!("{FIX}/ca.pem")).unwrap() {
            roots.add(c).unwrap();
        }
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&SupportedProtocolVersion] = if tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let b = ClientConfig::builder_with_provider(p)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots);
        let mut ccfg = if client_cert {
            let chain = load_ca(&format!("{FIX}/client.pem")).unwrap();
            let key = PrivateKeyDer::from_pem_file(format!("{FIX}/client.key")).unwrap();
            b.with_client_auth_cert(chain, key).unwrap()
        } else {
            b.with_no_client_auth()
        };
        // Verify the server against backend.test regardless of the SNI sent.
        ccfg.enable_sni = sni.is_some();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));

        let (c, s) = tokio::io::duplex(64 * 1024);
        let server = async {
            let start =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), s)
                    .await
                    .map_err(|e| e.to_string())?;
            let sni = start.client_hello().server_name().map(str::to_string);
            let (name, cfg) = set.select("websecure", sni.as_deref()).ok_or("no config")?;
            let mut tls = start.into_stream(cfg).await.map_err(|e| e.to_string())?;
            use tokio::io::AsyncWriteExt;
            tls.write_all(b"x").await.map_err(|e| e.to_string())?;
            Ok::<_, String>(name.to_string())
        };
        let name = ServerName::try_from(sni.unwrap_or("backend.test").to_string()).unwrap();
        let client = async {
            let mut tls = connector
                .connect(name, c)
                .await
                .map_err(|e| e.to_string())?;
            use tokio::io::AsyncReadExt;
            let mut b = [0u8; 1];
            tls.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        };
        let (s, c) = tokio::join!(server, client);
        c?;
        s
    }

    #[tokio::test]
    async fn mtls_required_for_mapped_host() {
        let set = set(&opts(), ROUTERS).unwrap();
        assert!(
            handshake(&set, Some("backend.test"), false, false)
                .await
                .is_err()
        );
        assert_eq!(
            handshake(&set, Some("backend.test"), true, false)
                .await
                .unwrap(),
            "mtls"
        );
    }

    #[tokio::test]
    async fn other_hosts_use_default_option() {
        let set = set(&opts(), ROUTERS).unwrap();
        assert_eq!(
            set.option_for("websecure", Some("www.public.test")),
            Some("default")
        );
        assert_eq!(
            set.option_for("websecure", Some("BACKEND.test")),
            Some("mtls")
        );
        // No SNI: default option and default (only) certificate.
        assert_eq!(
            handshake(&set, None, false, false).await.unwrap(),
            "default"
        );
    }

    #[tokio::test]
    async fn min_version_enforced() {
        let routers =
            r#"    r: {rule: "Host(`backend.test`)", service: s, tls: {options: modern}}"#;
        let set = set(&opts(), routers).unwrap();
        assert!(
            handshake(&set, Some("backend.test"), false, true)
                .await
                .is_err()
        );
        assert!(
            handshake(&set, Some("backend.test"), false, false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn sni_strict_rejects_unknown_and_missing_sni() {
        let extra = "  options:\n    default:\n      sniStrict: true";
        let routers = r#"    r: {rule: "PathPrefix(`/`)", service: s}"#;
        let set = set(extra, routers).unwrap();
        assert!(handshake(&set, None, false, false).await.is_err());
        assert!(
            handshake(&set, Some("unknown.test"), false, false)
                .await
                .is_err()
        );
        assert!(
            handshake(&set, Some("backend.test"), false, false)
                .await
                .is_ok()
        );
    }

    #[test]
    fn invalid_options_are_errors() {
        let r = r#"    r: {rule: "Host(`a.test`)", service: s, tls: {options: x}}"#;
        for bad in [
            "  options:\n    x: {clientAuth: {clientAuthType: RequireAndVerifyClientCrt, caFiles: [\"FIX/client-ca.pem\"]}}",
            "  options:\n    x: {clientAuth: {clientAuthType: RequireAndVerifyClientCert}}",
            "  options:\n    x: {minVersion: VersionTLS14}",
            "  options:\n    x: {minVersion: VersionTLS13, maxVersion: VersionTLS12}",
            "  options:\n    x: {cipherSuites: [TLS_BOGUS]}",
            "  options:\n    x: {curvePreferences: [CurveBogus]}",
            "  options:\n    y: {}",
        ] {
            assert!(set(&bad.replace("FIX", FIX), r).is_err(), "{bad}");
        }
        // weak CBC suites are skipped, not fatal
        let ok = "  options:\n    x: {cipherSuites: [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]}";
        assert!(set(ok, r).is_ok());
    }

    #[test]
    fn ca_files_without_type_require_verification() {
        let ca = ClientAuth {
            ca_files: vec![format!("{FIX}/client-ca.pem")],
            client_auth_type: None,
        };
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let v = client_verifier(Some(&ca), &p).unwrap().unwrap();
        assert!(v.client_auth_mandatory());
    }

    #[test]
    fn tls_entrypoint_without_certs_is_error() {
        let yaml =
            "entryPoints:\n  websecure:\n    address: \"127.0.0.1:1\"\n    http: {tls: {}}\n";
        let cfg = Config::from_yaml_str(yaml).unwrap();
        assert!(TlsOptionSet::build(&cfg, None).is_err());
    }
}
