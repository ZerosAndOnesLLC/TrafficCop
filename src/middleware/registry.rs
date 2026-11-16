use super::auth_wrappers::{DigestAuthWrapper, ForwardAuthWrapper, JwtWrapper};
use super::builtin::{
    AddPrefixMiddleware, BasicAuthMiddleware, CorsMiddleware, DigestAuthMiddleware,
    ForwardAuthMiddleware, HeadersMiddleware, IpAllowListMiddleware, IpDenyListMiddleware,
    JwtMiddleware, RateLimitMiddleware, RedirectSchemeMiddleware, ReplacePathMiddleware,
    ReplacePathRegexMiddleware, StripPrefixMiddleware, StripPrefixRegexMiddleware,
};
use super::traffic_wrappers::{
    ContentTypeWrapper, InFlightReqWrapper, PassTlsClientCertWrapper, RedirectRegexWrapper,
};
use super::{BoxFuture, Middleware, Next};
use crate::config::MiddlewareConfig;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Request, Response, StatusCode, body::Incoming};
use rustls::pki_types::CertificateDer;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, warn};

/// Request context injected via request extensions before middleware chain runs
#[derive(Clone)]
pub struct RequestContext {
    /// The client's socket address.
    pub remote_addr: SocketAddr,
    /// Whether the connection arrived over TLS.
    pub is_tls: bool,
    /// Client certificate chain presented during the TLS handshake (leaf first).
    pub client_certs: Option<Arc<Vec<CertificateDer<'static>>>>,
}

/// Registry of instantiated middleware, keyed by name.
///
/// Construction fails if any middleware cannot be built: a router must never
/// run with a configured middleware silently missing.
pub struct MiddlewareRegistry {
    middlewares: HashMap<String, Arc<dyn Middleware>>,
    /// Chain name -> flattened list of non-chain middleware names.
    chains: HashMap<String, Vec<String>>,
}

impl MiddlewareRegistry {
    /// Build registry from config middleware definitions.
    pub fn from_config(configs: &HashMap<String, MiddlewareConfig>) -> Result<Self, String> {
        let mut middlewares: HashMap<String, Arc<dyn Middleware>> = HashMap::new();

        for (name, config) in configs {
            if config.chain.is_some() {
                continue;
            }
            let mw = Self::create_middleware(name, config)
                .map_err(|e| format!("middleware '{name}': {e}"))?;
            debug!("Registered middleware '{}'", name);
            middlewares.insert(name.clone(), mw);
        }

        let mut chains = HashMap::new();
        for (name, config) in configs {
            if config.chain.is_some() {
                let mut out = Vec::new();
                let mut stack = HashSet::new();
                Self::flatten(name, configs, &mut stack, &mut out)?;
                chains.insert(name.clone(), out);
            }
        }

        Ok(Self {
            middlewares,
            chains,
        })
    }

    /// Expand a chain into its leaf middleware names, rejecting cycles and
    /// unknown references.
    fn flatten(
        name: &str,
        configs: &HashMap<String, MiddlewareConfig>,
        stack: &mut HashSet<String>,
        out: &mut Vec<String>,
    ) -> Result<(), String> {
        let config = configs
            .get(name)
            .ok_or_else(|| format!("chain references unknown middleware '{name}'"))?;
        let Some(chain) = &config.chain else {
            out.push(name.to_string());
            return Ok(());
        };
        if !stack.insert(name.to_string()) {
            return Err(format!("middleware chain cycle detected at '{name}'"));
        }
        if chain.middlewares.is_empty() {
            return Err(format!("chain '{name}' has no middlewares"));
        }
        for child in &chain.middlewares {
            Self::flatten(child, configs, stack, out)?;
        }
        stack.remove(name);
        Ok(())
    }

    /// Look up middleware by name and return the ordered list of instances,
    /// expanding chains. Any unknown name is an error: callers must refuse
    /// the request rather than serve it without the middleware.
    pub fn resolve(&self, names: &[String]) -> Result<Vec<Arc<dyn Middleware>>, String> {
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            if let Some(mw) = self.middlewares.get(name) {
                out.push(Arc::clone(mw));
            } else if let Some(flat) = self.chains.get(name) {
                for leaf in flat {
                    let mw = self
                        .middlewares
                        .get(leaf)
                        .ok_or_else(|| format!("middleware '{leaf}' not found"))?;
                    out.push(Arc::clone(mw));
                }
            } else {
                return Err(format!("middleware '{name}' not found"));
            }
        }
        Ok(out)
    }

    fn create_middleware(
        name: &str,
        config: &MiddlewareConfig,
    ) -> Result<Arc<dyn Middleware>, String> {
        let types = config.configured_types();
        match types.len() {
            0 => return Err("no middleware type configured".to_string()),
            1 => {}
            _ => {
                return Err(format!(
                    "multiple middleware types in one definition are not supported: {}",
                    types.join(", ")
                ));
            }
        }
        let name = name.to_string();

        if let Some(headers_config) = &config.headers {
            let headers = HeadersMiddleware::new(headers_config.clone());
            if let Some(cors) = CorsMiddleware::from_headers_config(headers_config) {
                return Ok(Arc::new(HeadersAndCorsWrapper {
                    name,
                    headers,
                    cors,
                }));
            }
            return Ok(Arc::new(HeadersWrapper {
                name,
                inner: headers,
            }));
        }

        if let Some(rl_config) = &config.rate_limit {
            return Ok(Arc::new(RateLimitWrapper {
                name,
                inner: RateLimitMiddleware::new(rl_config.clone()),
            }));
        }

        if let Some(allow_config) = config.get_ip_allow_list() {
            return Ok(Arc::new(IpAllowWrapper {
                name,
                inner: IpAllowListMiddleware::new(allow_config),
            }));
        }

        if let Some(deny_config) = &config.ip_deny_list {
            return Ok(Arc::new(IpDenyWrapper {
                name,
                inner: IpDenyListMiddleware::new(deny_config),
            }));
        }

        if let Some(auth_config) = &config.basic_auth {
            return Ok(Arc::new(BasicAuthWrapper {
                name,
                inner: BasicAuthMiddleware::new(auth_config.clone()),
            }));
        }

        if let Some(c) = &config.digest_auth {
            return Ok(Arc::new(DigestAuthWrapper {
                name,
                inner: DigestAuthMiddleware::new(c.clone())?,
            }));
        }

        if let Some(c) = &config.forward_auth {
            return Ok(Arc::new(ForwardAuthWrapper {
                name,
                inner: ForwardAuthMiddleware::new(c.clone())?,
            }));
        }

        if let Some(c) = &config.jwt {
            let inner = JwtMiddleware::new(c.clone()).ok_or(
                "jwt: invalid configuration (supported: HS256/HS384/HS512 with a secret and a valid headerName)",
            )?;
            return Ok(Arc::new(JwtWrapper {
                name,
                inner,
                forward_headers: c.forward_claims.values().cloned().collect(),
            }));
        }

        if let Some(redirect_config) = &config.redirect_scheme {
            return Ok(Arc::new(RedirectSchemeWrapper {
                name,
                inner: RedirectSchemeMiddleware::new(redirect_config.clone()),
            }));
        }

        if let Some(c) = &config.redirect_regex {
            return Ok(Arc::new(RedirectRegexWrapper::new(name, c)?));
        }

        if let Some(c) = &config.in_flight_req {
            return Ok(Arc::new(InFlightReqWrapper::new(name, c)?));
        }

        if config.content_type.is_some() {
            return Ok(Arc::new(ContentTypeWrapper { name }));
        }

        if let Some(c) = &config.pass_tls_client_cert {
            return Ok(Arc::new(PassTlsClientCertWrapper::new(name, c)));
        }

        if let Some(strip_config) = &config.strip_prefix {
            return Ok(Arc::new(StripPrefixWrapper {
                name,
                inner: StripPrefixMiddleware::new(strip_config.clone()),
            }));
        }

        if let Some(prefix_config) = &config.add_prefix {
            return Ok(Arc::new(AddPrefixWrapper {
                name,
                inner: AddPrefixMiddleware::new(prefix_config.clone()),
            }));
        }

        if let Some(replace_config) = &config.replace_path {
            return Ok(Arc::new(ReplacePathWrapper {
                name,
                inner: ReplacePathMiddleware::new(replace_config.clone()),
            }));
        }

        if let Some(c) = &config.strip_prefix_regex {
            let inner = StripPrefixRegexMiddleware::new(c.clone())
                .ok_or("stripPrefixRegex: invalid regex")?;
            return Ok(Arc::new(StripPrefixRegexWrapper { name, inner }));
        }

        if let Some(c) = &config.replace_path_regex {
            let inner = ReplacePathRegexMiddleware::new(c.clone())
                .ok_or("replacePathRegex: invalid regex")?;
            return Ok(Arc::new(ReplacePathRegexWrapper { name, inner }));
        }

        // Not yet implemented, and not access controls: accepted with a loud
        // warning so existing configs keep starting. Tracked publicly.
        if config.compress.is_some()
            || config.retry.is_some()
            || config.circuit_breaker.is_some()
            || config.errors.is_some()
            || config.grpc_web.is_some()
        {
            warn!(
                "middleware '{}': type '{}' is accepted but NOT applied yet; requests pass through unchanged",
                name,
                config.middleware_type()
            );
            return Ok(Arc::new(NotAppliedWrapper { name }));
        }

        Err(format!(
            "middleware type '{}' is not supported yet",
            config.middleware_type()
        ))
    }
}

// --- Wrapper implementations ---

/// Build a plain-text error response with the given status code and message.
pub(super) fn error_response(
    status: StatusCode,
    msg: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain")
        .body(
            Full::new(Bytes::from(msg.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Extract the client IP from the request's [`RequestContext`] extension.
pub(super) fn get_client_ip(req: &Request<Incoming>) -> Option<IpAddr> {
    req.extensions()
        .get::<RequestContext>()
        .map(|ctx| ctx.remote_addr.ip())
}

// --- Headers ---
struct HeadersWrapper {
    name: String,
    inner: HeadersMiddleware,
}

impl Middleware for HeadersWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            self.inner.apply_request(req.headers_mut());
            let mut resp = next.run(req).await?;
            self.inner.apply_response(resp.headers_mut());
            Ok(resp)
        })
    }
}

// --- Headers + CORS ---
struct HeadersAndCorsWrapper {
    name: String,
    headers: HeadersMiddleware,
    cors: CorsMiddleware,
}

impl Middleware for HeadersAndCorsWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            // Handle CORS preflight
            if self.cors.is_preflight(&req) {
                if let Some(resp) = self.cors.handle_preflight(&req) {
                    let (parts, _) = resp.into_parts();
                    return Ok(Response::from_parts(
                        parts,
                        Full::new(Bytes::new())
                            .map_err(|never| match never {})
                            .boxed(),
                    ));
                }
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "CORS origin not allowed",
                ));
            }

            let origin = CorsMiddleware::get_origin(&req);
            self.headers.apply_request(req.headers_mut());
            let mut resp = next.run(req).await?;
            self.headers.apply_response(resp.headers_mut());
            self.cors
                .apply_headers(origin.as_deref(), resp.headers_mut());
            Ok(resp)
        })
    }
}

// --- Rate Limit ---
struct RateLimitWrapper {
    name: String,
    inner: RateLimitMiddleware,
}

impl Middleware for RateLimitWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some(ip) = get_client_ip(&req)
                && !self.inner.is_allowed(ip)
            {
                return Ok(error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded",
                ));
            }
            next.run(req).await
        })
    }
}

// --- IP Allow ---
struct IpAllowWrapper {
    name: String,
    inner: IpAllowListMiddleware,
}

impl Middleware for IpAllowWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if self.inner.has_rules()
                && let Some(ip) = get_client_ip(&req)
                && !self.inner.is_allowed(ip)
            {
                let status = StatusCode::from_u16(self.inner.reject_status_code())
                    .unwrap_or(StatusCode::FORBIDDEN);
                return Ok(error_response(status, "Forbidden"));
            }
            next.run(req).await
        })
    }
}

// --- IP Deny ---
struct IpDenyWrapper {
    name: String,
    inner: IpDenyListMiddleware,
}

impl Middleware for IpDenyWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if self.inner.has_rules()
                && let Some(ip) = get_client_ip(&req)
                && self.inner.is_denied(ip)
            {
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            next.run(req).await
        })
    }
}

// --- Basic Auth ---
struct BasicAuthWrapper {
    name: String,
    inner: BasicAuthMiddleware,
}

impl Middleware for BasicAuthWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if !self.inner.is_authenticated(&req) {
                let resp = self.inner.unauthorized_response();
                let (parts, _) = resp.into_parts();
                return Ok(Response::from_parts(
                    parts,
                    Full::new(Bytes::from("Unauthorized"))
                        .map_err(|never| match never {})
                        .boxed(),
                ));
            }
            next.run(req).await
        })
    }
}

// --- Redirect Scheme ---
struct RedirectSchemeWrapper {
    name: String,
    inner: RedirectSchemeMiddleware,
}

impl Middleware for RedirectSchemeWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            let is_tls = req
                .extensions()
                .get::<RequestContext>()
                .map(|ctx| ctx.is_tls)
                .unwrap_or(false);

            if self.inner.should_redirect(is_tls) {
                let resp = self.inner.build_redirect(&req);
                let (parts, _) = resp.into_parts();
                return Ok(Response::from_parts(
                    parts,
                    Full::new(Bytes::new())
                        .map_err(|never| match never {})
                        .boxed(),
                ));
            }
            next.run(req).await
        })
    }
}

// --- Strip Prefix ---
struct StripPrefixWrapper {
    name: String,
    inner: StripPrefixMiddleware,
}

impl Middleware for StripPrefixWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some((new_uri, prefix)) = self.inner.transform_uri(req.uri()) {
                *req.uri_mut() = new_uri;
                if let Ok(val) = HeaderValue::from_str(&prefix) {
                    req.headers_mut().insert("X-Forwarded-Prefix", val);
                }
            }
            next.run(req).await
        })
    }
}

// --- Add Prefix ---
struct AddPrefixWrapper {
    name: String,
    inner: AddPrefixMiddleware,
}

impl Middleware for AddPrefixWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some(new_uri) = self.inner.transform_uri(req.uri()) {
                *req.uri_mut() = new_uri;
            }
            next.run(req).await
        })
    }
}

// --- Replace Path ---
struct ReplacePathWrapper {
    name: String,
    inner: ReplacePathMiddleware,
}

impl Middleware for ReplacePathWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some((new_uri, original)) = self.inner.transform_uri(req.uri()) {
                *req.uri_mut() = new_uri;
                if let Ok(val) = HeaderValue::from_str(&original) {
                    req.headers_mut().insert("X-Replaced-Path", val);
                }
            }
            next.run(req).await
        })
    }
}

// --- Strip Prefix Regex ---
struct StripPrefixRegexWrapper {
    name: String,
    inner: StripPrefixRegexMiddleware,
}

impl Middleware for StripPrefixRegexWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some((new_uri, prefix)) = self.inner.transform_uri(req.uri()) {
                *req.uri_mut() = new_uri;
                if let Ok(val) = HeaderValue::from_str(&prefix) {
                    req.headers_mut().insert("X-Forwarded-Prefix", val);
                }
            }
            next.run(req).await
        })
    }
}

// --- Replace Path Regex ---
struct ReplacePathRegexWrapper {
    name: String,
    inner: ReplacePathRegexMiddleware,
}

impl Middleware for ReplacePathRegexWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some((new_uri, original)) = self.inner.transform_uri(req.uri()) {
                *req.uri_mut() = new_uri;
                if let Ok(val) = HeaderValue::from_str(&original) {
                    req.headers_mut().insert("X-Replaced-Path", val);
                }
            }
            next.run(req).await
        })
    }
}

// --- Accepted but not yet applied (compress, retry, circuitBreaker, errors, grpcWeb) ---
struct NotAppliedWrapper {
    name: String,
}

impl Middleware for NotAppliedWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        next.run(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configs(yaml: &str) -> HashMap<String, MiddlewareConfig> {
        serde_norway::from_str(yaml).unwrap()
    }

    fn names(v: &[Arc<dyn Middleware>]) -> Vec<&str> {
        v.iter().map(|m| m.name()).collect()
    }

    const AUTH: &str = r#"
auth:
  basicAuth:
    users: ["u:$2y$05$c3RYpRMhSVOWHM6Ld2Lp8uFV3xJ6eOTW2QHC.JxHgbm2cU0vXkLz."]
hdr:
  headers:
    customRequestHeaders: {X-A: "1"}
"#;

    #[test]
    fn chain_is_flattened_in_order() {
        let c = configs(&format!(
            "{AUTH}\ninner:\n  chain:\n    middlewares: [hdr]\nouter:\n  chain:\n    middlewares: [auth, inner]\n"
        ));
        let r = MiddlewareRegistry::from_config(&c).unwrap();
        let got = r.resolve(&["outer".into()]).unwrap();
        assert_eq!(names(&got), vec!["auth", "hdr"]);
    }

    #[test]
    fn chain_cycle_and_unknown_ref_rejected() {
        let c = configs("a:\n  chain:\n    middlewares: [b]\nb:\n  chain:\n    middlewares: [a]\n");
        assert!(
            MiddlewareRegistry::from_config(&c)
                .err()
                .unwrap()
                .contains("cycle")
        );
        let c = configs("a:\n  chain:\n    middlewares: [missing]\n");
        assert!(
            MiddlewareRegistry::from_config(&c)
                .err()
                .unwrap()
                .contains("missing")
        );
    }

    #[test]
    fn resolve_unknown_name_fails_closed() {
        let r = MiddlewareRegistry::from_config(&configs(AUTH)).unwrap();
        assert!(r.resolve(&["nope".into()]).is_err());
        assert!(r.resolve(&["auth".into(), "nope".into()]).is_err());
    }

    #[test]
    fn previously_skipped_types_now_build() {
        let c = configs(
            r#"
fa:
  forwardAuth: {address: "http://auth:9091/verify"}
da:
  digestAuth: {users: ["test:traefik:a2688e031edb4be6a3797f3882655c05"]}
jw:
  jwt: {secret: "s", algorithm: "HS256"}
rr:
  redirectRegex: {regex: "^http://a/(.*)", replacement: "http://b/${1}"}
ifr:
  inFlightReq: {amount: 10}
ct:
  contentType: {}
pc:
  passTLSClientCert: {pem: true}
rt:
  retry: {attempts: 3}
"#,
        );
        let r = MiddlewareRegistry::from_config(&c).unwrap();
        for n in ["fa", "da", "jw", "rr", "ifr", "ct", "pc", "rt"] {
            assert!(r.resolve(&[n.into()]).is_ok(), "{n}");
        }
    }

    #[test]
    fn unsupported_or_invalid_definitions_are_errors() {
        for yaml in [
            "x:\n  buffering: {maxRequestBodyBytes: 10}\n",
            "x:\n  forwardAuth: {address: \"not a url\"}\n",
            "x:\n  digestAuth: {users: [\"admin:plaintext\"]}\n",
            "x:\n  jwt: {algorithm: \"RS256\"}\n",
            "x:\n  inFlightReq: {amount: 0}\n",
            "x: {}\n",
            "x:\n  addPrefix: {prefix: /a}\n  stripPrefix: {prefixes: [/b]}\n",
        ] {
            assert!(
                MiddlewareRegistry::from_config(&configs(yaml)).is_err(),
                "should reject: {yaml}"
            );
        }
    }
}
