use super::builtin::{
    BasicAuthMiddleware, CorsMiddleware, HeadersMiddleware, IpAllowListMiddleware,
    IpDenyListMiddleware, RateLimitMiddleware, RedirectSchemeMiddleware,
    AddPrefixMiddleware, StripPrefixMiddleware, ReplacePathMiddleware,
    StripPrefixRegexMiddleware, ReplacePathRegexMiddleware,
};
use super::{BoxFuture, Middleware, Next};
use crate::config::MiddlewareConfig;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{body::Incoming, Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, warn};

/// Request context injected via request extensions before middleware chain runs
#[derive(Clone)]
pub struct RequestContext {
    pub remote_addr: SocketAddr,
    pub is_tls: bool,
}

/// Registry of instantiated middleware, keyed by name
pub struct MiddlewareRegistry {
    middlewares: HashMap<String, Arc<dyn Middleware>>,
}

impl MiddlewareRegistry {
    /// Build registry from config middleware definitions
    pub fn from_config(configs: &HashMap<String, MiddlewareConfig>) -> Self {
        let mut middlewares: HashMap<String, Arc<dyn Middleware>> = HashMap::new();

        for (name, config) in configs {
            if let Some(mw) = Self::create_middleware(name, config) {
                debug!("Registered middleware '{}'", name);
                middlewares.insert(name.clone(), mw);
            } else {
                warn!("Unsupported middleware type for '{}': {}", name, config.middleware_type());
            }
        }

        Self { middlewares }
    }

    /// Look up middleware by name, returns ordered list of middleware instances
    pub fn resolve(&self, names: &[String]) -> Vec<Arc<dyn Middleware>> {
        names
            .iter()
            .filter_map(|name| {
                let mw = self.middlewares.get(name);
                if mw.is_none() {
                    warn!("Middleware '{}' not found in registry", name);
                }
                mw.cloned()
            })
            .collect()
    }

    fn create_middleware(name: &str, config: &MiddlewareConfig) -> Option<Arc<dyn Middleware>> {
        // Headers middleware
        if let Some(headers_config) = &config.headers {
            let headers = HeadersMiddleware::new(headers_config.clone());
            // Also check for CORS config within headers
            let cors = CorsMiddleware::from_headers_config(headers_config);
            if let Some(cors) = cors {
                return Some(Arc::new(HeadersAndCorsWrapper {
                    name: name.to_string(),
                    headers,
                    cors,
                }));
            }
            return Some(Arc::new(HeadersWrapper {
                name: name.to_string(),
                inner: headers,
            }));
        }

        // Rate limit middleware
        if let Some(rl_config) = &config.rate_limit {
            let limiter = RateLimitMiddleware::new(rl_config.clone());
            return Some(Arc::new(RateLimitWrapper {
                name: name.to_string(),
                inner: limiter,
            }));
        }

        // IP allowlist
        if let Some(allow_config) = config.get_ip_allow_list() {
            let filter = IpAllowListMiddleware::new(allow_config);
            return Some(Arc::new(IpAllowWrapper {
                name: name.to_string(),
                inner: filter,
            }));
        }

        // IP denylist
        if let Some(deny_config) = &config.ip_deny_list {
            let filter = IpDenyListMiddleware::new(deny_config);
            return Some(Arc::new(IpDenyWrapper {
                name: name.to_string(),
                inner: filter,
            }));
        }

        // Basic auth
        if let Some(auth_config) = &config.basic_auth {
            let auth = BasicAuthMiddleware::new(auth_config.clone());
            return Some(Arc::new(BasicAuthWrapper {
                name: name.to_string(),
                inner: auth,
            }));
        }

        // Redirect scheme
        if let Some(redirect_config) = &config.redirect_scheme {
            let redirect = RedirectSchemeMiddleware::new(redirect_config.clone());
            return Some(Arc::new(RedirectSchemeWrapper {
                name: name.to_string(),
                inner: redirect,
            }));
        }

        // Strip prefix
        if let Some(strip_config) = &config.strip_prefix {
            let strip = StripPrefixMiddleware::new(strip_config.clone());
            return Some(Arc::new(StripPrefixWrapper {
                name: name.to_string(),
                inner: strip,
            }));
        }

        // Add prefix
        if let Some(prefix_config) = &config.add_prefix {
            let add = AddPrefixMiddleware::new(prefix_config.clone());
            return Some(Arc::new(AddPrefixWrapper {
                name: name.to_string(),
                inner: add,
            }));
        }

        // Replace path
        if let Some(replace_config) = &config.replace_path {
            let replace = ReplacePathMiddleware::new(replace_config.clone());
            return Some(Arc::new(ReplacePathWrapper {
                name: name.to_string(),
                inner: replace,
            }));
        }

        // Strip prefix regex
        if let Some(strip_regex_config) = &config.strip_prefix_regex
            && let Some(strip) = StripPrefixRegexMiddleware::new(strip_regex_config.clone()) {
                return Some(Arc::new(StripPrefixRegexWrapper {
                    name: name.to_string(),
                    inner: strip,
                }));
            }

        // Replace path regex
        if let Some(replace_regex_config) = &config.replace_path_regex
            && let Some(replace) = ReplacePathRegexMiddleware::new(replace_regex_config.clone()) {
                return Some(Arc::new(ReplacePathRegexWrapper {
                    name: name.to_string(),
                    inner: replace,
                }));
            }

        // Compress middleware
        if let Some(compress_config) = &config.compress {
            return Some(Arc::new(CompressWrapper {
                name: name.to_string(),
                min_size: compress_config.min_response_body_bytes,
            }));
        }

        None
    }
}

// --- Wrapper implementations ---

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
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

fn get_client_ip(req: &Request<Incoming>) -> Option<IpAddr> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            // Handle CORS preflight
            if self.cors.is_preflight(&req) {
                if let Some(resp) = self.cors.handle_preflight(&req) {
                    let (parts, _) = resp.into_parts();
                    return Ok(Response::from_parts(
                        parts,
                        Full::new(Bytes::new()).map_err(|never| match never {}).boxed(),
                    ));
                }
                return Ok(error_response(StatusCode::FORBIDDEN, "CORS origin not allowed"));
            }

            let origin = CorsMiddleware::get_origin(&req);
            self.headers.apply_request(req.headers_mut());
            let mut resp = next.run(req).await?;
            self.headers.apply_response(resp.headers_mut());
            self.cors.apply_headers(origin.as_deref(), resp.headers_mut());
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if let Some(ip) = get_client_ip(&req)
                && !self.inner.is_allowed(ip) {
                    return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if self.inner.has_rules()
                && let Some(ip) = get_client_ip(&req)
                    && !self.inner.is_allowed(ip) {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if self.inner.has_rules()
                && let Some(ip) = get_client_ip(&req)
                    && self.inner.is_denied(ip) {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            if !self.inner.is_authenticated(&req) {
                let resp = self.inner.unauthorized_response();
                let (parts, _) = resp.into_parts();
                return Ok(Response::from_parts(
                    parts,
                    Full::new(Bytes::from("Unauthorized")).map_err(|never| match never {}).boxed(),
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        Box::pin(async move {
            let is_tls = req.extensions()
                .get::<RequestContext>()
                .map(|ctx| ctx.is_tls)
                .unwrap_or(false);

            if self.inner.should_redirect(is_tls) {
                let resp = self.inner.build_redirect(&req);
                let (parts, _) = resp.into_parts();
                return Ok(Response::from_parts(
                    parts,
                    Full::new(Bytes::new()).map_err(|never| match never {}).boxed(),
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, mut req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
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

// --- Compress (placeholder — actual compression requires body collection) ---
struct CompressWrapper {
    name: String,
    #[allow(dead_code)]
    min_size: u64,
}

impl Middleware for CompressWrapper {
    fn name(&self) -> &str { &self.name }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        // Compression needs to collect the response body and re-encode it,
        // which requires significant changes to the response pipeline.
        // For now, pass through — compression will be done at the response level
        // when the full middleware pipeline supports body transformation.
        Box::pin(async move { next.run(req).await })
    }
}
