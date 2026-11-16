//! Pipeline adapters for inFlightReq, redirectRegex, contentType and passTLSClientCert.

use super::client_cert::{format_info, format_pem};
use super::registry::{RequestContext, error_response};
use super::source::SourceExtractor;
use super::{BoxFuture, Middleware, Next};
use crate::config::{
    InFlightReqConfig, PassTlsClientCertConfig, RedirectRegexConfig, TlsClientCertInfo,
};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::{HOST, HeaderValue, LOCATION};
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use regex::Regex;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::task::{Context, Poll};

type HttpResult = Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>;

// --- inFlightReq ---

type Counters = Arc<DashMap<String, AtomicI64>>;

/// Limits simultaneous in-flight requests per source (Traefik inFlightReq).
/// A request counts until its response body has been fully sent or dropped.
pub struct InFlightReqWrapper {
    name: String,
    amount: i64,
    source: SourceExtractor,
    counters: Counters,
}

impl InFlightReqWrapper {
    /// Build from config; `amount` must be positive.
    pub fn new(name: String, c: &InFlightReqConfig) -> Result<Self, String> {
        if c.amount <= 0 {
            return Err("inFlightReq: amount must be greater than 0".to_string());
        }
        Ok(Self {
            name,
            amount: c.amount,
            source: SourceExtractor::from_config(c.source_criterion.as_ref())
                .map_err(|e| format!("inFlightReq: {e}"))?,
            counters: Arc::new(DashMap::new()),
        })
    }

    /// Try to take a slot for `key`. Increment happens under the shard lock so
    /// it can't race with the zero-count cleanup in [`InFlightGuard`].
    fn acquire(&self, key: String) -> Option<InFlightGuard> {
        let entry = self
            .counters
            .entry(key.clone())
            .or_insert_with(|| AtomicI64::new(0));
        let prev = entry.fetch_add(1, Ordering::AcqRel);
        if prev >= self.amount {
            entry.fetch_sub(1, Ordering::AcqRel);
            drop(entry);
            self.counters
                .remove_if(&key, |_, v| v.load(Ordering::Acquire) == 0);
            return None;
        }
        drop(entry);
        Some(InFlightGuard {
            counters: Arc::clone(&self.counters),
            key,
        })
    }
}

/// Releases an in-flight slot on drop.
struct InFlightGuard {
    counters: Counters,
    key: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(c) = self.counters.get(&self.key) {
            c.fetch_sub(1, Ordering::AcqRel);
        }
        self.counters
            .remove_if(&self.key, |_, v| v.load(Ordering::Acquire) <= 0);
    }
}

pin_project_lite::pin_project! {
    /// Response body that holds an in-flight slot until it completes or is dropped.
    struct GuardedBody<B> {
        #[pin]
        inner: B,
        guard: Option<InFlightGuard>,
    }
}

impl<B: Body> Body for GuardedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let res = this.inner.poll_frame(cx);
        if let Poll::Ready(None) = res {
            this.guard.take();
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Middleware for InFlightReqWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            let Some(key) = self.source.extract(&req) else {
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                ));
            };
            let Some(guard) = self.acquire(key) else {
                return Ok(error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too Many Requests",
                ));
            };
            let resp = next.run(req).await?;
            Ok(resp.map(|b| {
                GuardedBody {
                    inner: b,
                    guard: Some(guard),
                }
                .boxed()
            }))
        })
    }
}

// --- redirectRegex ---

/// Redirects when the full request URL matches a regex (Traefik redirectRegex).
pub struct RedirectRegexWrapper {
    name: String,
    regex: Regex,
    replacement: String,
    permanent: bool,
}

impl RedirectRegexWrapper {
    /// Build from config; an invalid regex is a configuration error.
    pub fn new(name: String, c: &RedirectRegexConfig) -> Result<Self, String> {
        Ok(Self {
            name,
            regex: Regex::new(&c.regex)
                .map_err(|e| format!("redirectRegex: invalid regex: {e}"))?,
            replacement: c.replacement.clone(),
            permanent: c.permanent,
        })
    }

    /// Target URL if this request should be redirected.
    fn target<B>(&self, req: &Request<B>) -> Option<String> {
        let is_tls = req
            .extensions()
            .get::<RequestContext>()
            .is_some_and(|c| c.is_tls);
        let host = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| req.uri().authority().map(|a| a.to_string()))
            .unwrap_or_default();
        let uri = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let old = format!(
            "{}://{}{}",
            if is_tls { "https" } else { "http" },
            host,
            uri
        );
        if !self.regex.is_match(&old) {
            return None;
        }
        let new = self
            .regex
            .replace_all(&old, self.replacement.as_str())
            .into_owned();
        (new != old).then_some(new)
    }

    fn status(&self, method: &Method) -> StatusCode {
        match (self.permanent, method == Method::GET) {
            (true, true) => StatusCode::MOVED_PERMANENTLY,
            (true, false) => StatusCode::PERMANENT_REDIRECT,
            (false, true) => StatusCode::FOUND,
            (false, false) => StatusCode::TEMPORARY_REDIRECT,
        }
    }
}

impl Middleware for RedirectRegexWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            let Some(target) = self.target(&req) else {
                return next.run(req).await;
            };
            let Ok(loc) = HeaderValue::from_str(&target) else {
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                ));
            };
            let mut resp = Response::new(Empty::new().map_err(|never| match never {}).boxed());
            *resp.status_mut() = self.status(req.method());
            resp.headers_mut().insert(LOCATION, loc);
            Ok(resp)
        })
    }
}

// --- contentType ---

/// Traefik's contentType middleware disables Content-Type sniffing. TrafficCop
/// never sniffs response types, so this is correctly a pass-through.
pub struct ContentTypeWrapper {
    pub(super) name: String,
}

impl Middleware for ContentTypeWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(&'a self, req: Request<Incoming>, next: Next<'a>) -> BoxFuture<'a, HttpResult> {
        next.run(req)
    }
}

// --- passTLSClientCert ---

const CERT_HEADER: &str = "x-forwarded-tls-client-cert";
const CERT_INFO_HEADER: &str = "x-forwarded-tls-client-cert-info";

/// Forwards the client certificate (PEM and/or selected fields) to the backend.
/// Client-supplied copies of these headers are always removed.
pub struct PassTlsClientCertWrapper {
    name: String,
    pem: bool,
    info: Option<TlsClientCertInfo>,
}

impl PassTlsClientCertWrapper {
    /// Build from config.
    pub fn new(name: String, c: &PassTlsClientCertConfig) -> Self {
        Self {
            name,
            pem: c.pem,
            info: c.info.clone(),
        }
    }
}

impl Middleware for PassTlsClientCertWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            req.headers_mut().remove(CERT_HEADER);
            req.headers_mut().remove(CERT_INFO_HEADER);

            let certs = req
                .extensions()
                .get::<RequestContext>()
                .and_then(|c| c.client_certs.clone());
            if let Some(certs) = certs.filter(|c| !c.is_empty()) {
                if self.pem
                    && let Ok(v) = HeaderValue::from_str(&format_pem(&certs))
                {
                    req.headers_mut().insert(CERT_HEADER, v);
                }
                if let Some(info) = &self.info
                    && let Some(s) = format_info(&certs, info)
                    && let Ok(v) = HeaderValue::from_str(&s)
                {
                    req.headers_mut().insert(CERT_INFO_HEADER, v);
                }
            }
            next.run(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(regex: &str, repl: &str, permanent: bool) -> RedirectRegexWrapper {
        RedirectRegexWrapper::new(
            "r".into(),
            &RedirectRegexConfig {
                regex: regex.into(),
                replacement: repl.into(),
                permanent,
            },
        )
        .unwrap()
    }

    #[test]
    fn redirect_regex_matches_full_url() {
        let w = rr(r"^http://localhost/(.*)", "http://mydomain/${1}", false);
        let req = Request::builder()
            .uri("/foo?a=1")
            .header(HOST, "localhost")
            .body(())
            .unwrap();
        assert_eq!(w.target(&req).as_deref(), Some("http://mydomain/foo?a=1"));
        assert_eq!(w.status(&Method::GET), StatusCode::FOUND);
        assert_eq!(w.status(&Method::POST), StatusCode::TEMPORARY_REDIRECT);
        let p = rr("x", "y", true);
        assert_eq!(p.status(&Method::GET), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(p.status(&Method::PUT), StatusCode::PERMANENT_REDIRECT);
    }

    #[test]
    fn redirect_regex_no_match_or_identity_passes() {
        let w = rr(r"^https://other/", "https://x/", false);
        let req = Request::builder()
            .uri("/")
            .header(HOST, "h")
            .body(())
            .unwrap();
        assert_eq!(w.target(&req), None);
        let same = rr(r"^(.*)$", "$1", false);
        assert_eq!(same.target(&req), None);
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(
            RedirectRegexWrapper::new(
                "r".into(),
                &RedirectRegexConfig {
                    regex: "(".into(),
                    replacement: String::new(),
                    permanent: false
                }
            )
            .is_err()
        );
        assert!(
            InFlightReqWrapper::new(
                "i".into(),
                &InFlightReqConfig {
                    amount: 0,
                    source_criterion: None
                }
            )
            .is_err()
        );
    }

    #[test]
    fn in_flight_limit_and_release() {
        let w = InFlightReqWrapper::new(
            "i".into(),
            &InFlightReqConfig {
                amount: 2,
                source_criterion: None,
            },
        )
        .unwrap();
        let a = w.acquire("k".into()).unwrap();
        let b = w.acquire("k".into()).unwrap();
        assert!(w.acquire("k".into()).is_none());
        assert!(w.acquire("other".into()).is_some());
        drop(a);
        let c = w.acquire("k".into()).unwrap();
        drop(b);
        drop(c);
        assert!(w.counters.get("k").is_none(), "idle keys are cleaned up");
    }
}
