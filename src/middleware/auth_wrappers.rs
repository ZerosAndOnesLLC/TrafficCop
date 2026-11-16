//! Pipeline adapters for authentication middlewares (forwardAuth, digestAuth, jwt).

use super::builtin::{
    AuthResult, DigestAuthMiddleware, DigestAuthResult, ForwardAuthMiddleware,
    ForwardAuthRequestInfo, JwtMiddleware,
};
use super::registry::{RequestContext, error_response};
use super::{BoxFuture, Middleware, Next};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, HeaderName, HeaderValue, SET_COOKIE};
use hyper::{Request, Response, StatusCode, body::Incoming};

type HttpResult = Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>;

fn full(body: impl Into<Bytes>) -> BoxBody<Bytes, hyper::Error> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

fn into_boxed(resp: Response<String>) -> Response<BoxBody<Bytes, hyper::Error>> {
    resp.map(full)
}

// --- forwardAuth ---

/// Delegates the allow/deny decision to an external HTTP service.
pub struct ForwardAuthWrapper {
    pub(super) name: String,
    pub(super) inner: ForwardAuthMiddleware,
}

impl Middleware for ForwardAuthWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            let Some(ctx) = req.extensions().get::<RequestContext>().cloned() else {
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                ));
            };
            let info = ForwardAuthRequestInfo {
                client_ip: ctx.remote_addr.ip(),
                is_tls: ctx.is_tls,
            };

            match self.inner.authenticate(&req, &info).await {
                Err(_) => Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                )),
                Ok(AuthResult::Denied {
                    status,
                    headers,
                    body,
                }) => {
                    let mut resp = Response::new(full(body));
                    *resp.status_mut() = status;
                    *resp.headers_mut() = headers;
                    Ok(resp)
                }
                Ok(AuthResult::Allowed {
                    remove_request_headers,
                    request_headers,
                    response_cookies,
                }) => {
                    let h = req.headers_mut();
                    // Strip client-supplied copies of identity headers so a
                    // missing auth-response header can't be spoofed.
                    for name in &remove_request_headers {
                        h.remove(name);
                    }
                    let spoofable: Vec<HeaderName> = h
                        .keys()
                        .filter(|n| self.inner.matches_response_regex(n))
                        .cloned()
                        .collect();
                    for name in spoofable {
                        h.remove(&name);
                    }
                    for (name, value) in request_headers.iter() {
                        h.append(name.clone(), value.clone());
                    }

                    let mut resp = next.run(req).await?;
                    for cookie in response_cookies {
                        resp.headers_mut().append(SET_COOKIE, cookie);
                    }
                    Ok(resp)
                }
            }
        })
    }
}

// --- digestAuth ---

/// HTTP Digest authentication.
pub struct DigestAuthWrapper {
    pub(super) name: String,
    pub(super) inner: DigestAuthMiddleware,
}

impl Middleware for DigestAuthWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            let user = match self.inner.authenticate(&req) {
                DigestAuthResult::Authenticated(u) => u,
                DigestAuthResult::Stale => {
                    return Ok(into_boxed(self.inner.unauthorized_response(true)));
                }
                DigestAuthResult::NeedsAuth | DigestAuthResult::Invalid => {
                    return Ok(into_boxed(self.inner.unauthorized_response(false)));
                }
            };
            if let Some(field) = self.inner.header_field() {
                match HeaderValue::from_str(&user) {
                    Ok(v) => {
                        req.headers_mut().insert(field.clone(), v);
                    }
                    Err(_) => {
                        req.headers_mut().remove(field);
                    }
                }
            }
            if self.inner.remove_header() {
                req.headers_mut().remove(AUTHORIZATION);
            }
            next.run(req).await
        })
    }
}

// --- jwt ---

/// Bearer JWT validation (TrafficCop extension; not part of Traefik OSS).
pub struct JwtWrapper {
    pub(super) name: String,
    pub(super) inner: JwtMiddleware,
    /// Header names fed from claims; always stripped from the client request.
    pub(super) forward_headers: Vec<String>,
}

impl Middleware for JwtWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        mut req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, HttpResult> {
        Box::pin(async move {
            let result = match self.inner.validate(&req) {
                Ok(r) => r,
                Err((_, msg)) => return Ok(into_boxed(self.inner.unauthorized_response(&msg))),
            };
            let h = req.headers_mut();
            for name in &self.forward_headers {
                h.remove(name.as_str());
            }
            if result.strip_auth_header {
                h.remove(AUTHORIZATION);
            }
            for (name, value) in result.headers_to_add.iter() {
                h.insert(name.clone(), value.clone());
            }
            next.run(req).await
        })
    }
}
