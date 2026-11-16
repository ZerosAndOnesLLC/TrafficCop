use crate::config::ForwardAuthConfig;
use bytes::Bytes;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, LOCATION, SET_COOKIE,
};
use hyper::{Method, Request, StatusCode};
use regex::Regex;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_METHOD: &str = "x-forwarded-method";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";
const X_FORWARDED_HOST: &str = "x-forwarded-host";
const X_FORWARDED_URI: &str = "x-forwarded-uri";
const X_FORWARDED_PORT: &str = "x-forwarded-port";

/// Hop-by-hop headers never copied between the client, auth server and backend.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// ForwardAuth middleware delegates authentication to an external service.
/// Semantics follow Traefik's forwardAuth: a 2xx from the auth server lets the
/// request through, anything else is returned to the client verbatim.
pub struct ForwardAuthMiddleware {
    client: Client,
    address: String,
    trust_forward_header: bool,
    auth_response_headers: Vec<HeaderName>,
    auth_response_headers_regex: Option<Regex>,
    auth_request_headers: Vec<HeaderName>,
    add_auth_cookies_to_response: Vec<String>,
}

/// Facts about the incoming connection the auth request needs.
pub struct ForwardAuthRequestInfo {
    /// Client IP from the socket peer.
    pub client_ip: std::net::IpAddr,
    /// Whether the client connection is TLS.
    pub is_tls: bool,
}

/// Outcome of asking the auth server.
pub enum AuthResult {
    /// 2xx: forward the request after applying these changes.
    Allowed {
        /// Request headers to delete before forwarding (anti-spoofing).
        remove_request_headers: Vec<HeaderName>,
        /// Request headers copied from the auth response.
        request_headers: HeaderMap,
        /// `Set-Cookie` values from the auth response to add to the final response.
        response_cookies: Vec<HeaderValue>,
    },
    /// Non-2xx: return this response to the client.
    Denied {
        /// Status from the auth server.
        status: StatusCode,
        /// Headers from the auth server (hop-by-hop removed).
        headers: HeaderMap,
        /// Body from the auth server.
        body: Bytes,
    },
}

impl ForwardAuthMiddleware {
    /// Create from config. Any invalid setting is a configuration error.
    pub fn new(config: ForwardAuthConfig) -> Result<Self, String> {
        match url::Url::parse(&config.address) {
            Ok(u) if matches!(u.scheme(), "http" | "https") && u.has_host() => {}
            _ => {
                return Err(format!(
                    "forwardAuth address '{}' is not a valid http(s) URL",
                    config.address
                ));
            }
        }

        // Never follow redirects: a 3xx from the auth server (e.g. to a login
        // page) must reach the client, not be followed into a 200.
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());

        if let Some(tls) = &config.tls {
            if let Some(ca) = &tls.ca {
                let pem = std::fs::read(ca)
                    .map_err(|e| format!("forwardAuth tls.ca '{ca}' unreadable: {e}"))?;
                for cert in reqwest::Certificate::from_pem_bundle(&pem)
                    .map_err(|e| format!("forwardAuth tls.ca '{ca}' invalid: {e}"))?
                {
                    builder = builder.add_root_certificate(cert);
                }
            }
            match (&tls.cert, &tls.key) {
                (Some(cert), Some(key)) => {
                    let mut pem = std::fs::read(cert)
                        .map_err(|e| format!("forwardAuth tls.cert '{cert}' unreadable: {e}"))?;
                    pem.extend(
                        std::fs::read(key)
                            .map_err(|e| format!("forwardAuth tls.key '{key}' unreadable: {e}"))?,
                    );
                    let id = reqwest::Identity::from_pem(&pem)
                        .map_err(|e| format!("forwardAuth tls cert/key invalid: {e}"))?;
                    builder = builder.identity(id);
                }
                (None, None) => {}
                _ => return Err("forwardAuth tls.cert and tls.key must be set together".into()),
            }
            if tls.insecure_skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        let client = builder
            .build()
            .map_err(|e| format!("forwardAuth client: {e}"))?;

        let parse_names = |names: &[String], field: &str| {
            names
                .iter()
                .map(|h| {
                    HeaderName::try_from(h.as_str())
                        .map_err(|_| format!("forwardAuth {field}: invalid header name '{h}'"))
                })
                .collect::<Result<Vec<_>, _>>()
        };

        let auth_response_headers_regex = match &config.auth_response_headers_regex {
            Some(r) => Some(
                Regex::new(&format!("(?i){r}"))
                    .map_err(|e| format!("forwardAuth authResponseHeadersRegex invalid: {e}"))?,
            ),
            None => None,
        };

        Ok(Self {
            client,
            address: config.address,
            trust_forward_header: config.trust_forward_header,
            auth_response_headers: parse_names(
                &config.auth_response_headers,
                "authResponseHeaders",
            )?,
            auth_response_headers_regex,
            auth_request_headers: parse_names(&config.auth_request_headers, "authRequestHeaders")?,
            add_auth_cookies_to_response: config.add_auth_cookies_to_response,
        })
    }

    /// Build the header set sent to the auth server (Traefik `writeHeader`).
    pub fn auth_request_headers<B>(
        &self,
        req: &Request<B>,
        info: &ForwardAuthRequestInfo,
    ) -> HeaderMap {
        let src = req.headers();
        let mut out = HeaderMap::new();

        if self.auth_request_headers.is_empty() {
            for (name, value) in src.iter() {
                out.append(name.clone(), value.clone());
            }
        } else {
            for name in &self.auth_request_headers {
                for value in src.get_all(name) {
                    out.append(name.clone(), value.clone());
                }
            }
        }
        for h in HOP_BY_HOP {
            out.remove(*h);
        }
        out.remove(CONNECTION);
        out.remove(CONTENT_LENGTH);
        out.remove(HOST);

        let trusted = |name: &str| -> Option<HeaderValue> {
            if self.trust_forward_header {
                src.get(name).filter(|v| !v.is_empty()).cloned()
            } else {
                None
            }
        };

        // X-Forwarded-For: client IP, appended to the prior chain only when trusted.
        let mut xff = info.client_ip.to_string();
        if self.trust_forward_header {
            let prior: Vec<&str> = src
                .get_all(X_FORWARDED_FOR)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            if !prior.is_empty() {
                xff = format!("{}, {}", prior.join(", "), xff);
            }
        }
        set(&mut out, X_FORWARDED_FOR, HeaderValue::from_str(&xff).ok());

        set(
            &mut out,
            X_FORWARDED_METHOD,
            trusted(X_FORWARDED_METHOD)
                .or_else(|| HeaderValue::from_str(req.method().as_str()).ok()),
        );

        let proto = if info.is_tls { "https" } else { "http" };
        set(
            &mut out,
            X_FORWARDED_PROTO,
            trusted(X_FORWARDED_PROTO).or(Some(HeaderValue::from_static(proto))),
        );

        let host = src.get(HOST).cloned().or_else(|| {
            req.uri()
                .authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
        });
        set(
            &mut out,
            X_FORWARDED_HOST,
            trusted(X_FORWARDED_HOST).or(host.clone()),
        );

        let port = host
            .as_ref()
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.rsplit_once(':').map(|(_, p)| p.to_string()))
            .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or_else(|| if info.is_tls { "443" } else { "80" }.to_string());
        set(
            &mut out,
            X_FORWARDED_PORT,
            trusted(X_FORWARDED_PORT).or_else(|| HeaderValue::from_str(&port).ok()),
        );

        let uri = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        set(
            &mut out,
            X_FORWARDED_URI,
            trusted(X_FORWARDED_URI).or_else(|| HeaderValue::from_str(uri).ok()),
        );

        out
    }

    /// Ask the auth server. `Err` means the auth server could not be reached
    /// or answered unusably; callers must deny (500), never allow.
    pub async fn authenticate<B>(
        &self,
        req: &Request<B>,
        info: &ForwardAuthRequestInfo,
    ) -> Result<AuthResult, String> {
        let headers = self.auth_request_headers(req, info);
        let response = self
            .client
            .request(Method::GET, &self.address)
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                warn!("forwardAuth request to {} failed: {}", self.address, e);
                format!("auth service unavailable: {e}")
            })?;

        let status = response.status();
        let auth_headers = response.headers().clone();

        if status.is_success() {
            // Request headers matching the regex are stripped by the wrapper
            // via `matches_response_regex`, since it holds the live request.
            let remove = self.auth_response_headers.clone();
            let mut request_headers = HeaderMap::new();

            for name in &self.auth_response_headers {
                for v in auth_headers.get_all(name) {
                    request_headers.append(name.clone(), v.clone());
                }
            }
            if let Some(re) = &self.auth_response_headers_regex {
                for (name, v) in auth_headers.iter() {
                    if re.is_match(name.as_str()) && !self.auth_response_headers.contains(name) {
                        request_headers.append(name.clone(), v.clone());
                    }
                }
            }

            let response_cookies = auth_headers
                .get_all(SET_COOKIE)
                .iter()
                .filter(|v| {
                    v.to_str()
                        .ok()
                        .and_then(|s| s.split_once('='))
                        .map(|(n, _)| {
                            self.add_auth_cookies_to_response
                                .iter()
                                .any(|want| want == n.trim())
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            debug!("forwardAuth allowed ({} headers)", request_headers.len());
            return Ok(AuthResult::Allowed {
                remove_request_headers: remove,
                request_headers,
                response_cookies,
            });
        }

        let location = auth_headers
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|l| self.resolve_location(l));
        let mut headers = auth_headers;
        for h in HOP_BY_HOP {
            headers.remove(*h);
        }
        headers.remove(CONTENT_LENGTH);
        if let Some(Some(loc)) = location {
            headers.insert(LOCATION, loc);
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("auth service body: {e}"))?;
        debug!("forwardAuth denied with status {}", status);
        Ok(AuthResult::Denied {
            status,
            headers,
            body,
        })
    }

    /// Whether a request header must be stripped before forwarding because it
    /// matches `authResponseHeadersRegex` (Traefik deletes these to stop spoofing).
    pub fn matches_response_regex(&self, name: &HeaderName) -> bool {
        self.auth_response_headers_regex
            .as_ref()
            .is_some_and(|re| re.is_match(name.as_str()))
    }

    /// Resolve a (possibly relative) Location against the auth address, as Go's
    /// `Response.Location()` does in Traefik.
    fn resolve_location(&self, loc: &str) -> Option<HeaderValue> {
        let resolved = url::Url::parse(&self.address)
            .ok()
            .and_then(|base| base.join(loc).ok())
            .map(|u| u.to_string())
            .unwrap_or_else(|| loc.to_string());
        HeaderValue::from_str(&resolved).ok()
    }
}

fn set(map: &mut HeaderMap, name: &'static str, value: Option<HeaderValue>) {
    match value {
        Some(v) => {
            map.insert(name, v);
        }
        None => {
            map.remove(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(trust: bool) -> ForwardAuthConfig {
        ForwardAuthConfig {
            address: "http://auth.local/verify".to_string(),
            trust_forward_header: trust,
            auth_response_headers: vec!["X-User-Id".to_string()],
            auth_response_headers_regex: Some("^X-Auth-.*".to_string()),
            auth_request_headers: vec![],
            tls: None,
            add_auth_cookies_to_response: vec![],
        }
    }

    fn info() -> ForwardAuthRequestInfo {
        ForwardAuthRequestInfo {
            client_ip: "198.51.100.7".parse().unwrap(),
            is_tls: true,
        }
    }

    #[test]
    fn rejects_bad_address() {
        let mut c = cfg(false);
        c.address = "ftp://x".into();
        assert!(ForwardAuthMiddleware::new(c).is_err());
        let mut c = cfg(false);
        c.auth_response_headers_regex = Some("(".into());
        assert!(ForwardAuthMiddleware::new(c).is_err());
    }

    #[test]
    fn untrusted_forward_headers_are_overwritten() {
        let mw = ForwardAuthMiddleware::new(cfg(false)).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/admin/x?y=1")
            .header(HOST, "app.example.com")
            .header("x-forwarded-uri", "/public")
            .header("x-forwarded-for", "10.0.0.1")
            .header("authorization", "Bearer t")
            .body(())
            .unwrap();
        let h = mw.auth_request_headers(&req, &info());
        assert_eq!(h["x-forwarded-uri"], "/admin/x?y=1");
        assert_eq!(h.get_all("x-forwarded-uri").iter().count(), 1);
        assert_eq!(h["x-forwarded-for"], "198.51.100.7");
        assert_eq!(h["x-forwarded-method"], "POST");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["x-forwarded-host"], "app.example.com");
        assert_eq!(h["x-forwarded-port"], "443");
        assert_eq!(h["authorization"], "Bearer t");
        assert!(h.get(HOST).is_none());
    }

    #[test]
    fn trusted_forward_headers_are_kept() {
        let mw = ForwardAuthMiddleware::new(cfg(true)).unwrap();
        let req = Request::builder()
            .uri("/x")
            .header(HOST, "app.example.com")
            .header("x-forwarded-uri", "/orig")
            .header("x-forwarded-for", "10.0.0.1")
            .body(())
            .unwrap();
        let h = mw.auth_request_headers(&req, &info());
        assert_eq!(h["x-forwarded-uri"], "/orig");
        assert_eq!(h["x-forwarded-for"], "10.0.0.1, 198.51.100.7");
    }

    #[test]
    fn auth_request_headers_filter() {
        let mut c = cfg(false);
        c.auth_request_headers = vec!["Cookie".into()];
        let mw = ForwardAuthMiddleware::new(c).unwrap();
        let req = Request::builder()
            .uri("/")
            .header("cookie", "a=b")
            .header("authorization", "x")
            .body(())
            .unwrap();
        let h = mw.auth_request_headers(&req, &info());
        assert_eq!(h["cookie"], "a=b");
        assert!(h.get("authorization").is_none());
    }

    #[test]
    fn relative_location_resolved_against_auth_address() {
        let mw = ForwardAuthMiddleware::new(cfg(false)).unwrap();
        assert_eq!(
            mw.resolve_location("/login").unwrap(),
            "http://auth.local/login"
        );
        assert_eq!(
            mw.resolve_location("https://sso.example.com/").unwrap(),
            "https://sso.example.com/"
        );
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    /// Spawn a one-route auth server returning `status` with `headers`.
    async fn auth_server(status: u16, headers: Vec<(&'static str, &'static str)>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let headers = headers.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
                        let headers = headers.clone();
                        async move {
                            let mut b = hyper::Response::builder().status(status);
                            for (k, v) in headers {
                                b = b.header(k, v);
                            }
                            Ok::<_, std::convert::Infallible>(
                                b.body(Full::new(Bytes::from_static(b"auth-body"))).unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        format!("http://{addr}/verify")
    }

    fn mw(address: String) -> ForwardAuthMiddleware {
        ForwardAuthMiddleware::new(ForwardAuthConfig {
            address,
            trust_forward_header: false,
            auth_response_headers: vec!["X-Auth-User".into()],
            auth_response_headers_regex: None,
            auth_request_headers: vec![],
            tls: None,
            add_auth_cookies_to_response: vec!["sess".into()],
        })
        .unwrap()
    }

    fn info() -> ForwardAuthRequestInfo {
        ForwardAuthRequestInfo {
            client_ip: "127.0.0.1".parse().unwrap(),
            is_tls: false,
        }
    }

    #[tokio::test]
    async fn redirect_is_returned_not_followed() {
        let addr = auth_server(302, vec![("location", "/login"), ("set-cookie", "csrf=1")]).await;
        let req = Request::builder().uri("/admin").body(()).unwrap();
        match mw(addr.clone()).authenticate(&req, &info()).await.unwrap() {
            AuthResult::Denied {
                status,
                headers,
                body,
            } => {
                assert_eq!(status, StatusCode::FOUND);
                let base = addr.trim_end_matches("/verify");
                assert_eq!(headers[LOCATION], format!("{base}/login").as_str());
                assert_eq!(headers[SET_COOKIE], "csrf=1");
                assert_eq!(&body[..], b"auth-body");
            }
            AuthResult::Allowed { .. } => panic!("3xx must deny"),
        }
    }

    #[tokio::test]
    async fn success_forwards_headers_and_cookies() {
        let addr = auth_server(
            200,
            vec![
                ("x-auth-user", "alice"),
                ("set-cookie", "sess=abc"),
                ("set-cookie", "other=1"),
            ],
        )
        .await;
        let req = Request::builder().uri("/").body(()).unwrap();
        match mw(addr).authenticate(&req, &info()).await.unwrap() {
            AuthResult::Allowed {
                remove_request_headers,
                request_headers,
                response_cookies,
            } => {
                assert_eq!(
                    remove_request_headers,
                    vec![HeaderName::from_static("x-auth-user")]
                );
                assert_eq!(request_headers["x-auth-user"], "alice");
                assert_eq!(response_cookies, vec![HeaderValue::from_static("sess=abc")]);
            }
            AuthResult::Denied { .. } => panic!("2xx must allow"),
        }
    }

    #[tokio::test]
    async fn unreachable_auth_server_is_error() {
        let req = Request::builder().uri("/").body(()).unwrap();
        assert!(
            mw("http://127.0.0.1:1/verify".into())
                .authenticate(&req, &info())
                .await
                .is_err()
        );
    }
}
