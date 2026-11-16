//! EntryPoint `http.redirections.entryPoint` (Traefik): every request on the
//! entrypoint is redirected to another entrypoint/scheme.

use crate::config::{Config, EntryPoint};
use anyhow::{Result, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::header::{HOST, HeaderValue, LOCATION};
use hyper::{Method, Request, Response, StatusCode};

/// Resolved redirection for one entrypoint.
#[derive(Debug, Clone)]
pub struct EntryPointRedirect {
    scheme: String,
    /// Port to put in Location; `None` when it is the scheme default.
    port: Option<u16>,
    permanent: bool,
}

/// Port of an entrypoint address like `:443`, `0.0.0.0:443`, `[::]:443/tcp`.
pub fn address_port(address: &str) -> Option<u16> {
    let addr = address.split('/').next().unwrap_or(address);
    addr.rsplit_once(':')?.1.parse().ok()
}

impl EntryPointRedirect {
    /// Build for `ep`, resolving `to` as an entrypoint name or `:port`.
    pub fn from_config(config: &Config, ep_name: &str, ep: &EntryPoint) -> Result<Option<Self>> {
        let Some(r) = ep
            .http
            .as_ref()
            .and_then(|h| h.redirections.as_ref())
            .and_then(|r| r.entry_point.as_ref())
        else {
            return Ok(None);
        };
        let scheme = r.scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            bail!("entryPoint '{ep_name}': redirections scheme must be http or https");
        }
        let port = match config.entry_points.get(&r.to) {
            Some(target) => address_port(&target.address),
            None => address_port(&r.to),
        };
        let Some(port) = port else {
            bail!(
                "entryPoint '{ep_name}': redirections.entryPoint.to '{}' is not an entrypoint or :port",
                r.to
            );
        };
        let default = if scheme == "https" { 443 } else { 80 };
        Ok(Some(Self {
            scheme,
            port: (port != default).then_some(port),
            permanent: r.permanent,
        }))
    }

    /// Redirect response for `req` (Traefik redirectScheme status codes).
    pub fn respond<B>(&self, req: &Request<B>) -> Response<BoxBody<Bytes, hyper::Error>> {
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri().host())
            .unwrap_or("");
        let host = strip_port(host);
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let location = match self.port {
            Some(p) => format!("{}://{}:{}{}", self.scheme, host, p, pq),
            None => format!("{}://{}{}", self.scheme, host, pq),
        };
        let status = match (self.permanent, req.method() == Method::GET) {
            (true, true) => StatusCode::MOVED_PERMANENTLY,
            (true, false) => StatusCode::PERMANENT_REDIRECT,
            (false, true) => StatusCode::FOUND,
            (false, false) => StatusCode::TEMPORARY_REDIRECT,
        };
        let mut resp = Response::new(Empty::new().map_err(|never| match never {}).boxed());
        *resp.status_mut() = status;
        if let Ok(v) = HeaderValue::from_str(&location) {
            resp.headers_mut().insert(LOCATION, v);
        } else {
            *resp.status_mut() = StatusCode::BAD_REQUEST;
        }
        resp
    }
}

/// Host without its port; IPv6 literals keep their brackets.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|end| &host[..=end]).unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(to: &str, websecure_addr: &str) -> (Config, Option<EntryPointRedirect>) {
        let yaml = format!(
            "entryPoints:\n  web:\n    address: \"127.0.0.1:80\"\n    http:\n      redirections:\n        entryPoint: {{to: \"{to}\"}}\n  websecure: {{address: \"{websecure_addr}\"}}\n"
        );
        let c = Config::from_yaml_str(&yaml).unwrap();
        let r = EntryPointRedirect::from_config(&c, "web", &c.entry_points["web"]).unwrap();
        (c, r)
    }

    fn loc(r: &EntryPointRedirect, method: &str, host: &str, uri: &str) -> (u16, String) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, host)
            .body(())
            .unwrap();
        let resp = r.respond(&req);
        (
            resp.status().as_u16(),
            resp.headers()[LOCATION].to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn redirect_to_https_default_port() {
        let (_, r) = cfg("websecure", "127.0.0.1:443");
        let r = r.unwrap();
        assert_eq!(
            loc(&r, "GET", "example.com:80", "/a?b=1"),
            (301, "https://example.com/a?b=1".into())
        );
        assert_eq!(
            loc(&r, "POST", "example.com", "/a"),
            (308, "https://example.com/a".into())
        );
    }

    #[test]
    fn redirect_keeps_non_default_port_and_accepts_port_literal() {
        let (_, r) = cfg("websecure", "127.0.0.1:8443");
        assert_eq!(
            loc(&r.unwrap(), "GET", "h", "/"),
            (301, "https://h:8443/".into())
        );
        let (_, r) = cfg(":9443", "127.0.0.1:443");
        assert_eq!(
            loc(&r.unwrap(), "GET", "[::1]:80", "/"),
            (301, "https://[::1]:9443/".into())
        );
    }

    #[test]
    fn unknown_target_is_error() {
        let yaml = "entryPoints:\n  web:\n    address: \"127.0.0.1:80\"\n    http:\n      redirections:\n        entryPoint: {to: nowhere}\n";
        assert!(Config::from_yaml_str(yaml).is_err());
    }
}
