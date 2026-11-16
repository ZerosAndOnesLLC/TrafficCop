//! Source-criterion extraction shared by middlewares that bucket requests per
//! client (inFlightReq, rateLimit). Mirrors Traefik's `sourceCriterion`.

use super::registry::RequestContext;
use crate::config::{IpStrategy, SourceCriterion};
use hyper::Request;
use hyper::header::HOST;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// How to derive the bucketing key for a request.
pub enum SourceExtractor {
    /// Client IP taken from the socket peer.
    RemoteAddr,
    /// Client IP picked from `X-Forwarded-For` by depth (1 = rightmost entry).
    Depth(usize),
    /// Rightmost `X-Forwarded-For` entry that is not in the excluded set.
    Excluded(Vec<IpNetwork>),
    /// Value of a request header.
    Header(hyper::header::HeaderName),
    /// Request host.
    Host,
}

impl SourceExtractor {
    /// Build from Traefik `sourceCriterion`. Absent criterion means remote address.
    /// Invalid values are configuration errors.
    pub fn from_config(criterion: Option<&SourceCriterion>) -> Result<Self, String> {
        let Some(c) = criterion else {
            return Ok(Self::RemoteAddr);
        };

        let set = [
            c.ip_strategy.is_some(),
            c.request_header_name.is_some(),
            c.request_host,
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if set > 1 {
            return Err(
                "sourceCriterion: only one of ipStrategy, requestHeaderName, requestHost may be set"
                    .to_string(),
            );
        }

        if let Some(name) = &c.request_header_name {
            let h = hyper::header::HeaderName::try_from(name.as_str())
                .map_err(|_| format!("sourceCriterion.requestHeaderName '{name}' is invalid"))?;
            return Ok(Self::Header(h));
        }
        if c.request_host {
            return Ok(Self::Host);
        }
        match &c.ip_strategy {
            Some(s) => Self::from_ip_strategy(s),
            None => Ok(Self::RemoteAddr),
        }
    }

    fn from_ip_strategy(s: &IpStrategy) -> Result<Self, String> {
        if s.depth > 0 {
            if !s.excluded_ips.is_empty() {
                return Err("ipStrategy: depth and excludedIPs are mutually exclusive".to_string());
            }
            return Ok(Self::Depth(s.depth as usize));
        }
        if !s.excluded_ips.is_empty() {
            let nets = s
                .excluded_ips
                .iter()
                .map(|e| parse_net(e))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Self::Excluded(nets));
        }
        Ok(Self::RemoteAddr)
    }

    /// Extract the key. `None` means the key could not be determined; callers
    /// must treat that as a failure (Traefik answers 500), never as "allow".
    pub fn extract<B>(&self, req: &Request<B>) -> Option<String> {
        match self {
            Self::RemoteAddr => remote_ip(req).map(|ip| ip.to_string()),
            Self::Depth(depth) => {
                let xff = forwarded_for(req);
                if *depth > xff.len() {
                    return None;
                }
                xff.get(xff.len() - depth).map(|s| s.to_string())
            }
            Self::Excluded(nets) => forwarded_for(req)
                .into_iter()
                .rev()
                .find(|entry| match entry.parse::<IpAddr>() {
                    Ok(ip) => !nets.iter().any(|n| n.contains(ip)),
                    Err(_) => true,
                })
                .map(|s| s.to_string()),
            Self::Header(name) => req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            Self::Host => req
                .headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
                .or_else(|| req.uri().host().map(|h| h.to_string())),
        }
    }
}

/// Parse an IP or CIDR into a network (bare IPs become /32 or /128).
pub fn parse_net(s: &str) -> Result<IpNetwork, String> {
    let s = s.trim();
    s.parse::<IpNetwork>()
        .or_else(|_| s.parse::<IpAddr>().map(IpNetwork::from))
        .map_err(|_| format!("invalid IP or CIDR '{s}'"))
}

fn remote_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<RequestContext>()
        .map(|c| c.remote_addr.ip())
}

/// All `X-Forwarded-For` entries across header lines, left to right.
fn forwarded_for<B>(req: &Request<B>) -> Vec<String> {
    req.headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn req(xff: Option<&str>) -> Request<()> {
        let mut b = Request::builder().uri("/").header(HOST, "example.com");
        if let Some(x) = xff {
            b = b.header("x-forwarded-for", x);
        }
        let mut r = b.body(()).unwrap();
        r.extensions_mut().insert(RequestContext {
            remote_addr: "192.0.2.9:1234".parse::<SocketAddr>().unwrap(),
            is_tls: false,
            client_certs: None,
        });
        r
    }

    fn crit(depth: u32, excluded: &[&str]) -> SourceCriterion {
        SourceCriterion {
            ip_strategy: Some(IpStrategy {
                depth,
                excluded_ips: excluded.iter().map(|s| s.to_string()).collect(),
                ipv6_subnet: None,
            }),
            request_header_name: None,
            request_host: false,
        }
    }

    #[test]
    fn default_is_remote_addr() {
        let e = SourceExtractor::from_config(None).unwrap();
        assert_eq!(
            e.extract(&req(Some("1.1.1.1"))).as_deref(),
            Some("192.0.2.9")
        );
    }

    #[test]
    fn depth_matches_traefik() {
        // Traefik docs: XFF "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1", depth 2 -> 12.0.0.1
        let r = req(Some("10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1"));
        let e = SourceExtractor::from_config(Some(&crit(2, &[]))).unwrap();
        assert_eq!(e.extract(&r).as_deref(), Some("12.0.0.1"));
        let e = SourceExtractor::from_config(Some(&crit(1, &[]))).unwrap();
        assert_eq!(e.extract(&r).as_deref(), Some("13.0.0.1"));
        let e = SourceExtractor::from_config(Some(&crit(5, &[]))).unwrap();
        assert_eq!(e.extract(&r), None);
    }

    #[test]
    fn excluded_ips_skip_from_right() {
        let r = req(Some("10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1"));
        let e = SourceExtractor::from_config(Some(&crit(0, &["12.0.0.1", "13.0.0.0/24"]))).unwrap();
        assert_eq!(e.extract(&r).as_deref(), Some("11.0.0.1"));
    }

    #[test]
    fn invalid_excluded_ip_is_error() {
        assert!(SourceExtractor::from_config(Some(&crit(0, &["10.0.0.0/33"]))).is_err());
    }

    #[test]
    fn header_and_host() {
        let c = SourceCriterion {
            ip_strategy: None,
            request_header_name: Some("x-user".into()),
            request_host: false,
        };
        let e = SourceExtractor::from_config(Some(&c)).unwrap();
        assert_eq!(e.extract(&req(None)), None);
        let c = SourceCriterion {
            ip_strategy: None,
            request_header_name: None,
            request_host: true,
        };
        let e = SourceExtractor::from_config(Some(&c)).unwrap();
        assert_eq!(e.extract(&req(None)).as_deref(), Some("example.com"));
    }
}
