use crate::config::{IpAllowListConfig, IpDenyListConfig, IpStrategy};
use crate::middleware::source::{SourceExtractor, parse_net};
use hyper::Request;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Parse `sourceRange`; empty or invalid entries are configuration errors
/// (an allow-list must never silently become allow-all).
fn ranges(source_range: &[String], what: &str) -> Result<Vec<IpNetwork>, String> {
    if source_range.is_empty() {
        return Err(format!("{what}: sourceRange must not be empty"));
    }
    source_range
        .iter()
        .map(|s| parse_net(s).map_err(|e| format!("{what}: {e}")))
        .collect()
}

fn extractor(strategy: Option<&IpStrategy>, what: &str) -> Result<SourceExtractor, String> {
    SourceExtractor::from_ip_strategy_opt(strategy).map_err(|e| format!("{what}: {e}"))
}

/// Client IP per the configured ipStrategy (remote address by default).
fn client_ip<B>(x: &SourceExtractor, req: &Request<B>) -> Option<IpAddr> {
    x.extract(req)?.parse().ok()
}

/// IP allowlist middleware (Traefik ipAllowList)
pub struct IpAllowListMiddleware {
    source_range: Vec<IpNetwork>,
    extractor: SourceExtractor,
    reject_status_code: u16,
}

impl IpAllowListMiddleware {
    /// Create from config. Invalid or empty ranges are errors.
    pub fn new(config: &IpAllowListConfig) -> Result<Self, String> {
        Ok(Self {
            source_range: ranges(&config.source_range, "ipAllowList")?,
            extractor: extractor(config.ip_strategy.as_ref(), "ipAllowList")?,
            reject_status_code: config.reject_status_code.unwrap_or(403),
        })
    }

    /// Whether `ip` is in the allowed ranges.
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.source_range.iter().any(|n| n.contains(ip))
    }

    /// Whether the request is allowed. A client IP that cannot be determined
    /// (e.g. ipStrategy depth beyond X-Forwarded-For) is rejected.
    pub fn allows<B>(&self, req: &Request<B>) -> bool {
        client_ip(&self.extractor, req).is_some_and(|ip| self.is_allowed(ip))
    }

    /// Get the reject status code
    pub fn reject_status_code(&self) -> u16 {
        self.reject_status_code
    }
}

/// IP denylist middleware (TrafficCop extension)
pub struct IpDenyListMiddleware {
    source_range: Vec<IpNetwork>,
    extractor: SourceExtractor,
}

impl IpDenyListMiddleware {
    /// Create from config. Invalid or empty ranges are errors.
    pub fn new(config: &IpDenyListConfig) -> Result<Self, String> {
        Ok(Self {
            source_range: ranges(&config.source_range, "ipDenyList")?,
            extractor: extractor(config.ip_strategy.as_ref(), "ipDenyList")?,
        })
    }

    /// Whether `ip` is in the denied ranges.
    #[inline]
    pub fn is_denied(&self, ip: IpAddr) -> bool {
        self.source_range.iter().any(|n| n.contains(ip))
    }

    /// Whether the request must be rejected (denied IP, or IP undeterminable).
    pub fn denies<B>(&self, req: &Request<B>) -> bool {
        client_ip(&self.extractor, req).is_none_or(|ip| self.is_denied(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::RequestContext;

    fn allow(
        ranges: &[&str],
        strategy: Option<IpStrategy>,
    ) -> Result<IpAllowListMiddleware, String> {
        IpAllowListMiddleware::new(&IpAllowListConfig {
            source_range: ranges.iter().map(|s| s.to_string()).collect(),
            ip_strategy: strategy,
            reject_status_code: None,
        })
    }

    fn req(peer: &str, xff: Option<&str>) -> Request<()> {
        let mut b = Request::builder().uri("/");
        if let Some(x) = xff {
            b = b.header("x-forwarded-for", x);
        }
        let mut r = b.body(()).unwrap();
        r.extensions_mut().insert(RequestContext {
            remote_addr: format!("{peer}:1").parse().unwrap(),
            is_tls: false,
            client_certs: None,
        });
        r
    }

    #[test]
    fn ranges_and_ipv6() {
        let m = allow(&["192.168.1.100", "10.0.0.0/8", "2001:db8::/32"], None).unwrap();
        assert!(m.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(m.is_allowed("10.200.0.1".parse().unwrap()));
        assert!(m.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(!m.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn invalid_or_empty_ranges_are_errors() {
        assert!(allow(&["10.0.0.0/33"], None).is_err());
        assert!(allow(&["10.0.0.0/8", "nope"], None).is_err());
        assert!(allow(&[], None).is_err());
    }

    #[test]
    fn ip_strategy_depth_and_failure() {
        let s = IpStrategy {
            depth: 2,
            excluded_ips: vec![],
            ipv6_subnet: None,
        };
        let m = allow(&["12.0.0.1"], Some(s)).unwrap();
        assert!(m.allows(&req("1.1.1.1", Some("10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1"))));
        assert!(
            !m.allows(&req("12.0.0.1", Some("13.0.0.1"))),
            "depth beyond XFF rejects"
        );
    }

    #[test]
    fn deny_list() {
        let d = IpDenyListMiddleware::new(&IpDenyListConfig {
            source_range: vec!["10.0.0.0/8".into()],
            ip_strategy: None,
        })
        .unwrap();
        assert!(d.denies(&req("10.1.1.1", None)));
        assert!(!d.denies(&req("8.8.8.8", None)));
    }
}
