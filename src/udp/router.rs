use crate::config::Config;
use crate::tcp::rule::{ConnInfo, TcpRule};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::debug;

/// UDP router (TrafficCop extension: Traefik UDP routers have no rule).
pub struct UdpRouter {
    /// Routes per entrypoint, in precedence order.
    routers: HashMap<String, Vec<UdpRoute>>,
}

/// A resolved UDP route
#[derive(Clone)]
pub struct UdpRoute {
    /// Route name
    pub name: String,
    /// Target service name
    pub service: String,
    /// Middlewares to apply
    pub middlewares: Vec<String>,
    /// Routing rule
    pub rule: UdpRule,
    /// Effective priority (explicit non-zero value, else rule length).
    pub priority: i64,
}

/// UDP rule: `*` / `HostSNI(`*`)` or `ClientIP(...)`, optionally combined with
/// `&&`, `||`, `!`. Parsed strictly; anything else is an error.
#[derive(Clone)]
pub struct UdpRule(TcpRule);

impl UdpRule {
    /// Parse a UDP rule. An empty rule (Traefik UDP routers have none) matches all.
    pub fn parse(rule: &str) -> Result<Self, String> {
        if rule.trim().is_empty() {
            return Ok(Self(TcpRule::Any));
        }
        let r = TcpRule::parse(rule)?;
        fn check(r: &TcpRule) -> Result<(), String> {
            match r {
                TcpRule::Any | TcpRule::ClientIp(_) => Ok(()),
                TcpRule::And(a, b) | TcpRule::Or(a, b) => check(a).and(check(b)),
                TcpRule::Not(a) => check(a),
                _ => Err("UDP rules only support ClientIP and *".to_string()),
            }
        }
        check(&r)?;
        Ok(Self(r))
    }

    /// Whether a datagram from `client_addr` matches.
    pub fn matches(&self, client_addr: Option<SocketAddr>) -> bool {
        self.0.matches(&ConnInfo {
            sni: None,
            alpn: &[],
            client_ip: client_addr.map(|a| a.ip()),
        })
    }
}

impl UdpRouter {
    /// Build from configuration. An unparseable rule is an error.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let mut routers: HashMap<String, Vec<UdpRoute>> = HashMap::new();

        for (name, router_config) in config.udp_routers() {
            let rule = UdpRule::parse(&router_config.rule)
                .map_err(|e| format!("UDP router '{name}': {e}"))?;
            let priority = if router_config.priority != 0 {
                i64::from(router_config.priority)
            } else {
                router_config.rule.trim().len() as i64
            };
            let route = UdpRoute {
                name: name.clone(),
                service: router_config.service.clone(),
                middlewares: router_config.middlewares.clone(),
                rule,
                priority,
            };

            let entrypoints = if router_config.entry_points.is_empty() {
                config.entry_points.keys().cloned().collect()
            } else {
                router_config.entry_points.clone()
            };
            for ep in entrypoints {
                routers.entry(ep).or_default().push(route.clone());
            }
        }

        for routes in routers.values_mut() {
            routes.sort_by(|a, b| {
                b.priority
                    .cmp(&a.priority)
                    .then_with(|| a.name.cmp(&b.name))
            });
        }

        Ok(Self { routers })
    }

    /// Match a datagram to a route
    pub fn match_datagram(
        &self,
        entrypoint: &str,
        client_addr: Option<SocketAddr>,
    ) -> Option<&UdpRoute> {
        let route = self
            .routers
            .get(entrypoint)?
            .iter()
            .find(|r| r.rule.matches(client_addr))?;
        debug!(
            "UDP: Matched route '{}' for entrypoint '{}' (client: {:?})",
            route.name, entrypoint, client_addr
        );
        Some(route)
    }

    /// Check if this router has any routes for the given entrypoint
    pub fn has_routes_for(&self, entrypoint: &str) -> bool {
        self.routers.get(entrypoint).is_some_and(|r| !r.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Option<SocketAddr> {
        Some(format!("{s}:1234").parse().unwrap())
    }

    #[test]
    fn rules_parse_strictly() {
        assert!(UdpRule::parse("*").unwrap().matches(addr("1.1.1.1")));
        assert!(UdpRule::parse("").unwrap().matches(addr("1.1.1.1")));
        let r = UdpRule::parse("ClientIP(`192.168.1.0/24`)").unwrap();
        assert!(r.matches(addr("192.168.1.100")));
        assert!(!r.matches(addr("10.0.0.1")));
        assert!(!r.matches(None));
        for bad in [
            "ClientIP(`192.168.1.0/33`)",
            "HostSNI(`a`)",
            "garbage",
            "ClientIP(`a`",
        ] {
            assert!(UdpRule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn negation_and_combination() {
        let r = UdpRule::parse("ClientIP(`10.0.0.0/8`) && !ClientIP(`10.9.0.0/16`)").unwrap();
        assert!(r.matches(addr("10.1.1.1")));
        assert!(!r.matches(addr("10.9.1.1")));
    }
}
