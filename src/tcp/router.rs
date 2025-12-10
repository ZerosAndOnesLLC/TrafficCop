use crate::config::{Config, TcpRouterTls};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::debug;

/// TCP router for matching connections to services
pub struct TcpRouter {
    /// Routers by entrypoint
    routers: HashMap<String, Vec<TcpRoute>>,
    /// Catch-all routers (rule = "*")
    catch_all: HashMap<String, TcpRoute>,
}

/// A resolved TCP route
#[derive(Clone)]
pub struct TcpRoute {
    /// Route name
    pub name: String,
    /// Target service name
    pub service: String,
    /// Middlewares to apply
    pub middlewares: Vec<String>,
    /// TLS configuration
    pub tls: Option<TcpRouterTls>,
    /// Routing rule
    pub rule: TcpRule,
    /// Priority
    pub priority: i32,
}

/// TCP routing rules
#[derive(Clone)]
pub enum TcpRule {
    /// Match any connection (catch-all)
    CatchAll,
    /// Match by SNI hostname (for TLS connections)
    HostSNI(Vec<String>),
    /// Match by client IP (CIDR)
    ClientIP(Vec<IpNetwork>),
}

impl TcpRule {
    /// Parse a rule string (Traefik-compatible syntax)
    pub fn parse(rule: &str) -> Self {
        let rule = rule.trim();

        // Catch-all
        if rule == "*" || rule.to_lowercase() == "hostsni(`*`)" {
            return TcpRule::CatchAll;
        }

        // HostSNI rule
        if let Some(hosts) = Self::extract_hostsni(rule) {
            return TcpRule::HostSNI(hosts);
        }

        // ClientIP rule
        if let Some(ips) = Self::extract_clientip(rule) {
            let networks: Vec<IpNetwork> = ips
                .iter()
                .filter_map(|ip| ip.parse().ok())
                .collect();
            if !networks.is_empty() {
                return TcpRule::ClientIP(networks);
            }
        }

        // Default to catch-all if parsing fails
        TcpRule::CatchAll
    }

    /// Extract hostnames from HostSNI rule
    fn extract_hostsni(rule: &str) -> Option<Vec<String>> {
        // Match patterns like: HostSNI(`example.com`) or HostSNI(`example.com`, `other.com`)
        let rule_lower = rule.to_lowercase();
        if !rule_lower.starts_with("hostsni(") {
            return None;
        }

        let inner = &rule[8..rule.len().saturating_sub(1)]; // Remove "HostSNI(" and ")"
        let hosts: Vec<String> = inner
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                // Remove backticks
                s.trim_matches('`').trim_matches('\'').trim_matches('"').to_string()
            })
            .filter(|s| !s.is_empty() && s != "*")
            .collect();

        if hosts.is_empty() {
            None
        } else {
            Some(hosts)
        }
    }

    /// Extract IP ranges from ClientIP rule
    fn extract_clientip(rule: &str) -> Option<Vec<String>> {
        let rule_lower = rule.to_lowercase();
        if !rule_lower.starts_with("clientip(") {
            return None;
        }

        let inner = &rule[9..rule.len().saturating_sub(1)];
        let ips: Vec<String> = inner
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_matches('`').trim_matches('\'').trim_matches('"').to_string())
            .collect();

        if ips.is_empty() {
            None
        } else {
            Some(ips)
        }
    }

    /// Check if a connection matches this rule
    pub fn matches(&self, sni: Option<&str>, client_addr: Option<SocketAddr>) -> bool {
        match self {
            TcpRule::CatchAll => true,
            TcpRule::HostSNI(hosts) => {
                if let Some(sni) = sni {
                    hosts.iter().any(|h| {
                        if h.starts_with("*.") {
                            // Wildcard match
                            let suffix = &h[1..]; // Remove the *
                            sni.ends_with(suffix) || sni == &h[2..]
                        } else {
                            h.eq_ignore_ascii_case(sni)
                        }
                    })
                } else {
                    false
                }
            }
            TcpRule::ClientIP(networks) => {
                if let Some(addr) = client_addr {
                    networks.iter().any(|net| net.contains(addr.ip()))
                } else {
                    false
                }
            }
        }
    }
}

impl TcpRouter {
    /// Create a new TCP router from configuration
    pub fn from_config(config: &Config) -> Self {
        let mut routers: HashMap<String, Vec<TcpRoute>> = HashMap::new();
        let mut catch_all: HashMap<String, TcpRoute> = HashMap::new();

        for (name, router_config) in config.tcp_routers() {
            let rule = TcpRule::parse(&router_config.rule);
            let is_catch_all = matches!(rule, TcpRule::CatchAll);

            let route = TcpRoute {
                name: name.clone(),
                service: router_config.service.clone(),
                middlewares: router_config.middlewares.clone(),
                tls: router_config.tls.clone(),
                rule,
                priority: router_config.priority,
            };

            // Determine which entrypoints this router applies to
            let entrypoints = if router_config.entry_points.is_empty() {
                // If no entrypoints specified, apply to all
                config.entry_points.keys().cloned().collect()
            } else {
                router_config.entry_points.clone()
            };

            for ep in entrypoints {
                if is_catch_all {
                    // Only keep highest priority catch-all per entrypoint
                    if let Some(existing) = catch_all.get(&ep) {
                        if route.priority > existing.priority {
                            catch_all.insert(ep, route.clone());
                        }
                    } else {
                        catch_all.insert(ep, route.clone());
                    }
                } else {
                    routers.entry(ep).or_default().push(route.clone());
                }
            }
        }

        // Sort routers by priority (higher first)
        for routes in routers.values_mut() {
            routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        }

        Self { routers, catch_all }
    }

    /// Match a connection to a route
    pub fn match_connection(
        &self,
        entrypoint: &str,
        sni: Option<&str>,
        client_addr: Option<SocketAddr>,
    ) -> Option<&TcpRoute> {
        // Try specific routers first
        if let Some(routes) = self.routers.get(entrypoint) {
            for route in routes {
                if route.rule.matches(sni, client_addr) {
                    debug!(
                        "TCP: Matched route '{}' for entrypoint '{}' (SNI: {:?})",
                        route.name, entrypoint, sni
                    );
                    return Some(route);
                }
            }
        }

        // Fall back to catch-all
        if let Some(route) = self.catch_all.get(entrypoint) {
            debug!(
                "TCP: Using catch-all route '{}' for entrypoint '{}'",
                route.name, entrypoint
            );
            return Some(route);
        }

        None
    }

    /// Check if TLS passthrough is enabled for a route
    pub fn is_tls_passthrough(&self, route: &TcpRoute) -> bool {
        route.tls.as_ref().map(|t| t.passthrough).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_catch_all() {
        let rule = TcpRule::parse("*");
        assert!(matches!(rule, TcpRule::CatchAll));

        let rule = TcpRule::parse("HostSNI(`*`)");
        assert!(matches!(rule, TcpRule::CatchAll));
    }

    #[test]
    fn test_parse_hostsni() {
        let rule = TcpRule::parse("HostSNI(`example.com`)");
        if let TcpRule::HostSNI(hosts) = rule {
            assert_eq!(hosts, vec!["example.com"]);
        } else {
            panic!("Expected HostSNI rule");
        }
    }

    #[test]
    fn test_parse_hostsni_multiple() {
        let rule = TcpRule::parse("HostSNI(`example.com`, `other.com`)");
        if let TcpRule::HostSNI(hosts) = rule {
            assert_eq!(hosts, vec!["example.com", "other.com"]);
        } else {
            panic!("Expected HostSNI rule");
        }
    }

    #[test]
    fn test_hostsni_wildcard_match() {
        let rule = TcpRule::parse("HostSNI(`*.example.com`)");
        assert!(rule.matches(Some("sub.example.com"), None));
        assert!(rule.matches(Some("deep.sub.example.com"), None));
        assert!(!rule.matches(Some("other.com"), None));
    }

    #[test]
    fn test_clientip_match() {
        let rule = TcpRule::parse("ClientIP(`192.168.1.0/24`)");
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        assert!(rule.matches(None, Some(addr)));

        let addr: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        assert!(!rule.matches(None, Some(addr)));
    }
}
