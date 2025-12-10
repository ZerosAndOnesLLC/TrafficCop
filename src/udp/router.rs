use crate::config::Config;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::debug;

/// UDP router for matching datagrams to services
pub struct UdpRouter {
    /// Routers by entrypoint
    routers: HashMap<String, Vec<UdpRoute>>,
    /// Catch-all routers (rule = "*")
    catch_all: HashMap<String, UdpRoute>,
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
    /// Priority
    pub priority: i32,
}

/// UDP routing rules
/// Note: UDP doesn't support SNI since there's no TLS handshake
#[derive(Clone)]
pub enum UdpRule {
    /// Match any datagram (catch-all)
    CatchAll,
    /// Match by client IP (CIDR)
    ClientIP(Vec<IpNetwork>),
}

impl UdpRule {
    /// Parse a rule string (Traefik-compatible syntax)
    pub fn parse(rule: &str) -> Self {
        let rule = rule.trim();

        // Catch-all
        if rule == "*" {
            return UdpRule::CatchAll;
        }

        // ClientIP rule
        if let Some(ips) = Self::extract_clientip(rule) {
            let networks: Vec<IpNetwork> = ips
                .iter()
                .filter_map(|ip| ip.parse().ok())
                .collect();
            if !networks.is_empty() {
                return UdpRule::ClientIP(networks);
            }
        }

        // Default to catch-all if parsing fails
        UdpRule::CatchAll
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

    /// Check if a datagram matches this rule
    pub fn matches(&self, client_addr: Option<SocketAddr>) -> bool {
        match self {
            UdpRule::CatchAll => true,
            UdpRule::ClientIP(networks) => {
                if let Some(addr) = client_addr {
                    networks.iter().any(|net| net.contains(addr.ip()))
                } else {
                    false
                }
            }
        }
    }
}

impl UdpRouter {
    /// Create a new UDP router from configuration
    pub fn from_config(config: &Config) -> Self {
        let mut routers: HashMap<String, Vec<UdpRoute>> = HashMap::new();
        let mut catch_all: HashMap<String, UdpRoute> = HashMap::new();

        for (name, router_config) in config.udp_routers() {
            let rule = UdpRule::parse(&router_config.rule);
            let is_catch_all = matches!(rule, UdpRule::CatchAll);

            let route = UdpRoute {
                name: name.clone(),
                service: router_config.service.clone(),
                middlewares: router_config.middlewares.clone(),
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

    /// Match a datagram to a route
    pub fn match_datagram(
        &self,
        entrypoint: &str,
        client_addr: Option<SocketAddr>,
    ) -> Option<&UdpRoute> {
        // Try specific routers first
        if let Some(routes) = self.routers.get(entrypoint) {
            for route in routes {
                if route.rule.matches(client_addr) {
                    debug!(
                        "UDP: Matched route '{}' for entrypoint '{}' (client: {:?})",
                        route.name, entrypoint, client_addr
                    );
                    return Some(route);
                }
            }
        }

        // Fall back to catch-all
        if let Some(route) = self.catch_all.get(entrypoint) {
            debug!(
                "UDP: Using catch-all route '{}' for entrypoint '{}'",
                route.name, entrypoint
            );
            return Some(route);
        }

        None
    }

    /// Check if this router has any routes for the given entrypoint
    pub fn has_routes_for(&self, entrypoint: &str) -> bool {
        self.routers.contains_key(entrypoint) || self.catch_all.contains_key(entrypoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_catch_all() {
        let rule = UdpRule::parse("*");
        assert!(matches!(rule, UdpRule::CatchAll));
    }

    #[test]
    fn test_parse_clientip() {
        let rule = UdpRule::parse("ClientIP(`192.168.1.0/24`)");
        if let UdpRule::ClientIP(networks) = rule {
            assert_eq!(networks.len(), 1);
        } else {
            panic!("Expected ClientIP rule");
        }
    }

    #[test]
    fn test_clientip_match() {
        let rule = UdpRule::parse("ClientIP(`192.168.1.0/24`)");
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        assert!(rule.matches(Some(addr)));

        let addr: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        assert!(!rule.matches(Some(addr)));
    }

    #[test]
    fn test_catch_all_always_matches() {
        let rule = UdpRule::CatchAll;
        let addr: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        assert!(rule.matches(Some(addr)));
        assert!(rule.matches(None));
    }
}
