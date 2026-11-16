use super::rule::{ConnInfo, TcpRule};
use crate::config::{Config, TcpRouterTls};
use std::collections::HashMap;
use tracing::debug;

/// TCP router for matching connections to services.
pub struct TcpRouter {
    /// Routes per entrypoint, in precedence order.
    routers: HashMap<String, Vec<TcpRoute>>,
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
    /// Effective priority (explicit non-zero value, else rule length).
    pub priority: i64,
}

impl TcpRouter {
    /// Build from configuration. An unparseable rule is an error.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let mut routers: HashMap<String, Vec<TcpRoute>> = HashMap::new();

        for (name, router_config) in config.tcp_routers() {
            let rule = TcpRule::parse(&router_config.rule)
                .map_err(|e| format!("TCP router '{name}': {e}"))?;
            let priority = if router_config.priority != 0 {
                i64::from(router_config.priority)
            } else {
                router_config.rule.trim().len() as i64
            };

            let route = TcpRoute {
                name: name.clone(),
                service: router_config.service.clone(),
                middlewares: router_config.middlewares.clone(),
                tls: router_config.tls.clone(),
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

    /// Highest-precedence route matching the connection.
    pub fn match_connection(&self, entrypoint: &str, conn: &ConnInfo<'_>) -> Option<&TcpRoute> {
        let route = self
            .routers
            .get(entrypoint)?
            .iter()
            .find(|r| r.rule.matches(conn))?;
        debug!(
            "TCP: Matched route '{}' for entrypoint '{}' (SNI: {:?})",
            route.name, entrypoint, conn.sni
        );
        Some(route)
    }

    /// Check if TLS passthrough is enabled for a route
    pub fn is_tls_passthrough(&self, route: &TcpRoute) -> bool {
        route.tls.as_ref().map(|t| t.passthrough).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(routers: &str) -> TcpRouter {
        let yaml = format!(
            "entryPoints:\n  tcp: {{address: \"127.0.0.1:1\"}}\ntcp:\n  routers:\n{routers}\n  services:\n    s:\n      loadBalancer: {{servers: [{{address: \"127.0.0.1:2\"}}]}}\n"
        );
        TcpRouter::from_config(&Config::from_yaml_str(&yaml).unwrap()).unwrap()
    }

    fn hit(r: &TcpRouter, sni: Option<&str>, ip: &str) -> String {
        let conn = ConnInfo {
            sni,
            alpn: &[],
            client_ip: Some(ip.parse().unwrap()),
        };
        r.match_connection("tcp", &conn)
            .map(|r| r.name.clone())
            .unwrap_or_default()
    }

    #[test]
    fn priority_is_rule_length_and_deterministic() {
        for _ in 0..16 {
            let r = router(
                "    all: {rule: \"HostSNI(`*`)\", service: s}\n    db: {rule: \"HostSNI(`db.example.com`)\", service: s}\n    office: {rule: \"HostSNI(`*`) && ClientIP(`10.0.0.0/8`)\", service: s}",
            );
            // office (38 chars) > db (25) > all (12)
            assert_eq!(hit(&r, Some("db.example.com"), "1.1.1.1"), "db");
            assert_eq!(hit(&r, None, "10.1.1.1"), "office");
            assert_eq!(hit(&r, None, "8.8.8.8"), "all");
        }
    }

    #[test]
    fn invalid_rule_rejects_config() {
        let yaml = "entryPoints:\n  tcp: {address: \"127.0.0.1:1\"}\ntcp:\n  routers:\n    r: {rule: \"ClientIP(`10.0.0.0/33`) && HostSNI(`*`)\", service: s}\n  services:\n    s:\n      loadBalancer: {servers: [{address: \"127.0.0.1:2\"}]}\n";
        assert!(Config::from_yaml_str(yaml).is_err());
    }
}
