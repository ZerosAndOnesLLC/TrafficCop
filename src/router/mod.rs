//! Request routing engine that matches incoming requests to backend services.

mod matcher;
mod rule;

pub use matcher::RouteMatcher;
pub use rule::{Rule, RuleParser};

use crate::config::Config;
use std::collections::HashMap;

/// Routes incoming requests to services using rule-based matching with host and entrypoint indexing.
pub struct Router {
    routes: Vec<Route>,
    /// Pre-computed candidate route indices per entrypoint (sorted by priority).
    /// Includes both entrypoint-specific and catch-all routes.
    candidates_by_ep: HashMap<String, Vec<usize>>,
    /// Routes with no entrypoint restriction, sorted by priority.
    catch_all: Vec<usize>,
    /// Host -> route indices for O(1) host lookup (routes with top-level Host rule).
    host_index: HashMap<String, Vec<usize>>,
    /// Entrypoint `http.middlewares`, applied before every router's own.
    ep_middlewares: HashMap<String, Vec<String>>,
}

/// A single routing rule that maps matched requests to a service.
pub struct Route {
    /// Unique name identifying this route.
    pub name: String,
    /// Entrypoints this route is bound to (empty means all).
    pub entrypoints: Vec<String>,
    /// Compiled matcher for evaluating incoming requests.
    pub matcher: RouteMatcher,
    /// Name of the backend service to forward to.
    pub service: String,
    /// Ordered list of middleware names to apply.
    pub middlewares: Vec<String>,
    /// Effective priority (higher wins). Traefik semantics: an explicit
    /// non-zero `priority`, otherwise the length of the rule string.
    pub priority: i64,
    /// Whether this route has been indexed by host (skip in non-host scan)
    host_indexed: bool,
}

impl Router {
    /// Build a router from config, pre-computing entrypoint and host indexes.
    pub fn from_config(config: &Config) -> Self {
        let mut routes: Vec<Route> = config
            .routers()
            .iter()
            .filter_map(|(name, router_config)| {
                match RouteMatcher::from_rule(&router_config.rule) {
                    Ok(matcher) => Some(Route {
                        name: name.clone(),
                        entrypoints: router_config.entry_points.clone(),
                        matcher,
                        service: router_config.service.clone(),
                        middlewares: router_config.middlewares.clone(),
                        priority: effective_priority(router_config.priority, &router_config.rule),
                        host_indexed: false,
                    }),
                    Err(e) => {
                        tracing::error!("Failed to parse rule for router '{}': {}", name, e);
                        None
                    }
                }
            })
            .collect();

        // Total order: priority desc, then name asc (Traefik's tie-break).
        // Route index therefore equals precedence rank, which match_request
        // relies on when merging host-indexed and other candidates.
        routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });

        // Build host index
        let mut host_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, route) in routes.iter_mut().enumerate() {
            let hosts = route.matcher.extract_hosts();
            if !hosts.is_empty() {
                route.host_indexed = true;
                for host in hosts {
                    host_index
                        .entry(host.to_ascii_lowercase())
                        .or_default()
                        .push(idx);
                }
            }
        }

        // Build entrypoint index
        let mut candidates_by_ep: HashMap<String, Vec<usize>> = HashMap::new();
        let mut catch_all: Vec<usize> = Vec::new();
        let mut all_eps: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for (idx, route) in routes.iter().enumerate() {
            if route.entrypoints.is_empty() {
                catch_all.push(idx);
            } else {
                for ep in &route.entrypoints {
                    all_eps.insert(ep.as_str());
                    candidates_by_ep.entry(ep.clone()).or_default().push(idx);
                }
            }
        }

        // Merge catch-all routes into each entrypoint's list, kept in index
        // (= precedence) order.
        for candidates in candidates_by_ep.values_mut() {
            candidates.extend_from_slice(&catch_all);
            candidates.sort_unstable();
            candidates.dedup();
        }

        let ep_middlewares = config
            .entry_points
            .iter()
            .filter_map(|(name, ep)| {
                let mws = &ep.http.as_ref()?.middlewares;
                (!mws.is_empty()).then(|| (name.clone(), mws.clone()))
            })
            .collect();

        Self {
            routes,
            candidates_by_ep,
            catch_all,
            host_index,
            ep_middlewares,
        }
    }

    /// Middlewares configured on the entrypoint (`http.middlewares`).
    pub fn entrypoint_middlewares(&self, entrypoint: &str) -> &[String] {
        self.ep_middlewares
            .get(entrypoint)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Find the highest-priority route matching the given request attributes.
    pub fn match_request(
        &self,
        entrypoint: &str,
        host: Option<&str>,
        path: &str,
        query: Option<&str>,
        method: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> Option<&Route> {
        // Get candidate indices for this entrypoint
        let candidates = self
            .candidates_by_ep
            .get(entrypoint)
            .map(|v| v.as_slice())
            .unwrap_or(&self.catch_all);

        // Host-indexed routes for this host (only routes whose rule requires
        // a Host). Both lists are in precedence order; merge them so a
        // higher-priority non-host route is never shadowed by a host route.
        static NO_HOST: Vec<usize> = Vec::new();
        let host_candidates = host
            .and_then(|h| self.host_index.get(&h.to_ascii_lowercase()))
            .unwrap_or(&NO_HOST);

        let (mut i, mut j) = (0, 0);
        loop {
            let next = match (host_candidates.get(i), candidates.get(j)) {
                (Some(&h), Some(&c)) if h <= c => {
                    i += 1;
                    h
                }
                (_, Some(&c)) => {
                    j += 1;
                    // Host-indexed routes are only reachable via their host.
                    if self.routes[c].host_indexed {
                        continue;
                    }
                    c
                }
                (Some(&h), None) => {
                    i += 1;
                    h
                }
                (None, None) => return None,
            };
            let route = &self.routes[next];
            let ep_match =
                route.entrypoints.is_empty() || route.entrypoints.iter().any(|ep| ep == entrypoint);
            if ep_match && route.matcher.matches(host, path, query, method, headers) {
                return Some(route);
            }
        }
    }
}

/// Traefik default priority: explicit non-zero value, else rule length.
fn effective_priority(configured: i32, rule: &str) -> i64 {
    if configured != 0 {
        i64::from(configured)
    } else {
        rule.len() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(routers: &str) -> Router {
        let yaml = format!(
            "entryPoints:\n  web: {{address: \"127.0.0.1:8080\"}}\nhttp:\n  routers:\n{routers}\n  services:\n    s:\n      loadBalancer: {{servers: [{{url: \"http://127.0.0.1:9\"}}]}}\n"
        );
        Router::from_config(&Config::from_yaml_str(&yaml).unwrap())
    }

    fn hit(r: &Router, host: &str, path: &str) -> String {
        r.match_request(
            "web",
            Some(host),
            path,
            None,
            Some("GET"),
            &hyper::HeaderMap::new(),
        )
        .map(|r| r.name.clone())
        .unwrap_or_default()
    }

    #[test]
    fn default_priority_is_rule_length() {
        // Repeat to shake out HashMap iteration order.
        for _ in 0..32 {
            let r = router(
                "    catchall: {rule: \"PathPrefix(`/`)\", service: s}\n    admin: {rule: \"PathPrefix(`/admin`)\", service: s}",
            );
            assert_eq!(hit(&r, "a.com", "/admin/x"), "admin");
            assert_eq!(hit(&r, "a.com", "/other"), "catchall");
        }
    }

    #[test]
    fn ties_break_by_name() {
        for _ in 0..32 {
            let r = router(
                "    zeta: {rule: \"PathPrefix(`/x`)\", service: s}\n    alpha: {rule: \"PathPrefix(`/y`) || PathPrefix(`/x`)\", service: s, priority: 20}\n    beta: {rule: \"PathPrefix(`/x`) || Path(`/q`)\", service: s, priority: 20}",
            );
            assert_eq!(hit(&r, "h", "/x"), "alpha");
        }
    }

    #[test]
    fn explicit_priority_beats_host_index() {
        let r = router(
            "    byhost: {rule: \"Host(`a.com`)\", service: s, priority: 1}\n    vip: {rule: \"PathPrefix(`/vip`)\", service: s, priority: 1000}",
        );
        assert_eq!(hit(&r, "a.com", "/vip"), "vip");
        assert_eq!(hit(&r, "a.com", "/other"), "byhost");
        assert_eq!(hit(&r, "b.com", "/other"), "");
    }

    #[test]
    fn host_route_beats_lower_priority_path_route() {
        let r = router(
            "    byhost: {rule: \"Host(`a.com`) && PathPrefix(`/api`)\", service: s}\n    api: {rule: \"PathPrefix(`/api`)\", service: s}",
        );
        assert_eq!(hit(&r, "A.com", "/api/v1"), "byhost");
        assert_eq!(hit(&r, "b.com", "/api/v1"), "api");
    }
}
