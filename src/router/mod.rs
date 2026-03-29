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
    /// Priority for route ordering (higher wins).
    pub priority: i32,
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
                        priority: router_config.priority,
                        host_indexed: false,
                    }),
                    Err(e) => {
                        tracing::error!("Failed to parse rule for router '{}': {}", name, e);
                        None
                    }
                }
            })
            .collect();

        // Sort by priority (higher first)
        routes.sort_by(|a, b| b.priority.cmp(&a.priority));

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

        // Pre-merge catch-all routes into each entrypoint's candidate list
        for candidates in candidates_by_ep.values_mut() {
            let mut merged = Vec::with_capacity(candidates.len() + catch_all.len());
            let mut i = 0;
            let mut j = 0;
            // Merge two sorted-by-priority lists
            while i < candidates.len() && j < catch_all.len() {
                if routes[candidates[i]].priority >= routes[catch_all[j]].priority {
                    merged.push(candidates[i]);
                    i += 1;
                } else {
                    merged.push(catch_all[j]);
                    j += 1;
                }
            }
            merged.extend_from_slice(&candidates[i..]);
            merged.extend_from_slice(&catch_all[j..]);
            *candidates = merged;
        }

        Self {
            routes,
            candidates_by_ep,
            catch_all,
            host_index,
        }
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

        // Fast path: if host is provided, check host-indexed routes first
        if let Some(h) = host {
            let host_lower = h.to_ascii_lowercase();
            if let Some(host_candidates) = self.host_index.get(&host_lower) {
                // Check host-indexed routes that also match this entrypoint
                for &idx in host_candidates {
                    let route = &self.routes[idx];
                    let ep_match = route.entrypoints.is_empty()
                        || route.entrypoints.iter().any(|ep| ep == entrypoint);
                    if ep_match && route.matcher.matches(Some(h), path, query, method, headers) {
                        return Some(route);
                    }
                }
            }
        }

        // Scan non-host-indexed routes for this entrypoint
        for &idx in candidates {
            let route = &self.routes[idx];
            if route.host_indexed {
                continue; // Already checked via host index
            }
            if route.matcher.matches(host, path, query, method, headers) {
                return Some(route);
            }
        }

        None
    }
}
