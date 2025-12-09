mod matcher;
mod rule;

pub use matcher::RouteMatcher;
pub use rule::{Rule, RuleParser};

use crate::config::Config;

pub struct Router {
    routes: Vec<Route>,
}

pub struct Route {
    pub name: String,
    pub entrypoints: Vec<String>,
    pub matcher: RouteMatcher,
    pub service: String,
    pub middlewares: Vec<String>,
    pub priority: i32,
}

impl Router {
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

        Self { routes }
    }

    pub fn match_request(
        &self,
        entrypoint: &str,
        host: Option<&str>,
        path: &str,
        headers: &hyper::HeaderMap,
    ) -> Option<&Route> {
        self.routes.iter().find(|route| {
            // Check entrypoint matches (empty means all entrypoints)
            let ep_match = route.entrypoints.is_empty()
                || route.entrypoints.iter().any(|ep| ep == entrypoint);

            if !ep_match {
                return false;
            }

            // Check rule matches
            route.matcher.matches(host, path, headers)
        })
    }
}
