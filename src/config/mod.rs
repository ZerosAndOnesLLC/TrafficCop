pub mod duration;
mod types;
pub mod watcher;

pub use duration::Duration;
pub use types::*;
pub use watcher::{watch_config_async, ConfigWatcher};

use anyhow::{Context, Result};
use std::path::Path;

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;

        config.validate()?;

        Ok(config)
    }

    /// Get routers from the http config
    pub fn routers(&self) -> &std::collections::HashMap<String, Router> {
        static EMPTY: std::sync::OnceLock<std::collections::HashMap<String, Router>> =
            std::sync::OnceLock::new();
        self.http
            .as_ref()
            .map(|h| &h.routers)
            .unwrap_or_else(|| EMPTY.get_or_init(std::collections::HashMap::new))
    }

    /// Get services from the http config
    pub fn services(&self) -> &std::collections::HashMap<String, Service> {
        static EMPTY: std::sync::OnceLock<std::collections::HashMap<String, Service>> =
            std::sync::OnceLock::new();
        self.http
            .as_ref()
            .map(|h| &h.services)
            .unwrap_or_else(|| EMPTY.get_or_init(std::collections::HashMap::new))
    }

    /// Get middlewares from the http config
    pub fn middlewares(&self) -> &std::collections::HashMap<String, MiddlewareConfig> {
        static EMPTY: std::sync::OnceLock<std::collections::HashMap<String, MiddlewareConfig>> =
            std::sync::OnceLock::new();
        self.http
            .as_ref()
            .map(|h| &h.middlewares)
            .unwrap_or_else(|| EMPTY.get_or_init(std::collections::HashMap::new))
    }

    pub fn validate(&self) -> Result<()> {
        // Validate entrypoints
        if self.entry_points.is_empty() {
            anyhow::bail!("At least one entryPoint must be defined");
        }

        // Validate services
        for (name, service) in self.services() {
            if let Some(lb) = &service.load_balancer {
                if lb.servers.is_empty() {
                    anyhow::bail!("Service '{}' must have at least one server", name);
                }
                for server in &lb.servers {
                    url::Url::parse(&server.url).with_context(|| {
                        format!("Invalid server URL in service '{}': {}", name, server.url)
                    })?;
                }
            } else if let Some(w) = &service.weighted {
                if w.services.is_empty() {
                    anyhow::bail!("Weighted service '{}' must reference at least one service", name);
                }
            } else if let Some(m) = &service.mirroring {
                if m.service.is_empty() {
                    anyhow::bail!("Mirroring service '{}' must have a main service", name);
                }
            } else {
                anyhow::bail!("Service '{}' must have loadBalancer, weighted, or mirroring configured", name);
            }
        }

        // Validate routers reference valid services
        for (name, router) in self.routers() {
            if !self.services().contains_key(&router.service) {
                anyhow::bail!(
                    "Router '{}' references non-existent service '{}'",
                    name,
                    router.service
                );
            }

            // Validate middleware references
            for mw_name in &router.middlewares {
                // Handle middleware references with @provider suffix (e.g., "auth@file")
                let mw_name_clean = mw_name.split('@').next().unwrap_or(mw_name);
                if !self.middlewares().contains_key(mw_name_clean) && !self.middlewares().contains_key(mw_name) {
                    anyhow::bail!(
                        "Router '{}' references non-existent middleware '{}'",
                        name,
                        mw_name
                    );
                }
            }

            // Validate entrypoint references
            for ep_name in &router.entry_points {
                if !self.entry_points.contains_key(ep_name) {
                    anyhow::bail!(
                        "Router '{}' references non-existent entryPoint '{}'",
                        name,
                        ep_name
                    );
                }
            }
        }

        Ok(())
    }
}
