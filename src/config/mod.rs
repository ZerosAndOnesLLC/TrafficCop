mod types;
pub mod watcher;

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

    pub fn validate(&self) -> Result<()> {
        // Validate entrypoints
        if self.entrypoints.is_empty() {
            anyhow::bail!("At least one entrypoint must be defined");
        }

        // Validate services
        for (name, service) in &self.services {
            if service.servers.is_empty() {
                anyhow::bail!("Service '{}' must have at least one server", name);
            }

            for server in &service.servers {
                url::Url::parse(&server.url)
                    .with_context(|| format!("Invalid server URL in service '{}': {}", name, server.url))?;
            }
        }

        // Validate routers reference valid services
        for (name, router) in &self.routers {
            if !self.services.contains_key(&router.service) {
                anyhow::bail!(
                    "Router '{}' references non-existent service '{}'",
                    name,
                    router.service
                );
            }

            // Validate middleware references
            for mw_name in &router.middlewares {
                if !self.middlewares.contains_key(mw_name) {
                    anyhow::bail!(
                        "Router '{}' references non-existent middleware '{}'",
                        name,
                        mw_name
                    );
                }
            }

            // Validate entrypoint references
            for ep_name in &router.entrypoints {
                if !self.entrypoints.contains_key(ep_name) {
                    anyhow::bail!(
                        "Router '{}' references non-existent entrypoint '{}'",
                        name,
                        ep_name
                    );
                }
            }
        }

        Ok(())
    }
}
