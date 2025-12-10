use crate::config::{Config, ConfigProviderConfig, HttpProviderConfig};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Trait for configuration providers
#[async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Fetch the current configuration
    async fn fetch(&self) -> anyhow::Result<String>;

    /// Get the provider name
    fn name(&self) -> &str;

    /// Get the poll interval
    fn poll_interval(&self) -> Duration;
}

/// HTTP configuration provider
pub struct HttpConfigProvider {
    config: HttpProviderConfig,
    client: reqwest::Client,
    last_etag: RwLock<Option<String>>,
}

impl HttpConfigProvider {
    /// Create a new HTTP config provider
    pub fn new(config: HttpProviderConfig) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout.as_std())
            .connect_timeout(Duration::from_secs(10));

        // Configure TLS if needed
        if let Some(tls) = &config.tls {
            if tls.insecure_skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }

            // Add CA cert if provided
            if let Some(ca_path) = &tls.ca {
                let ca_cert = std::fs::read(ca_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read CA cert: {}", e))?;
                let cert = reqwest::Certificate::from_pem(&ca_cert)
                    .map_err(|e| anyhow::anyhow!("Failed to parse CA cert: {}", e))?;
                builder = builder.add_root_certificate(cert);
            }

            // Add client cert if provided
            if let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) {
                let cert = std::fs::read(cert_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read client cert: {}", e))?;
                let key = std::fs::read(key_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read client key: {}", e))?;

                let mut pem = cert;
                pem.extend_from_slice(&key);

                let identity = reqwest::Identity::from_pem(&pem)
                    .map_err(|e| anyhow::anyhow!("Failed to create identity: {}", e))?;
                builder = builder.identity(identity);
            }
        }

        let client = builder.build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            config,
            client,
            last_etag: RwLock::new(None),
        })
    }
}

#[async_trait]
impl ConfigProvider for HttpConfigProvider {
    async fn fetch(&self) -> anyhow::Result<String> {
        let mut request = self.client.get(&self.config.endpoint);

        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        // Add basic auth if configured
        if let Some(auth) = &self.config.basic_auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }

        // Add If-None-Match header for caching
        let last_etag = self.last_etag.read().await.clone();
        if let Some(etag) = &last_etag {
            request = request.header("If-None-Match", etag);
        }

        let response = request.send().await
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;

        // Handle 304 Not Modified
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Err(anyhow::anyhow!("Config not modified"));
        }

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP request failed with status: {}",
                response.status()
            ));
        }

        // Store ETag for next request
        if let Some(etag) = response.headers().get("etag") {
            if let Ok(etag_str) = etag.to_str() {
                *self.last_etag.write().await = Some(etag_str.to_string());
            }
        }

        let content = response.text().await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

        Ok(content)
    }

    fn name(&self) -> &str {
        "http"
    }

    fn poll_interval(&self) -> Duration {
        self.config.poll_interval.as_std()
    }
}

/// Configuration provider manager
#[allow(dead_code)]
pub struct ConfigProviderManager {
    providers: Vec<Box<dyn ConfigProvider>>,
    current_config: RwLock<Option<Config>>,
    on_config_change: RwLock<Option<Box<dyn Fn(Config) + Send + Sync>>>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

#[allow(dead_code)]
impl ConfigProviderManager {
    /// Create a new config provider manager from configuration
    pub fn new(provider_configs: &[ConfigProviderConfig]) -> anyhow::Result<Self> {
        let mut providers: Vec<Box<dyn ConfigProvider>> = Vec::new();

        for config in provider_configs {
            match config {
                ConfigProviderConfig::Http(http_config) => {
                    let provider = HttpConfigProvider::new(http_config.clone())?;
                    providers.push(Box::new(provider));
                }
                ConfigProviderConfig::S3(_) => {
                    warn!("S3 config provider not yet implemented");
                }
                ConfigProviderConfig::Consul(_) => {
                    warn!("Consul config provider not yet implemented");
                }
            }
        }

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        Ok(Self {
            providers,
            current_config: RwLock::new(None),
            on_config_change: RwLock::new(None),
            shutdown_tx,
        })
    }

    /// Set the callback for config changes
    pub async fn set_on_change<F>(&self, callback: F)
    where
        F: Fn(Config) + Send + Sync + 'static,
    {
        *self.on_config_change.write().await = Some(Box::new(callback));
    }

    /// Start polling all providers
    pub fn start_polling(self: Arc<Self>) {
        for (idx, provider) in self.providers.iter().enumerate() {
            let interval = provider.poll_interval();
            let provider_name = provider.name().to_string();
            let manager = Arc::clone(&self);
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            tokio::spawn(async move {
                let mut interval_timer = tokio::time::interval(interval);
                // Skip first tick (immediate)
                interval_timer.tick().await;

                loop {
                    tokio::select! {
                        _ = interval_timer.tick() => {
                            debug!("Polling config provider: {}", provider_name);
                            if let Err(e) = manager.poll_provider(idx).await {
                                if !e.to_string().contains("not modified") {
                                    warn!("Config provider {} error: {}", provider_name, e);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            debug!("Config provider {} polling stopped", provider_name);
                            break;
                        }
                    }
                }
            });
        }
    }

    /// Poll a specific provider
    async fn poll_provider(&self, provider_idx: usize) -> anyhow::Result<()> {
        let provider = self.providers.get(provider_idx)
            .ok_or_else(|| anyhow::anyhow!("Provider not found"))?;

        let content = provider.fetch().await?;

        // Parse the config
        let new_config: Config = serde_yaml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config: {}", e))?;

        // Validate
        new_config.validate()
            .map_err(|e| anyhow::anyhow!("Config validation failed: {}", e))?;

        // Check if config changed
        let current = self.current_config.read().await;
        let config_changed = current.is_none() || {
            let current_yaml = serde_yaml::to_string(current.as_ref().unwrap()).unwrap_or_default();
            let new_yaml = serde_yaml::to_string(&new_config).unwrap_or_default();
            current_yaml != new_yaml
        };
        drop(current);

        if config_changed {
            info!("Configuration updated from {} provider", provider.name());

            // Update current config
            *self.current_config.write().await = Some(new_config.clone());

            // Call callback
            if let Some(callback) = self.on_config_change.read().await.as_ref() {
                callback(new_config);
            }
        }

        Ok(())
    }

    /// Fetch config from all providers (first success wins)
    pub async fn fetch_initial(&self) -> anyhow::Result<Config> {
        for provider in &self.providers {
            match provider.fetch().await {
                Ok(content) => {
                    let config: Config = serde_yaml::from_str(&content)?;
                    config.validate()?;
                    *self.current_config.write().await = Some(config.clone());
                    info!("Initial config loaded from {} provider", provider.name());
                    return Ok(config);
                }
                Err(e) => {
                    warn!("Provider {} failed: {}", provider.name(), e);
                }
            }
        }

        Err(anyhow::anyhow!("All config providers failed"))
    }

    /// Shutdown the provider manager
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_http_provider_creation() {
        let config = HttpProviderConfig {
            endpoint: "http://localhost:8080/config".to_string(),
            poll_interval: crate::config::Duration::from_secs(30),
            timeout: crate::config::Duration::from_secs(10),
            headers: HashMap::new(),
            tls: None,
            basic_auth: None,
        };

        let provider = HttpConfigProvider::new(config);
        assert!(provider.is_ok());
    }
}
