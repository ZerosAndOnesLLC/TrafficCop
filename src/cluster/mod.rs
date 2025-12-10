mod manager;
mod provider;

pub use manager::ClusterManager;
pub use provider::{ConfigProvider, HttpConfigProvider};

use crate::config::{ClusterConfig, StoreConfig as ConfigStoreConfig};
use crate::store::{Store, ValkeyConfig, ValkeyStore, LocalStore};
use std::sync::Arc;
use tracing::info;

/// Create a store from the cluster configuration
pub async fn create_store_from_config(config: &ClusterConfig) -> anyhow::Result<Arc<dyn Store>> {
    let store_config = config.store.as_ref();

    match store_config {
        Some(ConfigStoreConfig::Redis(redis_config)) => {
            let valkey_config = ValkeyConfig {
                endpoints: redis_config.endpoints.clone(),
                password: redis_config.password.clone(),
                username: redis_config.username.clone(),
                db: redis_config.db,
                tls: redis_config.tls.as_ref().map(|t| crate::store::ValkeyTlsConfig {
                    ca: t.ca.clone(),
                    cert: t.cert.clone(),
                    key: t.key.clone(),
                    insecure_skip_verify: t.insecure_skip_verify,
                }),
                pool_size: 10,
                key_prefix: redis_config.root_key.clone(),
                connect_timeout: redis_config.timeout.clone(),
                operation_timeout: crate::config::Duration::from_secs(1),
                sentinel: redis_config.sentinel.as_ref().map(|s| crate::store::SentinelConfig {
                    master_name: s.master_name.clone(),
                    endpoints: redis_config.endpoints.clone(),
                    password: s.password.clone(),
                }),
            };

            let store = ValkeyStore::new(&valkey_config).await
                .map_err(|e| anyhow::anyhow!("Failed to connect to Valkey: {}", e))?;

            info!("Connected to distributed store (Valkey/Redis)");
            Ok(Arc::new(store))
        }
        Some(ConfigStoreConfig::Local) | None => {
            info!("Using local in-memory store (single node mode)");
            Ok(Arc::new(LocalStore::new()))
        }
    }
}
