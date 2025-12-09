mod listener;

pub use listener::Listener;

use crate::config::{watch_config_async, Config};
use crate::proxy::ProxyHandler;
use crate::router::Router;
use crate::service::ServiceManager;
use anyhow::Result;
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

/// Shared state that can be hot-reloaded
pub struct SharedState {
    pub router: ArcSwap<Router>,
    pub services: ArcSwap<ServiceManager>,
}

impl SharedState {
    pub fn new(config: &Config) -> Self {
        Self {
            router: ArcSwap::from_pointee(Router::from_config(config)),
            services: ArcSwap::from_pointee(ServiceManager::new(config)),
        }
    }

    /// Reload state from new config
    pub fn reload(&self, config: &Config) {
        let new_router = Router::from_config(config);
        let new_services = ServiceManager::new(config);

        self.router.store(Arc::new(new_router));
        self.services.store(Arc::new(new_services));

        info!("Router and services reloaded");
    }
}

pub struct Server {
    config_path: PathBuf,
    config: Arc<ArcSwap<Config>>,
    state: Arc<SharedState>,
    proxy: Arc<ProxyHandler>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self::with_path(config, PathBuf::from("config.yaml"))
    }

    pub fn with_path(config: Config, config_path: PathBuf) -> Self {
        let state = Arc::new(SharedState::new(&config));
        let config = Arc::new(ArcSwap::from_pointee(config));
        let proxy = Arc::new(ProxyHandler::new());

        Self {
            config_path,
            config,
            state,
            proxy,
        }
    }

    pub async fn run(&self) -> Result<()> {
        // Start health checks for all services
        self.state.services.load().start_health_checks();

        let config = self.config.load();
        let mut handles = Vec::new();

        // Collect entrypoints to avoid lifetime issues
        let entrypoints: Vec<_> = config
            .entrypoints
            .iter()
            .map(|(name, ep)| (name.clone(), ep.clone()))
            .collect();

        for (name, entrypoint) in entrypoints {
            let listener = Listener::new(
                name.clone(),
                entrypoint,
                Arc::clone(&self.state),
                Arc::clone(&self.proxy),
            );

            let listener_name = name.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = listener.serve().await {
                    error!("Listener '{}' error: {}", listener_name, e);
                }
            });

            handles.push(handle);
        }

        // Start config watcher
        let config_path_str = self.config_path.to_string_lossy().to_string();
        let config_arc = Arc::clone(&self.config);
        let state_arc = Arc::clone(&self.state);

        let watcher_handle = tokio::spawn(async move {
            let (mut rx, _handle) = watch_config_async(config_path_str).await;

            while let Ok(new_config) = rx.recv().await {
                info!("Hot reloading configuration...");

                // Update config
                config_arc.store(Arc::new(new_config.clone()));

                // Reload router and services
                state_arc.reload(&new_config);

                // Restart health checks with new services
                state_arc.services.load().start_health_checks();
            }
        });

        info!("Server started with hot reload enabled, waiting for shutdown signal");

        // Wait for shutdown signal
        shutdown_signal().await;

        info!("Shutdown signal received, stopping server");

        // Stop watcher
        watcher_handle.abort();

        // Cancel all listeners
        for handle in handles {
            handle.abort();
        }

        info!("Server stopped");

        Ok(())
    }

    pub fn reload_config(&self, config: Config) -> Result<()> {
        config.validate()?;
        self.config.store(Arc::new(config.clone()));
        self.state.reload(&config);
        info!("Configuration reloaded manually");
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
