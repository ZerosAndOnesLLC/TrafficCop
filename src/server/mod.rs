mod listener;

pub use listener::Listener;

use crate::config::{watch_config_async, Config};
use crate::proxy::ProxyHandler;
use crate::router::Router;
use crate::service::ServiceManager;
use crate::tls::{AcmeManager, CertificateResolver, PendingChallenge};
use anyhow::Result;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Tracks active connections for graceful shutdown
pub struct ConnectionTracker {
    active: AtomicUsize,
    draining: AtomicBool,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// Increment active connection count, returns false if draining
    #[inline]
    pub fn connection_start(&self) -> bool {
        if self.draining.load(Ordering::Acquire) {
            return false;
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Decrement active connection count
    #[inline]
    pub fn connection_end(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current active connection count
    #[inline]
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Start draining - reject new connections
    pub fn start_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    /// Check if draining
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Wait for all connections to finish, with timeout
    pub async fn wait_for_drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        let check_interval = Duration::from_millis(100);

        loop {
            let count = self.active_count();
            if count == 0 {
                info!("All connections drained");
                return;
            }

            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "Drain timeout reached with {} active connections remaining",
                    count
                );
                return;
            }

            tokio::time::sleep(check_interval).await;
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state that can be hot-reloaded
pub struct SharedState {
    pub router: ArcSwap<Router>,
    pub services: ArcSwap<ServiceManager>,
    pub connections: ConnectionTracker,
    /// Pending ACME challenges for HTTP-01 validation
    pub acme_challenges: Arc<RwLock<HashMap<String, PendingChallenge>>>,
    /// Certificate resolver for SNI-based cert selection
    pub cert_resolver: Option<Arc<CertificateResolver>>,
}

impl SharedState {
    pub fn new(config: &Config) -> Self {
        Self {
            router: ArcSwap::from_pointee(Router::from_config(config)),
            services: ArcSwap::from_pointee(ServiceManager::new(config)),
            connections: ConnectionTracker::new(),
            acme_challenges: Arc::new(RwLock::new(HashMap::new())),
            cert_resolver: None,
        }
    }

    /// Create with ACME manager
    pub fn with_acme(config: &Config, acme_manager: &AcmeManager) -> Self {
        Self {
            router: ArcSwap::from_pointee(Router::from_config(config)),
            services: ArcSwap::from_pointee(ServiceManager::new(config)),
            connections: ConnectionTracker::new(),
            acme_challenges: acme_manager.get_pending_challenges(),
            cert_resolver: Some(acme_manager.get_resolver()),
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
    #[allow(dead_code)] // Kept alive for renewal task
    acme_manager: Option<Arc<AcmeManager>>,
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
            acme_manager: None,
        }
    }

    /// Create server with ACME support
    pub fn with_acme(
        config: Config,
        config_path: PathBuf,
        acme_manager: Arc<AcmeManager>,
    ) -> Self {
        let state = Arc::new(SharedState::with_acme(&config, &acme_manager));
        let config = Arc::new(ArcSwap::from_pointee(config));
        let proxy = Arc::new(ProxyHandler::new());

        Self {
            config_path,
            config,
            state,
            proxy,
            acme_manager: Some(acme_manager),
        }
    }

    pub async fn run(&self) -> Result<()> {
        // Start health checks for all services
        self.state.services.load().start_health_checks();

        let config = self.config.load();
        let mut handles = Vec::new();

        // Collect entrypoints to avoid lifetime issues
        let entrypoints: Vec<_> = config
            .entry_points
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

        info!("Shutdown signal received, starting graceful drain");

        // Stop watcher
        watcher_handle.abort();

        // Start draining - reject new connections
        self.state.connections.start_drain();

        // Wait for existing connections to complete (30 second timeout)
        let drain_timeout = Duration::from_secs(30);
        let active = self.state.connections.active_count();
        if active > 0 {
            info!(
                "Waiting for {} active connections to drain (timeout: {:?})",
                active, drain_timeout
            );
            self.state.connections.wait_for_drain(drain_timeout).await;
        }

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
