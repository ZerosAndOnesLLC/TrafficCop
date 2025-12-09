use crate::config::Config;
use anyhow::Result;
use notify::{recommended_watcher, Event, EventKind, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Config watcher that monitors config file for changes and notifies subscribers
pub struct ConfigWatcher {
    config_path: String,
    tx: broadcast::Sender<Config>,
}

impl ConfigWatcher {
    /// Create a new config watcher
    pub fn new(config_path: &str) -> (Self, broadcast::Receiver<Config>) {
        let (tx, rx) = broadcast::channel(16);
        (
            Self {
                config_path: config_path.to_string(),
                tx,
            },
            rx,
        )
    }

    /// Subscribe to config changes
    pub fn subscribe(&self) -> broadcast::Receiver<Config> {
        self.tx.subscribe()
    }

    /// Start watching the config file
    /// This is a blocking operation that should be run in a dedicated task
    pub fn watch(self) -> Result<()> {
        let (sync_tx, sync_rx) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = recommended_watcher(sync_tx)?;
        watcher.watch(Path::new(&self.config_path), RecursiveMode::NonRecursive)?;

        info!("Watching config file for changes: {}", self.config_path);

        // Debounce: wait for writes to complete before reloading
        let mut last_event = std::time::Instant::now();
        let debounce_duration = Duration::from_millis(100);

        loop {
            match sync_rx.recv() {
                Ok(Ok(event)) => {
                    // Only handle modify/create events
                    if !matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_)
                    ) {
                        continue;
                    }

                    // Debounce: skip if too soon after last event
                    let now = std::time::Instant::now();
                    if now.duration_since(last_event) < debounce_duration {
                        continue;
                    }
                    last_event = now;

                    debug!("Config file changed: {:?}", event);

                    // Small delay to ensure file write is complete
                    std::thread::sleep(Duration::from_millis(50));

                    match Config::load(Path::new(&self.config_path)) {
                        Ok(config) => {
                            if let Err(e) = config.validate() {
                                warn!("Invalid config after change: {}", e);
                                continue;
                            }

                            info!("Config reloaded successfully");
                            if self.tx.send(config).is_err() {
                                debug!("No config subscribers, stopping watcher");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to reload config: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Watch error: {:?}", e);
                }
                Err(e) => {
                    error!("Channel error: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Async wrapper for config watching
pub async fn watch_config_async(config_path: String) -> (broadcast::Receiver<Config>, tokio::task::JoinHandle<()>) {
    let (watcher, rx) = ConfigWatcher::new(&config_path);

    let handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = watcher.watch() {
            error!("Config watcher error: {}", e);
        }
    });

    (rx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_watcher_creation() {
        let (watcher, _rx) = ConfigWatcher::new("/tmp/test_config.yaml");
        let _rx2 = watcher.subscribe();
        // Just verify it creates without panic
    }
}
