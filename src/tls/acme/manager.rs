use super::client::AcmeClient;
use super::storage::StorageManager;
use crate::tls::CertificateResolver;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info};

/// ACME manager that handles certificate lifecycle
pub struct AcmeManager {
    storage: Arc<StorageManager>,
    client: Arc<RwLock<AcmeClient>>,
    resolver: Arc<CertificateResolver>,
    pending_challenges: Arc<RwLock<HashMap<String, super::client::PendingChallenge>>>,
    renewal_interval: Duration,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub async fn new(
        storage_path: &str,
        email: &str,
        ca_server: Option<&str>,
    ) -> Result<Self> {
        let storage = Arc::new(StorageManager::new(storage_path)?);
        let mut client = AcmeClient::new(Arc::clone(&storage), email, ca_server);

        // Initialize client (fetch directory, load/create account)
        client.init().await?;

        let pending_challenges = client.get_pending_challenges();

        // Create resolver with ACME storage
        let mut resolver = CertificateResolver::new();
        resolver.set_acme_storage(Arc::clone(&storage));

        Ok(Self {
            storage,
            client: Arc::new(RwLock::new(client)),
            resolver: Arc::new(resolver),
            pending_challenges,
            renewal_interval: Duration::from_secs(12 * 60 * 60), // Check every 12 hours
        })
    }

    /// Get the certificate resolver for TLS
    pub fn get_resolver(&self) -> Arc<CertificateResolver> {
        Arc::clone(&self.resolver)
    }

    /// Get the pending challenges map for the HTTP-01 handler
    pub fn get_pending_challenges(
        &self,
    ) -> Arc<RwLock<HashMap<String, super::client::PendingChallenge>>> {
        Arc::clone(&self.pending_challenges)
    }

    /// Request a certificate for the given domains
    pub async fn obtain_certificate(&self, domains: &[String]) -> Result<()> {
        info!("Requesting certificate for domains: {:?}", domains);

        let mut client = self.client.write().await;
        client.order_certificate(domains).await?;

        // Refresh resolver cache
        self.resolver.refresh_acme_cache();

        Ok(())
    }

    /// Ensure certificates exist for all configured domains
    pub async fn ensure_certificates(&self, domains: &[Vec<String>]) -> Result<()> {
        for domain_set in domains {
            if domain_set.is_empty() {
                continue;
            }

            let primary = &domain_set[0];

            // Check if we already have a valid certificate
            if let Some(cert) = self.storage.get_certificate(primary) {
                if !cert.needs_renewal() {
                    info!("Certificate for {} is valid, skipping", primary);
                    continue;
                }
                info!("Certificate for {} needs renewal", primary);
            }

            // Obtain new certificate
            if let Err(e) = self.obtain_certificate(domain_set).await {
                error!("Failed to obtain certificate for {:?}: {}", domain_set, e);
            }
        }

        Ok(())
    }

    /// Start the automatic renewal background task
    pub fn start_renewal_task(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(self.renewal_interval).await;

                info!("Checking certificates for renewal...");

                let certs_needing_renewal = self.storage.get_certificates_needing_renewal();

                for cert in certs_needing_renewal {
                    info!(
                        "Renewing certificate for {} (expires at {})",
                        cert.domain, cert.not_after
                    );

                    match self.obtain_certificate(&cert.domains).await {
                        Ok(_) => {
                            info!("Successfully renewed certificate for {}", cert.domain);
                        }
                        Err(e) => {
                            error!("Failed to renew certificate for {}: {}", cert.domain, e);
                        }
                    }
                }
            }
        });
    }
}

/// Builder for AcmeManager with options
pub struct AcmeManagerBuilder {
    storage_path: String,
    email: String,
    ca_server: Option<String>,
    domains: Vec<Vec<String>>,
}

impl AcmeManagerBuilder {
    pub fn new(email: &str, storage_path: &str) -> Self {
        Self {
            storage_path: storage_path.to_string(),
            email: email.to_string(),
            ca_server: None,
            domains: Vec::new(),
        }
    }

    /// Use Let's Encrypt staging server (for testing)
    pub fn staging(mut self) -> Self {
        self.ca_server = Some(
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
        );
        self
    }

    /// Use Let's Encrypt production server
    pub fn production(mut self) -> Self {
        self.ca_server = Some("https://acme-v02.api.letsencrypt.org/directory".to_string());
        self
    }

    /// Use a custom CA server
    pub fn ca_server(mut self, url: &str) -> Self {
        self.ca_server = Some(url.to_string());
        self
    }

    /// Add domains to manage
    pub fn domain(mut self, domains: Vec<String>) -> Self {
        self.domains.push(domains);
        self
    }

    /// Build and initialize the ACME manager
    pub async fn build(self) -> Result<Arc<AcmeManager>> {
        let manager = AcmeManager::new(
            &self.storage_path,
            &self.email,
            self.ca_server.as_deref(),
        )
        .await?;

        let manager = Arc::new(manager);

        // Ensure certificates for all domains
        if !self.domains.is_empty() {
            manager.ensure_certificates(&self.domains).await?;
        }

        // Start renewal task
        Arc::clone(&manager).start_renewal_task();

        Ok(manager)
    }
}
