use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Storage for ACME account and certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeStorage {
    /// ACME account information
    #[serde(default)]
    pub account: Option<AcmeAccount>,

    /// Stored certificates by domain
    #[serde(default)]
    pub certificates: HashMap<String, StoredCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// Account URL from ACME server
    pub url: String,

    /// Account private key (PEM encoded)
    pub private_key_pem: String,

    /// Registration email
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// The main domain this certificate is for
    pub domain: String,

    /// All domains covered (including SANs)
    pub domains: Vec<String>,

    /// Certificate chain (PEM encoded)
    pub certificate_pem: String,

    /// Private key (PEM encoded)
    pub private_key_pem: String,

    /// Certificate expiry timestamp (Unix seconds)
    pub not_after: u64,

    /// Certificate start timestamp (Unix seconds)
    pub not_before: u64,
}

impl StoredCertificate {
    /// Check if certificate needs renewal (30 days before expiry)
    pub fn needs_renewal(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Renew if less than 30 days until expiry
        let thirty_days = 30 * 24 * 60 * 60;
        self.not_after.saturating_sub(thirty_days) < now
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.not_after < now
    }

    /// Parse certificate into rustls format
    pub fn parse_certificate(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut reader = BufReader::new(self.certificate_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse stored certificate")?;
        Ok(certs)
    }

    /// Parse private key into rustls format
    pub fn parse_private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let mut reader = BufReader::new(self.private_key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader)
            .context("Failed to parse private key")?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
        Ok(key)
    }
}

impl Default for AcmeStorage {
    fn default() -> Self {
        Self {
            account: None,
            certificates: HashMap::new(),
        }
    }
}

/// Thread-safe storage manager
pub struct StorageManager {
    path: String,
    data: Arc<RwLock<AcmeStorage>>,
}

impl StorageManager {
    /// Load or create storage at the given path
    pub fn new(path: &str) -> Result<Self> {
        let data = if Path::new(path).exists() {
            info!("Loading ACME storage from {}", path);
            let file = File::open(path).context("Failed to open ACME storage file")?;
            let reader = BufReader::new(file);
            serde_json::from_reader(reader).context("Failed to parse ACME storage")?
        } else {
            info!("Creating new ACME storage at {}", path);
            AcmeStorage::default()
        };

        Ok(Self {
            path: path.to_string(),
            data: Arc::new(RwLock::new(data)),
        })
    }

    /// Save storage to disk
    pub fn save(&self) -> Result<()> {
        let data = self.data.read();

        // Create parent directories if needed
        if let Some(parent) = Path::new(&self.path).parent() {
            fs::create_dir_all(parent).context("Failed to create storage directory")?;
        }

        // Write atomically via temp file
        let temp_path = format!("{}.tmp", self.path);
        {
            let file = File::create(&temp_path).context("Failed to create temp storage file")?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &*data).context("Failed to serialize storage")?;
        }

        fs::rename(&temp_path, &self.path).context("Failed to rename temp storage file")?;

        debug!("Saved ACME storage to {}", self.path);
        Ok(())
    }

    /// Get account info
    pub fn get_account(&self) -> Option<AcmeAccount> {
        self.data.read().account.clone()
    }

    /// Set account info
    pub fn set_account(&self, account: AcmeAccount) -> Result<()> {
        {
            let mut data = self.data.write();
            data.account = Some(account);
        }
        self.save()
    }

    /// Get certificate for a domain
    pub fn get_certificate(&self, domain: &str) -> Option<StoredCertificate> {
        let data = self.data.read();

        // First try exact match
        if let Some(cert) = data.certificates.get(domain) {
            return Some(cert.clone());
        }

        // Try to find a certificate that covers this domain (including wildcards)
        for cert in data.certificates.values() {
            if cert.domains.contains(&domain.to_string()) {
                return Some(cert.clone());
            }

            // Check wildcard match
            for cert_domain in &cert.domains {
                if cert_domain.starts_with("*.") {
                    let wildcard_base = &cert_domain[2..];
                    if domain.ends_with(wildcard_base)
                        && domain[..domain.len() - wildcard_base.len()].matches('.').count() == 0
                    {
                        // Single label before the wildcard base
                        if !domain[..domain.len() - wildcard_base.len() - 1].contains('.') {
                            return Some(cert.clone());
                        }
                    }
                }
            }
        }

        None
    }

    /// Store a certificate
    pub fn store_certificate(&self, cert: StoredCertificate) -> Result<()> {
        let domain = cert.domain.clone();
        {
            let mut data = self.data.write();
            data.certificates.insert(domain.clone(), cert);
        }
        info!("Stored certificate for {}", domain);
        self.save()
    }

    /// Get all certificates that need renewal
    pub fn get_certificates_needing_renewal(&self) -> Vec<StoredCertificate> {
        let data = self.data.read();
        data.certificates
            .values()
            .filter(|c| c.needs_renewal())
            .cloned()
            .collect()
    }

    /// Get all valid certificates
    pub fn get_all_certificates(&self) -> Vec<StoredCertificate> {
        let data = self.data.read();
        data.certificates
            .values()
            .filter(|c| !c.is_expired())
            .cloned()
            .collect()
    }

    /// Remove a certificate
    pub fn remove_certificate(&self, domain: &str) -> Result<()> {
        {
            let mut data = self.data.write();
            data.certificates.remove(domain);
        }
        self.save()
    }

    /// Get a clone of the inner Arc for sharing
    pub fn get_shared(&self) -> Arc<RwLock<AcmeStorage>> {
        Arc::clone(&self.data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_needs_renewal() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate expiring in 60 days - no renewal needed
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            domains: vec!["example.com".to_string()],
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            not_after: now + 60 * 24 * 60 * 60,
            not_before: now - 30 * 24 * 60 * 60,
        };
        assert!(!cert.needs_renewal());

        // Certificate expiring in 20 days - needs renewal
        let cert = StoredCertificate {
            domain: "example.com".to_string(),
            domains: vec!["example.com".to_string()],
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            not_after: now + 20 * 24 * 60 * 60,
            not_before: now - 70 * 24 * 60 * 60,
        };
        assert!(cert.needs_renewal());
    }
}
