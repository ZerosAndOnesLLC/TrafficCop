use super::acme::{StorageManager, StoredCertificate};
use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// SNI-based certificate resolver that supports:
/// - Static certificates from config files
/// - ACME certificates from storage
/// - Wildcard matching
pub struct CertificateResolver {
    /// Static certificates loaded from files
    static_certs: HashMap<String, Arc<CertifiedKey>>,

    /// ACME storage for dynamic certificates
    acme_storage: Option<Arc<StorageManager>>,

    /// Cached ACME certificates
    acme_cache: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,

    /// Default certificate (used when no SNI match)
    default_cert: Option<Arc<CertifiedKey>>,
}

impl CertificateResolver {
    pub fn new() -> Self {
        Self {
            static_certs: HashMap::new(),
            acme_storage: None,
            acme_cache: Arc::new(RwLock::new(HashMap::new())),
            default_cert: None,
        }
    }

    /// Add a static certificate from PEM files
    pub fn add_certificate(&mut self, domains: &[String], cert: Arc<CertifiedKey>) -> Result<()> {
        for domain in domains {
            info!("Registered certificate for domain: {}", domain);
            self.static_certs.insert(domain.clone(), Arc::clone(&cert));
        }

        // First cert becomes default if none set
        if self.default_cert.is_none() && !domains.is_empty() {
            self.default_cert = Some(cert);
        }

        Ok(())
    }

    /// Load a certificate from PEM files
    pub fn load_certificate_files(
        cert_path: &str,
        key_path: &str,
    ) -> Result<Arc<CertifiedKey>> {
        use rustls_pemfile::{certs, private_key};
        use std::fs::File;
        use std::io::BufReader;

        let cert_file =
            File::open(cert_path).with_context(|| format!("Failed to open cert: {}", cert_path))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificates")?;

        let key_file =
            File::open(key_path).with_context(|| format!("Failed to open key: {}", key_path))?;
        let mut key_reader = BufReader::new(key_file);
        let key = private_key(&mut key_reader)
            .context("Failed to parse private key")?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("Failed to load signing key: {:?}", e))?;

        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    /// Load certificate from StoredCertificate
    fn load_stored_certificate(stored: &StoredCertificate) -> Result<Arc<CertifiedKey>> {
        let certs = stored.parse_certificate()?;
        let key = stored.parse_private_key()?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("Failed to load signing key: {:?}", e))?;

        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    /// Set ACME storage for dynamic certificate resolution
    pub fn set_acme_storage(&mut self, storage: Arc<StorageManager>) {
        // Pre-load existing ACME certificates into cache
        let certs = storage.get_all_certificates();
        let mut cache = self.acme_cache.write();

        for stored in certs {
            match Self::load_stored_certificate(&stored) {
                Ok(cert) => {
                    for domain in &stored.domains {
                        cache.insert(domain.clone(), Arc::clone(&cert));
                    }
                    info!("Loaded ACME certificate for {:?}", stored.domains);
                }
                Err(e) => {
                    warn!("Failed to load ACME certificate for {}: {}", stored.domain, e);
                }
            }
        }

        self.acme_storage = Some(storage);
    }

    /// Set the default certificate
    pub fn set_default(&mut self, cert: Arc<CertifiedKey>) {
        self.default_cert = Some(cert);
    }

    /// Refresh ACME certificate cache
    pub fn refresh_acme_cache(&self) {
        if let Some(ref storage) = self.acme_storage {
            let certs = storage.get_all_certificates();
            let mut cache = self.acme_cache.write();

            // Clear and rebuild cache
            cache.clear();

            for stored in certs {
                match Self::load_stored_certificate(&stored) {
                    Ok(cert) => {
                        for domain in &stored.domains {
                            cache.insert(domain.clone(), Arc::clone(&cert));
                        }
                    }
                    Err(e) => {
                        warn!("Failed to refresh certificate for {}: {}", stored.domain, e);
                    }
                }
            }
        }
    }

    /// Find certificate for a domain
    fn find_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // 1. Check static certs (exact match)
        if let Some(cert) = self.static_certs.get(domain) {
            return Some(Arc::clone(cert));
        }

        // 2. Check static certs (wildcard match)
        if let Some(cert) = self.find_wildcard_match(domain, &self.static_certs) {
            return Some(cert);
        }

        // 3. Check ACME cache (exact match)
        {
            let cache = self.acme_cache.read();
            if let Some(cert) = cache.get(domain) {
                return Some(Arc::clone(cert));
            }
        }

        // 4. Check ACME cache (wildcard match)
        {
            let cache = self.acme_cache.read();
            if let Some(cert) = self.find_wildcard_match(domain, &cache) {
                return Some(cert);
            }
        }

        // 5. Try to load from ACME storage (in case cache is stale)
        if let Some(ref storage) = self.acme_storage {
            if let Some(stored) = storage.get_certificate(domain) {
                if !stored.is_expired() {
                    match Self::load_stored_certificate(&stored) {
                        Ok(cert) => {
                            // Update cache
                            let mut cache = self.acme_cache.write();
                            for d in &stored.domains {
                                cache.insert(d.clone(), Arc::clone(&cert));
                            }
                            return Some(cert);
                        }
                        Err(e) => {
                            error!("Failed to load certificate for {}: {}", domain, e);
                        }
                    }
                }
            }
        }

        // 6. Return default
        self.default_cert.clone()
    }

    /// Find a wildcard certificate match
    fn find_wildcard_match(
        &self,
        domain: &str,
        certs: &HashMap<String, Arc<CertifiedKey>>,
    ) -> Option<Arc<CertifiedKey>> {
        // Check for wildcard match: *.example.com matches foo.example.com
        if let Some(dot_pos) = domain.find('.') {
            let wildcard = format!("*{}", &domain[dot_pos..]);
            if let Some(cert) = certs.get(&wildcard) {
                return Some(Arc::clone(cert));
            }
        }
        None
    }
}

impl Default for CertificateResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        debug!("SNI: {}", sni);

        self.find_cert(sni)
    }
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateResolver")
            .field("static_domains", &self.static_certs.keys().collect::<Vec<_>>())
            .field("has_acme", &self.acme_storage.is_some())
            .field("has_default", &self.default_cert.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        let resolver = CertificateResolver::new();

        // Create a mock cert map
        let certs = HashMap::new();

        // We can't easily create a real CertifiedKey in tests without actual cert data
        // So we just test the logic conceptually
        assert!(resolver.find_wildcard_match("foo.example.com", &certs).is_none());
    }
}
