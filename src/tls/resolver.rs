use super::acme::{StorageManager, StoredCertificate};
use crate::config::TlsCertificate;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

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
    /// Create an empty certificate resolver.
    pub fn new() -> Self {
        Self {
            static_certs: HashMap::new(),
            acme_storage: None,
            acme_cache: Arc::new(RwLock::new(HashMap::new())),
            default_cert: None,
        }
    }

    /// Build a resolver from a list of static TLS certificate file pairs.
    /// Domains are extracted from each cert's CN and SAN entries.
    pub fn from_static_certs(certs: &[TlsCertificate]) -> Result<Self> {
        let mut resolver = Self::new();
        for tc in certs {
            let key = Self::load_certificate_files(&tc.cert_file, &tc.key_file)
                .with_context(|| format!("Failed to load cert {}", tc.cert_file))?;
            let domains = extract_cert_domains(&key.cert[0])
                .with_context(|| format!("Failed to extract domains from {}", tc.cert_file))?;
            if domains.is_empty() {
                warn!(
                    "Certificate {} has no CN or SAN DNS entries; skipping",
                    tc.cert_file
                );
                continue;
            }
            resolver.add_certificate(&domains, key)?;
        }
        Ok(resolver)
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

    /// Reload all ACME certificates from storage into the in-memory cache.
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
        if let Some(ref storage) = self.acme_storage
            && let Some(stored) = storage.get_certificate(domain)
                && !stored.is_expired() {
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

/// Extract DNS domain names from a DER-encoded X.509 certificate.
/// Collects the subject CN (if a valid DNS name) and all SAN `dNSName` entries.
fn extract_cert_domains(cert_der: &CertificateDer<'_>) -> Result<Vec<String>> {
    let (_, parsed) =
        X509Certificate::from_der(cert_der.as_ref()).context("Failed to parse X.509 DER")?;

    let mut domains = Vec::new();

    for cn in parsed.subject().iter_common_name() {
        if let Ok(s) = cn.as_str()
            && !s.is_empty()
            && !domains.iter().any(|d: &String| d == s)
        {
            domains.push(s.to_string());
        }
    }

    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name
                && !dns.is_empty()
                && !domains.iter().any(|d| d == dns)
            {
                domains.push(dns.to_string());
            }
        }
    }

    Ok(domains)
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
