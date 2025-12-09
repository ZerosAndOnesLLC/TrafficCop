use crate::config::{ClientAuth, TlsOptions};
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

/// Client authentication mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientAuthMode {
    /// No client certificate required (default)
    NoClientCert,
    /// Request client certificate but don't require it
    RequestClientCert,
    /// Require any valid client certificate
    RequireAnyClientCert,
    /// Require client certificate and verify against CA
    VerifyClientCertIfGiven,
    /// Require client certificate and verify against CA (strict)
    RequireAndVerifyClientCert,
}

impl ClientAuthMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "noclientcert" | "no_client_cert" | "" => ClientAuthMode::NoClientCert,
            "requestclientcert" | "request_client_cert" => ClientAuthMode::RequestClientCert,
            "requireanyclientcert" | "require_any_client_cert" => ClientAuthMode::RequireAnyClientCert,
            "verifyclientcertifgiven" | "verify_client_cert_if_given" => ClientAuthMode::VerifyClientCertIfGiven,
            "requireandverifyclientcert" | "require_and_verify_client_cert" => ClientAuthMode::RequireAndVerifyClientCert,
            _ => ClientAuthMode::NoClientCert,
        }
    }
}

/// mTLS configuration builder
pub struct MtlsConfigBuilder {
    client_auth_mode: ClientAuthMode,
    ca_certs: Vec<CertificateDer<'static>>,
}

impl MtlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            client_auth_mode: ClientAuthMode::NoClientCert,
            ca_certs: Vec::new(),
        }
    }

    /// Build from TLS options config
    pub fn from_tls_options(options: &TlsOptions) -> Result<Self> {
        let mut builder = Self::new();

        if let Some(ref client_auth) = options.client_auth {
            builder = builder.with_client_auth(client_auth)?;
        }

        Ok(builder)
    }

    /// Configure client authentication
    pub fn with_client_auth(mut self, client_auth: &ClientAuth) -> Result<Self> {
        // Set auth mode
        if let Some(ref auth_type) = client_auth.client_auth_type {
            self.client_auth_mode = ClientAuthMode::from_str(auth_type);
        }

        // Load CA certificates for client verification
        for ca_file in &client_auth.ca_files {
            let certs = load_certs(ca_file)?;
            self.ca_certs.extend(certs);
        }

        Ok(self)
    }

    /// Build a ServerConfig with mTLS enabled
    pub fn build_with_cert(
        self,
        server_certs: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig> {
        let config = match self.client_auth_mode {
            ClientAuthMode::NoClientCert => {
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(server_certs, server_key)
                    .context("Failed to build TLS config")?
            }
            ClientAuthMode::RequestClientCert
            | ClientAuthMode::VerifyClientCertIfGiven
            | ClientAuthMode::RequireAnyClientCert
            | ClientAuthMode::RequireAndVerifyClientCert => {
                // Build root cert store from CA certs
                let mut root_store = RootCertStore::empty();
                for cert in &self.ca_certs {
                    root_store.add(cert.clone())
                        .context("Failed to add CA certificate to root store")?;
                }

                // Create client verifier based on mode
                let client_verifier = match self.client_auth_mode {
                    ClientAuthMode::VerifyClientCertIfGiven => {
                        WebPkiClientVerifier::builder(Arc::new(root_store))
                            .allow_unauthenticated()
                            .build()
                            .context("Failed to build client verifier")?
                    }
                    _ => {
                        // RequireAndVerifyClientCert or others that require verification
                        WebPkiClientVerifier::builder(Arc::new(root_store))
                            .build()
                            .context("Failed to build client verifier")?
                    }
                };

                ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(server_certs, server_key)
                    .context("Failed to build TLS config with client auth")?
            }
        };

        Ok(config)
    }

    /// Build with a certificate resolver (for SNI)
    pub fn build_with_resolver(
        self,
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<ServerConfig> {
        let config = match self.client_auth_mode {
            ClientAuthMode::NoClientCert => {
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(resolver)
            }
            ClientAuthMode::RequestClientCert
            | ClientAuthMode::VerifyClientCertIfGiven
            | ClientAuthMode::RequireAnyClientCert
            | ClientAuthMode::RequireAndVerifyClientCert => {
                // Build root cert store from CA certs
                let mut root_store = RootCertStore::empty();
                for cert in &self.ca_certs {
                    root_store.add(cert.clone())
                        .context("Failed to add CA certificate to root store")?;
                }

                let client_verifier = match self.client_auth_mode {
                    ClientAuthMode::VerifyClientCertIfGiven => {
                        WebPkiClientVerifier::builder(Arc::new(root_store))
                            .allow_unauthenticated()
                            .build()
                            .context("Failed to build client verifier")?
                    }
                    _ => {
                        WebPkiClientVerifier::builder(Arc::new(root_store))
                            .build()
                            .context("Failed to build client verifier")?
                    }
                };

                ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_cert_resolver(resolver)
            }
        };

        Ok(config)
    }

    /// Get the configured client auth mode
    pub fn client_auth_mode(&self) -> ClientAuthMode {
        self.client_auth_mode
    }
}

impl Default for MtlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Load certificates from a PEM file
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open certificate file: {}", path))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse certificates from: {}", path))?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in file: {}", path);
    }

    Ok(certs)
}

/// Extract client certificate info from a TLS connection
pub struct ClientCertInfo {
    /// The client certificate chain (DER encoded)
    pub chain: Vec<Vec<u8>>,
    /// Subject CN (Common Name) if available
    pub subject_cn: Option<String>,
    /// Subject DN (Distinguished Name)
    pub subject_dn: Option<String>,
    /// Issuer DN
    pub issuer_dn: Option<String>,
    /// Serial number (hex string)
    pub serial: Option<String>,
    /// Not before (RFC 3339)
    pub not_before: Option<String>,
    /// Not after (RFC 3339)
    pub not_after: Option<String>,
}

impl ClientCertInfo {
    /// Create empty cert info
    pub fn empty() -> Self {
        Self {
            chain: Vec::new(),
            subject_cn: None,
            subject_dn: None,
            issuer_dn: None,
            serial: None,
            not_before: None,
            not_after: None,
        }
    }

    /// Check if client certificate was provided
    pub fn has_cert(&self) -> bool {
        !self.chain.is_empty()
    }

    /// Get PEM-encoded certificate
    pub fn pem(&self) -> Option<String> {
        if self.chain.is_empty() {
            return None;
        }

        // Base64 encode the first certificate
        let cert = &self.chain[0];
        let encoded = base64_encode(cert);

        Some(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            encoded.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

/// Base64 encode bytes
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;

        while bits >= 6 {
            bits -= 6;
            result.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
        }
    }

    if bits > 0 {
        buffer <<= 6 - bits;
        result.push(ALPHABET[(buffer & 0x3F) as usize] as char);
    }

    // Add padding
    while result.len() % 4 != 0 {
        result.push('=');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_auth_mode_from_str() {
        assert_eq!(ClientAuthMode::from_str(""), ClientAuthMode::NoClientCert);
        assert_eq!(ClientAuthMode::from_str("NoClientCert"), ClientAuthMode::NoClientCert);
        assert_eq!(ClientAuthMode::from_str("RequestClientCert"), ClientAuthMode::RequestClientCert);
        assert_eq!(ClientAuthMode::from_str("RequireAnyClientCert"), ClientAuthMode::RequireAnyClientCert);
        assert_eq!(ClientAuthMode::from_str("VerifyClientCertIfGiven"), ClientAuthMode::VerifyClientCertIfGiven);
        assert_eq!(ClientAuthMode::from_str("RequireAndVerifyClientCert"), ClientAuthMode::RequireAndVerifyClientCert);
    }

    #[test]
    fn test_mtls_builder_default() {
        let builder = MtlsConfigBuilder::new();
        assert_eq!(builder.client_auth_mode(), ClientAuthMode::NoClientCert);
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_client_cert_info_empty() {
        let info = ClientCertInfo::empty();
        assert!(!info.has_cert());
        assert!(info.pem().is_none());
    }

    #[test]
    fn test_client_cert_info_pem() {
        let mut info = ClientCertInfo::empty();
        info.chain = vec![vec![0x30, 0x82, 0x01, 0x22]]; // Minimal fake DER

        assert!(info.has_cert());
        let pem = info.pem().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
    }
}
