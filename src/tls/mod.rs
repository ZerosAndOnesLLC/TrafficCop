use crate::config::{EntrypointTls, TlsConfig};
use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn from_config(tls_config: &TlsConfig) -> Result<Option<Self>> {
        if tls_config.certificates.is_empty() {
            return Ok(None);
        }

        let cert_config = &tls_config.certificates[0];
        let config = Self::build_server_config(&cert_config.cert_file, &cert_config.key_file)?;

        Ok(Some(Self {
            config: Arc::new(config),
        }))
    }

    pub fn from_entrypoint_tls(tls_config: &EntrypointTls) -> Result<Self> {
        let cert_file = tls_config
            .cert_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cert_file is required for TLS"))?;
        let key_file = tls_config
            .key_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("key_file is required for TLS"))?;

        let config = Self::build_server_config(cert_file, key_file)?;

        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn from_files(cert_path: &str, key_path: &str) -> Result<Self> {
        let config = Self::build_server_config(cert_path, key_path)?;

        Ok(Self {
            config: Arc::new(config),
        })
    }

    fn build_server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
        let cert_file = File::open(cert_path)
            .with_context(|| format!("Failed to open cert file: {}", cert_path))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificates")?;

        let key_file = File::open(key_path)
            .with_context(|| format!("Failed to open key file: {}", key_path))?;
        let mut key_reader = BufReader::new(key_file);
        let key = private_key(&mut key_reader)
            .context("Failed to parse private key")?
            .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build TLS config")?;

        // Enable ALPN for HTTP/2 and HTTP/1.1
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }

    pub fn get_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }
}
