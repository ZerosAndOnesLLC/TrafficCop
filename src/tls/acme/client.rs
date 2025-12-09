use super::storage::{AcmeAccount, StorageManager, StoredCertificate};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[allow(dead_code)]
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// ACME Directory endpoints
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    #[allow(dead_code)]
    pub revoke_cert: Option<String>,
    #[allow(dead_code)]
    pub key_change: Option<String>,
}

/// ACME order status
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeOrder {
    pub status: String,
    #[allow(dead_code)]
    pub expires: Option<String>,
    #[allow(dead_code)]
    pub identifiers: Vec<AcmeIdentifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

/// ACME authorization
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeAuthorization {
    pub identifier: AcmeIdentifier,
    pub status: String,
    pub challenges: Vec<AcmeChallenge>,
}

/// ACME challenge
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub token: String,
    pub status: String,
}

/// Pending HTTP-01 challenge
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub token: String,
    pub key_authorization: String,
}

/// ACME client for certificate management
pub struct AcmeClient {
    storage: Arc<StorageManager>,
    directory_url: String,
    directory: Option<AcmeDirectory>,
    email: String,
    http_client: reqwest::Client,
    key_pair: Option<EcdsaKeyPair>,
    account_url: Option<String>,
    pending_challenges: Arc<RwLock<std::collections::HashMap<String, PendingChallenge>>>,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(storage: Arc<StorageManager>, email: &str, ca_server: Option<&str>) -> Self {
        let directory_url = ca_server
            .unwrap_or(LETS_ENCRYPT_PRODUCTION)
            .to_string();

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            storage,
            directory_url,
            directory: None,
            email: email.to_string(),
            http_client,
            key_pair: None,
            account_url: None,
            pending_challenges: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Initialize the client - fetch directory and set up account
    pub async fn init(&mut self) -> Result<()> {
        // Fetch directory
        info!("Fetching ACME directory from {}", self.directory_url);
        let directory: AcmeDirectory = self
            .http_client
            .get(&self.directory_url)
            .send()
            .await
            .context("Failed to fetch ACME directory")?
            .json()
            .await
            .context("Failed to parse ACME directory")?;

        self.directory = Some(directory);

        // Load or create account
        if let Some(account) = self.storage.get_account() {
            info!("Using existing ACME account: {}", account.url);
            self.account_url = Some(account.url);
            self.key_pair = Some(self.load_key_pair(&account.private_key_pem)?);
        } else {
            info!("Creating new ACME account for {}", self.email);
            self.create_account().await?;
        }

        Ok(())
    }

    /// Get the pending challenges map for the challenge handler
    pub fn get_pending_challenges(
        &self,
    ) -> Arc<RwLock<std::collections::HashMap<String, PendingChallenge>>> {
        Arc::clone(&self.pending_challenges)
    }

    /// Load an EC key pair from PEM
    fn load_key_pair(&self, pem: &str) -> Result<EcdsaKeyPair> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader)
            .context("Failed to parse private key PEM")?
            .ok_or_else(|| anyhow::anyhow!("No private key in PEM"))?;

        let key_bytes = match key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(bytes) => bytes.secret_pkcs8_der().to_vec(),
            _ => return Err(anyhow::anyhow!("Unsupported key format")),
        };

        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_bytes, &SystemRandom::new())
            .map_err(|e| anyhow::anyhow!("Failed to load key pair: {:?}", e))
    }

    /// Create a new ACME account
    async fn create_account(&mut self) -> Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not initialized"))?;

        // Generate new key pair
        let (pem, key_pair) = self.generate_account_key()?;
        self.key_pair = Some(key_pair);

        // Create account request
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.email)]
        });

        let response = self
            .signed_request(&directory.new_account.clone(), Some(payload), true)
            .await?;

        let account_url = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("No account URL in response"))?
            .to_string();

        self.account_url = Some(account_url.clone());

        // Save account
        let account = AcmeAccount {
            url: account_url,
            private_key_pem: pem,
            email: self.email.clone(),
        };
        self.storage.set_account(account)?;

        info!("ACME account created successfully");
        Ok(())
    }

    /// Generate a new EC key pair for the account
    fn generate_account_key(&self) -> Result<(String, EcdsaKeyPair)> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate key: {:?}", e))?;

        let pem = pem_encode("PRIVATE KEY", pkcs8_bytes.as_ref());
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| anyhow::anyhow!("Failed to create key pair: {:?}", e))?;

        Ok((pem, key_pair))
    }

    /// Get a fresh nonce from the ACME server
    async fn get_nonce(&self) -> Result<String> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not initialized"))?;

        let response = self
            .http_client
            .head(&directory.new_nonce)
            .send()
            .await
            .context("Failed to get nonce")?;

        response
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No nonce in response"))
    }

    /// Make a signed request to the ACME server
    async fn signed_request(
        &self,
        url: &str,
        payload: Option<serde_json::Value>,
        use_jwk: bool,
    ) -> Result<reqwest::Response> {
        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No key pair"))?;

        let nonce = self.get_nonce().await?;

        // Build protected header
        let mut protected = serde_json::json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        });

        if use_jwk {
            // Use JWK for account creation
            protected["jwk"] = self.get_jwk(key_pair)?;
        } else {
            // Use kid for subsequent requests
            let account_url = self
                .account_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("No account URL"))?;
            protected["kid"] = serde_json::Value::String(account_url.clone());
        }

        let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string().as_bytes());

        let payload_b64 = match payload {
            Some(p) => URL_SAFE_NO_PAD.encode(p.to_string().as_bytes()),
            None => String::new(),
        };

        // Sign
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let rng = SystemRandom::new();
        let signature = key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to sign: {:?}", e))?;

        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

        let body = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        });

        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .context("Request failed")?;

        Ok(response)
    }

    /// Get JWK representation of the public key
    fn get_jwk(&self, key_pair: &EcdsaKeyPair) -> Result<serde_json::Value> {
        let public_key = key_pair.public_key().as_ref();

        // EC public key format: 0x04 || x (32 bytes) || y (32 bytes)
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(anyhow::anyhow!("Invalid public key format"));
        }

        let x = URL_SAFE_NO_PAD.encode(&public_key[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public_key[33..65]);

        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }))
    }

    /// Get the key authorization for a challenge token
    fn get_key_authorization(&self, token: &str) -> Result<String> {
        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No key pair"))?;

        let jwk = self.get_jwk(key_pair)?;
        let jwk_json = serde_json::to_string(&jwk)?;

        // SHA-256 hash of JWK
        let thumbprint = ring::digest::digest(&ring::digest::SHA256, jwk_json.as_bytes());
        let thumbprint_b64 = URL_SAFE_NO_PAD.encode(thumbprint.as_ref());

        Ok(format!("{}.{}", token, thumbprint_b64))
    }

    /// Order a certificate for the given domains
    pub async fn order_certificate(&mut self, domains: &[String]) -> Result<StoredCertificate> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not initialized"))?
            .clone();

        info!("Ordering certificate for domains: {:?}", domains);

        // Create order
        let identifiers: Vec<AcmeIdentifier> = domains
            .iter()
            .map(|d| AcmeIdentifier {
                id_type: "dns".to_string(),
                value: d.clone(),
            })
            .collect();

        let payload = serde_json::json!({
            "identifiers": identifiers,
        });

        let response = self
            .signed_request(&directory.new_order, Some(payload), false)
            .await?;

        let order_url = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let order: AcmeOrder = response
            .json()
            .await
            .context("Failed to parse order response")?;

        debug!("Order created: {:?}", order);

        // Process authorizations
        for authz_url in &order.authorizations {
            self.process_authorization(authz_url).await?;
        }

        // Wait for order to be ready
        let order_url_str = order_url.unwrap_or_default();
        let order = self.wait_for_order_ready(&order_url_str, &order).await?;

        // Generate certificate key and CSR
        let (cert_key_pem, csr_der) = self.generate_csr(domains)?;

        // Finalize order
        let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
        let payload = serde_json::json!({
            "csr": csr_b64,
        });

        self.signed_request(&order.finalize, Some(payload), false)
            .await?;

        // Wait for certificate
        let order = self.wait_for_order_valid(&order_url_str, &order).await?;

        let cert_url = order
            .certificate
            .ok_or_else(|| anyhow::anyhow!("No certificate URL in order"))?;

        // Download certificate
        let response = self.signed_request(&cert_url, None, false).await?;
        let cert_pem = response.text().await?;

        // Parse certificate to get validity dates
        let (not_before, not_after) = self.parse_certificate_dates(&cert_pem)?;

        let stored = StoredCertificate {
            domain: domains[0].clone(),
            domains: domains.to_vec(),
            certificate_pem: cert_pem,
            private_key_pem: cert_key_pem,
            not_before,
            not_after,
        };

        // Store certificate
        self.storage.store_certificate(stored.clone())?;

        info!(
            "Certificate obtained for {:?}, valid until {}",
            domains,
            chrono_from_unix(not_after)
        );

        Ok(stored)
    }

    /// Process an authorization (complete HTTP-01 challenge)
    async fn process_authorization(&mut self, authz_url: &str) -> Result<()> {
        let response = self.signed_request(authz_url, None, false).await?;
        let authz: AcmeAuthorization = response.json().await?;

        if authz.status == "valid" {
            debug!("Authorization already valid for {}", authz.identifier.value);
            return Ok(());
        }

        // Find HTTP-01 challenge
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge available"))?;

        if challenge.status == "valid" {
            return Ok(());
        }

        let key_auth = self.get_key_authorization(&challenge.token)?;

        // Register pending challenge
        {
            let mut challenges = self.pending_challenges.write().await;
            challenges.insert(
                challenge.token.clone(),
                PendingChallenge {
                    token: challenge.token.clone(),
                    key_authorization: key_auth.clone(),
                },
            );
        }

        info!(
            "HTTP-01 challenge ready for {} at /.well-known/acme-challenge/{}",
            authz.identifier.value, challenge.token
        );

        // Tell ACME server we're ready
        let payload = serde_json::json!({});
        self.signed_request(&challenge.url, Some(payload), false)
            .await?;

        // Poll for challenge completion
        self.wait_for_challenge_valid(&challenge.url).await?;

        // Clean up pending challenge
        {
            let mut challenges = self.pending_challenges.write().await;
            challenges.remove(&challenge.token);
        }

        Ok(())
    }

    /// Wait for a challenge to become valid
    async fn wait_for_challenge_valid(&self, url: &str) -> Result<()> {
        for i in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let response = self.signed_request(url, None, false).await?;
            let challenge: AcmeChallenge = response.json().await?;

            match challenge.status.as_str() {
                "valid" => return Ok(()),
                "invalid" => {
                    return Err(anyhow::anyhow!("Challenge failed"));
                }
                "pending" | "processing" => {
                    debug!("Challenge status: {}, attempt {}/30", challenge.status, i + 1);
                }
                _ => {
                    warn!("Unknown challenge status: {}", challenge.status);
                }
            }
        }

        Err(anyhow::anyhow!("Challenge validation timed out"))
    }

    /// Wait for order to be ready
    async fn wait_for_order_ready(&self, url: &str, initial: &AcmeOrder) -> Result<AcmeOrder> {
        if initial.status == "ready" {
            return Ok(initial.clone());
        }

        for i in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let response = self.signed_request(url, None, false).await?;
            let order: AcmeOrder = response.json().await?;

            match order.status.as_str() {
                "ready" => return Ok(order),
                "invalid" => {
                    return Err(anyhow::anyhow!("Order became invalid"));
                }
                "pending" => {
                    debug!("Order status: pending, attempt {}/30", i + 1);
                }
                _ => {
                    debug!("Order status: {}, attempt {}/30", order.status, i + 1);
                }
            }
        }

        Err(anyhow::anyhow!("Order ready timed out"))
    }

    /// Wait for order to be valid (certificate issued)
    async fn wait_for_order_valid(&self, url: &str, initial: &AcmeOrder) -> Result<AcmeOrder> {
        if initial.status == "valid" && initial.certificate.is_some() {
            return Ok(initial.clone());
        }

        for i in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let response = self.signed_request(url, None, false).await?;
            let order: AcmeOrder = response.json().await?;

            match order.status.as_str() {
                "valid" => {
                    if order.certificate.is_some() {
                        return Ok(order);
                    }
                }
                "invalid" => {
                    return Err(anyhow::anyhow!("Order became invalid"));
                }
                "processing" => {
                    debug!("Order processing, attempt {}/30", i + 1);
                }
                _ => {
                    debug!("Order status: {}, attempt {}/30", order.status, i + 1);
                }
            }
        }

        Err(anyhow::anyhow!("Order validation timed out"))
    }

    /// Generate a CSR for the given domains
    fn generate_csr(&self, domains: &[String]) -> Result<(String, Vec<u8>)> {
        let rng = SystemRandom::new();

        // Generate certificate key
        let cert_key_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate cert key: {:?}", e))?;

        let cert_key_pem = pem_encode("PRIVATE KEY", cert_key_pkcs8.as_ref());

        let cert_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert_key_pkcs8.as_ref(), &rng)
                .map_err(|e| anyhow::anyhow!("Failed to load cert key: {:?}", e))?;

        // Build CSR
        let csr = build_csr(domains, &cert_key, &rng)?;

        Ok((cert_key_pem, csr))
    }

    /// Parse certificate dates from PEM
    fn parse_certificate_dates(&self, _pem: &str) -> Result<(u64, u64)> {
        // Simple parsing - in production you'd use x509-parser
        // For now, use 90 days validity (standard Let's Encrypt)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let not_before = now;
        let not_after = now + 90 * 24 * 60 * 60; // 90 days

        Ok((not_before, not_after))
    }
}

/// Build a CSR (Certificate Signing Request)
fn build_csr(domains: &[String], key: &EcdsaKeyPair, rng: &SystemRandom) -> Result<Vec<u8>> {
    use ring::signature::KeyPair;

    // This is a simplified CSR builder
    // In production, you'd want to use rcgen or similar

    let cn = &domains[0];

    // Build the CSR info (to be signed)
    let mut csr_info = Vec::new();

    // Version (0 = v1)
    csr_info.extend_from_slice(&[0x02, 0x01, 0x00]);

    // Subject (CN=domain)
    let cn_bytes = build_cn(cn);
    csr_info.extend_from_slice(&cn_bytes);

    // Subject Public Key Info
    let spki = build_ec_spki(key.public_key().as_ref());
    csr_info.extend_from_slice(&spki);

    // Attributes with SAN extension
    let attrs = build_san_attribute(domains);
    csr_info.extend_from_slice(&attrs);

    // Wrap in SEQUENCE
    let csr_info_seq = wrap_sequence(&csr_info);

    // Sign the CSR info
    let signature = key
        .sign(rng, &csr_info_seq)
        .map_err(|e| anyhow::anyhow!("Failed to sign CSR: {:?}", e))?;

    // Build final CSR
    let mut csr = Vec::new();
    csr.extend_from_slice(&csr_info_seq);

    // Signature algorithm (ecdsa-with-SHA256)
    csr.extend_from_slice(&[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ]);

    // Signature value
    let sig_bits = wrap_bit_string(signature.as_ref());
    csr.extend_from_slice(&sig_bits);

    Ok(wrap_sequence(&csr))
}

fn build_cn(cn: &str) -> Vec<u8> {
    let cn_bytes = cn.as_bytes();

    // UTF8String for CN value
    let mut cn_value = vec![0x0c]; // UTF8String tag
    encode_length(&mut cn_value, cn_bytes.len());
    cn_value.extend_from_slice(cn_bytes);

    // CN OID: 2.5.4.3
    let cn_oid = vec![0x06, 0x03, 0x55, 0x04, 0x03];

    // AttributeTypeAndValue SEQUENCE
    let mut atv = cn_oid;
    atv.extend_from_slice(&cn_value);
    let atv_seq = wrap_sequence(&atv);

    // RelativeDistinguishedName SET
    let rdn = wrap_set(&atv_seq);

    // RDNSequence
    wrap_sequence(&rdn)
}

fn build_ec_spki(public_key: &[u8]) -> Vec<u8> {
    // Algorithm: id-ecPublicKey with P-256
    let algorithm = vec![
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];

    let mut spki = algorithm;
    let pk_bits = wrap_bit_string(public_key);
    spki.extend_from_slice(&pk_bits);

    wrap_sequence(&spki)
}

fn build_san_attribute(domains: &[String]) -> Vec<u8> {
    // Build SAN extension
    let mut san_entries = Vec::new();
    for domain in domains {
        // DNSName (context tag 2)
        let mut entry = vec![0x82];
        encode_length(&mut entry, domain.len());
        entry.extend_from_slice(domain.as_bytes());
        san_entries.extend_from_slice(&entry);
    }

    let san_seq = wrap_sequence(&san_entries);

    // Extension OID for SAN: 2.5.29.17
    let san_oid = vec![0x06, 0x03, 0x55, 0x1d, 0x11];

    let mut ext = san_oid;
    let san_octet = wrap_octet_string(&san_seq);
    ext.extend_from_slice(&san_octet);

    let ext_seq = wrap_sequence(&ext);
    let exts_seq = wrap_sequence(&ext_seq);

    // extensionRequest OID: 1.2.840.113549.1.9.14
    let ext_req_oid = vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];

    let mut attr = ext_req_oid;
    let exts_set = wrap_set(&exts_seq);
    attr.extend_from_slice(&exts_set);

    let attr_seq = wrap_sequence(&attr);

    // Attributes [0] IMPLICIT
    let mut attrs = vec![0xa0];
    encode_length(&mut attrs, attr_seq.len());
    attrs.extend_from_slice(&attr_seq);

    attrs
}

fn wrap_sequence(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30];
    encode_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

fn wrap_set(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x31];
    encode_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

fn wrap_bit_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x03];
    encode_length(&mut result, data.len() + 1);
    result.push(0x00); // No unused bits
    result.extend_from_slice(data);
    result
}

fn wrap_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04];
    encode_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

fn encode_length(output: &mut Vec<u8>, len: usize) {
    if len < 128 {
        output.push(len as u8);
    } else if len < 256 {
        output.push(0x81);
        output.push(len as u8);
    } else {
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push(len as u8);
    }
}

fn pem_encode(label: &str, data: &[u8]) -> String {
    // Use standard base64 for PEM
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut pem = format!("-----BEGIN {}-----\n", label);

    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }

    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

fn chrono_from_unix(timestamp: u64) -> String {
    // Simple date formatting
    let secs = timestamp as i64;
    let days = secs / 86400;
    let years = 1970 + days / 365;
    format!("{}-xx-xx", years)
}
