//! ACME protocol implementation for automatic certificate issuance and renewal.

mod challenge;
mod client;
mod manager;
mod storage;

/// HTTP-01 challenge handler and standalone request matcher.
pub use challenge::{try_handle_challenge, ChallengeHandler};
/// ACME protocol client for account management and certificate ordering.
pub use client::{AcmeClient, PendingChallenge};
/// Certificate lifecycle manager with automatic renewal.
pub use manager::{AcmeManager, AcmeManagerBuilder};
/// Persistent storage for ACME accounts and certificates.
pub use storage::{AcmeAccount, AcmeStorage, StorageManager, StoredCertificate};
