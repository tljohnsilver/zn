//! Secret Vault Abstraction
//!
//! Provides a unified interface for key management, supporting:
//! - Local (In-Memory/Config-based)
//! - HSM (via PKCS#11 - Placeholder)
//! - Cloud KMS (AWS KMS)

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms as kms;

#[async_trait]
pub trait SecretVault: Send + Sync {
    /// Get a symmetric key for encryption (e.g. for audit logs)
    async fn get_encryption_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Sign data using an asymmetric key (e.g. for policy signatures)
    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
}

/// Local vault that uses configuration-provided keys
pub struct LocalVault {
    encryption_key: Option<Vec<u8>>,
}

impl LocalVault {
    pub fn new(encryption_key: Option<String>) -> Self {
        let key = encryption_key.and_then(|k| hex::decode(k).ok());
        Self {
            encryption_key: key,
        }
    }
}

#[async_trait]
impl SecretVault for LocalVault {
    async fn get_encryption_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        self.encryption_key
            .clone()
            .ok_or_else(|| anyhow!("Encryption key not configured in local vault"))
    }

    async fn sign_data(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(
            "Asymmetric signing not yet implemented for local vault"
        ))
    }
}

/// AWS KMS Vault implementation
pub struct AwsKmsVault {
    client: kms::Client,
}

impl AwsKmsVault {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = kms::Client::new(&config);
        Self { client }
    }
}

#[async_trait]
impl SecretVault for AwsKmsVault {
    async fn get_encryption_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| anyhow!("AWS KMS error: {}", e))?;

        let blob = resp
            .plaintext
            .ok_or_else(|| anyhow!("KMS response missing plaintext key"))?;

        Ok(blob.into_inner())
    }

    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        use aws_sdk_kms::primitives::Blob;

        let resp = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(data))
            .signing_algorithm(kms::types::SigningAlgorithmSpec::RsassaPssSha256)
            .send()
            .await
            .map_err(|e| anyhow!("AWS KMS signing error: {}", e))?;

        let signature = resp
            .signature
            .ok_or_else(|| anyhow!("KMS response missing signature"))?;

        Ok(signature.into_inner())
    }
}
