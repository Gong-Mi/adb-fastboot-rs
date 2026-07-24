//! RSA key operations mirroring AOSP `vendor/adb/crypto/key.cpp`.
//!
//! Provides RSA 2048-bit key generation, signing, verification, PEM I/O,
//! and the `AdbAuth` convenience wrapper.

use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use thiserror::Error;

use crate::constants::*;
use crate::header::AdbMessageHeader;

/// Size of Android RSA public key structure in binary format (524 bytes)
pub const ANDROID_PUBKEY_ENCODED_SIZE: usize = 524;
pub const ANDROID_PUBKEY_MODULUS_SIZE: usize = 256;
pub const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: u32 = 64;

/// Errors that can occur during RSA authentication operations.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("RSA crypto error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid token length: expected {expected}, got {got}")]
    InvalidTokenLength { expected: usize, got: usize },

    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),

    #[error("Not an AUTH message")]
    NotAuthMessage,

    #[error("Unsupported auth sub-type: {0}")]
    UnsupportedAuthType(u32),
}

/// Generates a new 2048-bit RSA private key
pub fn generate_rsa_key() -> Result<RsaPrivateKey, AuthError> {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    Ok(private_key)
}

/// Sign ADB token (typically 20 bytes) using RSA private key (PKCS#1 v1.5 + SHA-1)
pub fn sign_token(private_key: &RsaPrivateKey, token: &[u8]) -> Result<Vec<u8>, AuthError> {
    let signer = SigningKey::<Sha1>::new(private_key.clone());
    let signature = signer.sign(token);
    Ok(signature.to_vec())
}

/// Verify signature against ADB token using RSA public key
pub fn verify_token_signature(
    public_key: &RsaPublicKey,
    token: &[u8],
    signature: &[u8],
) -> Result<bool, AuthError> {
    let verifying_key = VerifyingKey::<Sha1>::new(public_key.clone());
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| AuthError::InvalidPublicKeyFormat("Invalid signature length".to_string()))?;
    Ok(verifying_key.verify(token, &sig).is_ok())
}

/// Load RsaPrivateKey from PEM encoded string
pub fn load_private_key_from_pem(pem_str: &str) -> Result<RsaPrivateKey, AuthError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem_str) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem_str) {
        return Ok(key);
    }
    Err(AuthError::InvalidPublicKeyFormat(
        "Failed to parse RSA private key PEM".to_string(),
    ))
}

/// Export RsaPrivateKey to PKCS#8 PEM encoded string
pub fn export_private_key_to_pem(private_key: &RsaPrivateKey) -> Result<String, AuthError> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|e| {
            AuthError::InvalidPublicKeyFormat(format!(
                "Failed to encode RSA private key PEM: {}",
                e
            ))
        })
}

/// Structure holding ADB RSA auth state/helper
#[derive(Debug, Clone)]
pub struct AdbAuth {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    label: String,
}

impl AdbAuth {
    pub fn new(private_key: RsaPrivateKey, label: &str) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            label: label.to_string(),
        }
    }

    pub fn generate(label: &str) -> Result<Self, AuthError> {
        let private_key = generate_rsa_key()?;
        Ok(Self::new(private_key, label))
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Build A_AUTH (SIGNATURE) payload for given token
    pub fn build_signature_payload(&self, token: &[u8]) -> Result<Vec<u8>, AuthError> {
        sign_token(&self.private_key, token)
    }

    /// Build A_AUTH (RSAKEY) payload with "user@hostname\0" suffix
    pub fn build_rsakey_payload(&self) -> Result<Vec<u8>, AuthError> {
        // encode_adb_public_key_string is in rsa_2048_key.rs
        crate::crypto::rsa_2048_key::encode_adb_public_key_string(&self.public_key, &self.label)
    }

    /// Create A_AUTH (SIGNATURE) message (header + payload)
    pub fn make_signature_message(
        &self,
        token: &[u8],
    ) -> Result<(AdbMessageHeader, Vec<u8>), AuthError> {
        let payload = self.build_signature_payload(token)?;
        let header = AdbMessageHeader::new_auth(A_AUTH_SIGNATURE, &payload);
        Ok((header, payload))
    }

    /// Create A_AUTH (RSAKEY) message (header + payload)
    pub fn make_rsakey_message(&self) -> Result<(AdbMessageHeader, Vec<u8>), AuthError> {
        let payload = self.build_rsakey_payload()?;
        let header = AdbMessageHeader::new_auth(A_AUTH_RSAKEY, &payload);
        Ok((header, payload))
    }
}
