//! RSA key operations mirroring AOSP `vendor/adb/crypto/key.cpp`.
//!
//! Provides RSA 2048-bit key generation, signing, verification, PEM I/O,
//! and the `AdbAuth` convenience wrapper.

use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{hazmat::{PrehashSigner, PrehashVerifier}, SignatureEncoding};
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

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

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

/// Sign ADB's 20-byte token as the already-computed SHA-1 digest expected by
/// AOSP's RSA_sign(NID_sha1, token, 20, ...). The token is random data; it
/// must be encoded directly in DigestInfo, not hashed again.
pub fn sign_token(private_key: &RsaPrivateKey, token: &[u8]) -> Result<Vec<u8>, AuthError> {
    if token.len() != 20 {
        return Err(AuthError::InvalidTokenLength { expected: 20, got: token.len() });
    }
    let signer = SigningKey::<Sha1>::new(private_key.clone());
    let signature = signer.sign_prehash(token)
        .map_err(|e| AuthError::InvalidPublicKeyFormat(format!("RSA prehash signing failed: {e}")))?;
    Ok(signature.to_vec())
}

/// Verify an ADB token signature using the same prehash convention as adbd's
/// RSA_verify(NID_sha1, token, 20, ...).
pub fn verify_token_signature(
    public_key: &RsaPublicKey,
    token: &[u8],
    signature: &[u8],
) -> Result<bool, AuthError> {
    if token.len() != 20 {
        return Err(AuthError::InvalidTokenLength { expected: 20, got: token.len() });
    }
    let verifying_key = VerifyingKey::<Sha1>::new(public_key.clone());
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| AuthError::InvalidPublicKeyFormat("Invalid signature length".to_string()))?;
    Ok(verifying_key.verify_prehash(token, &sig).is_ok())
}

/// Load RsaPrivateKey from PEM encoded string
pub fn load_private_key_from_pem(pem_str: &str) -> Result<RsaPrivateKey, AuthError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    // Tolerate trailing whitespace/newlines: files written with a final
    // newline (and AOSP-written keys) must parse. AOSP `PEM_read_RSAPrivateKey`
    // ignores trailing data after the last PEM block.
    let trimmed = pem_str.trim_matches(|c: char| c.is_whitespace());

    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
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

    /// AOSP `adb_auth_init()` semantics: load the persistent user key
    /// (`$HOME/.android/adbkey`, generated on first use).
    pub fn load_persistent() -> Result<Self, AuthError> {
        load_userkey()
    }
}

// ---------------------------------------------------------------------------
// AOSP client/auth.cpp key lifecycle (merged from the Sep line)
// ---------------------------------------------------------------------------

/// Unix-only helper: create a file with 0600 from the start (AOSP uses
/// umask 077 around the private key write).
trait OpenOptionsMode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl OpenOptionsMode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
}

#[cfg(not(unix))]
impl OpenOptionsMode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        self
    }
}

/// AOSP `adb_get_homedir_path()` (adb_utils.cpp:275-290): `$HOME`.
pub fn adb_get_homedir_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// AOSP `adb_get_android_dir_path()` (adb_utils.cpp:310-320): `$HOME/.android`,
/// created (0750) if missing.
pub fn adb_get_android_dir_path() -> Result<std::path::PathBuf, AuthError> {
    let home = adb_get_homedir_path().ok_or_else(|| {
        AuthError::InvalidPublicKeyFormat("HOME not set; cannot locate .android dir".to_string())
    })?;
    let dir = home.join(".android");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// AOSP `adb_auth_get_userkey_path()` (client/auth.cpp:204-207):
/// `<android_dir>/adbkey`.
pub fn adb_auth_get_userkey_path() -> Result<std::path::PathBuf, AuthError> {
    Ok(adb_get_android_dir_path()?.join("adbkey"))
}

/// Default ADB public key label ("user@hostname" analog).
pub fn default_key_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    format!("{user}@{host}")
}

/// AOSP `generate_key()` (client/auth.cpp:61-107): write a fresh 2048-bit
/// private key (PKCS#8 PEM) plus its `.pub` ADB public key string.
/// Private key is written with 0600 permissions (umask 077 in AOSP).
pub fn generate_key(file: &std::path::Path) -> Result<(), AuthError> {
    let private_key = generate_rsa_key()?;
    let pem = export_private_key_to_pem(&private_key)?;
    let pubkey = crate::crypto::rsa_2048_key::encode_adb_public_key_string(
        &RsaPublicKey::from(&private_key),
        &default_key_label(),
    )?;

    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode_0600()
        .open(file)?;
    f.write_all(pem.as_bytes())?;
    let mut pub_path = file.to_path_buf();
    pub_path.set_extension("pub");
    let mut pf = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(pub_path)?;
    pf.write_all(&pubkey)?;
    Ok(())
}

/// AOSP `load_userkey()` (client/auth.cpp:209-226): load `$HOME/.android/adbkey`,
/// generating it on first use when absent.
pub fn load_userkey() -> Result<AdbAuth, AuthError> {
    let path = adb_auth_get_userkey_path()?;
    if !path.exists() {
        generate_key(&path)?;
    }
    let pem = std::fs::read_to_string(&path)?;
    let private_key = load_private_key_from_pem(&pem)?;
    Ok(AdbAuth::new(private_key, &default_key_label()))
}

/// AOSP `get_vendor_keys()` (client/auth.cpp:228-244): split `ADB_VENDOR_KEYS`
/// on the path separator, dropping empty entries.
pub fn get_vendor_keys() -> Vec<std::path::PathBuf> {
    let raw = match std::env::var("ADB_VENDOR_KEYS") {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    raw.split(':')
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

/// AOSP `adb_auth_init()` key loading (client/auth.cpp:422-434): the user key
/// first, then each `ADB_VENDOR_KEYS` entry (file or directory of PEM keys).
/// Returns every successfully loaded key in AOSP order (user key first).
pub fn load_all_keys() -> Result<Vec<AdbAuth>, AuthError> {
    let mut keys = vec![load_userkey()?];
    keys.extend(load_vendor_keys_only());
    Ok(keys)
}

/// Load only the ADB_VENDOR_KEYS entries (no user key, no side effects).
pub fn load_vendor_keys_only() -> Vec<AdbAuth> {
    let mut keys = Vec::new();
    for path in get_vendor_keys() {
        if path.is_dir() {
            let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(&path) {
                Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
                Err(_) => continue,
            };
            entries.sort();
            for entry in entries {
                if let Ok(pem) = std::fs::read_to_string(&entry) {
                    if let Ok(k) = load_private_key_from_pem(&pem) {
                        keys.push(AdbAuth::new(k, &default_key_label()));
                    }
                }
            }
        } else if let Ok(pem) = std::fs::read_to_string(&path) {
            if let Ok(k) = load_private_key_from_pem(&pem) {
                keys.push(AdbAuth::new(k, &default_key_label()));
            }
        }
    }
    keys
}

/// AOSP client-side AUTH response state (client/auth.cpp `send_auth_response`
/// + `atransport::NextKey`): answer each A_AUTH TOKEN with a SIGNATURE from
/// the next available private key; when all keys are exhausted, send the
/// user key's RSAPUBLICKEY once (kCsUnauthorized → framework confirmation).
pub struct AuthResponder {
    keys: Vec<AdbAuth>,
    next_key: usize,
    pubkey_sent: bool,
}

impl AuthResponder {
    /// Build from the full AOSP key list (`adb_auth_init()` order: user key
    /// first, then ADB_VENDOR_KEYS).
    pub fn from_key_list(keys: Vec<AdbAuth>) -> Self {
        Self {
            keys,
            next_key: 0,
            pubkey_sent: false,
        }
    }

    /// Build from a single key (test/helper convenience).
    pub fn single(key: AdbAuth) -> Self {
        Self::from_key_list(vec![key])
    }

    /// AOSP `send_auth_response`: given an A_AUTH TOKEN payload, produce the
    /// next response. Returns:
    /// - `Ok(Some((SIGNATURE header, payload)))` while keys remain;
    /// - `Ok(Some((RSAKEY header, payload)))` once, when keys are exhausted;
    /// - `Ok(None)` after the public key has been sent (AOSP stays in
    ///   kCsUnauthorized; further TOKENs restart the key rotation).
    pub fn respond_to_token(
        &mut self,
        token: &[u8],
    ) -> Result<Option<(AdbMessageHeader, Vec<u8>)>, AuthError> {
        if self.next_key < self.keys.len() {
            let key = &self.keys[self.next_key];
            self.next_key += 1;
            return key.make_signature_message(token).map(Some);
        }
        if !self.pubkey_sent {
            self.pubkey_sent = true;
            return self.keys[0].make_rsakey_message().map(Some);
        }
        // All keys tried and public key already sent: restart rotation
        // (matches AOSP staying in kCsUnauthorized until adbd re-tokens).
        self.next_key = 0;
        self.pubkey_sent = false;
        let key = &self.keys[self.next_key];
        self.next_key = 1;
        key.make_signature_message(token).map(Some)
    }

    /// Number of private keys available for SIGNATURE responses.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Whether the RSAPUBLICKEY fallback has been emitted.
    pub fn pubkey_sent(&self) -> bool {
        self.pubkey_sent
    }
}
