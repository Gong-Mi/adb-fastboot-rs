use byteorder::{ByteOrder, LittleEndian};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use thiserror::Error;

use crate::constants::*;
use crate::header::AdbMessageHeader;

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

/// Size of Android RSA public key structure in binary format (524 bytes)
pub const ANDROID_PUBKEY_ENCODED_SIZE: usize = 524;
pub const ANDROID_PUBKEY_MODULUS_SIZE: usize = 256;
pub const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: u32 = 64;

/// Generates a new 2048-bit RSA private key
pub fn generate_rsa_key() -> Result<RsaPrivateKey, AuthError> {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    Ok(private_key)
}

/// AOSP `adb_get_homedir_path()`: `$HOME` (adb_utils.cpp:275-290).
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

/// AOSP `generate_key()` (client/auth.cpp:61-107): write a fresh 2048-bit
/// private key (PKCS#8 PEM) plus its `.pub` ADB public key string.
/// Private key is written with 0600 permissions (umask 077 in AOSP).
pub fn generate_key(file: &std::path::Path) -> Result<(), AuthError> {
    let private_key = generate_rsa_key()?;
    let pem = export_private_key_to_pem(&private_key)?;
    let pubkey = encode_adb_public_key_string(
        &RsaPublicKey::from(&private_key),
        &default_key_label(),
    )?;

    use std::io::Write;
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_0600()
        .open(file)?;
    f.write_all(pem.as_bytes())?;
    f.write_all(b"\n")?;
    std::fs::write(
        format!("{}.pub", file.display()),
        format!("{}\n", String::from_utf8_lossy(&pubkey)),
    )?;
    Ok(())
}

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

/// Default ADB public key label ("user@hostname" analog).
pub fn default_key_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    format!("{user}@{host}")
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

/// Encode an RSA public key into Android binary RSAPublicKey format (524 bytes)
pub fn encode_android_pubkey_binary(public_key: &RsaPublicKey) -> Result<Vec<u8>, AuthError> {
    let n = public_key.n();
    let e = public_key.e();

    let n_bytes = n.to_bytes_le();
    if n_bytes.len() > ANDROID_PUBKEY_MODULUS_SIZE {
        return Err(AuthError::InvalidPublicKeyFormat(
            "Modulus size exceeds 2048 bits".to_string(),
        ));
    }

    let mut modulus = [0u8; ANDROID_PUBKEY_MODULUS_SIZE];
    modulus[..n_bytes.len()].copy_from_slice(&n_bytes);

    // Compute n0inv = -1 / N[0] mod 2^32
    let n0 = LittleEndian::read_u32(&modulus[0..4]);
    if n0 % 2 == 0 {
        return Err(AuthError::InvalidPublicKeyFormat(
            "Modulus must be odd".to_string(),
        ));
    }

    // Newton-Raphson iteration for modular inverse mod 2^32
    let mut inv = 1u32;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    let n0inv = 0u32.wrapping_sub(inv);

    // Compute rr = (2^2048)^2 mod N
    let r = BigUint::from(1u32) << (ANDROID_PUBKEY_MODULUS_SIZE * 8);
    let r_sqr = &r * &r;
    let rr_biguint = r_sqr % n;
    let rr_bytes = rr_biguint.to_bytes_le();
    let mut rr = [0u8; ANDROID_PUBKEY_MODULUS_SIZE];
    rr[..rr_bytes.len()].copy_from_slice(&rr_bytes);

    let mut e_buf = [0u8; 4];
    let e_bytes = e.to_bytes_le();
    let copy_len = e_bytes.len().min(4);
    e_buf[..copy_len].copy_from_slice(&e_bytes[..copy_len]);
    let exponent = LittleEndian::read_u32(&e_buf);

    let mut buf = vec![0u8; ANDROID_PUBKEY_ENCODED_SIZE];
    LittleEndian::write_u32(&mut buf[0..4], ANDROID_PUBKEY_MODULUS_SIZE_WORDS);
    LittleEndian::write_u32(&mut buf[4..8], n0inv);
    buf[8..264].copy_from_slice(&modulus);
    buf[264..520].copy_from_slice(&rr);
    LittleEndian::write_u32(&mut buf[520..524], exponent);

    Ok(buf)
}

/// Decode Android binary RSAPublicKey format (524 bytes) into RsaPublicKey
pub fn decode_android_pubkey_binary(buf: &[u8]) -> Result<RsaPublicKey, AuthError> {
    if buf.len() < ANDROID_PUBKEY_ENCODED_SIZE {
        return Err(AuthError::InvalidPublicKeyFormat(format!(
            "Buffer too short for RSAPublicKey: expected {}, got {}",
            ANDROID_PUBKEY_ENCODED_SIZE,
            buf.len()
        )));
    }

    let modulus_size_words = LittleEndian::read_u32(&buf[0..4]);
    if modulus_size_words != ANDROID_PUBKEY_MODULUS_SIZE_WORDS {
        return Err(AuthError::InvalidPublicKeyFormat(format!(
            "Unsupported modulus size words: {}",
            modulus_size_words
        )));
    }

    let modulus_bytes = &buf[8..264];
    let exponent = LittleEndian::read_u32(&buf[520..524]);

    let n = BigUint::from_bytes_le(modulus_bytes);
    let e = BigUint::from(exponent);

    let pubkey = RsaPublicKey::new(n, e)?;
    Ok(pubkey)
}

/// Encode RsaPublicKey to ADB public key formatted string: "base64_key user@hostname\0"
pub fn encode_adb_public_key_string(public_key: &RsaPublicKey, label: &str) -> Result<Vec<u8>, AuthError> {
    use base64::Engine;
    let binary = encode_android_pubkey_binary(public_key)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&binary);

    let label_trimmed = label.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    let result = format!("{} {}\0", b64, label_trimmed).into_bytes();
    Ok(result)
}

/// Parse ADB public key formatted string ("base64_key user@hostname\0" or "base64_key user@hostname")
pub fn parse_adb_public_key_string(key_str: &str) -> Result<(RsaPublicKey, String), AuthError> {
    use base64::Engine;
    let clean_str = key_str.trim_matches(|c| c == '\0' || c == '\r' || c == '\n');
    let parts: Vec<&str> = clean_str.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.is_empty() {
        return Err(AuthError::InvalidPublicKeyFormat("Empty key string".to_string()));
    }

    let b64_part = parts[0];
    let label = if parts.len() > 1 { parts[1].trim().to_string() } else { String::new() };

    let binary = base64::engine::general_purpose::STANDARD.decode(b64_part)?;
    let pubkey = decode_android_pubkey_binary(&binary)?;

    Ok((pubkey, label))
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
        .map_err(|e| AuthError::InvalidPublicKeyFormat(format!("Failed to encode RSA private key PEM: {}", e)))
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

    /// AOSP `adb_auth_init()` semantics: load the persistent user key
    /// (`$HOME/.android/adbkey`, generated on first use).
    pub fn load_persistent() -> Result<Self, AuthError> {
        load_userkey()
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
        encode_adb_public_key_string(&self.public_key, &self.label)
    }

    /// Create A_AUTH (SIGNATURE) message (header + payload)
    pub fn make_signature_message(&self, token: &[u8]) -> Result<(AdbMessageHeader, Vec<u8>), AuthError> {
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
    /// Build from the full AOSP key list (`adb_auth_init()` order:
    /// user key first, then ADB_VENDOR_KEYS).
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
    /// - `Ok(None)` after the public key has been sent (AOSP keeps waiting for
    ///   the framework decision; further TOKENs restart the key rotation).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::AuthType;

    /// HOME is process-global; tests that redirect it must serialize.
    static HOME_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_rsa_key_generation_and_sign_verify() {
        let auth = AdbAuth::generate("testuser@testhost").unwrap();
        let token = b"12345678901234567890"; // 20-byte token

        let signature = auth.build_signature_payload(token).unwrap();
        assert_eq!(signature.len(), 256); // 2048-bit RSA = 256 bytes

        let valid = verify_token_signature(auth.public_key(), token, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_android_pubkey_encode_decode_roundtrip() {
        let auth = AdbAuth::generate("user@hostname").unwrap();
        let binary = encode_android_pubkey_binary(auth.public_key()).unwrap();
        assert_eq!(binary.len(), ANDROID_PUBKEY_ENCODED_SIZE);

        let decoded_key = decode_android_pubkey_binary(&binary).unwrap();
        assert_eq!(decoded_key, *auth.public_key());
    }

    #[test]
    fn test_adb_public_key_string_format_and_parse() {
        let auth = AdbAuth::generate("alice@myhost").unwrap();
        let formatted_bytes = auth.build_rsakey_payload().unwrap();

        // Ensure ends with '\0'
        assert_eq!(*formatted_bytes.last().unwrap(), 0);

        let key_str = String::from_utf8(formatted_bytes).unwrap();
        assert!(key_str.contains("alice@myhost"));

        let (parsed_key, parsed_label) = parse_adb_public_key_string(&key_str).unwrap();
        assert_eq!(parsed_key, *auth.public_key());
        assert_eq!(parsed_label, "alice@myhost");
    }

    #[test]
    fn test_encode_adb_public_key_string_label_sanitization() {
        let auth = AdbAuth::generate("placeholder").unwrap();
        let dirty_label = " \t  bob@host.local \r\n\0  ";
        let formatted_bytes = encode_adb_public_key_string(auth.public_key(), dirty_label).unwrap();

        assert_eq!(*formatted_bytes.last().unwrap(), 0);
        let key_str = String::from_utf8(formatted_bytes).unwrap();
        assert!(key_str.ends_with(" bob@host.local\0"));

        let (parsed_key, parsed_label) = parse_adb_public_key_string(&key_str).unwrap();
        assert_eq!(parsed_key, *auth.public_key());
        assert_eq!(parsed_label, "bob@host.local");
    }

    #[test]
    fn test_pem_file_trailing_newline_roundtrip() {
        use std::io::Write;
        let k = generate_rsa_key().unwrap();
        let pem = export_private_key_to_pem(&k).unwrap();
        let path = std::env::temp_dir().join(format!("pem-probe-{}.pem", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(pem.as_bytes()).unwrap();
            // AOSP-written PEM files end with a newline.
            f.write_all(b"\n").unwrap();
        }
        let read_back = std::fs::read_to_string(&path).unwrap();
        let re = load_private_key_from_pem(&read_back)
            .expect("PEM with trailing newline must parse (AOSP PEM_read tolerates it)");
        assert_eq!(re, k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_pem_export_import_roundtrip() {
        let auth = AdbAuth::generate("testuser@testhost").unwrap();
        let pem = export_private_key_to_pem(auth.private_key()).unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let loaded = load_private_key_from_pem(&pem).unwrap();
        assert_eq!(loaded, *auth.private_key());
    }

    #[test]
    fn test_make_auth_messages() {
        let auth = AdbAuth::generate("user@host").unwrap();
        let token = b"sample_token_20_bytes";

        let (sig_hdr, sig_payload) = auth.make_signature_message(token).unwrap();
        assert_eq!(sig_hdr.command, A_AUTH);
        assert_eq!(sig_hdr.arg0, A_AUTH_SIGNATURE);
        assert_eq!(sig_hdr.data_length as usize, sig_payload.len());
        assert_eq!(sig_hdr.auth_type(), Some(AuthType::Signature));

        let (key_hdr, key_payload) = auth.make_rsakey_message().unwrap();
        assert_eq!(key_hdr.command, A_AUTH);
        assert_eq!(key_hdr.arg0, A_AUTH_RSAKEY);
        assert_eq!(key_hdr.data_length as usize, key_payload.len());
        assert_eq!(key_hdr.auth_type(), Some(AuthType::RsaKey));
        assert_eq!(*key_payload.last().unwrap(), 0); // Null byte suffix
    }

    #[test]
    fn test_persistent_key_generate_load_roundtrip() {
        let _guard = HOME_MUTEX.lock().unwrap();
        let home = std::env::temp_dir().join(format!("adb-rs-test-{}", std::process::id()));
        let prev_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let android_dir = adb_get_android_dir_path().unwrap();
        assert!(android_dir.ends_with(".android"));

        // First load generates the key (AOSP load_userkey semantics).
        let first = load_userkey().unwrap();
        let key_path = home.join(".android").join("adbkey");
        assert!(key_path.exists());
        assert!(key_path.with_extension("pub").exists());

        // Second load returns the SAME key (persistence).
        let second = load_userkey().unwrap();
        let token = b"01234567890123456789";
        let sig_a = first.build_signature_payload(token).unwrap();
        let sig_b = second.build_signature_payload(token).unwrap();
        assert_eq!(sig_a, sig_b, "persisted key must be reused across loads");

        // Private key file must not be world-readable (AOSP umask 077).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "adbkey must be 0600, got {mode:o}");
        }

        // Restore HOME so other tests are unaffected.
        if let Some(p) = prev_home {
            std::env::set_var("HOME", p);
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_vendor_keys_split_and_load_order() {
        let _guard = HOME_MUTEX.lock().unwrap();
        let home = std::env::temp_dir().join(format!("adb-rs-vk-{}", std::process::id()));
        let prev_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let k1 = AdbAuth::generate("vendor1@host").unwrap();
        let k2 = AdbAuth::generate("vendor2@host").unwrap();
        let dir = home.join("vendor-keys");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("k1.pem"),
            export_private_key_to_pem(k1.private_key()).unwrap(),
        )
        .unwrap();
        let single = home.join("k2.pem");
        std::fs::write(
            &single,
            export_private_key_to_pem(k2.private_key()).unwrap(),
        )
        .unwrap();

        std::env::set_var("ADB_VENDOR_KEYS", format!("{}::{}", dir.display(), single.display()));

        let keys = load_all_keys().unwrap();
        assert_eq!(keys.len(), 3, "user key + dir entry + file entry");
        // Order: user key first (AOSP adb_auth_init), then vendor keys.
        assert_eq!(keys[0].label(), default_key_label());

        // Every vendor key must verify the same token against its own pubkey.
        let token = b"vendor_keys_token20b";
        for k in &keys[1..] {
            let sig = k.build_signature_payload(token).unwrap();
            assert!(sign_token(k.private_key(), token).is_ok());
        }

        // get_vendor_keys drops empty entries (':' split check).
        std::env::set_var("ADB_VENDOR_KEYS", ":/a/path:");
        let parsed = get_vendor_keys();
        assert_eq!(parsed.len(), 1);

        if let Some(p) = prev_home {
            std::env::set_var("HOME", p);
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_auth_responder_rotation_and_pubkey_fallback() {
        let k1 = AdbAuth::generate("k1@host").unwrap();
        let k2 = AdbAuth::generate("k2@host").unwrap();
        let token = b"auth_responder_token!";

        let mut responder = AuthResponder::from_key_list(vec![k1.clone(), k2.clone()]);
        assert_eq!(responder.key_count(), 2);

        // 1st TOKEN → SIGNATURE from k1
        let (hdr1, p1) = responder.respond_to_token(token).unwrap().unwrap();
        assert_eq!(hdr1.arg0, A_AUTH_SIGNATURE);
        assert!(verify_token_signature(k1.public_key(), token, &p1).unwrap());

        // 2nd TOKEN → SIGNATURE from k2
        let (hdr2, p2) = responder.respond_to_token(token).unwrap().unwrap();
        assert_eq!(hdr2.arg0, A_AUTH_SIGNATURE);
        assert!(verify_token_signature(k2.public_key(), token, &p2).unwrap());

        // 3rd TOKEN → keys exhausted → RSAPUBLICKEY (k1's, AOSP user key)
        let (hdr3, p3) = responder.respond_to_token(token).unwrap().unwrap();
        assert_eq!(hdr3.arg0, A_AUTH_RSAKEY);
        assert!(responder.pubkey_sent());
        let expected_pub = String::from_utf8(k1.make_rsakey_message().unwrap().1).unwrap();
        assert_eq!(p3, expected_pub.into_bytes());

        // Further TOKENs restart the rotation (AOSP stays unauthorized but
        // keeps answering).
        let (hdr4, _) = responder.respond_to_token(token).unwrap().unwrap();
        assert_eq!(hdr4.arg0, A_AUTH_SIGNATURE);
        assert!(!responder.pubkey_sent());
    }
}
