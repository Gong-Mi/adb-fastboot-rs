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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::AuthType;

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
}
