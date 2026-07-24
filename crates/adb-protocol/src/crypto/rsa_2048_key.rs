//! RSA 2048-bit key encoding/decoding in AOSP binary format,
//! mirroring `vendor/adb/crypto/rsa_2048_key.cpp`.

use byteorder::{ByteOrder, LittleEndian};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

use crate::crypto::key::{AuthError, ANDROID_PUBKEY_ENCODED_SIZE, ANDROID_PUBKEY_MODULUS_SIZE, ANDROID_PUBKEY_MODULUS_SIZE_WORDS};

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
pub fn encode_adb_public_key_string(
    public_key: &RsaPublicKey,
    label: &str,
) -> Result<Vec<u8>, AuthError> {
    use base64::Engine;
    let binary = encode_android_pubkey_binary(public_key)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&binary);

    let label_trimmed = label.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    let result = format!("{} {}\0", b64, label_trimmed).into_bytes();
    Ok(result)
}

/// Parse ADB public key string ("base64_key user@hostname\0" or "base64_key user@hostname")
pub fn parse_adb_public_key_string(
    key_str: &str,
) -> Result<(RsaPublicKey, String), AuthError> {
    use base64::Engine;
    let clean_str = key_str.trim_matches(|c| c == '\0' || c == '\r' || c == '\n');
    let parts: Vec<&str> = clean_str.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.is_empty() {
        return Err(AuthError::InvalidPublicKeyFormat("Empty key string".to_string()));
    }

    let b64_part = parts[0];
    let label = if parts.len() > 1 {
        parts[1].trim().to_string()
    } else {
        String::new()
    };

    let binary = base64::engine::general_purpose::STANDARD.decode(b64_part)?;
    let pubkey = decode_android_pubkey_binary(&binary)?;

    Ok((pubkey, label))
}
