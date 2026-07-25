//! ADB AUTH protocol — RSA key management and signing.
//!
//! This module is a re-export shim for backward compatibility.
//! The actual implementation lives under [`crate::crypto`]:
//!
//! - `crypto::key` — RSA key generation, signing, verification, PEM I/O, AdbAuth
//! - `crypto::rsa_2048_key` — Android binary RSAPublicKey encode/decode
//!
//! All items that were previously exported directly from this module
//! remain accessible via `use crate::auth::*` or the re-exports below.

pub use crate::crypto::key::{
    generate_rsa_key, load_private_key_from_pem, export_private_key_to_pem, sign_token,
    verify_token_signature, AdbAuth, AuthError, ANDROID_PUBKEY_ENCODED_SIZE,
    ANDROID_PUBKEY_MODULUS_SIZE, ANDROID_PUBKEY_MODULUS_SIZE_WORDS,
};
pub use crate::crypto::rsa_2048_key::{
    decode_android_pubkey_binary, encode_adb_public_key_string, encode_android_pubkey_binary,
    parse_adb_public_key_string,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
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
        let formatted_bytes =
            encode_adb_public_key_string(auth.public_key(), dirty_label).unwrap();

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
        let token = b"sample_token_20_byte";

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
