//! ADB AUTH protocol — RSA key management and signing.
//!
//! This module is a re-export shim for backward compatibility.
//! The actual implementation lives under [`crate::crypto`]:
//!
//! - `crypto::key` — RSA key generation, signing, verification, PEM I/O,
//!   the AOSP key lifecycle (`load_userkey`/`load_all_keys`/`AuthResponder`),
//!   and `AdbAuth`
//! - `crypto::rsa_2048_key` — Android binary RSAPublicKey encode/decode
//!
//! All items that were previously exported directly from this module
//! remain accessible via `use crate::auth::*` or the re-exports below.

pub use crate::crypto::key::{
    adb_get_android_dir_path, adb_get_homedir_path, adb_auth_get_userkey_path,
    default_key_label, generate_key, get_vendor_keys, load_all_keys, load_userkey,
    load_vendor_keys_only, AuthResponder, AdbAuth, AuthError, ANDROID_PUBKEY_ENCODED_SIZE,
    ANDROID_PUBKEY_MODULUS_SIZE, ANDROID_PUBKEY_MODULUS_SIZE_WORDS,
};
pub use crate::crypto::key::{
    generate_rsa_key, load_private_key_from_pem, export_private_key_to_pem, sign_token,
    verify_token_signature,
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
        let token = b"auth_responder_token"; // 20 bytes (adbd tokens are SHA-1 sized)

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
