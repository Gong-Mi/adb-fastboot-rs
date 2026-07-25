//! ADB crypto operations, mirroring AOSP `vendor/adb/crypto/`.
pub mod key;
pub mod rsa_2048_key;
#[cfg(feature = "tls")]
pub mod x509_generator;

// Re-exports for convenience
pub use key::{
    generate_rsa_key, load_private_key_from_pem, export_private_key_to_pem, sign_token,
    verify_token_signature, AdbAuth, AuthError, ANDROID_PUBKEY_ENCODED_SIZE,
    ANDROID_PUBKEY_MODULUS_SIZE, ANDROID_PUBKEY_MODULUS_SIZE_WORDS,
};
pub use rsa_2048_key::{
    decode_android_pubkey_binary, encode_adb_public_key_string, encode_android_pubkey_binary,
    parse_adb_public_key_string,
};
#[cfg(feature = "tls")]
pub use x509_generator::{generate_self_signed_cert, CertError};
