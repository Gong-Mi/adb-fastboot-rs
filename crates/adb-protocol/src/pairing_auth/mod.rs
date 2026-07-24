//! AOSP pairing authentication primitives, mirroring `vendor/adb/pairing_auth/`.
pub mod aes_128_gcm;
pub mod pairing_auth;

// Re-exports for convenience
pub use aes_128_gcm::PairingCipher;
pub use pairing_auth::{Spake2, SpakeRole};
