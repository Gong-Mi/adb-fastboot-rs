//! AOSP pairing authentication primitives, mirroring `vendor/adb/pairing_auth/`.
//!
//! With `pairing-vendored`, the production path is the vendored BoringSSL
//! SPAKE2 + AES-128-GCM implementation (`pairing_auth_ffi`). The handwritten
//! Rust curve25519/SPAKE2 modules remain for reference and for builds where
//! the vendored C stack is unavailable; they are known-broken (see
//! AOSP_PAIRING_EVIDENCE.md P0-5) and must not back production pairing.
#[cfg(not(feature = "pairing-vendored"))]
pub mod aes_128_gcm;
#[cfg(not(feature = "pairing-vendored"))]
pub mod pairing_auth;

#[cfg(feature = "pairing-vendored")]
pub mod pairing_auth_ffi;

// Re-exports for convenience
#[cfg(not(feature = "pairing-vendored"))]
pub use aes_128_gcm::PairingCipher;
#[cfg(not(feature = "pairing-vendored"))]
pub use pairing_auth::{Spake2, SpakeRole};

#[cfg(feature = "pairing-vendored")]
pub use pairing_auth_ffi::{PairingAuth, PairingRole};

#[cfg(all(test, not(feature = "pairing-vendored")))]
mod tests {
    use super::pairing_auth::ExtendedPoint;

    #[test]
    fn test_base_point_encode_decode_roundtrip() {
        let base = ExtendedPoint::base();
        let bytes = base.encode();
        let decoded = ExtendedPoint::decode(&bytes).expect("base point decode failed");
        assert_eq!(bytes, decoded.encode());
    }

    #[test]
    fn test_point_add_encode_decode_sub_identity() {
        let p = ExtendedPoint::base();
        let m = ExtendedPoint::point_m();
        let p_plus_m = p.add(&m);
        let p_plus_m_bytes = p_plus_m.encode();
        let decoded_p_plus_m = ExtendedPoint::decode(&p_plus_m_bytes).expect("decode p_plus_m failed");
        let p_rec = decoded_p_plus_m.sub(&m);
        assert_eq!(p.encode(), p_rec.encode());
    }
}
