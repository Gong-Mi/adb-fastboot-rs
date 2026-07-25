//! AOSP pairing authentication primitives, mirroring `vendor/adb/pairing_auth/`.
pub mod aes_128_gcm;
pub mod pairing_auth;

// Re-exports for convenience
pub use aes_128_gcm::PairingCipher;
pub use pairing_auth::{Spake2, SpakeRole};

#[cfg(test)]
mod tests {
    use super::pairing_auth::{ExtendedPoint, Fe};

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
