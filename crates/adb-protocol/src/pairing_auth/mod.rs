//! AOSP pairing authentication primitives.
//!
//! Production pairing uses the vendored AOSP `pairing_auth` C API backed by
//! the pinned vendored BoringSSL source. This preserves Android's SPAKE2
//! scalar, cofactor, and small-precomputed-point semantics exactly.

pub mod aes_128_gcm;
pub mod pairing_auth_ffi;

#[cfg(not(feature = "pairing-vendored"))]
pub mod legacy_spake2;

#[cfg(not(feature = "pairing-vendored"))]
pub use legacy_spake2::{PairingCipher, Spake2, SpakeRole};
pub use pairing_auth_ffi::{PairingAuth, PairingRole};
