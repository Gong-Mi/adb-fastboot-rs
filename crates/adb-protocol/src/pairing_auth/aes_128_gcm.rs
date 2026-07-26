//! AES-128-GCM encryption for AOSP pairing, mirroring `vendor/adb/pairing_auth/aes_128_gcm.cpp`.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;

use crate::pairing::PairingError;

/// AES-128-GCM used by AOSP after SPAKE2.
pub struct PairingCipher {
    key: LessSafeKey,
    sequence: u64,
}

impl PairingCipher {
    /// AOSP `aes_128_gcm.cpp`: HKDF-SHA256 with null salt, IKM = SPAKE2 output,
    /// info = "adb pairing_auth aes-128-gcm key". The TLS exporter is never
    /// mixed in here; AOSP binds it earlier by appending it to the SPAKE
    /// password in `pairing_connection.cpp`.
    pub fn from_spake2_key(key_material: &[u8]) -> Result<Self, PairingError> {
        if key_material.is_empty() {
            return Err(PairingError::Crypto("empty SPAKE2 key material".into()));
        }

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(key_material);
        let okm = prk
            .expand(&[b"adb pairing_auth aes-128-gcm key"], Key16)
            .map_err(|_| PairingError::Crypto("HKDF expansion failed".into()))?;
        let mut key = [0u8; 16];
        okm.fill(&mut key)
            .map_err(|_| PairingError::Crypto("HKDF fill failed".into()))?;
        let unbound = UnboundKey::new(&AES_128_GCM, &key)
            .map_err(|_| PairingError::Crypto("AES-128-GCM key creation failed".into()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            sequence: 0,
        })
    }

    fn nonce(&self) -> Result<Nonce, PairingError> {
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&self.sequence.to_ne_bytes());
        Nonce::try_assume_unique_for_key(&bytes)
            .map_err(|_| PairingError::Crypto("invalid sequence nonce".into()))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let nonce = self.nonce()?;
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut out)
            .map_err(|_| PairingError::Crypto("AES-GCM encryption failed".into()))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let nonce = self.nonce()?;
        let mut in_out = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| PairingError::Crypto("AES-GCM decryption failed".into()))?
            .to_vec();
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(plain)
    }
}

struct Key16;
impl hkdf::KeyType for Key16 {
    fn len(&self) -> usize {
        16
    }
}
