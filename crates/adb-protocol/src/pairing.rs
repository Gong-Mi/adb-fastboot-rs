//! AOSP wireless pairing protocol primitives.
//!
//! The AOSP pairing connection is a TLS 1.3 channel followed by a six-byte
//! pairing header, SPAKE2 messages, and encrypted `PeerInfo` messages.  This
//! module deliberately does not expose the former SPAP protocol: that framing
//! was not accepted by AOSP devices.
//!
//! The repository currently has no implementation of BoringSSL's `SPAKE2_CTX`
//! (the AOSP primitive).  Consequently the public connection entry point
//! returns [`PairingError::UnsupportedSpake2`] rather than silently using a
//! different SPAKE2 variant or claiming device compatibility.

use std::io::{Read, Write};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;
use thiserror::Error;

/// AOSP pairing header size: version, type, big-endian payload length.
pub const PAIRING_HEADER_SIZE: usize = 6;
/// AOSP pairing protocol version.
pub const PAIRING_VERSION: u8 = 1;
/// Maximum payload accepted by the AOSP connection implementation.
pub const MAX_PAIRING_PAYLOAD: usize = 16 * 1024;

/// AOSP pairing packet types from `proto/pairing.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingPacketType {
    Spake2Msg = 0,
    PeerInfo = 1,
}

impl TryFrom<u8> for PairingPacketType {
    type Error = PairingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Spake2Msg),
            1 => Ok(Self::PeerInfo),
            other => Err(PairingError::InvalidHeader(format!("unknown packet type {other}"))),
        }
    }
}

/// AOSP pairing protocol errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("pairing code must be exactly 6 ASCII digits")]
    InvalidPairingCode,
    #[error("invalid AOSP pairing header: {0}")]
    InvalidHeader(String),
    #[error("invalid AOSP pairing payload: {0}")]
    InvalidPayload(String),
    #[error("pairing cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("AOSP SPAKE2 is unavailable: the current Rust dependencies do not provide BoringSSL-compatible Curve25519 SPAKE2")]
    UnsupportedSpake2,
    #[error("AOSP pairing requires a TLS exporter; plaintext pairing is refused")]
    TlsRequired,
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for PairingError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

/// A wire packet with the exact AOSP six-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPacket {
    pub version: u8,
    pub packet_type: PairingPacketType,
    pub payload: Vec<u8>,
}

impl PairingPacket {
    pub fn new(packet_type: PairingPacketType, payload: Vec<u8>) -> Result<Self, PairingError> {
        if payload.is_empty() || payload.len() > MAX_PAIRING_PAYLOAD {
            return Err(PairingError::InvalidPayload(format!(
                "payload length {} is outside 1..={MAX_PAIRING_PAYLOAD}",
                payload.len()
            )));
        }
        Ok(Self { version: PAIRING_VERSION, packet_type, payload })
    }

    pub fn encode_header(&self) -> [u8; PAIRING_HEADER_SIZE] {
        let len = (self.payload.len() as u32).to_be_bytes();
        [self.version, self.packet_type as u8, len[0], len[1], len[2], len[3]]
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PairingError> {
        writer.write_all(&self.encode_header())?;
        writer.write_all(&self.payload)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, PairingError> {
        let mut header = [0u8; PAIRING_HEADER_SIZE];
        reader.read_exact(&mut header)?;
        if header[0] != PAIRING_VERSION {
            return Err(PairingError::InvalidHeader(format!("unsupported version {}", header[0])));
        }
        let packet_type = PairingPacketType::try_from(header[1])?;
        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if len == 0 || len > MAX_PAIRING_PAYLOAD {
            return Err(PairingError::InvalidHeader(format!("unsafe payload length {len}")));
        }
        let mut payload = vec![0; len];
        reader.read_exact(&mut payload)?;
        Ok(Self { version: header[0], packet_type, payload })
    }
}

/// Validate the user-facing six-digit pairing code.
pub fn validate_pairing_code(code: &str) -> Result<(), PairingError> {
    let code = code.trim();
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(PairingError::InvalidPairingCode)
    }
}

/// AES-128-GCM used by AOSP after SPAKE2.
///
/// AOSP derives the key with HKDF-SHA256 and info
/// `adb pairing_auth aes-128-gcm key`.  Nonces are twelve zero bytes with the
/// native-endian 64-bit sequence in the first eight bytes; the nonce is not
/// transmitted.  The sequence is independently incremented per direction.
pub struct PairingCipher {
    key: LessSafeKey,
    sequence: u64,
}

impl PairingCipher {
    pub fn from_spake2_key(key_material: &[u8]) -> Result<Self, PairingError> {
        if key_material.is_empty() {
            return Err(PairingError::Crypto("empty SPAKE2 key material".into()));
        }
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(key_material);
        let okm = prk.expand(&[b"adb pairing_auth aes-128-gcm key"], Key16)
            .map_err(|_| PairingError::Crypto("HKDF expansion failed".into()))?;
        let mut key = [0u8; 16];
        okm.fill(&mut key).map_err(|_| PairingError::Crypto("HKDF fill failed".into()))?;
        let unbound = UnboundKey::new(&AES_128_GCM, &key)
            .map_err(|_| PairingError::Crypto("AES-128-GCM key creation failed".into()))?;
        Ok(Self { key: LessSafeKey::new(unbound), sequence: 0 })
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
        self.key.seal_in_place_append_tag(nonce, Aad::empty(), &mut out)
            .map_err(|_| PairingError::Crypto("AES-GCM encryption failed".into()))?;
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let nonce = self.nonce()?;
        let mut in_out = ciphertext.to_vec();
        let plain = self.key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| PairingError::Crypto("AES-GCM decryption failed".into()))?
            .to_vec();
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(plain)
    }
}

struct Key16;
impl hkdf::KeyType for Key16 {
    fn len(&self) -> usize { 16 }
}

/// A deliberately refusing client.  TLS setup and certificate persistence are
/// not complete in this CLI, and the exact AOSP SPAKE2 primitive is unavailable.
pub struct PairingClient {
    code: String,
}

impl PairingClient {
    pub fn new(code: &str) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self { code: code.trim().to_owned() })
    }

    pub fn pairing_code(&self) -> &str { &self.code }

    pub fn execute_pairing<T: Read + Write>(&mut self, _transport: &mut T) -> Result<(), PairingError> {
        Err(PairingError::UnsupportedSpake2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aosp_header_is_six_bytes_big_endian() {
        let packet = PairingPacket::new(PairingPacketType::Spake2Msg, vec![0xaa; 0x0102]).unwrap();
        assert_eq!(packet.encode_header(), [1, 0, 0, 0, 1, 2]);
        let mut wire = Vec::new();
        packet.write_to(&mut wire).unwrap();
        assert_eq!(wire.len(), 6 + 0x0102);
        assert_eq!(PairingPacket::read_from(&mut Cursor::new(wire)).unwrap(), packet);
    }

    #[test]
    fn rejects_legacy_spap_and_unknown_types() {
        assert!(PairingPacket::read_from(&mut Cursor::new(b"SPAP\x01\0\0\0".to_vec())).is_err());
        assert!(PairingPacket::read_from(&mut Cursor::new(vec![1, 9, 0, 0, 0, 1, 0])).is_err());
    }

    #[test]
    fn aosp_sequence_nonce_cipher_round_trip_and_no_nonce_on_wire() {
        let material = [7u8; 32];
        let mut enc = PairingCipher::from_spake2_key(&material).unwrap();
        let mut dec = PairingCipher::from_spake2_key(&material).unwrap();
        let wire = enc.encrypt(b"peer-info").unwrap();
        assert_eq!(wire.len(), b"peer-info".len() + 16);
        assert_eq!(dec.decrypt(&wire).unwrap(), b"peer-info");
        assert_ne!(wire, [&[0u8; 12][..], b"peer-info"].concat());
    }

    #[test]
    fn client_refuses_to_claim_compatibility() {
        let mut client = PairingClient::new("123456").unwrap();
        let mut io = Cursor::new(Vec::<u8>::new());
        assert_eq!(client.execute_pairing(&mut io), Err(PairingError::UnsupportedSpake2));
    }
}
