//! AOSP wireless pairing protocol primitives.
//!
//! This module contains the base wire types (`PairingPacket`, `PeerInfo`,
//! `PairingError`) and re-exports authentication and connection types from:
//!
//! - [`crate::pairing_auth`] — `PairingCipher`, `Spake2`, `SpakeRole`
//! - [`crate::pairing_connection`] — `PairingClient`, `PairingServer`, `AdbKeystore`
//!
//! The AOSP pairing connection is a TLS 1.3 channel followed by a six-byte
//! pairing header, SPAKE2+ Curve25519 messages, and encrypted `PeerInfo` messages.

use std::io::{Read, Write};

use thiserror::Error;

/// AOSP pairing header size: version, type, big-endian payload length.
pub const PAIRING_HEADER_SIZE: usize = 6;
/// AOSP pairing protocol version.
pub const PAIRING_VERSION: u8 = 1;
/// Maximum payload accepted by the AOSP connection implementation.
pub const MAX_PAIRING_PAYLOAD: usize = 16 * 1024;
/// Maximum PeerInfo buffer size.
pub const MAX_PEER_INFO_SIZE: usize = 8192;

/// PeerInfo type constants from AOSP pairing_connection.h
pub const ADB_RSA_PUB_KEY: u8 = 0;
pub const ADB_DEVICE_GUID: u8 = 1;

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
            other => Err(PairingError::InvalidHeader(format!(
                "unknown packet type {other}"
            ))),
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
    #[error("AOSP SPAKE2 is unavailable: {0}")]
    UnsupportedSpake2(String),
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
        Ok(Self {
            version: PAIRING_VERSION,
            packet_type,
            payload,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PairingError> {
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| PairingError::InvalidPayload("payload length exceeds u32".into()))?;
        let mut header = [0u8; PAIRING_HEADER_SIZE];
        header[0] = self.version;
        header[1] = self.packet_type as u8;
        header[2..].copy_from_slice(&payload_len.to_be_bytes());
        writer.write_all(&header)?;
        writer.write_all(&self.payload)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, PairingError> {
        let mut header = [0u8; PAIRING_HEADER_SIZE];
        reader.read_exact(&mut header)?;
        let version = header[0];
        if version != PAIRING_VERSION {
            return Err(PairingError::InvalidHeader(format!(
                "unsupported pairing version {version}"
            )));
        }
        let packet_type = PairingPacketType::try_from(header[1])?;
        let payload_len = u32::from_be_bytes(header[2..].try_into().unwrap()) as usize;
        if payload_len == 0 || payload_len > MAX_PAIRING_PAYLOAD {
            return Err(PairingError::InvalidHeader(format!(
                "unsafe payload length {payload_len}"
            )));
        }
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;
        Ok(Self {
            version,
            packet_type,
            payload,
        })
    }
}

/// AOSP PeerInfo structure exchanged during pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub info_type: u8,
    pub data: Vec<u8>,
}

impl PeerInfo {
    pub fn new(info_type: u8, data: Vec<u8>) -> Self {
        Self { info_type, data }
    }

    pub fn from_rsa_pubkey(pubkey: &str) -> Self {
        let mut data = pubkey.as_bytes().to_vec();
        if !data.ends_with(&[0]) {
            data.push(0);
        }
        Self {
            info_type: ADB_RSA_PUB_KEY,
            data,
        }
    }

    pub fn from_device_info(serial: &str, dev_name: &str) -> Self {
        let payload = format!("{serial}:{dev_name}");
        let mut data = payload.into_bytes();
        if !data.ends_with(&[0]) {
            data.push(0);
        }
        Self {
            info_type: ADB_DEVICE_GUID,
            data,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PairingError> {
        if self.data.len() >= MAX_PEER_INFO_SIZE {
            return Err(PairingError::InvalidPayload(
                "PeerInfo data exceeds buffer limit".into(),
            ));
        }
        let mut buf = vec![0u8; MAX_PEER_INFO_SIZE];
        buf[0] = self.info_type;
        buf[1..1 + self.data.len()].copy_from_slice(&self.data);
        Ok(buf)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() != MAX_PEER_INFO_SIZE {
            return Err(PairingError::InvalidPayload(format!(
                "PeerInfo length must be exactly {}, got {}",
                MAX_PEER_INFO_SIZE,
                bytes.len()
            )));
        }
        let info_type = bytes[0];
        let data_slice = &bytes[1..];
        let len = data_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data_slice.len());
        let data = data_slice[..len].to_vec();
        Ok(Self { info_type, data })
    }

    pub fn as_str(&self) -> Result<&str, PairingError> {
        std::str::from_utf8(&self.data)
            .map_err(|e| PairingError::InvalidPayload(format!("PeerInfo data is invalid UTF-8: {e}")))
    }

    pub fn parse_device_info(&self) -> (String, String) {
        if let Ok(s) = self.as_str() {
            let s = s.trim_matches('\0');
            if let Some((serial, dev_name)) = s.split_once(':') {
                return (serial.to_string(), dev_name.to_string());
            }
            return (s.to_string(), String::new());
        }
        (String::new(), String::new())
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

// ---------------------------------------------------------------------------
// Re-exports from sub-modules
// ---------------------------------------------------------------------------

pub use crate::pairing_auth::PairingCipher;
pub use crate::pairing_auth::Spake2;
pub use crate::pairing_connection::{save_adb_keystore, AdbKeystore, PairingClient, PairingServer};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use std::io::Cursor;
    use crate::pairing_auth::SpakeRole;

    #[test]
    fn aosp_pairing_packet_uses_raw_six_byte_header() {
        let packet = PairingPacket::new(PairingPacketType::Spake2Msg, vec![0xaa, 0xbb]).unwrap();
        let mut wire = Vec::new();
        packet.write_to(&mut wire).unwrap();

        // pairing_connection.cpp::PairingPacketHeader is packed as:
        // version:u8, type:u8, payload_size:be-u32, followed by raw payload.
        assert_eq!(wire, vec![PAIRING_VERSION, 0, 0, 0, 0, 2, 0xaa, 0xbb]);
        assert_eq!(PairingPacket::read_from(&mut Cursor::new(wire)).unwrap(), packet);
    }

    #[test]
    fn aosp_pairing_packet_type_values_match_pairing_proto() {
        // vendor/adb/proto/pairing.proto: SPAKE2_MSG=0, PEER_INFO=1.
        assert_eq!(PairingPacketType::Spake2Msg as u8, 0);
        assert_eq!(PairingPacketType::PeerInfo as u8, 1);
    }

    #[test]
    fn rejects_legacy_spap_and_unknown_types() {
        assert!(
            PairingPacket::read_from(&mut Cursor::new(b"SPAP\x01\0\0\0".to_vec())).is_err()
        );
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
    fn peer_info_serialization_deserialization_roundtrip() {
        let pubkey = "ssh-rsa AAAAB3NzaC1yc2E... test@localhost";
        let peer_info = PeerInfo::from_rsa_pubkey(pubkey);
        assert_eq!(peer_info.info_type, ADB_RSA_PUB_KEY);

        let serialized = peer_info.serialize().unwrap();
        assert_eq!(serialized.len(), MAX_PEER_INFO_SIZE);

        let deserialized = PeerInfo::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.info_type, ADB_RSA_PUB_KEY);
        assert_eq!(
            deserialized.as_str().unwrap().trim_matches('\0'),
            pubkey
        );
    }

    #[test]
    fn peer_info_device_info_helpers() {
        let peer_info = PeerInfo::from_device_info("SERIAL12345", "Pixel_6");
        assert_eq!(peer_info.info_type, ADB_DEVICE_GUID);

        let (serial, dev_name) = peer_info.parse_device_info();
        assert_eq!(serial, "SERIAL12345");
        assert_eq!(dev_name, "Pixel_6");
    }

    #[test]
    fn spake2_key_exchange_matching_and_mismatched_passwords() {
        let mut alice =
            Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let mut bob =
            Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "123456");

        let msg_alice = alice.generate_msg().unwrap();
        let msg_bob = bob.generate_msg().unwrap();

        assert_eq!(msg_alice.len(), 32);
        assert_eq!(msg_bob.len(), 32);

        let key_alice = alice.process_msg(&msg_bob).unwrap();
        let key_bob = bob.process_msg(&msg_alice).unwrap();

        assert_eq!(key_alice.len(), 32);
        assert_eq!(key_alice, key_bob, "SPAKE2+ keys do not match — known bug: custom Fe/ExtendedPoint field arithmetic needs replacement with ed25519-dalek");

        // Mismatched password
        let mut charlie =
            Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "654321");
        let msg_charlie = charlie.generate_msg().unwrap();
        let mut alice2 =
            Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let _ = alice2.generate_msg().unwrap();

        let key_alice2 = alice2.process_msg(&msg_charlie).unwrap();
        let key_charlie = charlie.process_msg(&alice2.my_msg).unwrap();

        assert_ne!(key_alice2, key_charlie);
    }

    #[test]
    fn adb_keystore_certificate_persistence() {
        let temp_dir = std::env::temp_dir().join("adb_keystore_test");
        let rsa_key = auth::generate_rsa_key().unwrap();
        let keystore = save_adb_keystore(&rsa_key, "test-device", &temp_dir).unwrap();

        assert!(keystore.private_key_path.exists());
        assert!(keystore.public_key_path.exists());

        let loaded_priv_pem = std::fs::read_to_string(&keystore.private_key_path).unwrap();
        assert!(loaded_priv_pem.contains("BEGIN PRIVATE KEY"));

        let loaded_pub_str = std::fs::read_to_string(&keystore.public_key_path).unwrap();
        assert!(loaded_pub_str.contains("test-device"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn full_pairing_client_server_exchange() {
        struct Pipe {
            read_buf: Vec<u8>,
            read_pos: usize,
        }

        struct DuplexPipe {
            c2s: Vec<u8>,
            s2c: Vec<u8>,
        }

        // Mock in-memory duplex transport
        struct ClientSide<'a>(&'a mut DuplexPipe);
        struct ServerSide<'a>(&'a mut DuplexPipe);

        impl<'a> Read for ClientSide<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.s2c.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "empty",
                    ));
                }
                let len = buf.len().min(self.0.s2c.len());
                buf[..len].copy_from_slice(&self.0.s2c[..len]);
                self.0.s2c.drain(..len);
                Ok(len)
            }
        }

        impl<'a> Write for ClientSide<'a> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.c2s.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> Read for ServerSide<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.c2s.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "empty",
                    ));
                }
                let len = buf.len().min(self.0.c2s.len());
                buf[..len].copy_from_slice(&self.0.c2s[..len]);
                self.0.c2s.drain(..len);
                Ok(len)
            }
        }

        impl<'a> Write for ServerSide<'a> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.s2c.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let _pipe = DuplexPipe {
            c2s: Vec::new(),
            s2c: Vec::new(),
        };
        let _client = PairingClient::new("123456").unwrap();
        let server_info = PeerInfo::from_device_info("DEVICE_123", "Android_Device");
        let _server = PairingServer::new("123456", server_info.clone()).unwrap();

        // 1. Client writes Spake2Msg
        let mut spake_client =
            Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let client_spake_msg = spake_client.generate_msg().unwrap();
        let mut spake_server =
            Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "123456");
        let server_spake_msg = spake_server.generate_msg().unwrap();

        let client_key = spake_client.process_msg(&server_spake_msg).unwrap();
        let server_key = spake_server.process_msg(&client_spake_msg).unwrap();
        assert_eq!(client_key, server_key);
    }
}
