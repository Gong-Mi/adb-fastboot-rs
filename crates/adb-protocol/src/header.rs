use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::constants::*;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HeaderError {
    #[error("Buffer too short: expected 24 bytes, got {0}")]
    BufferTooShort(usize),

    #[error("Magic mismatch: expected {expected:#x}, got {got:#x}")]
    MagicMismatch { expected: u32, got: u32 },

    #[error("Checksum mismatch: expected {expected:#x}, got {got:#x}")]
    ChecksumMismatch { expected: u32, got: u32 },
}

/// ADB AUTH Sub-type Enum (TOKEN=1, SIGNATURE=2, RSAKEY=3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Token,
    Signature,
    RsaKey,
    Unknown(u32),
}

impl AuthType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            A_AUTH_TOKEN => AuthType::Token,
            A_AUTH_SIGNATURE => AuthType::Signature,
            A_AUTH_RSAKEY => AuthType::RsaKey,
            other => AuthType::Unknown(other),
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            AuthType::Token => A_AUTH_TOKEN,
            AuthType::Signature => A_AUTH_SIGNATURE,
            AuthType::RsaKey => A_AUTH_RSAKEY,
            AuthType::Unknown(val) => *val,
        }
    }
}

/// ADB Auth Message helper structure for creating/handling AUTH packets
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMessage<'a> {
    pub auth_type: AuthType,
    pub data: &'a [u8],
}

impl<'a> AuthMessage<'a> {
    pub fn new(auth_type: AuthType, data: &'a [u8]) -> Self {
        Self { auth_type, data }
    }

    pub fn token(data: &'a [u8]) -> Self {
        Self::new(AuthType::Token, data)
    }

    pub fn signature(data: &'a [u8]) -> Self {
        Self::new(AuthType::Signature, data)
    }

    pub fn rsakey(data: &'a [u8]) -> Self {
        Self::new(AuthType::RsaKey, data)
    }

    pub fn to_header(&self) -> AdbMessageHeader {
        AdbMessageHeader::new_auth(self.auth_type.to_u32(), self.data)
    }
}

/// ADB 24-byte packet header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdbMessageHeader {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_check: u32,
    pub magic: u32,
}

impl AdbMessageHeader {
    pub const SIZE: usize = 24;

    pub fn new(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Self {
        let data_length = payload.len() as u32;
        let data_check = 0; // ADB_VERSION 0x01000001+: skip checksum
        let magic = command ^ 0xFFFFFFFF;

        Self {
            command,
            arg0,
            arg1,
            data_length,
            data_check,
            magic,
        }
    }

    /// Create an AdbMessageHeader with legacy V1 checksum calculated from payload
    pub fn new_v1_legacy(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Self {
        let mut header = Self::new(command, arg0, arg1, payload);
        header.data_check = Self::calculate_checksum(payload);
        header
    }

    /// Set data_check to the calculated checksum of payload (for legacy ADB checksum support)
    pub fn with_checksum(mut self, payload: &[u8]) -> Self {
        self.data_check = Self::calculate_checksum(payload);
        self
    }

    /// Create an A_AUTH header with specified auth sub-type and payload
    pub fn new_auth(auth_type: u32, payload: &[u8]) -> Self {
        Self::new(A_AUTH, auth_type, 0, payload)
    }

    pub fn is_auth(&self) -> bool {
        self.command == A_AUTH
    }

    pub fn auth_type(&self) -> Option<AuthType> {
        if self.is_auth() {
            Some(AuthType::from_u32(self.arg0))
        } else {
            None
        }
    }

    pub fn calculate_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
    }

    pub fn encode(&self, out: &mut [u8; 24]) {
        LittleEndian::write_u32(&mut out[0..4], self.command);
        LittleEndian::write_u32(&mut out[4..8], self.arg0);
        LittleEndian::write_u32(&mut out[8..12], self.arg1);
        LittleEndian::write_u32(&mut out[12..16], self.data_length);
        LittleEndian::write_u32(&mut out[16..20], self.data_check);
        LittleEndian::write_u32(&mut out[20..24], self.magic);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, HeaderError> {
        if buf.len() < Self::SIZE {
            return Err(HeaderError::BufferTooShort(buf.len()));
        }

        let command = LittleEndian::read_u32(&buf[0..4]);
        let arg0 = LittleEndian::read_u32(&buf[4..8]);
        let arg1 = LittleEndian::read_u32(&buf[8..12]);
        let data_length = LittleEndian::read_u32(&buf[12..16]);
        let data_check = LittleEndian::read_u32(&buf[16..20]);
        let magic = LittleEndian::read_u32(&buf[20..24]);

        let expected_magic = command ^ 0xFFFFFFFF;
        if magic != expected_magic {
            return Err(HeaderError::MagicMismatch {
                expected: expected_magic,
                got: magic,
            });
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_check,
            magic,
        })
    }

    pub fn verify_payload(&self, payload: &[u8]) -> Result<(), HeaderError> {
        if payload.len() != self.data_length as usize {
            return Err(HeaderError::BufferTooShort(payload.len()));
        }
        // AOSP 0x01000001+ (skip checksum): data_check is 0 on modern adbd
        if self.data_check == 0 {
            return Ok(());
        }
        let calc = Self::calculate_checksum(payload);
        if calc != self.data_check {
            return Err(HeaderError::ChecksumMismatch {
                expected: self.data_check,
                got: calc,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::A_CNXN;

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let payload = b"host::features=shell_v2,cmd";
        let header = AdbMessageHeader::new(A_CNXN, 0x01000000, 256 * 1024, payload);

        let mut buf = [0u8; 24];
        header.encode(&mut buf);

        let decoded = AdbMessageHeader::decode(&buf).unwrap();
        assert_eq!(header, decoded);
        assert!(decoded.verify_payload(payload).is_ok());
    }

    #[test]
    fn test_header_corrupt_magic() {
        let payload = b"test";
        let header = AdbMessageHeader::new(A_CNXN, 0, 0, payload);
        let mut buf = [0u8; 24];
        header.encode(&mut buf);
        buf[20] ^= 0xFF; // Corrupt magic

        assert!(matches!(
            AdbMessageHeader::decode(&buf),
            Err(HeaderError::MagicMismatch { .. })
        ));
    }

    #[test]
    fn test_header_checksum_mismatch() {
        let payload = b"correct payload";
        let mut header = AdbMessageHeader::new(A_CNXN, 0, 0, payload);
        // Manually set a non-zero checksum to test mismatch detection
        // (new() now sets data_check=0 for ADB_VERSION 0x01000001+)
        header.data_check = header.data_check.wrapping_add(42);
        let corrupt_payload = b"corrupt payload"; // same length (15 bytes), different bytes

        assert!(matches!(
            header.verify_payload(corrupt_payload),
            Err(HeaderError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_header_skip_checksum_v1_compat() {
        let payload = b"modern adbd payload";
        let mut header = AdbMessageHeader::new(A_CNXN, 0, 0, payload);
        header.data_check = 0; // AOSP 0x01000001+

        assert!(header.verify_payload(payload).is_ok());
    }

    #[test]
    fn test_header_legacy_v1_checksum_helpers() {
        let payload = b"legacy adbd payload";
        let expected_checksum = AdbMessageHeader::calculate_checksum(payload);
        assert_ne!(expected_checksum, 0);

        let legacy_hdr = AdbMessageHeader::new_v1_legacy(A_CNXN, 0, 0, payload);
        assert_eq!(legacy_hdr.data_check, expected_checksum);
        assert!(legacy_hdr.verify_payload(payload).is_ok());

        let corrupt_payload = b"legacy adbd payloae"; // same length
        assert!(matches!(
            legacy_hdr.verify_payload(corrupt_payload),
            Err(HeaderError::ChecksumMismatch { .. })
        ));

        let builder_hdr = AdbMessageHeader::new(A_CNXN, 0, 0, payload).with_checksum(payload);
        assert_eq!(builder_hdr.data_check, expected_checksum);
        assert!(builder_hdr.verify_payload(payload).is_ok());
    }

    #[test]
    fn test_header_buffer_too_short() {
        let buf = [0u8; 10];
        assert_eq!(AdbMessageHeader::decode(&buf), Err(HeaderError::BufferTooShort(10)));
    }

    #[test]
    fn test_auth_message_and_header() {
        let token_data = b"random_20_bytes_token_data!!";
        let auth_msg = AuthMessage::token(token_data);
        assert_eq!(auth_msg.auth_type, AuthType::Token);

        let header = auth_msg.to_header();
        assert_eq!(header.command, A_AUTH);
        assert_eq!(header.arg0, A_AUTH_TOKEN);
        assert_eq!(header.arg1, 0);
        assert_eq!(header.data_length, token_data.len() as u32);

        assert!(header.is_auth());
        assert_eq!(header.auth_type(), Some(AuthType::Token));

        let sig_msg = AuthMessage::signature(b"rsa_signature_bytes");
        let sig_header = sig_msg.to_header();
        assert_eq!(sig_header.auth_type(), Some(AuthType::Signature));

        let key_msg = AuthMessage::rsakey(b"rsa_public_key_bytes");
        let key_header = key_msg.to_header();
        assert_eq!(key_header.auth_type(), Some(AuthType::RsaKey));
    }
}
