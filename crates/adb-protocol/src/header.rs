use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HeaderError {
    #[error("Buffer too short: expected 24 bytes, got {0}")]
    BufferTooShort(usize),

    #[error("Magic mismatch: expected {expected:#x}, got {got:#x}")]
    MagicMismatch { expected: u32, got: u32 },

    #[error("Checksum mismatch: expected {expected:#x}, got {got:#x}")]
    ChecksumMismatch { expected: u32, got: u32 },
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
        let data_check = Self::calculate_checksum(payload);
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
        let header = AdbMessageHeader::new(A_CNXN, 0, 0, payload);
        let corrupt_payload = b"corrupt payload"; // same length (15 bytes), different bytes

        assert!(matches!(
            header.verify_payload(corrupt_payload),
            Err(HeaderError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_header_buffer_too_short() {
        let buf = [0u8; 10];
        assert_eq!(AdbMessageHeader::decode(&buf), Err(HeaderError::BufferTooShort(10)));
    }
}
