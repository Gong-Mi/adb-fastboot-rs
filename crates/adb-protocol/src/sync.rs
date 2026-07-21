use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SyncProtocolError {
    #[error("Sync header too short: expected 8 bytes, got {0}")]
    HeaderTooShort(usize),
    #[error("Sync command failed with message: {0}")]
    SyncFail(String),
}

/// ADB Sync request/response header (8 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncMessageHeader {
    pub id: u32,
    pub length: u32,
}

impl SyncMessageHeader {
    pub const SIZE: usize = 8;

    pub fn new(id: u32, length: u32) -> Self {
        Self { id, length }
    }

    pub fn encode(&self, out: &mut [u8; 8]) {
        LittleEndian::write_u32(&mut out[0..4], self.id);
        LittleEndian::write_u32(&mut out[4..8], self.length);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < Self::SIZE {
            return Err(SyncProtocolError::HeaderTooShort(buf.len()));
        }
        let id = LittleEndian::read_u32(&buf[0..4]);
        let length = LittleEndian::read_u32(&buf[4..8]);
        Ok(Self { id, length })
    }
}

/// ADB STAT response struct (12 bytes payload after STAT header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatResponse {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

impl SyncStatResponse {
    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < 12 {
            return Err(SyncProtocolError::HeaderTooShort(buf.len()));
        }
        let mode = LittleEndian::read_u32(&buf[0..4]);
        let size = LittleEndian::read_u32(&buf[4..8]);
        let mtime = LittleEndian::read_u32(&buf[8..12]);
        Ok(Self { mode, size, mtime })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_header_roundtrip() {
        let hdr = SyncMessageHeader::new(crate::constants::SYNC_SEND, 1024);
        let mut buf = [0u8; 8];
        hdr.encode(&mut buf);

        let decoded = SyncMessageHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn test_sync_stat_decode() {
        let mut buf = [0u8; 12];
        LittleEndian::write_u32(&mut buf[0..4], 0o100644); // regular file -rw-r--r--
        LittleEndian::write_u32(&mut buf[4..8], 2048); // size
        LittleEndian::write_u32(&mut buf[8..12], 1720000000); // mtime

        let stat = SyncStatResponse::decode(&buf).unwrap();
        assert_eq!(stat.mode, 0o100644);
        assert_eq!(stat.size, 2048);
        assert_eq!(stat.mtime, 1720000000);
    }
}
