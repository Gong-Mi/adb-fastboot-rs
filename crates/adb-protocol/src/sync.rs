use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SyncProtocolError {
    #[error("Sync header too short: expected {expected} bytes, got {got}")]
    HeaderTooShort { expected: usize, got: usize },
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
            return Err(SyncProtocolError::HeaderTooShort {
                expected: Self::SIZE,
                got: buf.len(),
            });
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
    pub const SIZE: usize = 12;

    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < Self::SIZE {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: Self::SIZE,
                got: buf.len(),
            });
        }
        let mode = LittleEndian::read_u32(&buf[0..4]);
        let size = LittleEndian::read_u32(&buf[4..8]);
        let mtime = LittleEndian::read_u32(&buf[8..12]);
        Ok(Self { mode, size, mtime })
    }
}

/// ADB STAT_V2 / LSTAT_V2 response struct (72 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatV2Response {
    pub id: u32,
    pub error: u32,
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

impl SyncStatV2Response {
    pub const SIZE: usize = 72;

    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < Self::SIZE {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: Self::SIZE,
                got: buf.len(),
            });
        }
        let id = LittleEndian::read_u32(&buf[0..4]);
        let error = LittleEndian::read_u32(&buf[4..8]);
        let dev = LittleEndian::read_u64(&buf[8..16]);
        let ino = LittleEndian::read_u64(&buf[16..24]);
        let mode = LittleEndian::read_u32(&buf[24..28]);
        let nlink = LittleEndian::read_u32(&buf[28..32]);
        let uid = LittleEndian::read_u32(&buf[32..36]);
        let gid = LittleEndian::read_u32(&buf[36..40]);
        let size = LittleEndian::read_u64(&buf[40..48]);
        let atime = LittleEndian::read_i64(&buf[48..56]);
        let mtime = LittleEndian::read_i64(&buf[56..64]);
        let ctime = LittleEndian::read_i64(&buf[64..72]);

        Ok(Self {
            id,
            error,
            dev,
            ino,
            mode,
            nlink,
            uid,
            gid,
            size,
            atime,
            mtime,
            ctime,
        })
    }

    pub fn encode(&self, out: &mut [u8; 72]) {
        LittleEndian::write_u32(&mut out[0..4], self.id);
        LittleEndian::write_u32(&mut out[4..8], self.error);
        LittleEndian::write_u64(&mut out[8..16], self.dev);
        LittleEndian::write_u64(&mut out[16..24], self.ino);
        LittleEndian::write_u32(&mut out[24..28], self.mode);
        LittleEndian::write_u32(&mut out[28..32], self.nlink);
        LittleEndian::write_u32(&mut out[32..36], self.uid);
        LittleEndian::write_u32(&mut out[36..40], self.gid);
        LittleEndian::write_u64(&mut out[40..48], self.size);
        LittleEndian::write_i64(&mut out[48..56], self.atime);
        LittleEndian::write_i64(&mut out[56..64], self.mtime);
        LittleEndian::write_i64(&mut out[64..72], self.ctime);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{SYNC_SEND, SYNC_STA2};

    #[test]
    fn test_sync_header_roundtrip() {
        let hdr = SyncMessageHeader::new(SYNC_SEND, 1024);
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

    #[test]
    fn test_sync_stat_v2_roundtrip() {
        let original = SyncStatV2Response {
            id: SYNC_STA2,
            error: 0,
            dev: 2049,
            ino: 12345678,
            mode: 0o100644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            size: 104857600, // > 4GB or 100MB
            atime: 1720000001,
            mtime: 1720000002,
            ctime: 1720000003,
        };

        let mut buf = [0u8; 72];
        original.encode(&mut buf);

        let decoded = SyncStatV2Response::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }
}
