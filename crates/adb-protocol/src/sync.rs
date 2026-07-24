use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SyncProtocolError {
    #[error("Sync header too short: expected {expected} bytes, got {got}")]
    HeaderTooShort { expected: usize, got: usize },
    #[error("Sync command failed with message: {0}")]
    SyncFail(String),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Invalid message structure or size overflow: {0}")]
    InvalidMessage(String),
}

/// Helper function to validate path inputs for ADB SYNC requests.
fn validate_path(path: &str, allow_comma: bool) -> Result<(), SyncProtocolError> {
    if path.is_empty() {
        return Err(SyncProtocolError::InvalidPath(
            "Path cannot be empty".to_string(),
        ));
    }
    if path.contains('\0') {
        return Err(SyncProtocolError::InvalidPath(
            "Path cannot contain NUL byte".to_string(),
        ));
    }
    if !allow_comma && path.contains(',') {
        return Err(SyncProtocolError::InvalidPath(
            "Path cannot contain ',' in V1 SEND request".to_string(),
        ));
    }
    if u32::try_from(path.len()).is_err() {
        return Err(SyncProtocolError::InvalidPath(
            "Path length exceeds u32::MAX".to_string(),
        ));
    }
    Ok(())
}

/// Helper function to convert i64 timestamp to u32 with saturating cast.
pub fn saturating_mtime_u32(mtime: i64) -> u32 {
    if mtime < 0 {
        0
    } else {
        u32::try_from(mtime).unwrap_or(u32::MAX)
    }
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

    pub fn exists(&self) -> bool {
        self.mode != 0 || self.size != 0 || self.mtime != 0
    }

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

    pub fn encode(&self, out: &mut [u8; 12]) {
        LittleEndian::write_u32(&mut out[0..4], self.mode);
        LittleEndian::write_u32(&mut out[4..8], self.size);
        LittleEndian::write_u32(&mut out[8..12], self.mtime);
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

    pub fn is_ok(&self) -> bool {
        self.error == 0
    }

    pub fn mtime_u32(&self) -> u32 {
        saturating_mtime_u32(self.mtime)
    }

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

/// Helper functions for building ADB SYNC protocol packets
pub fn build_sync_send_req(
    remote_path: &str,
    mode: u32,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(remote_path, false)?;
    let req_str = format!("{},{}", remote_path, mode);
    let len = u32::try_from(req_str.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Request payload length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_SEND, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(req_str.as_bytes());
    Ok(())
}

pub fn build_sync_data_chunk(chunk: &[u8], out: &mut Vec<u8>) -> Result<(), SyncProtocolError> {
    let len = u32::try_from(chunk.len()).map_err(|_| {
        SyncProtocolError::InvalidMessage("Data chunk size exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_DATA, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(chunk);
    Ok(())
}

pub fn build_sync_done(mtime: u32, out: &mut Vec<u8>) -> Result<(), SyncProtocolError> {
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_DONE, mtime);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    Ok(())
}

pub fn build_sync_done_u64(mtime: u64, out: &mut Vec<u8>) -> Result<(), SyncProtocolError> {
    let mtime_u32 = u32::try_from(mtime).unwrap_or(u32::MAX);
    build_sync_done(mtime_u32, out)
}

pub fn build_sync_recv_req(
    remote_path: &str,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(remote_path, true)?;
    let len = u32::try_from(remote_path.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Remote path length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_RECV, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(remote_path.as_bytes());
    Ok(())
}

pub fn build_sync_list_req(
    remote_path: &str,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(remote_path, true)?;
    let len = u32::try_from(remote_path.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Remote path length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_LIST, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(remote_path.as_bytes());
    Ok(())
}

pub fn build_sync_stat_req(
    remote_path: &str,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(remote_path, true)?;
    let len = u32::try_from(remote_path.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Remote path length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_STAT, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(remote_path.as_bytes());
    Ok(())
}

/// Build a SEND_V2 setup packet: SyncRequest(path_len) + path + sync_send_v2 { id, mode, flags }
pub fn build_send_v2_req(
    path: &str,
    mode: u32,
    flags: u32,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(path, true)?;
    let path_bytes = path.as_bytes();
    let len = u32::try_from(path_bytes.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Path length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_SEND_V2, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(path_bytes);
    // sync_send_v2: id (u32=SYNC_SEND_V2), mode (u32), flags (u32)
    let mut extra = [0u8; 12];
    LittleEndian::write_u32(&mut extra[0..4], crate::constants::SYNC_SEND_V2);
    LittleEndian::write_u32(&mut extra[4..8], mode);
    LittleEndian::write_u32(&mut extra[8..12], flags);
    out.extend_from_slice(&extra);
    Ok(())
}

/// Build a RECV_V2 setup packet: SyncRequest(path_len) + path + sync_recv_v2 { id, flags }
pub fn build_recv_v2_req(
    path: &str,
    flags: u32,
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    validate_path(path, true)?;
    let path_bytes = path.as_bytes();
    let len = u32::try_from(path_bytes.len()).map_err(|_| {
        SyncProtocolError::InvalidPath("Path length exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_RECV_V2, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(path_bytes);
    // sync_recv_v2: id (u32=SYNC_RECV_V2), flags (u32)
    let mut extra = [0u8; 8];
    LittleEndian::write_u32(&mut extra[0..4], crate::constants::SYNC_RECV_V2);
    LittleEndian::write_u32(&mut extra[4..8], flags);
    out.extend_from_slice(&extra);
    Ok(())
}

/// Build a data block: SyncRequest(ID_DATA, compressed_len) + compressed_data
pub fn build_sync_data_block(
    compressed_data: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), SyncProtocolError> {
    let len = u32::try_from(compressed_data.len()).map_err(|_| {
        SyncProtocolError::InvalidMessage("Compressed data size exceeds u32::MAX".to_string())
    })?;
    let hdr = SyncMessageHeader::new(crate::constants::SYNC_DATA, len);
    let mut hdr_buf = [0u8; 8];
    hdr.encode(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(compressed_data);
    Ok(())
}

/// ADB DENT (directory entry) response struct (20 bytes header + namelen bytes name)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDentResponse {
    pub id: u32,
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
    pub namelen: u32,
    pub name: String,
}

impl SyncDentResponse {
    pub const HEADER_SIZE: usize = 20;

    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let id = LittleEndian::read_u32(&buf[0..4]);
        let mode = LittleEndian::read_u32(&buf[4..8]);
        let size = LittleEndian::read_u32(&buf[8..12]);
        let mtime = LittleEndian::read_u32(&buf[12..16]);
        let namelen = LittleEndian::read_u32(&buf[16..20]);

        let total = Self::HEADER_SIZE
            .checked_add(namelen as usize)
            .ok_or_else(|| {
                SyncProtocolError::InvalidMessage(
                    "Directory entry namelen addition overflowed".to_string(),
                )
            })?;

        if buf.len() < total {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: total,
                got: buf.len(),
            });
        }
        let name = String::from_utf8_lossy(&buf[20..total]).to_string();
        Ok(Self {
            id,
            mode,
            size,
            mtime,
            namelen,
            name,
        })
    }

    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE.saturating_add(self.namelen as usize)
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), SyncProtocolError> {
        let name_bytes = self.name.as_bytes();
        let actual_namelen = u32::try_from(name_bytes.len()).map_err(|_| {
            SyncProtocolError::InvalidMessage("Entry name length exceeds u32::MAX".to_string())
        })?;
        let mut hdr = [0u8; 20];
        LittleEndian::write_u32(&mut hdr[0..4], self.id);
        LittleEndian::write_u32(&mut hdr[4..8], self.mode);
        LittleEndian::write_u32(&mut hdr[8..12], self.size);
        LittleEndian::write_u32(&mut hdr[12..16], self.mtime);
        LittleEndian::write_u32(&mut hdr[16..20], actual_namelen);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(name_bytes);
        Ok(())
    }
}

/// ADB DENT_V2 response struct (76 bytes header + namelen bytes name)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDentV2Response {
    pub stat: SyncStatV2Response,
    pub namelen: u32,
    pub name: String,
}

impl SyncDentV2Response {
    pub const HEADER_SIZE: usize = 76;

    pub fn decode(buf: &[u8]) -> Result<Self, SyncProtocolError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let stat = SyncStatV2Response::decode(&buf[0..72])?;
        let namelen = LittleEndian::read_u32(&buf[72..76]);
        let total = Self::HEADER_SIZE
            .checked_add(namelen as usize)
            .ok_or_else(|| {
                SyncProtocolError::InvalidMessage(
                    "Directory entry V2 namelen addition overflowed".to_string(),
                )
            })?;

        if buf.len() < total {
            return Err(SyncProtocolError::HeaderTooShort {
                expected: total,
                got: buf.len(),
            });
        }
        let name = String::from_utf8_lossy(&buf[76..total]).to_string();
        Ok(Self { stat, namelen, name })
    }

    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE.saturating_add(self.namelen as usize)
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), SyncProtocolError> {
        let name_bytes = self.name.as_bytes();
        let actual_namelen = u32::try_from(name_bytes.len()).map_err(|_| {
            SyncProtocolError::InvalidMessage("Entry V2 name length exceeds u32::MAX".to_string())
        })?;
        let mut stat_buf = [0u8; 72];
        self.stat.encode(&mut stat_buf);
        out.extend_from_slice(&stat_buf);
        let mut len_buf = [0u8; 4];
        LittleEndian::write_u32(&mut len_buf, actual_namelen);
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(name_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{SYNC_DENT_V2, SYNC_SEND, SYNC_STA2};

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
        assert!(stat.exists());
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
        assert!(decoded.is_ok());
        assert_eq!(decoded.mtime_u32(), 1720000002);
    }

    #[test]
    fn test_sync_dent_response_encode_decode() {
        let dent = SyncDentResponse {
            id: crate::constants::SYNC_DENT,
            mode: 0o100644,
            size: 1024,
            mtime: 1720000000,
            namelen: 8,
            name: "test.txt".to_string(),
        };

        let mut out = Vec::new();
        dent.encode(&mut out).unwrap();
        assert_eq!(out.len(), 20 + 8);

        let decoded = SyncDentResponse::decode(&out).unwrap();
        assert_eq!(dent, decoded);
        assert_eq!(decoded.total_size(), 28);
    }

    #[test]
    fn test_sync_dent_v2_response_encode_decode() {
        let stat_v2 = SyncStatV2Response {
            id: SYNC_DENT_V2,
            error: 0,
            dev: 2049,
            ino: 12345678,
            mode: 0o100644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            size: 4096,
            atime: 1720000001,
            mtime: 1720000002,
            ctime: 1720000003,
        };
        let dent_v2 = SyncDentV2Response {
            stat: stat_v2,
            namelen: 8,
            name: "test.txt".to_string(),
        };

        let mut out = Vec::new();
        dent_v2.encode(&mut out).unwrap();
        assert_eq!(out.len(), 76 + 8);

        let decoded = SyncDentV2Response::decode(&out).unwrap();
        assert_eq!(dent_v2, decoded);
        assert_eq!(decoded.total_size(), 84);
    }

    #[test]
    fn test_sync_list_req_builder() {
        let mut buf = Vec::new();
        build_sync_list_req("/sdcard/testdir", &mut buf).unwrap();

        let hdr = SyncMessageHeader::decode(&buf[..8]).unwrap();
        assert_eq!(hdr.id, crate::constants::SYNC_LIST);
        assert_eq!(hdr.length, 15);
        assert_eq!(&buf[8..], b"/sdcard/testdir");
    }

    #[test]
    fn test_path_validation_empty() {
        let mut buf = Vec::new();
        assert!(build_sync_send_req("", 0o644, &mut buf).is_err());
        assert!(build_sync_recv_req("", &mut buf).is_err());
        assert!(build_sync_list_req("", &mut buf).is_err());
        assert!(build_sync_stat_req("", &mut buf).is_err());
        assert!(build_send_v2_req("", 0o644, 0, &mut buf).is_err());
        assert!(build_recv_v2_req("", 0, &mut buf).is_err());
    }

    #[test]
    fn test_path_validation_nul_byte() {
        let mut buf = Vec::new();
        assert!(build_sync_send_req("/sdcard/\0test", 0o644, &mut buf).is_err());
        assert!(build_sync_recv_req("/sdcard/\0test", &mut buf).is_err());
    }

    #[test]
    fn test_sync_send_req_comma_rejection() {
        let mut buf = Vec::new();
        // V1 send should reject paths containing ','
        assert_eq!(
            build_sync_send_req("/sdcard/foo,bar", 0o644, &mut buf),
            Err(SyncProtocolError::InvalidPath(
                "Path cannot contain ',' in V1 SEND request".to_string()
            ))
        );
        // V2 send allows ','
        assert!(build_send_v2_req("/sdcard/foo,bar", 0o644, 0, &mut buf).is_ok());
    }

    #[test]
    fn test_sync_dent_namelen_overflow() {
        let mut buf = vec![0u8; 20];
        // Set namelen to u32::MAX
        LittleEndian::write_u32(&mut buf[16..20], u32::MAX);

        let err = SyncDentResponse::decode(&buf);
        assert!(err.is_err());
    }

    #[test]
    fn test_saturating_mtime_u32() {
        assert_eq!(saturating_mtime_u32(-100), 0);
        assert_eq!(saturating_mtime_u32(1000), 1000);
        assert_eq!(saturating_mtime_u32(i64::MAX), u32::MAX);
    }
}
