use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

pub const SPARSE_HEADER_MAGIC: u32 = 0xED26FF3A;

pub const CHUNK_TYPE_RAW: u16 = 0xCAC1;
pub const CHUNK_TYPE_FILL: u16 = 0xCAC2;
pub const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
pub const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SparseError {
    #[error("Header too short: expected 28 bytes, got {0}")]
    HeaderTooShort(usize),
    #[error("Invalid magic: expected {SPARSE_HEADER_MAGIC:#x}, got {0:#x}")]
    InvalidMagic(u32),
    #[error("Unsupported version: {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_hdr_sz: u16,
    pub chunk_hdr_sz: u16,
    pub blk_sz: u32,
    pub total_blks: u32,
    pub total_chunks: u32,
    pub image_checksum: u32,
}

impl SparseHeader {
    pub const SIZE: usize = 28;

    pub fn decode(buf: &[u8]) -> Result<Self, SparseError> {
        if buf.len() < Self::SIZE {
            return Err(SparseError::HeaderTooShort(buf.len()));
        }

        let magic = LittleEndian::read_u32(&buf[0..4]);
        if magic != SPARSE_HEADER_MAGIC {
            return Err(SparseError::InvalidMagic(magic));
        }

        let major_version = LittleEndian::read_u16(&buf[4..6]);
        let minor_version = LittleEndian::read_u16(&buf[6..8]);
        if major_version != 1 {
            return Err(SparseError::UnsupportedVersion {
                major: major_version,
                minor: minor_version,
            });
        }

        let file_hdr_sz = LittleEndian::read_u16(&buf[8..10]);
        let chunk_hdr_sz = LittleEndian::read_u16(&buf[10..12]);
        let blk_sz = LittleEndian::read_u32(&buf[12..16]);
        let total_blks = LittleEndian::read_u32(&buf[16..20]);
        let total_chunks = LittleEndian::read_u32(&buf[20..24]);
        let image_checksum = LittleEndian::read_u32(&buf[24..28]);

        Ok(Self {
            magic,
            major_version,
            minor_version,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
            image_checksum,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseChunkHeader {
    pub chunk_type: u16,
    pub reserved1: u16,
    pub chunk_sz: u32,
    pub total_sz: u32,
}

impl SparseChunkHeader {
    pub const SIZE: usize = 12;

    pub fn decode(buf: &[u8]) -> Result<Self, SparseError> {
        if buf.len() < Self::SIZE {
            return Err(SparseError::HeaderTooShort(buf.len()));
        }
        let chunk_type = LittleEndian::read_u16(&buf[0..2]);
        let reserved1 = LittleEndian::read_u16(&buf[2..4]);
        let chunk_sz = LittleEndian::read_u32(&buf[4..8]);
        let total_sz = LittleEndian::read_u32(&buf[8..12]);

        Ok(Self {
            chunk_type,
            reserved1,
            chunk_sz,
            total_sz,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_header_decode() {
        let mut buf = [0u8; 28];
        LittleEndian::write_u32(&mut buf[0..4], SPARSE_HEADER_MAGIC);
        LittleEndian::write_u16(&mut buf[4..6], 1); // major
        LittleEndian::write_u16(&mut buf[6..8], 0); // minor
        LittleEndian::write_u16(&mut buf[8..10], 28);
        LittleEndian::write_u16(&mut buf[10..12], 12);
        LittleEndian::write_u32(&mut buf[12..16], 4096);
        LittleEndian::write_u32(&mut buf[16..20], 1024);
        LittleEndian::write_u32(&mut buf[20..24], 5);
        LittleEndian::write_u32(&mut buf[24..28], 0);

        let hdr = SparseHeader::decode(&buf).unwrap();
        assert_eq!(hdr.blk_sz, 4096);
        assert_eq!(hdr.total_blks, 1024);
        assert_eq!(hdr.total_chunks, 5);
    }
}
