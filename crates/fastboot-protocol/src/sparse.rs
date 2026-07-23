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
    #[error("Invalid file header size: expected >= 28, got {0}")]
    InvalidFileHeaderSize(u16),
    #[error("Invalid chunk header size: expected >= 12, got {0}")]
    InvalidChunkHeaderSize(u16),
    #[error("Max download size too small: max {max_size}, min required {min_required}")]
    MaxDownloadSizeTooSmall { max_size: usize, min_required: usize },
    #[error("Unaligned chunk data: length {len} is not a multiple of block size {blk_sz}")]
    UnalignedChunkData { len: usize, blk_sz: u32 },
    #[error("Invalid block size: {0}")]
    InvalidBlockSize(u32),
    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(u32),
    #[error("Buffer too short for chunk payload: expected {expected}, got {got}")]
    ChunkPayloadTooShort { expected: usize, got: usize },
    #[error("Unknown chunk type: {0:#x}")]
    UnknownChunkType(u16),
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

    pub fn new(blk_sz: u32, total_blks: u32, total_chunks: u32) -> Self {
        Self {
            magic: SPARSE_HEADER_MAGIC,
            major_version: 1,
            minor_version: 0,
            file_hdr_sz: Self::SIZE as u16,
            chunk_hdr_sz: SparseChunkHeader::SIZE as u16,
            blk_sz,
            total_blks,
            total_chunks,
            image_checksum: 0,
        }
    }

    pub fn encode(&self) -> [u8; 28] {
        let mut buf = [0u8; 28];
        LittleEndian::write_u32(&mut buf[0..4], self.magic);
        LittleEndian::write_u16(&mut buf[4..6], self.major_version);
        LittleEndian::write_u16(&mut buf[6..8], self.minor_version);
        LittleEndian::write_u16(&mut buf[8..10], self.file_hdr_sz);
        LittleEndian::write_u16(&mut buf[10..12], self.chunk_hdr_sz);
        LittleEndian::write_u32(&mut buf[12..16], self.blk_sz);
        LittleEndian::write_u32(&mut buf[16..20], self.total_blks);
        LittleEndian::write_u32(&mut buf[20..24], self.total_chunks);
        LittleEndian::write_u32(&mut buf[24..28], self.image_checksum);
        buf
    }

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
        if file_hdr_sz < Self::SIZE as u16 {
            return Err(SparseError::InvalidFileHeaderSize(file_hdr_sz));
        }

        let chunk_hdr_sz = LittleEndian::read_u16(&buf[10..12]);
        if chunk_hdr_sz < SparseChunkHeader::SIZE as u16 {
            return Err(SparseError::InvalidChunkHeaderSize(chunk_hdr_sz));
        }

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

    pub fn new(chunk_type: u16, chunk_sz: u32, total_sz: u32) -> Self {
        Self {
            chunk_type,
            reserved1: 0,
            chunk_sz,
            total_sz,
        }
    }

    pub fn encode(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        LittleEndian::write_u16(&mut buf[0..2], self.chunk_type);
        LittleEndian::write_u16(&mut buf[2..4], self.reserved1);
        LittleEndian::write_u32(&mut buf[4..8], self.chunk_sz);
        LittleEndian::write_u32(&mut buf[8..12], self.total_sz);
        buf
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseChunk {
    pub chunk_type: u16,
    pub chunk_blocks: u32,
    pub payload: Vec<u8>,
}

impl SparseChunk {
    pub fn total_size(&self) -> usize {
        SparseChunkHeader::SIZE + self.payload.len()
    }

    pub fn raw(data: Vec<u8>, blk_sz: u32) -> Result<Self, SparseError> {
        if blk_sz == 0 {
            return Err(SparseError::InvalidBlockSize(0));
        }
        if data.is_empty() {
            return Err(SparseError::InvalidChunkSize(0));
        }
        if data.len() % (blk_sz as usize) != 0 {
            return Err(SparseError::UnalignedChunkData {
                len: data.len(),
                blk_sz,
            });
        }
        let chunk_blocks = (data.len() / (blk_sz as usize)) as u32;
        Ok(Self {
            chunk_type: CHUNK_TYPE_RAW,
            chunk_blocks,
            payload: data,
        })
    }

    pub fn fill(fill_val: u32, blocks: u32) -> Result<Self, SparseError> {
        if blocks == 0 {
            return Err(SparseError::InvalidChunkSize(0));
        }
        let mut payload = vec![0u8; 4];
        LittleEndian::write_u32(&mut payload, fill_val);
        Ok(Self {
            chunk_type: CHUNK_TYPE_FILL,
            chunk_blocks: blocks,
            payload,
        })
    }

    pub fn dont_care(blocks: u32) -> Result<Self, SparseError> {
        if blocks == 0 {
            return Err(SparseError::InvalidChunkSize(0));
        }
        Ok(Self {
            chunk_type: CHUNK_TYPE_DONT_CARE,
            chunk_blocks: blocks,
            payload: Vec::new(),
        })
    }

    pub fn crc32(crc: u32) -> Result<Self, SparseError> {
        let mut payload = vec![0u8; 4];
        LittleEndian::write_u32(&mut payload, crc);
        Ok(Self {
            chunk_type: CHUNK_TYPE_CRC32,
            chunk_blocks: 0,
            payload,
        })
    }

    pub fn fill_value(&self) -> Option<u32> {
        if self.chunk_type == CHUNK_TYPE_FILL && self.payload.len() == 4 {
            Some(LittleEndian::read_u32(&self.payload))
        } else {
            None
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let total_sz = self.total_size() as u32;
        let hdr = SparseChunkHeader::new(self.chunk_type, self.chunk_blocks, total_sz);
        let mut buf = Vec::with_capacity(self.total_size());
        buf.extend_from_slice(&hdr.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseChunkBuilder {
    pub block_size: u32,
}

impl SparseChunkBuilder {
    pub fn new(block_size: u32) -> Self {
        Self { block_size }
    }

    pub fn raw(&self, data: Vec<u8>) -> Result<SparseChunk, SparseError> {
        SparseChunk::raw(data, self.block_size)
    }

    pub fn fill(&self, fill_val: u32, blocks: u32) -> Result<SparseChunk, SparseError> {
        SparseChunk::fill(fill_val, blocks)
    }

    pub fn dont_care(&self, blocks: u32) -> Result<SparseChunk, SparseError> {
        SparseChunk::dont_care(blocks)
    }

    pub fn crc32(&self, crc: u32) -> Result<SparseChunk, SparseError> {
        SparseChunk::crc32(crc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseFile {
    pub header: SparseHeader,
    pub chunks: Vec<SparseChunk>,
}

impl SparseFile {
    pub fn new(blk_sz: u32) -> Self {
        Self {
            header: SparseHeader::new(blk_sz, 0, 0),
            chunks: Vec::new(),
        }
    }

    pub fn add_chunk(&mut self, chunk: SparseChunk) {
        self.header.total_blks += chunk.chunk_blocks;
        self.chunks.push(chunk);
        self.header.total_chunks = self.chunks.len() as u32;
    }

    pub fn total_blocks(&self) -> u32 {
        self.chunks.iter().map(|c| c.chunk_blocks).sum()
    }

    pub fn total_size(&self) -> usize {
        SparseHeader::SIZE + self.chunks.iter().map(|c| c.total_size()).sum::<usize>()
    }

    pub fn encode(&self) -> Vec<u8> {
        let total_blks = self.total_blocks();
        let total_chunks = self.chunks.len() as u32;

        let mut header = self.header;
        header.total_blks = total_blks;
        header.total_chunks = total_chunks;

        let mut buf = Vec::with_capacity(self.total_size());
        buf.extend_from_slice(&header.encode());

        for chunk in &self.chunks {
            buf.extend_from_slice(&chunk.encode());
        }

        buf
    }

    pub fn from_raw(raw_data: &[u8], blk_sz: u32) -> Self {
        let blk_sz = if blk_sz == 0 { 4096 } else { blk_sz };
        let mut file = Self::new(blk_sz);

        if raw_data.is_empty() {
            return file;
        }

        let rem = raw_data.len() % (blk_sz as usize);
        let padded_len = if rem == 0 {
            raw_data.len()
        } else {
            raw_data.len() + (blk_sz as usize - rem)
        };

        let mut data = Vec::with_capacity(padded_len);
        data.extend_from_slice(raw_data);
        if rem != 0 {
            data.resize(padded_len, 0);
        }

        let chunk_builder = SparseChunkBuilder::new(blk_sz);
        if let Ok(chunk) = chunk_builder.raw(data) {
            file.add_chunk(chunk);
        }

        file
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let total_bytes = self.header.total_blks as usize * self.header.blk_sz as usize;
        let mut raw = Vec::with_capacity(total_bytes);
        for chunk in &self.chunks {
            match chunk.chunk_type {
                CHUNK_TYPE_RAW => {
                    raw.extend_from_slice(&chunk.payload);
                }
                CHUNK_TYPE_FILL => {
                    let fill_bytes = chunk.chunk_blocks as usize * self.header.blk_sz as usize;
                    if chunk.payload.len() == 4 {
                        let fill_val = LittleEndian::read_u32(&chunk.payload);
                        let pattern = fill_val.to_le_bytes();
                        for _ in 0..(fill_bytes / 4) {
                            raw.extend_from_slice(&pattern);
                        }
                    } else {
                        raw.resize(raw.len() + fill_bytes, 0);
                    }
                }
                CHUNK_TYPE_DONT_CARE => {
                    let dont_care_bytes = chunk.chunk_blocks as usize * self.header.blk_sz as usize;
                    raw.resize(raw.len() + dont_care_bytes, 0);
                }
                CHUNK_TYPE_CRC32 => {}
                _ => {}
            }
        }
        raw
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, SparseError> {
        let header = SparseHeader::decode(buf)?;
        let mut offset = header.file_hdr_sz as usize;
        let mut chunks = Vec::with_capacity(header.total_chunks as usize);

        for _ in 0..header.total_chunks {
            if offset + (header.chunk_hdr_sz as usize) > buf.len() {
                return Err(SparseError::HeaderTooShort(buf.len()));
            }

            let chunk_hdr = SparseChunkHeader::decode(&buf[offset..])?;
            let payload_offset = offset + (header.chunk_hdr_sz as usize);
            if (chunk_hdr.total_sz as usize) < (header.chunk_hdr_sz as usize) {
                return Err(SparseError::InvalidChunkHeaderSize(chunk_hdr.total_sz as u16));
            }
            let payload_len = (chunk_hdr.total_sz as usize) - (header.chunk_hdr_sz as usize);

            if payload_offset + payload_len > buf.len() {
                return Err(SparseError::ChunkPayloadTooShort {
                    expected: payload_offset + payload_len,
                    got: buf.len(),
                });
            }

            match chunk_hdr.chunk_type {
                CHUNK_TYPE_RAW => {
                    let expected_len = chunk_hdr.chunk_sz as usize * header.blk_sz as usize;
                    if payload_len != expected_len {
                        return Err(SparseError::ChunkPayloadTooShort {
                            expected: expected_len,
                            got: payload_len,
                        });
                    }
                }
                CHUNK_TYPE_FILL => {
                    if payload_len != 4 {
                        return Err(SparseError::ChunkPayloadTooShort {
                            expected: 4,
                            got: payload_len,
                        });
                    }
                }
                CHUNK_TYPE_DONT_CARE => {
                    if payload_len != 0 {
                        return Err(SparseError::ChunkPayloadTooShort {
                            expected: 0,
                            got: payload_len,
                        });
                    }
                }
                CHUNK_TYPE_CRC32 => {
                    if payload_len != 4 {
                        return Err(SparseError::ChunkPayloadTooShort {
                            expected: 4,
                            got: payload_len,
                        });
                    }
                }
                other => return Err(SparseError::UnknownChunkType(other)),
            }

            let payload = buf[payload_offset..payload_offset + payload_len].to_vec();
            chunks.push(SparseChunk {
                chunk_type: chunk_hdr.chunk_type,
                chunk_blocks: chunk_hdr.chunk_sz,
                payload,
            });

            offset += chunk_hdr.total_sz as usize;
        }

        Ok(Self { header, chunks })
    }

    pub fn split(&self, max_size: usize) -> Result<Vec<Self>, SparseError> {
        let blk_sz = self.header.blk_sz as usize;
        if blk_sz == 0 {
            return Err(SparseError::InvalidBlockSize(0));
        }

        let min_required = SparseHeader::SIZE + SparseChunkHeader::SIZE + blk_sz;
        if max_size < min_required {
            return Err(SparseError::MaxDownloadSizeTooSmall {
                max_size,
                min_required,
            });
        }

        let mut splits = Vec::new();
        let mut current_file = Self::new(self.header.blk_sz);

        for chunk in &self.chunks {
            let mut remaining_blocks = chunk.chunk_blocks;
            let mut raw_offset = 0;

            while remaining_blocks > 0 || chunk.chunk_type == CHUNK_TYPE_CRC32 {
                let current_len = current_file.total_size();
                let avail = max_size.saturating_sub(current_len);

                match chunk.chunk_type {
                    CHUNK_TYPE_RAW => {
                        let avail_payload = avail.saturating_sub(SparseChunkHeader::SIZE);
                        let blocks_that_fit = avail_payload / blk_sz;

                        if blocks_that_fit == 0 {
                            if !current_file.chunks.is_empty() {
                                splits.push(current_file);
                                current_file = Self::new(self.header.blk_sz);
                                continue;
                            } else {
                                return Err(SparseError::MaxDownloadSizeTooSmall {
                                    max_size,
                                    min_required,
                                });
                            }
                        }

                        let take_blocks = std::cmp::min(remaining_blocks, blocks_that_fit as u32);
                        let take_bytes = take_blocks as usize * blk_sz;

                        let slice_payload = chunk.payload[raw_offset..raw_offset + take_bytes].to_vec();
                        current_file.add_chunk(SparseChunk {
                            chunk_type: CHUNK_TYPE_RAW,
                            chunk_blocks: take_blocks,
                            payload: slice_payload,
                        });

                        remaining_blocks -= take_blocks;
                        raw_offset += take_bytes;
                    }
                    CHUNK_TYPE_FILL => {
                        if avail < SparseChunkHeader::SIZE + 4 {
                            if !current_file.chunks.is_empty() {
                                splits.push(current_file);
                                current_file = Self::new(self.header.blk_sz);
                                continue;
                            } else {
                                return Err(SparseError::MaxDownloadSizeTooSmall {
                                    max_size,
                                    min_required,
                                });
                            }
                        }

                        current_file.add_chunk(SparseChunk {
                            chunk_type: CHUNK_TYPE_FILL,
                            chunk_blocks: remaining_blocks,
                            payload: chunk.payload.clone(),
                        });
                        remaining_blocks = 0;
                    }
                    CHUNK_TYPE_DONT_CARE => {
                        if avail < SparseChunkHeader::SIZE {
                            if !current_file.chunks.is_empty() {
                                splits.push(current_file);
                                current_file = Self::new(self.header.blk_sz);
                                continue;
                            } else {
                                return Err(SparseError::MaxDownloadSizeTooSmall {
                                    max_size,
                                    min_required,
                                });
                            }
                        }

                        current_file.add_chunk(SparseChunk {
                            chunk_type: CHUNK_TYPE_DONT_CARE,
                            chunk_blocks: remaining_blocks,
                            payload: Vec::new(),
                        });
                        remaining_blocks = 0;
                    }
                    CHUNK_TYPE_CRC32 => {
                        if avail < SparseChunkHeader::SIZE + 4 {
                            if !current_file.chunks.is_empty() {
                                splits.push(current_file);
                                current_file = Self::new(self.header.blk_sz);
                                continue;
                            } else {
                                return Err(SparseError::MaxDownloadSizeTooSmall {
                                    max_size,
                                    min_required,
                                });
                            }
                        }

                        current_file.add_chunk(SparseChunk {
                            chunk_type: CHUNK_TYPE_CRC32,
                            chunk_blocks: 0,
                            payload: chunk.payload.clone(),
                        });
                        break;
                    }
                    other => return Err(SparseError::UnknownChunkType(other)),
                }
            }
        }

        if !current_file.chunks.is_empty() {
            splits.push(current_file);
        }

        Ok(splits)
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

    #[test]
    fn test_sparse_chunk_header_decode() {
        let mut buf = [0u8; 12];
        LittleEndian::write_u16(&mut buf[0..2], CHUNK_TYPE_RAW);
        LittleEndian::write_u16(&mut buf[2..4], 0);
        LittleEndian::write_u32(&mut buf[4..8], 10); // 10 blocks
        LittleEndian::write_u32(&mut buf[8..12], 12 + 40960); // header + payload

        let chunk = SparseChunkHeader::decode(&buf).unwrap();
        assert_eq!(chunk.chunk_type, CHUNK_TYPE_RAW);
        assert_eq!(chunk.chunk_sz, 10);
        assert_eq!(chunk.total_sz, 40972);
    }

    #[test]
    fn test_sparse_header_invalid_magic() {
        let buf = [0u8; 28];
        assert!(matches!(SparseHeader::decode(&buf), Err(SparseError::InvalidMagic(0))));
    }

    #[test]
    fn test_sparse_header_invalid_header_sizes() {
        let mut buf = [0u8; 28];
        LittleEndian::write_u32(&mut buf[0..4], SPARSE_HEADER_MAGIC);
        LittleEndian::write_u16(&mut buf[4..6], 1); // major
        LittleEndian::write_u16(&mut buf[6..8], 0); // minor

        // Test invalid file_hdr_sz (< 28)
        LittleEndian::write_u16(&mut buf[8..10], 20);
        LittleEndian::write_u16(&mut buf[10..12], 12);
        assert_eq!(
            SparseHeader::decode(&buf),
            Err(SparseError::InvalidFileHeaderSize(20))
        );

        // Test invalid chunk_hdr_sz (< 12)
        LittleEndian::write_u16(&mut buf[8..10], 28);
        LittleEndian::write_u16(&mut buf[10..12], 8);
        assert_eq!(
            SparseHeader::decode(&buf),
            Err(SparseError::InvalidChunkHeaderSize(8))
        );
    }

    #[test]
    fn test_sparse_chunk_builder() {
        let builder = SparseChunkBuilder::new(4096);
        let raw_data = vec![0xABu8; 4096];
        let chunk_raw = builder.raw(raw_data.clone()).unwrap();
        assert_eq!(chunk_raw.chunk_type, CHUNK_TYPE_RAW);
        assert_eq!(chunk_raw.chunk_blocks, 1);
        assert_eq!(chunk_raw.payload, raw_data);

        let chunk_fill = builder.fill(0x12345678, 5).unwrap();
        assert_eq!(chunk_fill.chunk_type, CHUNK_TYPE_FILL);
        assert_eq!(chunk_fill.chunk_blocks, 5);
        assert_eq!(chunk_fill.payload, vec![0x78, 0x56, 0x34, 0x12]);

        let chunk_dont_care = builder.dont_care(10).unwrap();
        assert_eq!(chunk_dont_care.chunk_type, CHUNK_TYPE_DONT_CARE);
        assert_eq!(chunk_dont_care.chunk_blocks, 10);
        assert!(chunk_dont_care.payload.is_empty());
    }

    #[test]
    fn test_sparse_file_encode_decode_roundtrip() {
        let builder = SparseChunkBuilder::new(4096);
        let mut file = SparseFile::new(4096);

        let raw1 = vec![0x11u8; 4096 * 2];
        file.add_chunk(builder.raw(raw1.clone()).unwrap());
        file.add_chunk(builder.fill(0xDEADBEEF, 10).unwrap());
        file.add_chunk(builder.dont_care(5).unwrap());

        let encoded = file.encode();
        let decoded = SparseFile::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.header.blk_sz, 4096);
        assert_eq!(decoded.header.total_blks, 17);
        assert_eq!(decoded.header.total_chunks, 3);
        assert_eq!(decoded.chunks.len(), 3);

        assert_eq!(decoded.chunks[0].chunk_type, CHUNK_TYPE_RAW);
        assert_eq!(decoded.chunks[0].chunk_blocks, 2);
        assert_eq!(decoded.chunks[0].payload, raw1);

        assert_eq!(decoded.chunks[1].chunk_type, CHUNK_TYPE_FILL);
        assert_eq!(decoded.chunks[1].chunk_blocks, 10);

        assert_eq!(decoded.chunks[2].chunk_type, CHUNK_TYPE_DONT_CARE);
        assert_eq!(decoded.chunks[2].chunk_blocks, 5);
    }

    #[test]
    fn test_sparse_file_split_large_raw() {
        // Create 12 KB raw image (3 blocks of 4096)
        let mut raw_data = Vec::new();
        for i in 0..3 {
            raw_data.extend(vec![i as u8 + 1; 4096]);
        }

        let sparse_file = SparseFile::from_raw(&raw_data, 4096);
        assert_eq!(sparse_file.total_blocks(), 3);

        // max_size = 8500 bytes.
        // Each block + headers in RAW chunk = 40 + 4096 = 4136.
        // 2 blocks = 40 + 8192 = 8232 <= 8500.
        // 3 blocks = 40 + 12288 = 12328 > 8500.
        // Expect split into 2 files: first with 2 blocks, second with 1 block.
        let max_size = 8500;
        let splits = sparse_file.split(max_size).unwrap();
        assert_eq!(splits.len(), 2);

        assert_eq!(splits[0].total_blocks(), 2);
        assert!(splits[0].encode().len() <= max_size);
        assert_eq!(splits[0].chunks[0].payload[0..4096], raw_data[0..4096]);
        assert_eq!(splits[0].chunks[0].payload[4096..8192], raw_data[4096..8192]);

        assert_eq!(splits[1].total_blocks(), 1);
        assert!(splits[1].encode().len() <= max_size);
        assert_eq!(splits[1].chunks[0].payload, raw_data[8192..12288]);
    }

    #[test]
    fn test_sparse_file_split_max_size_too_small() {
        let raw_data = vec![0x55u8; 4096];
        let sparse_file = SparseFile::from_raw(&raw_data, 4096);
        // max_size too small (< 28 + 12 + 4096 = 4136)
        let res = sparse_file.split(4000);
        assert!(matches!(res, Err(SparseError::MaxDownloadSizeTooSmall { .. })));
    }

    #[test]
    fn test_fill_chunk_fill_value_helper() {
        let builder = SparseChunkBuilder::new(4096);
        let chunk = builder.fill(0xCAFEBABE, 8).unwrap();
        assert_eq!(chunk.chunk_type, CHUNK_TYPE_FILL);
        assert_eq!(chunk.chunk_blocks, 8);
        assert_eq!(chunk.fill_value(), Some(0xCAFEBABE));

        let raw_chunk = builder.raw(vec![0u8; 4096]).unwrap();
        assert_eq!(raw_chunk.fill_value(), None);
    }

    #[test]
    fn test_sparse_file_with_fill_to_raw() {
        let builder = SparseChunkBuilder::new(4096);
        let mut file = SparseFile::new(4096);

        let raw_bytes = vec![0x12u8; 4096];
        file.add_chunk(builder.raw(raw_bytes.clone()).unwrap());
        file.add_chunk(builder.fill(0xAABBCCDD, 2).unwrap());
        file.add_chunk(builder.dont_care(1).unwrap());

        assert_eq!(file.total_blocks(), 4);
        let unsparsed = file.to_raw();
        assert_eq!(unsparsed.len(), 4 * 4096);
        assert_eq!(&unsparsed[0..4096], raw_bytes.as_slice());

        // Check fill pattern repeated across 2 blocks (8192 bytes = 2048 x u32)
        let fill_pat = 0xAABBCCDDu32.to_le_bytes();
        for chunk_idx in 0..2048 {
            let offset = 4096 + chunk_idx * 4;
            assert_eq!(&unsparsed[offset..offset + 4], &fill_pat);
        }

        // Check dont_care block (4096 zero bytes)
        assert_eq!(&unsparsed[4096 + 8192..], &vec![0u8; 4096]);
    }

    #[test]
    fn test_sparse_file_split_with_fill_chunks() {
        let builder = SparseChunkBuilder::new(4096);
        let mut file = SparseFile::new(4096);

        // RAW chunk: 2 blocks (2 * 4096 = 8192 payload bytes) -> total chunk size = 12 + 8192 = 8204
        let raw_data = vec![0xFFu8; 8192];
        file.add_chunk(builder.raw(raw_data).unwrap());
        // FILL chunk: 100 blocks -> total chunk size = 12 + 4 = 16 bytes
        file.add_chunk(builder.fill(0x12345678, 100).unwrap());

        // Total sparse file size = 28 + 8204 + 16 = 8248 bytes.
        // Split with max_size = 8240 bytes (fits header + RAW chunk of 2 blocks = 28 + 8204 = 8232 bytes, but NOT the fill chunk).
        let max_size = 8240;
        let splits = file.split(max_size).unwrap();
        assert_eq!(splits.len(), 2);

        // First file: RAW chunk
        assert_eq!(splits[0].chunks.len(), 1);
        assert_eq!(splits[0].chunks[0].chunk_type, CHUNK_TYPE_RAW);
        assert_eq!(splits[0].chunks[0].chunk_blocks, 2);
        assert!(splits[0].encode().len() <= max_size);

        // Second file: FILL chunk
        assert_eq!(splits[1].chunks.len(), 1);
        assert_eq!(splits[1].chunks[0].chunk_type, CHUNK_TYPE_FILL);
        assert_eq!(splits[1].chunks[0].chunk_blocks, 100);
        assert_eq!(splits[1].chunks[0].fill_value(), Some(0x12345678));
        assert!(splits[1].encode().len() <= max_size);
    }

    #[test]
    fn test_sparse_file_invalid_fill_payload_len() {
        let mut buf = Vec::new();
        // File header
        let hdr = SparseHeader::new(4096, 1, 1);
        buf.extend_from_slice(&hdr.encode());

        // Chunk header with CHUNK_TYPE_FILL, chunk_sz = 1 block, total_sz = 12 + 8 = 20 (payload_len = 8, invalid for FILL)
        let chunk_hdr = SparseChunkHeader::new(CHUNK_TYPE_FILL, 1, 20);
        buf.extend_from_slice(&chunk_hdr.encode());
        buf.extend_from_slice(&[0u8; 8]); // 8 bytes instead of 4

        let res = SparseFile::from_bytes(&buf);
        assert!(matches!(res, Err(SparseError::ChunkPayloadTooShort { expected: 4, got: 8 })));
    }
}
