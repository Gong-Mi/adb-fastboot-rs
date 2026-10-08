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
    #[error("Logical block count mismatch: header {expected}, chunks {got}")]
    BlockCountMismatch { expected: u32, got: u64 },
    #[error("Unknown chunk type: {0:#x}")]
    UnknownChunkType(u16),
    #[error("Chunk count mismatch: header {expected}, chunks {got}")]
    ChunkCountMismatch { expected: u32, got: usize },
    #[error("Sparse size arithmetic overflow: {0}")]
    SizeOverflow(&'static str),
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
        let header = Self {
            magic: LittleEndian::read_u32(&buf[0..4]),
            major_version: LittleEndian::read_u16(&buf[4..6]),
            minor_version: LittleEndian::read_u16(&buf[6..8]),
            file_hdr_sz: LittleEndian::read_u16(&buf[8..10]),
            chunk_hdr_sz: LittleEndian::read_u16(&buf[10..12]),
            blk_sz: LittleEndian::read_u32(&buf[12..16]),
            total_blks: LittleEndian::read_u32(&buf[16..20]),
            total_chunks: LittleEndian::read_u32(&buf[20..24]),
            image_checksum: LittleEndian::read_u32(&buf[24..28]),
        };
        header.validate_format()?;
        Ok(header)
    }

    fn validate_format(&self) -> Result<(), SparseError> {
        if self.magic != SPARSE_HEADER_MAGIC {
            return Err(SparseError::InvalidMagic(self.magic));
        }
        if self.major_version != 1 {
            return Err(SparseError::UnsupportedVersion {
                major: self.major_version,
                minor: self.minor_version,
            });
        }
        if self.file_hdr_sz < Self::SIZE as u16 {
            return Err(SparseError::InvalidFileHeaderSize(self.file_hdr_sz));
        }
        if self.chunk_hdr_sz < SparseChunkHeader::SIZE as u16 {
            return Err(SparseError::InvalidChunkHeaderSize(self.chunk_hdr_sz));
        }
        Ok(())
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

    /// Structural validation shared by parsing and resparse. Checksums are
    /// deliberately not verified (the existing libsparse crc=false contract).
    /// CRC32 has four payload bytes but must contribute zero output blocks.
    /// Empty files remain valid; zero-length data chunks do not.
    fn validate(&self) -> Result<(), SparseError> {
        self.header.validate_format()?;
        let blk_sz = self.header.blk_sz as usize;
        if blk_sz == 0 || blk_sz % 4 != 0 {
            return Err(SparseError::InvalidBlockSize(self.header.blk_sz));
        }
        if self.chunks.len() != self.header.total_chunks as usize {
            return Err(SparseError::ChunkCountMismatch {
                expected: self.header.total_chunks,
                got: self.chunks.len(),
            });
        }
        let mut total_blocks = 0u64;
        let mut wire_size = self.header.file_hdr_sz as usize;
        for chunk in &self.chunks {
            let expected = match chunk.chunk_type {
                CHUNK_TYPE_RAW => (chunk.chunk_blocks as usize)
                    .checked_mul(blk_sz)
                    .ok_or(SparseError::SizeOverflow("RAW block bytes"))?,
                CHUNK_TYPE_FILL | CHUNK_TYPE_CRC32 => 4,
                CHUNK_TYPE_DONT_CARE => 0,
                other => return Err(SparseError::UnknownChunkType(other)),
            };
            if chunk.chunk_type == CHUNK_TYPE_CRC32 {
                if chunk.chunk_blocks != 0 {
                    return Err(SparseError::InvalidChunkSize(chunk.chunk_blocks));
                }
            } else if chunk.chunk_blocks == 0 {
                return Err(SparseError::InvalidChunkSize(0));
            }
            if chunk.payload.len() != expected {
                return Err(SparseError::ChunkPayloadTooShort {
                    expected,
                    got: chunk.payload.len(),
                });
            }
            // FILL and DONT_CARE expand without a corresponding wire payload;
            // check their logical byte lengths as well as RAW's multiplication.
            (chunk.chunk_blocks as usize)
                .checked_mul(blk_sz)
                .ok_or(SparseError::SizeOverflow("logical chunk bytes"))?;
            let chunk_size = (self.header.chunk_hdr_sz as usize)
                .checked_add(chunk.payload.len())
                .ok_or(SparseError::SizeOverflow("chunk wire size"))?;
            u32::try_from(chunk_size).map_err(|_| SparseError::SizeOverflow("chunk total_sz"))?;
            wire_size = wire_size
                .checked_add(chunk_size)
                .ok_or(SparseError::SizeOverflow("file wire size"))?;
            total_blocks = total_blocks
                .checked_add(u64::from(chunk.chunk_blocks))
                .ok_or(SparseError::SizeOverflow("logical block sum"))?;
        }
        if total_blocks != u64::from(self.header.total_blks) {
            return Err(SparseError::BlockCountMismatch {
                expected: self.header.total_blks,
                got: total_blocks,
            });
        }
        (self.header.total_blks as usize)
            .checked_mul(blk_sz)
            .ok_or(SparseError::SizeOverflow("logical image bytes"))?;
        Ok(())
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, SparseError> {
        let header = SparseHeader::decode(buf)?;
        let mut offset = header.file_hdr_sz as usize;
        if offset > buf.len() {
            return Err(SparseError::HeaderTooShort(buf.len()));
        }
        // total_chunks is untrusted. Do not reserve memory from it before
        // proving the corresponding chunk headers actually exist in the input.
        let mut chunks = Vec::new();
        for _ in 0..header.total_chunks {
            let payload_offset = offset
                .checked_add(header.chunk_hdr_sz as usize)
                .ok_or(SparseError::SizeOverflow("chunk header offset"))?;
            if payload_offset > buf.len() {
                return Err(SparseError::HeaderTooShort(buf.len()));
            }
            let chunk_hdr = SparseChunkHeader::decode(&buf[offset..payload_offset])?;
            let payload_len = (chunk_hdr.total_sz as usize)
                .checked_sub(header.chunk_hdr_sz as usize)
                .ok_or(SparseError::InvalidChunkSize(chunk_hdr.total_sz))?;
            let end = payload_offset
                .checked_add(payload_len)
                .ok_or(SparseError::SizeOverflow("chunk payload end"))?;
            let payload =
                buf.get(payload_offset..end)
                    .ok_or(SparseError::ChunkPayloadTooShort {
                        expected: end,
                        got: buf.len(),
                    })?;
            chunks.push(SparseChunk {
                chunk_type: chunk_hdr.chunk_type,
                chunk_blocks: chunk_hdr.chunk_sz,
                payload: payload.to_vec(),
            });
            offset = end;
        }
        let file = Self { header, chunks };
        file.validate()?;
        Ok(file)
    }

    /// Resparse downloads for repeated flashes of the same partition. Each
    /// download starts at block zero, so gaps (including other downloads' data)
    /// must be DONT_CARE chunks and every download must retain the full span.
    /// This mirrors libsparse sparse_file_resparse/write_all_blocks, not payload
    /// concatenation. Original whole-image checksums do not describe a split.
    pub fn split(&self, max_size: usize) -> Result<Vec<Self>, SparseError> {
        // Public structs may be mutated after parsing. Reuse the same strict
        // validator rather than maintaining a second set of format semantics.
        self.validate()?;
        let blk_sz = self.header.blk_sz as usize;
        let span = self.header.total_blks;
        let header_size = SparseHeader::SIZE;
        let chunk_header = SparseChunkHeader::SIZE;
        let too_small = |min_required| SparseError::MaxDownloadSizeTooSmall {
            max_size,
            min_required,
        };
        if max_size < header_size {
            return Err(too_small(header_size));
        }

        let finish = |mut file: Self, end: u32| -> Result<Self, SparseError> {
            if end < span {
                file.add_chunk(SparseChunk::dont_care(span - end)?);
            }
            if file.total_size() > max_size {
                return Err(too_small(file.total_size()));
            }
            Ok(file)
        };
        let mut splits = Vec::new();
        let mut current = Self::new(self.header.blk_sz);
        let mut current_size = header_size;
        let mut current_end = 0;
        let mut logical_block = 0;

        for chunk in &self.chunks {
            if chunk.chunk_type == CHUNK_TYPE_DONT_CARE {
                logical_block += chunk.chunk_blocks;
                continue;
            }
            if chunk.chunk_type == CHUNK_TYPE_CRC32 {
                // A full-image CRC is not a CRC of any partial download. As in
                // libsparse's CRC-disabled writer, emit no stale checksum.
                continue;
            }
            let mut remaining_blocks = chunk.chunk_blocks;
            let mut raw_offset = 0;
            while remaining_blocks > 0 {
                let gap = logical_block - current_end;
                let gap_size = if gap > 0 { chunk_header } else { 0 };
                let base_size = current_size + gap_size + chunk_header;
                let tail_size = if logical_block + remaining_blocks < span {
                    chunk_header
                } else {
                    0
                };
                let take_blocks = if chunk.chunk_type == CHUNK_TYPE_RAW {
                    // A partial RAW needs a trailing skip even if the original
                    // RAW ends at the image boundary. Include metadata BEFORE
                    // choosing how many blocks fit in max-download-size.
                    let room = max_size.saturating_sub(base_size);
                    let all_fit = remaining_blocks as usize <= room / blk_sz;
                    let room = if all_fit && tail_size == 0 {
                        room
                    } else {
                        room.saturating_sub(chunk_header)
                    };
                    remaining_blocks.min((room / blk_sz).min(u32::MAX as usize) as u32)
                } else if base_size + 4 + tail_size <= max_size {
                    remaining_blocks
                } else {
                    0
                };

                if take_blocks == 0 {
                    if !current.chunks.is_empty() {
                        // Flush only a file containing actual data. An empty
                        // download cannot make progress; fail instead of retry.
                        splits.push(finish(current, current_end)?);
                        current = Self::new(self.header.blk_sz);
                        current_size = header_size;
                        current_end = 0;
                        continue;
                    }
                    let payload_size = if chunk.chunk_type == CHUNK_TYPE_RAW { blk_sz } else { 4 };
                    let min_tail = if logical_block + 1 < span && chunk.chunk_type == CHUNK_TYPE_RAW {
                        chunk_header
                    } else {
                        tail_size
                    };
                    return Err(too_small(base_size + payload_size + min_tail));
                }

                if gap > 0 {
                    current.add_chunk(SparseChunk::dont_care(gap)?);
                }
                let payload = if chunk.chunk_type == CHUNK_TYPE_RAW {
                    let take_bytes = take_blocks as usize * blk_sz;
                    let payload = chunk.payload[raw_offset..raw_offset + take_bytes].to_vec();
                    raw_offset += take_bytes;
                    payload
                } else {
                    chunk.payload.clone()
                };
                current_size = base_size + payload.len();
                current.add_chunk(SparseChunk {
                    chunk_type: chunk.chunk_type,
                    chunk_blocks: take_blocks,
                    payload,
                });
                logical_block += take_blocks;
                current_end = logical_block;
                remaining_blocks -= take_blocks;
            }
        }
        if !current.chunks.is_empty() || splits.is_empty() {
            splits.push(finish(current, current_end)?);
        }
        Ok(splits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent wire fixtures from AOSP libsparse/sparse_format.h and
    // sparse_read.cpp @545d2487e38192a2ce25040897ced877cf6b4f53. Never use
    // SparseFile::encode: it rewrites total_blks and would hide bad headers.
    fn sparse_wire(block_size: u32, total_blocks: u32, chunks: &[(u16, u32, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(0xed26ff3au32.to_le_bytes());
        for value in [1u16, 0, 28, 12] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [block_size, total_blocks, chunks.len() as u32, 0] {
            bytes.extend(value.to_le_bytes());
        }
        for &(kind, blocks, payload) in chunks {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(0u16.to_le_bytes());
            bytes.extend(blocks.to_le_bytes());
            bytes.extend((12 + payload.len() as u32).to_le_bytes());
            bytes.extend(payload);
        }
        bytes
    }

    #[test]
    fn test_parse_rejects_wrong_logical_block_sum_without_split() {
        for (declared, chunks, got) in [
            (2, vec![(0xcac3, 1, &[][..])], 1),
            (1, vec![(0xcac3, 2, &[][..])], 2),
            (1, vec![], 0),
            // Wide checked accumulation, not u32 wrapping back to zero.
            (
                0,
                vec![(0xcac3, u32::MAX, &[][..]), (0xcac3, 1, &[][..])],
                0x1_0000_0000,
            ),
        ] {
            assert_eq!(
                SparseFile::from_bytes(&sparse_wire(4096, declared, &chunks)),
                Err(SparseError::BlockCountMismatch {
                    expected: declared,
                    got
                })
            );
        }
    }

    #[test]
    fn test_parse_and_split_reject_the_same_bad_block_and_payload_contracts() {
        for (block_size, declared, chunks) in [
            (0, 0, vec![]),
            (6, 1, vec![(0xcac2, 1, &b"FILL"[..])]),
            (4096, 1, vec![(0xcac4, 1, &b"CRC!"[..])]),
            (4096, 0, vec![(0xcac1, 0, &[][..])]),
            (4096, 0, vec![(0xcac2, 0, &b"FILL"[..])]),
            (4096, 0, vec![(0xcac3, 0, &[][..])]),
            (4096, 1, vec![(0xcac1, 1, &b"SHORT"[..])]),
            (4096, 1, vec![(0xcac2, 1, &b"TOO LONG"[..])]),
            (4096, 1, vec![(0xcac3, 1, &b"x"[..])]),
            (4096, 0, vec![(0xcac4, 0, &b"x"[..])]),
            (4096, 0, vec![(0xffff, 0, &[][..])]),
            // Multiplication must not wrap to the tiny actual payload.
            (
                0xffff_fffc,
                0xffff_ffff,
                vec![(0xcac1, 0xffff_ffff, &[][..])],
            ),
        ] {
            let bytes = sparse_wire(block_size, declared, &chunks);
            let file = SparseFile {
                header: SparseHeader::decode(&bytes).unwrap(),
                chunks: chunks
                    .iter()
                    .map(|&(kind, blocks, payload)| SparseChunk {
                        chunk_type: kind,
                        chunk_blocks: blocks,
                        payload: payload.to_vec(),
                    })
                    .collect(),
            };
            let parsed = SparseFile::from_bytes(&bytes);
            let split = file.split(65536);
            assert!(parsed.is_err(), "parser accepted {file:?}");
            assert!(split.is_err(), "split accepted {file:?}");
            assert_eq!(
                parsed.unwrap_err(),
                split.unwrap_err(),
                "validation drift: {file:?}"
            );
        }
    }

    #[test]
    fn test_parse_checks_extended_header_bounds_even_for_empty_image() {
        let mut bytes = sparse_wire(4096, 0, &[]);
        bytes[8..10].copy_from_slice(&36u16.to_le_bytes());
        assert!(
            SparseFile::from_bytes(&bytes).is_err(),
            "missing extended header bytes"
        );
        bytes.extend([0; 8]);
        assert!(SparseFile::from_bytes(&bytes).unwrap().chunks.is_empty());
    }

    #[test]
    fn test_parse_rejects_crc_output_blocks_without_split() {
        let bytes = sparse_wire(4096, 1, &[(0xcac4, 1, &b"CRC!"[..])]);
        assert_eq!(
            SparseFile::from_bytes(&bytes),
            Err(SparseError::InvalidChunkSize(1))
        );
    }

    #[test]
    fn test_parse_framing_and_counts_fail_closed_without_large_reserves() {
        let mut bytes = sparse_wire(4096, 1, &[(0xcac3, 1, &[])]);
        bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            SparseFile::from_bytes(&bytes),
            Err(SparseError::HeaderTooShort(_))
        ));
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            SparseFile::from_bytes(&bytes),
            Err(SparseError::ChunkPayloadTooShort { .. })
        ));
        for size in [0u32, 1, 11] {
            bytes[36..40].copy_from_slice(&size.to_le_bytes());
            assert_eq!(
                SparseFile::from_bytes(&bytes),
                Err(SparseError::InvalidChunkSize(size))
            );
        }
        let bytes = sparse_wire(
            16,
            3,
            &[
                (0xcac1, 1, &[0x11; 16]),
                (0xcac2, 1, &b"FILL"[..]),
                (0xcac3, 1, &[]),
            ],
        );
        for end in 0..bytes.len() {
            assert!(
                SparseFile::from_bytes(&bytes[..end]).is_err(),
                "truncated image accepted at {end}"
            );
        }
        let mut file = SparseFile::from_bytes(&bytes).unwrap();
        file.header.total_chunks = 2;
        assert_eq!(
            file.split(65536),
            Err(SparseError::ChunkCountMismatch {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn test_parse_preserves_empty_fill_holes_extensions_and_unverified_crc() {
        let pattern = [0x78, 0x56, 0x34, 0x12];
        for bytes in [
            sparse_wire(4096, 0, &[]), // existing Rust empty-image contract
            sparse_wire(4096, 2, &[(0xcac2, 2, &pattern)]),
            sparse_wire(4096, 2, &[(0xcac3, 2, &[])]),
            sparse_wire(4096, 1, &[(0xcac3, 1, &[]), (0xcac4, 0, &pattern)]),
        ] {
            let file = SparseFile::from_bytes(&bytes).unwrap();
            for split in file.split(65536).unwrap() {
                assert_eq!(split.header.total_blks, file.header.total_blks);
            }
        }
        // Higher minor versions, reserved fields, extended headers and unchecked
        // checksum values remain accepted (libsparse import with crc=false).
        let mut bytes = sparse_wire(4096, 1, &[]);
        bytes[6..8].copy_from_slice(&7u16.to_le_bytes());
        bytes[8..10].copy_from_slice(&36u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&16u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        bytes.extend([0xa5; 8]);
        for (kind, blocks, payload) in [(0xcac3u16, 1u32, &[][..]), (0xcac4, 0, &pattern[..])] {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(0x1234u16.to_le_bytes());
            bytes.extend(blocks.to_le_bytes());
            bytes.extend((16 + payload.len() as u32).to_le_bytes());
            bytes.extend([0xa5; 4]);
            bytes.extend(payload);
        }
        let file = SparseFile::from_bytes(&bytes).unwrap();
        assert_eq!(file.header.image_checksum, 0xdeadbeef);
        assert_eq!(file.chunks[1].chunk_blocks, 0);
        assert_eq!(file.chunks[1].payload, pattern);
        let splits = file.split(65536).unwrap();
        assert_eq!(splits[0].header.image_checksum, 0);
        assert!(splits[0]
            .chunks
            .iter()
            .all(|chunk| chunk.chunk_type != CHUNK_TYPE_CRC32));
    }

    #[test]
    #[ignore = "requires installed AOSP-derived simg2img; no downloads or device access"]
    fn test_parse_simg2img_structural_oracle() {
        let directory =
            std::env::temp_dir().join(format!("sparse-parse-oracle-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let pattern = [0x78, 0x56, 0x34, 0x12];
        let cases = [
            (
                "short-span",
                sparse_wire(4096, 2, &[(0xcac3, 1, &[])]),
                false,
                vec![],
            ),
            (
                "long-span",
                sparse_wire(4096, 1, &[(0xcac3, 2, &[])]),
                false,
                vec![],
            ),
            (
                "raw-size",
                sparse_wire(4096, 1, &[(0xcac1, 1, &pattern)]),
                false,
                vec![],
            ),
            (
                "fill-size",
                sparse_wire(4096, 1, &[(0xcac2, 1, &pattern[..3])]),
                false,
                vec![],
            ),
            (
                "skip-size",
                sparse_wire(4096, 1, &[(0xcac3, 1, &pattern)]),
                false,
                vec![],
            ),
            (
                "crc-size",
                sparse_wire(4096, 1, &[(0xcac3, 1, &[]), (0xcac4, 0, &pattern[..3])]),
                false,
                vec![],
            ),
            (
                "block-alignment",
                sparse_wire(6, 1, &[(0xcac3, 1, &[])]),
                false,
                vec![],
            ),
            (
                "holes",
                sparse_wire(4096, 1, &[(0xcac3, 1, &[])]),
                true,
                vec![0; 4096],
            ),
            (
                "fill",
                sparse_wire(4096, 1, &[(0xcac2, 1, &pattern)]),
                true,
                pattern.repeat(1024),
            ),
            (
                "unchecked-crc",
                sparse_wire(4096, 1, &[(0xcac3, 1, &[]), (0xcac4, 0, &pattern)]),
                true,
                vec![0; 4096],
            ),
        ];
        for (name, bytes, accepted, expected) in cases {
            let input = directory.join(format!("{name}.sparse"));
            let output = directory.join(format!("{name}.raw"));
            std::fs::write(&input, &bytes).unwrap();
            let result = std::process::Command::new("simg2img")
                .arg(&input)
                .arg(&output)
                .output()
                .unwrap();
            eprintln!(
                "simg2img {name}: rc={:?}, stderr={}",
                result.status.code(),
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.status.success(), accepted, "oracle {name}");
            assert_eq!(
                SparseFile::from_bytes(&bytes).is_ok(),
                accepted,
                "Rust {name}"
            );
            if accepted {
                assert_partition_eq(&std::fs::read(output).unwrap(), &expected);
            }
        }
        // Empty Rust sparse files remain legal; AOSP's import API explicitly
        // rejects total_blks=0 (sparse_read.cpp:629), so do not claim parity there.
        std::fs::remove_dir_all(directory).unwrap();
    }

    // Independent wire interpreter: every flash starts at partition offset zero.
    // Do not use from_bytes/to_raw: DONT_CARE must seek, not zero old data.
    fn apply_sparse_download(bytes: &[u8], partition: &mut [u8]) -> u32 {
        let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        assert_eq!(u32_at(0), 0xed26ff3a);
        let block_size = u32_at(12) as usize;
        let span = u32_at(16);
        let mut wire_offset = u16_at(8) as usize;
        let chunk_header_size = u16_at(10) as usize;
        let mut partition_offset = 0;
        for _ in 0..u32_at(20) {
            let kind = u16_at(wire_offset);
            let length = u32_at(wire_offset + 4) as usize * block_size;
            let wire_size = u32_at(wire_offset + 8) as usize;
            let payload = &bytes[wire_offset + chunk_header_size..wire_offset + wire_size];
            assert!(partition_offset + length <= partition.len());
            match kind {
                0xcac1 => {
                    assert_eq!(payload.len(), length);
                    partition[partition_offset..partition_offset + length].copy_from_slice(payload);
                }
                0xcac2 => {
                    assert_eq!(payload.len(), 4);
                    for (index, byte) in partition[partition_offset..partition_offset + length].iter_mut().enumerate() {
                        *byte = payload[index % 4];
                    }
                }
                0xcac3 => assert!(payload.is_empty()),
                0xcac4 => {
                    assert_eq!(length, 0);
                    assert_eq!(payload.len(), 4);
                }
                _ => panic!("unexpected sparse chunk {kind:#x}"),
            }
            partition_offset += length;
            wire_offset += wire_size;
        }
        assert_eq!(wire_offset, bytes.len());
        assert_eq!(partition_offset, span as usize * block_size);
        span
    }

    fn assert_partition_eq(actual: &[u8], expected: &[u8]) {
        assert_eq!(actual.len(), expected.len());
        let mismatch = actual.iter().zip(expected).position(|(actual, expected)| actual != expected);
        assert_eq!(mismatch, None, "first differing partition byte: {mismatch:?}");
    }

    #[test]
    fn test_split_raw_preserves_final_partition_and_full_span() {
        let raw: Vec<u8> = (1..=3).flat_map(|value| vec![value; 4096]).collect();
        let file = SparseFile::from_raw(&raw, 4096);
        let splits = file.split(8500).unwrap();
        assert_eq!(splits.len(), 2);
        let mut partition = vec![0; raw.len()];
        let mut spans = Vec::new();
        for split in &splits {
            let wire = split.encode();
            assert!(wire.len() <= 8500);
            spans.push(apply_sparse_download(&wire, &mut partition));
        }
        assert_partition_eq(&partition, &raw);
        assert_eq!(spans, vec![3, 3]);
    }

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
        let raw: Vec<u8> = (1..=3).flat_map(|value| vec![value; 4096]).collect();
        let file = SparseFile::from_raw(&raw, 4096);
        for max_size in [4160, 8232, 8244, 8500, usize::MAX] {
            let mut partition = vec![0xa5; raw.len()];
            for split in file.split(max_size).unwrap() {
                let bytes = split.encode();
                assert!(bytes.len() <= max_size);
                assert_eq!(apply_sparse_download(&bytes, &mut partition), 3);
            }
            assert_partition_eq(&partition, &raw);
        }
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
        let mut file = SparseFile::new(4096);
        file.add_chunk(SparseChunk::raw(vec![0xff; 8192], 4096).unwrap());
        file.add_chunk(SparseChunk::fill(0x12345678, 100).unwrap());
        let splits = file.split(8240).unwrap();
        let mut expected = vec![0xff; 8192];
        expected.extend((0..102400).flat_map(|_| [0x78, 0x56, 0x34, 0x12]));
        let mut partition = vec![0xa5; expected.len()];
        for split in splits {
            assert!(split.encode().len() <= 8240);
            assert_eq!(apply_sparse_download(&split.encode(), &mut partition), 102);
        }
        assert_partition_eq(&partition, &expected);
    }

    #[test]
    fn test_split_raw_metadata_limits_and_padded_boundaries() {
        let limits = [0, 27, 28, 39, 40, 4135, 4136, 4147, 4148, 4159, 4160, 8231, 8232, 8243, 8244, 8500, usize::MAX];
        for blocks in 0..=8 {
            let raw: Vec<u8> = (0..blocks * 4096).map(|index| (index % 251 + 1) as u8).collect();
            let file = SparseFile::from_raw(&raw, 4096);
            let minimum = match blocks {
                0 => 28,
                1 => 4136,
                2 => 4148,
                _ => 4160, // middle download needs both prefix and suffix skips
            };
            for limit in limits {
                let result = file.split(limit);
                if limit < minimum {
                    assert!(matches!(result, Err(SparseError::MaxDownloadSizeTooSmall { .. })), "blocks={blocks}, limit={limit}");
                    continue;
                }
                let mut partition = vec![0xa5; raw.len()];
                for split in result.unwrap() {
                    let wire = split.encode();
                    assert!(wire.len() <= limit);
                    assert_eq!(apply_sparse_download(&wire, &mut partition) as usize, blocks);
                }
                assert_partition_eq(&partition, &raw);
            }
        }
        for length in [1, 4095, 4096, 4097] {
            let raw = vec![0x37; length];
            let file = SparseFile::from_raw(&raw, 4096);
            let mut expected = raw.clone();
            expected.resize(length.div_ceil(4096) * 4096, 0);
            let mut partition = vec![0xa5; expected.len()];
            for split in file.split(4160).unwrap() {
                assert_eq!(apply_sparse_download(&split.encode(), &mut partition), file.header.total_blks);
            }
            assert_partition_eq(&partition, &expected);
        }
    }

    fn mixed_fixture() -> (SparseFile, Vec<u8>) {
        let mut file = SparseFile::new(16);
        file.add_chunk(SparseChunk::dont_care(2).unwrap());
        file.add_chunk(SparseChunk::raw((1..=48).collect(), 16).unwrap());
        file.add_chunk(SparseChunk::fill(0x12345678, 2).unwrap());
        file.add_chunk(SparseChunk::dont_care(2).unwrap());
        file.add_chunk(SparseChunk::raw((49..=112).collect(), 16).unwrap());
        file.add_chunk(SparseChunk::dont_care(1).unwrap());
        let mut expected = vec![0xa5; 32];
        expected.extend(1..=48);
        expected.extend((0..8).flat_map(|_| [0x78, 0x56, 0x34, 0x12]));
        expected.extend(vec![0xa5; 32]);
        expected.extend(49..=112);
        expected.extend(vec![0xa5; 16]);
        (file, expected)
    }

    #[test]
    fn test_split_mixed_preserves_holes_full_span_and_prior_downloads() {
        let (file, expected) = mixed_fixture();
        for max_size in [80, 81, 96, 100, 112, usize::MAX] {
            let mut partition = vec![0xa5; expected.len()];
            for split in file.split(max_size).unwrap() {
                let wire = split.encode();
                assert!(wire.len() <= max_size);
                assert_eq!(apply_sparse_download(&wire, &mut partition), 14);
                // Re-splitting an already offset-preserving download must also
                // retain those offsets, including leading and trailing skips.
                let mut resplit_partition = vec![0xa5; expected.len()];
                for resplit in split.split(80).unwrap() {
                    assert!(resplit.encode().len() <= 80);
                    assert_eq!(apply_sparse_download(&resplit.encode(), &mut resplit_partition), 14);
                }
                let mut one_split_partition = vec![0xa5; expected.len()];
                apply_sparse_download(&wire, &mut one_split_partition);
                assert_partition_eq(&resplit_partition, &one_split_partition);
            }
            assert_partition_eq(&partition, &expected);
        }
    }

    #[test]
    fn test_split_empty_fill_only_and_dont_care_only_exact_limits() {
        let empty = SparseFile::from_raw(&[], 4096);
        assert_eq!(empty.split(28).unwrap()[0].encode().len(), 28);
        let mut holes = SparseFile::new(4096);
        holes.add_chunk(SparseChunk::dont_care(2).unwrap());
        let mut partition = vec![0xa5; 8192];
        assert_eq!(apply_sparse_download(&holes.split(40).unwrap()[0].encode(), &mut partition), 2);
        assert_partition_eq(&partition, &vec![0xa5; 8192]);
        assert!(holes.split(39).is_err());
        let mut fill = SparseFile::new(4096);
        fill.add_chunk(SparseChunk::fill(0x12345678, 2).unwrap());
        assert!(fill.split(43).is_err());
        let bytes = fill.split(44).unwrap()[0].encode();
        assert_eq!(apply_sparse_download(&bytes, &mut partition), 2);
        let expected: Vec<u8> = (0..2048).flat_map(|_| [0x78, 0x56, 0x34, 0x12]).collect();
        assert_partition_eq(&partition, &expected);
        let mut largest_span = SparseFile::new(4096);
        largest_span.add_chunk(SparseChunk::dont_care(u32::MAX).unwrap());
        let output = largest_span.split(40).unwrap();
        assert_eq!(output[0].header.total_blks, u32::MAX);
        assert_eq!(output[0].encode().len(), 40);
    }

    #[test]
    fn test_split_fill_only_metadata_boundary() {
        let mut file = SparseFile::new(16);
        for value in [0x11111111, 0x22222222, 0x33333333] {
            file.add_chunk(SparseChunk::fill(value, 2).unwrap());
        }
        let expected: Vec<u8> = [0x11, 0x22, 0x33].into_iter()
            .flat_map(|value| vec![value; 32]).collect();
        let mut partition = vec![0xa5; expected.len()];
        for split in file.split(68).unwrap() {
            assert!(split.encode().len() <= 68);
            assert_eq!(apply_sparse_download(&split.encode(), &mut partition), 6);
        }
        assert_partition_eq(&partition, &expected);
        assert!(file.split(55).is_err());
    }

    #[test]
    fn test_split_removes_stale_checksums_and_normalizes_extended_headers() {
        let (mut file, expected) = mixed_fixture();
        file.header.file_hdr_sz = 36;
        file.header.chunk_hdr_sz = 16;
        file.header.image_checksum = 0xdeadbeef;
        file.add_chunk(SparseChunk::crc32(0xdeadbeef).unwrap());
        // Build a genuinely extended on-wire image, then exercise the parser's
        // representation instead of relying on encode's canonical layout.
        let mut extended = file.header.encode().to_vec();
        extended.extend([0; 8]);
        for chunk in &file.chunks {
            let header = SparseChunkHeader::new(
                chunk.chunk_type, chunk.chunk_blocks, 16 + chunk.payload.len() as u32,
            );
            extended.extend(header.encode());
            extended.extend([0; 4]);
            extended.extend(&chunk.payload);
        }
        let file = SparseFile::from_bytes(&extended).unwrap();
        let mut partition = vec![0xa5; expected.len()];
        for split in file.split(80).unwrap() {
            assert_eq!(split.header.file_hdr_sz, 28);
            assert_eq!(split.header.chunk_hdr_sz, 12);
            assert_eq!(split.header.image_checksum, 0);
            assert!(split.chunks.iter().all(|chunk| chunk.chunk_type != CHUNK_TYPE_CRC32));
            apply_sparse_download(&split.encode(), &mut partition);
        }
        assert_partition_eq(&partition, &expected);
    }

    #[test]
    fn test_split_impossible_limits_and_malformed_chunks_terminate_with_errors() {
        // At 4148 the first RAW download fits but a middle download cannot:
        // it needs a prefix skip + RAW block + trailing skip (4160 bytes).
        // A retry loop flushing skip-only files would never make progress.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let raw = SparseFile::from_raw(&vec![1; 3 * 4096], 4096);
            for limit in [0, 28, 4136, 4148, 4159] {
                assert!(matches!(raw.split(limit), Err(SparseError::MaxDownloadSizeTooSmall { .. })));
            }
            assert!(SparseFile::new(0).split(10000).is_err());
            let invalid_chunks = [
                SparseChunk { chunk_type: CHUNK_TYPE_RAW, chunk_blocks: 1, payload: vec![] },
                SparseChunk { chunk_type: CHUNK_TYPE_FILL, chunk_blocks: 1, payload: vec![] },
                SparseChunk { chunk_type: CHUNK_TYPE_DONT_CARE, chunk_blocks: 0, payload: vec![] },
                SparseChunk { chunk_type: CHUNK_TYPE_CRC32, chunk_blocks: 1, payload: vec![0; 4] },
                SparseChunk { chunk_type: 0xffff, chunk_blocks: 0, payload: vec![] },
            ];
            for chunk in invalid_chunks {
                let mut file = SparseFile::new(4096);
                file.add_chunk(chunk);
                assert!(file.split(10000).is_err());
            }
            let mut wrong_span = raw;
            wrong_span.header.total_blks = 2;
            assert_eq!(wrong_span.split(8500), Err(SparseError::BlockCountMismatch { expected: 2, got: 3 }));
            sender.send(()).unwrap();
        });
        receiver.recv_timeout(std::time::Duration::from_secs(2)).expect("split must fail, never hang or panic");
    }

    #[test]
    #[ignore = "requires installed AOSP-derived simg2img; no downloads or device access"]
    fn test_split_simg2img_oracle() {
        let directory = std::env::temp_dir().join(format!("fastboot-sparse-oracle-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (mixed, mut expected_mixed) = mixed_fixture();
        // simg2img creates a zero-filled raw file; use zero for original holes.
        for range in [0..32, 112..144, 208..224] {
            expected_mixed[range].fill(0);
        }
        let raw: Vec<u8> = (1..=3).flat_map(|value| vec![value; 4096]).collect();
        for (name, file, limit, expected) in [
            ("raw", SparseFile::from_raw(&raw, 4096), 8500, raw),
            ("mixed", mixed, 80, expected_mixed),
        ] {
            let original = directory.join(format!("{name}.sparse"));
            std::fs::write(&original, file.encode()).unwrap();
            let original_raw = directory.join(format!("{name}-original.raw"));
            assert!(std::process::Command::new("simg2img").arg(&original).arg(&original_raw).status().unwrap().success());
            let mut command = std::process::Command::new("simg2img");
            for (index, split) in file.split(limit).unwrap().iter().enumerate() {
                let path = directory.join(format!("{name}-{index}.sparse"));
                std::fs::write(&path, split.encode()).unwrap();
                command.arg(path);
            }
            let reconstructed = directory.join(format!("{name}-split.raw"));
            assert!(command.arg(&reconstructed).status().unwrap().success());
            assert_partition_eq(&std::fs::read(original_raw).unwrap(), &expected);
            assert_partition_eq(&std::fs::read(reconstructed).unwrap(), &expected);
        }
        std::fs::remove_dir_all(directory).unwrap();
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
