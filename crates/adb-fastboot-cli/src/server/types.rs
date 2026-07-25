//! Block I/O utilities for ADB packet assembly.
//!
//! Mirrors AOSP `vendor/adb/types.cpp` IOVector — a scatter-gather buffer that
//! accumulates data as a list of blocks (Vec<Vec<u8>>) and supports efficient
//! front-drain without copying.  Used by `APacketReader` to handle split ADB
//! headers and payloads across multiple socket reads.

use std::cmp;

// ---------------------------------------------------------------------------
// IOVector — non-contiguous byte buffer
// ---------------------------------------------------------------------------

/// A scatter-gather byte buffer backed by a list of blocks.
///
/// Data is stored as a `Vec<Vec<u8>>` — each `append()` call adds a new block
/// rather than copying into a single contiguous buffer.  `drain_front()` and
/// `copy_to()` operate across block boundaries, so callers don't need to worry
/// about internal fragmentation.
///
/// This matches AOSP's `IOVector` from `types.cpp` and avoids O(n) copies when
/// draining small amounts of data from the front of a large buffer.
#[derive(Debug, Clone)]
pub struct IOVector {
    /// Individual data blocks (most recently appended is last).
    blocks: Vec<Vec<u8>>,
    /// How many bytes from the front of the first block have been logically
    /// consumed.  This lets us avoid re-allocating / shifting on every drain.
    front_skip: usize,
    /// Total bytes across all blocks (excluding front_skip).
    total_len: usize,
}

impl IOVector {
    /// Create an empty `IOVector`.
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            front_skip: 0,
            total_len: 0,
        }
    }

    /// Return `true` if the buffer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Return the total number of buffered bytes.
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Append a byte slice as a new block.
    ///
    /// The data is stored in its own `Vec<u8>` to avoid copying existing blocks.
    pub fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.blocks.push(data.to_vec());
        self.total_len += data.len();
    }

    /// Copy up to `dst.len()` bytes from `offset` (from the logical start of
    /// the buffer) into `dst`, **without** consuming them.
    ///
    /// Returns the number of bytes actually copied (may be less than `dst.len()`
    /// if the buffer has fewer bytes starting at `offset`).
    pub fn copy_to(&self, offset: usize, dst: &mut [u8]) -> usize {
        if offset >= self.total_len || dst.is_empty() {
            return 0;
        }

        let mut remaining = cmp::min(dst.len(), self.total_len - offset);
        let mut dst_offset = 0;
        // Position within the logical buffer (already consumed front_skip bytes
        // of the first block are invisible to the logical view).
        let mut logical_pos = 0;

        for block in &self.blocks {
            // The effective start of this block's data: if it's the first block,
            // its first `front_skip` bytes have been logically consumed.
            let block_data_start = if logical_pos == 0 {
                self.front_skip
            } else {
                0
            };
            let block_data_end = block.len();
            let block_logical_size = block_data_end - block_data_start;

            let block_start = logical_pos;
            let block_end = block_start + block_logical_size;

            // Skip blocks entirely before our offset
            if offset >= block_end {
                logical_pos = block_end;
                continue;
            }

            // This block contains (or starts at) the offset
            let block_relative_offset = if offset > block_start {
                // Offset is somewhere inside this block's logical data
                block_data_start + (offset - block_start)
            } else {
                // Offset is before this block — start from this block's beginning
                block_data_start
            };

            let available = block.len() - block_relative_offset;
            let to_copy = cmp::min(remaining, available);

            dst[dst_offset..dst_offset + to_copy]
                .copy_from_slice(&block[block_relative_offset..block_relative_offset + to_copy]);

            dst_offset += to_copy;
            remaining -= to_copy;
            logical_pos = block_end;

            if remaining == 0 {
                break;
            }
        }

        dst_offset
    }

    /// Peek at the first `len` bytes without consuming them.
    /// Returns `None` if fewer than `len` bytes are available.
    pub fn peek(&self, len: usize) -> Option<Vec<u8>> {
        if self.total_len < len {
            return None;
        }
        let mut buf = vec![0u8; len];
        self.copy_to(0, &mut buf);
        Some(buf)
    }

    /// Drain (consume) the first `len` bytes from the buffer.
    ///
    /// This is efficient — it skips bytes in the front block without copying,
    /// and only removes empty blocks when they are fully consumed.
    ///
    /// # Panics
    ///
    /// Panics if `len > self.total_len`.
    pub fn drain_front(&mut self, len: usize) {
        assert!(len <= self.total_len, "drain_front: {len} > total_len {}", self.total_len);

        if len == 0 {
            return;
        }

        let mut remaining = len;

        // Remove bytes from the front, block by block
        while remaining > 0 && !self.blocks.is_empty() {
            let first_block = &self.blocks[0];
            let available = first_block.len() - self.front_skip;

            if available <= remaining {
                // Consume the rest of this block
                remaining -= available;
                self.total_len -= available;
                self.blocks.remove(0);
                self.front_skip = 0;
            } else {
                // Partially consume this block
                self.front_skip += remaining;
                self.total_len -= remaining;
                remaining = 0;
            }
        }
    }

    /// Remove all buffered data.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.front_skip = 0;
        self.total_len = 0;
    }

    /// Coalesce all blocks into a single contiguous `Vec<u8>`.
    ///
    /// This is an O(n) copy.  Prefer `peek()` / `drain_front()` for partial
    /// access, and only call `coalesce()` when a contiguous view is required
    /// (e.g. before handing the payload to a decoder that expects `&[u8]`).
    pub fn coalesce(&mut self) -> Vec<u8> {
        if self.blocks.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.total_len);
        for block in &self.blocks {
            result.extend_from_slice(block);
        }
        self.blocks = vec![result];
        self.front_skip = 0;
        self.blocks[0].clone()
    }
}

impl Default for IOVector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_iovector() {
        let v = IOVector::new();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        let mut buf = [0u8; 4];
        assert_eq!(v.copy_to(0, &mut buf), 0);
    }

    #[test]
    fn test_append_and_peek() {
        let mut v = IOVector::new();
        v.append(b"hello ");
        v.append(b"world");
        assert!(!v.is_empty());
        assert_eq!(v.len(), 11);

        let peeked = v.peek(11).unwrap();
        assert_eq!(&peeked, b"hello world");
    }

    #[test]
    fn test_drain_front_partial() {
        let mut v = IOVector::new();
        v.append(b"hello ");
        v.append(b"world");

        v.drain_front(6);
        assert_eq!(v.len(), 5);
        let peeked = v.peek(5).unwrap();
        assert_eq!(&peeked, b"world");
    }

    #[test]
    fn test_drain_front_exact_block() {
        let mut v = IOVector::new();
        v.append(b"hello");

        v.drain_front(5);
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_drain_front_multiple_blocks() {
        let mut v = IOVector::new();
        v.append(b"abc");
        v.append(b"def");
        v.append(b"ghi");

        v.drain_front(7);
        assert_eq!(v.len(), 2);
        let peeked = v.peek(2).unwrap();
        assert_eq!(&peeked, b"hi");
    }

    #[test]
    fn test_copy_to_with_offset() {
        let mut v = IOVector::new();
        v.append(b"one ");
        v.append(b"two ");
        v.append(b"three");

        let mut buf = [0u8; 7];
        let n = v.copy_to(4, &mut buf);
        assert_eq!(n, 7);
        assert_eq!(&buf, b"two thr");
    }

    #[test]
    fn test_coalesce() {
        let mut v = IOVector::new();
        v.append(b"hello ");
        v.append(b"world ");

        let data = v.coalesce();
        assert_eq!(&data[..12], b"hello world ");

        // After coalesce, internal state should have 1 block
        assert_eq!(v.blocks.len(), 1);
    }

    #[test]
    fn test_append_empty() {
        let mut v = IOVector::new();
        v.append(b"");
        assert!(v.is_empty());

        v.append(b"a");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut v = IOVector::new();
        v.append(b"data");
        assert!(!v.is_empty());
        v.clear();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_drain_zero() {
        let mut v = IOVector::new();
        v.append(b"test");
        v.drain_front(0);
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn test_peek_not_enough_data() {
        let mut v = IOVector::new();
        v.append(b"short");
        assert!(v.peek(10).is_none());
    }
}
