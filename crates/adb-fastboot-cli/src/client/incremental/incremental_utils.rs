//! Port of AOSP `client/incremental_utils.cpp` pure functions: verity tree
//! sizing and `.idsig` v2 header parsing. No transport / device dependency —
//! fully offline-testable.
//!
//! Constants and algorithms mirror incremental_utils.h/.cpp exactly:
//! - kBlockSize = 4096, kDigestSize = 32 (SHA-256), kMaxSignatureSize = 8096
//!   (incrementalfs.h)
//! - `verity_tree_blocks_for_file` walks the hash-tree levels bottom-up
//!   (incremental_utils.cpp:44-62)
//! - `.idsig` layout (read_id_sig_headers, incremental_utils.cpp:142-162):
//!   [version:i32-le][hashingInfo:{len:i32-le,bytes}][signingInfo:{len,bytes}]
//!   [treeSize:i32-le] — the signature blob keeps the length prefixes inline.

/// AOSP `kBlockSize` (incremental_utils.h:35).
pub const BLOCK_SIZE: i64 = 4096;
/// AOSP `kDigestSize` = SHA-256 (incremental_utils.h:37).
pub const DIGEST_SIZE: i64 = 32;
/// AOSP `kMaxSignatureSize` (incremental_utils.h:38, incrementalfs.h).
pub const MAX_SIGNATURE_SIZE: usize = 8096;
/// AOSP `IDSIG` extension (incremental_utils.h:40).
pub const IDSIG_EXTENSION: &str = ".idsig";

/// AOSP `verity_tree_blocks_for_file` (incremental_utils.cpp:44-62).
pub fn verity_tree_blocks_for_file(file_size: i64) -> i64 {
    if file_size == 0 {
        return 0;
    }
    let hash_per_block = BLOCK_SIZE / DIGEST_SIZE;

    let mut total_tree_block_count: i64 = 0;
    let block_count = 1 + (file_size - 1) / BLOCK_SIZE;
    let mut hash_block_count = block_count;
    while hash_block_count > 1 {
        hash_block_count = (hash_block_count + hash_per_block - 1) / hash_per_block;
        total_tree_block_count += hash_block_count;
    }
    total_tree_block_count
}

/// AOSP `verity_tree_size_for_file` (incremental_utils.cpp:65-67).
pub fn verity_tree_size_for_file(file_size: i64) -> i64 {
    verity_tree_blocks_for_file(file_size) * BLOCK_SIZE
}

/// Result of parsing an `.idsig` header: the raw signature bytes (length
/// prefixes kept inline, ready for base64 encoding) and the verity tree size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSigHeaders {
    pub signature: Vec<u8>,
    pub tree_size: i32,
}

/// Port of AOSP `read_id_sig_headers` (incremental_utils.cpp:142-162).
///
/// Reads `[version:i32][hashingInfo:{len+bytes}][signingInfo:{len+bytes}]
/// [treeSize:i32]` from `reader`. The signature vector accumulates the raw
/// bytes including the embedded length prefixes, matching the C++ appender
/// callbacks; `tree_size` is byte-swapped from LE.
pub fn read_id_sig_headers(reader: &mut dyn std::io::Read) -> Result<IdSigHeaders, String> {
    fn read_i32(reader: &mut dyn std::io::Read) -> Result<i32, String> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer).map_err(|error| {
            format!(
                "Failed to read int: {}",
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    "End of file".to_string()
                } else {
                    error.to_string()
                }
            )
        })?;
        Ok(i32::from_le_bytes(buffer))
    }

    fn append_bytes_with_size(
        reader: &mut dyn std::io::Read,
        signature: &mut Vec<u8>,
        bytes_left: &mut usize,
    ) -> Result<(), String> {
        let size = read_i32(reader)?;
        if size < 0 || size as usize > *bytes_left {
            return Err(format!("Invalid size {size}"));
        }
        if size == 0 {
            return Ok(());
        }
        *bytes_left -= size as usize;
        signature.extend_from_slice(&size.to_le_bytes());
        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data).map_err(|error| {
            format!(
                "Failed to read data: {}",
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    "End of file".to_string()
                } else {
                    error.to_string()
                }
            )
        })?;
        signature.extend_from_slice(&data);
        Ok(())
    }

    let mut signature = Vec::new();
    let version = read_i32(reader)?; // version
    signature.extend_from_slice(&version.to_le_bytes());

    let mut max_size = MAX_SIGNATURE_SIZE - std::mem::size_of::<i32>();
    append_bytes_with_size(reader, &mut signature, &mut max_size)?; // hashingInfo
    append_bytes_with_size(reader, &mut signature, &mut max_size)?; // signingInfo

    let tree_size = read_i32(reader)?; // size of the verity tree
    Ok(IdSigHeaders {
        signature,
        tree_size,
    })
}

/// AOSP `validate_signature` (incremental.cpp:141-157): signature length
/// bound plus verity tree size agreement with the file size.
pub fn validate_signature(
    signature: &[u8],
    tree_size: i32,
    file_size: i64,
) -> Result<(), String> {
    if signature.len() > MAX_SIGNATURE_SIZE {
        return Err(format!(
            "Signature is too long: {}. Max allowed is {}",
            signature.len(),
            MAX_SIGNATURE_SIZE
        ));
    }
    let expected = verity_tree_size_for_file(file_size);
    if tree_size != expected as i32 {
        return Err(format!(
            "Verity tree size mismatch [was {tree_size}, expected {expected}]"
        ));
    }
    Ok(())
}

/// AOSP `requires_v4_signature` (incremental.cpp:120-124): APKs and .sdm
/// files must carry a v4 signature.
pub fn requires_v4_signature(file: &str) -> bool {
    file.to_ascii_lowercase().ends_with(".apk")
        || file.to_ascii_lowercase().ends_with("sdm")
}

/// AOSP `read_signature` (incremental.cpp:126-139): open `<file>.idsig`;
/// ENOENT means "no signature" (empty signature, tree size 0), other
/// errors are fatal.
pub fn read_signature(signature_file: &Path) -> Result<IdSigHeaders, String> {
    if !signature_file.exists() {
        // ENOENT → empty signature, matching AOSP read_signature.
        return Ok(IdSigHeaders {
            signature: Vec::new(),
            tree_size: 0,
        });
    }
    let mut reader = std::fs::File::open(signature_file).map_err(|error| {
        format!(
            "Failed to open signature file '{}': {}",
            signature_file.display(),
            error
        )
    })?;
    read_id_sig_headers(&mut reader)
}

/// Base64-encode signature bytes (AOSP `encode_signature`,
/// incremental.cpp:160-174).
pub fn encode_signature(signature: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(signature)
}

use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verity_tree_sizes_match_aosp_reference_values() {
        // Walked by hand against incremental_utils.cpp:44-62 (hash_per_block=128):
        assert_eq!(verity_tree_blocks_for_file(0), 0);
        // 1 block file: no tree levels above the leaf layer.
        assert_eq!(verity_tree_blocks_for_file(4096), 0);
        // 2 blocks → level1: (2+127)/128 = 1 → stop; total = 1.
        assert_eq!(verity_tree_blocks_for_file(8192), 1);
        // 4097 bytes = 2 blocks (rounds up) → same as 8192.
        assert_eq!(verity_tree_blocks_for_file(4097), 1);
        // 4096 blocks → level1: (4096+127)/128 = 32, level2: (32+127)/128 = 1;
        // total = 33.
        assert_eq!(verity_tree_blocks_for_file(4096 * 4096), 33);
        assert_eq!(verity_tree_size_for_file(4096 * 4096), 33 * 4096);
    }

    #[test]
    fn read_id_sig_headers_parses_v2_layout() {
        // Build a minimal .idsig header: version=2, hashingInfo=[4]abcd,
        // signingInfo=[3]xyz, treeSize=8192 (LE).
        let mut input = Vec::new();
        input.extend_from_slice(&2i32.to_le_bytes());
        input.extend_from_slice(&4i32.to_le_bytes());
        input.extend_from_slice(b"abcd");
        input.extend_from_slice(&3i32.to_le_bytes());
        input.extend_from_slice(b"xyz");
        input.extend_from_slice(&8192i32.to_le_bytes());
        input.extend_from_slice(b"TRAILING_TREE_BYTES");

        let headers = read_id_sig_headers(&mut input.as_slice()).unwrap();
        // Signature keeps length prefixes inline: 4 (version) + (4+4) + (4+3) bytes.
        assert_eq!(headers.signature.len(), 4 + (4 + 4) + (4 + 3));
        assert_eq!(&headers.signature[..4], &2i32.to_le_bytes());
        assert_eq!(&headers.signature[4..8], &4i32.to_le_bytes());
        assert_eq!(&headers.signature[8..12], b"abcd");
        assert_eq!(&headers.signature[12..16], &3i32.to_le_bytes());
        assert_eq!(&headers.signature[16..19], b"xyz");
        assert_eq!(headers.tree_size, 8192);
    }

    #[test]
    fn read_id_sig_headers_rejects_oversized_and_truncated() {
        // hashingInfo length beyond kMaxSignatureSize - 4.
        let mut input = Vec::new();
        input.extend_from_slice(&2i32.to_le_bytes());
        input.extend_from_slice(&((MAX_SIGNATURE_SIZE) as i32).to_le_bytes());
        assert!(read_id_sig_headers(&mut input.as_slice())
            .unwrap_err()
            .contains("Invalid size"));

        // Truncated before treeSize.
        let mut input = Vec::new();
        input.extend_from_slice(&2i32.to_le_bytes());
        input.extend_from_slice(&0i32.to_le_bytes());
        assert!(read_id_sig_headers(&mut input.as_slice())
            .unwrap_err()
            .contains("End of file"));
    }
}
