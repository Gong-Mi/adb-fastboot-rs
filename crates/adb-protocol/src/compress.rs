use crate::constants::{SYNC_FLAG_BROTLI, SYNC_FLAG_LZ4, SYNC_FLAG_NONE, SYNC_FLAG_ZSTD};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    Compress(String),
    #[error("Decompression failed: {0}")]
    Decompress(String),
    #[error("Unknown compression type: {0}")]
    UnknownType(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Brotli,
    LZ4,
    Zstd,
}

impl CompressionType {
    /// Convert to SYNC_FLAG_* constant
    pub fn to_flag(self) -> u32 {
        match self {
            CompressionType::None => SYNC_FLAG_NONE,
            CompressionType::Brotli => SYNC_FLAG_BROTLI,
            CompressionType::LZ4 => SYNC_FLAG_LZ4,
            CompressionType::Zstd => SYNC_FLAG_ZSTD,
        }
    }

    /// Convert from SYNC_FLAG_* constant
    pub fn from_flag(flag: u32) -> Result<Self, CompressionError> {
        match flag {
            SYNC_FLAG_NONE => Ok(CompressionType::None),
            SYNC_FLAG_BROTLI => Ok(CompressionType::Brotli),
            SYNC_FLAG_LZ4 => Ok(CompressionType::LZ4),
            SYNC_FLAG_ZSTD => Ok(CompressionType::Zstd),
            _ => Err(CompressionError::UnknownType(flag)),
        }
    }
}

/// Compress data using the specified compression type.
/// For CompressionType::None, returns the input unchanged.
pub fn compress(ctype: CompressionType, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match ctype {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Brotli => {
            let mut out = Vec::new();
            brotli::BrotliCompress(
                &mut std::io::BufReader::new(data),
                &mut out,
                &brotli::enc::BrotliEncoderParams::default(),
            )
            .map_err(|e| CompressionError::Compress(e.to_string()))?;
            Ok(out)
        }
        CompressionType::LZ4 => {
            let compressed = lz4_flex::compress_prepend_size(data);
            Ok(compressed)
        }
        CompressionType::Zstd => {
            let compressed =
                zstd::encode_all(data, 3).map_err(|e| CompressionError::Compress(e.to_string()))?;
            Ok(compressed)
        }
    }
}

/// Decompress data using the specified compression type.
/// For CompressionType::None, returns the input unchanged.
pub fn decompress(ctype: CompressionType, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match ctype {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Brotli => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::BufReader::new(data), &mut out)
                .map_err(|e| CompressionError::Decompress(e.to_string()))?;
            Ok(out)
        }
        CompressionType::LZ4 => {
            let decompressed = lz4_flex::decompress_size_prepended(data)
                .map_err(|e| CompressionError::Decompress(e.to_string()))?;
            Ok(decompressed)
        }
        CompressionType::Zstd => {
            let decompressed = zstd::decode_all(data)
                .map_err(|e| CompressionError::Decompress(e.to_string()))?;
            Ok(decompressed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_type_flag_roundtrip() {
        for (ct, flag) in &[
            (CompressionType::None, SYNC_FLAG_NONE),
            (CompressionType::Brotli, SYNC_FLAG_BROTLI),
            (CompressionType::LZ4, SYNC_FLAG_LZ4),
            (CompressionType::Zstd, SYNC_FLAG_ZSTD),
        ] {
            assert_eq!(ct.to_flag(), *flag);
            assert_eq!(CompressionType::from_flag(*flag).unwrap(), *ct);
        }
    }

    #[test]
    fn test_compress_decompress_none() {
        let data = b"hello world";
        let compressed = compress(CompressionType::None, data).unwrap();
        assert_eq!(compressed, data);
        let decompressed = decompress(CompressionType::None, &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_decompress_lz4() {
        let data = b"hello world, this is a test of LZ4 compression in adb sendrecv_v2";
        let compressed = compress(CompressionType::LZ4, data).unwrap();
        assert!(compressed.len() <= data.len() + 8, "LZ4 should not expand much");
        let decompressed = decompress(CompressionType::LZ4, &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_decompress_brotli() {
        let data = b"hello world, this is a test of brotli compression in adb sendrecv_v2";
        let compressed = compress(CompressionType::Brotli, data).unwrap();
        let decompressed = decompress(CompressionType::Brotli, &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_decompress_zstd() {
        let data = b"hello world, this is a test of zstd compression in adb sendrecv_v2";
        let compressed = compress(CompressionType::Zstd, data).unwrap();
        let decompressed = decompress(CompressionType::Zstd, &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_from_flag_unknown_type() {
        let result = CompressionType::from_flag(0xFF);
        assert!(result.is_err());
        assert!(matches!(result, Err(CompressionError::UnknownType(0xFF))));
    }
}
