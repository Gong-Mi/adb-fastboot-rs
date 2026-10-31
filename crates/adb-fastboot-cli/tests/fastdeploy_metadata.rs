//! Offline tests for the fastdeploy `APKMetaData` computation.
//!
//! AOSP: `fastdeploy/deploypatchgenerator/patch_utils.cpp:34-80` and
//! `apk_archive.cpp:209-417`. The fixture zip is embedded as bytes so the
//! expected offsets/sizes/MD5s are fixed constants, not recomputed by the code
//! under test.

#[path = "../src/client/fastdeploy.rs"]
mod fastdeploy;

use fastdeploy::{
    calculate_local_file_entry_size, extract_metadata_from_apk, locate_central_directory,
    md5_digest, metadata_from_central_directory, parse_central_directory_record, ApkEntryMeta,
    FastDeployError,
};

/// Two stored entries, built once with Python's `zipfile` (fixed 1980-01-01
/// timestamps, no extra fields, no data descriptors):
///
/// * `classes.dex`   — 4 bytes, local header at 0
/// * `resources.arsc` — 3 bytes, local header at 45
const FIXTURE_APK_HEX: &str = concat!(
    "504b0304140000000000000021005aa39c7c04000000040000000b000000636c61737365732e646578deadbeef50",
    "4b0304140000000000000021001d80bc5503000000030000000e0000007265736f75726365732e61727363010203",
    "504b01021400140000000000000021005aa39c7c04000000040000000b0000000000000000000000800100000000",
    "636c61737365732e646578504b01021400140000000000000021001d80bc5503000000030000000e000000000000",
    "000000000080012d0000007265736f75726365732e61727363504b05060000000002000200750000005c00000000",
    "00",
);

fn fixture_apk() -> Vec<u8> {
    assert_eq!(FIXTURE_APK_HEX.len(), 462, "fixture hex must stay complete");
    (0..FIXTURE_APK_HEX.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&FIXTURE_APK_HEX[index..index + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn entry(md5_hex: &str, data_offset: i64, data_size: i64) -> ApkEntryMeta {
    let mut md5 = [0u8; 16];
    for (index, byte) in md5.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&md5_hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    ApkEntryMeta {
        md5,
        data_offset,
        data_size,
    }
}

#[test]
fn md5_matches_rfc1321_vectors() {
    assert_eq!(hex(&md5_digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5_digest(b"a")), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(hex(&md5_digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(&md5_digest(b"message digest")),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
    assert_eq!(
        hex(&md5_digest(b"abcdefghijklmnopqrstuvwxyz")),
        "c3fcd3d76192e4007dfb496cca67e13b"
    );
    assert_eq!(
        hex(&md5_digest(b"The quick brown fox jumps over the lazy dog")),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
    // Crosses the 64-byte block boundary with a non-trivial tail.
    assert_eq!(
        hex(&md5_digest(
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        )),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}

#[test]
fn extract_metadata_matches_fixed_apk() {
    let apk = fixture_apk();
    let metadata = extract_metadata_from_apk(&apk, "base.apk").unwrap();

    assert_eq!(metadata.absolute_path, "base.apk");
    assert_eq!(
        metadata.entries,
        vec![
            // MD5 of the central directory record for "classes.dex".
            entry("d57095036749fca3b0e0af6e8d8fec6a", 0, 45),
            // MD5 of the central directory record for "resources.arsc".
            entry("c5877b5ab62f1816652282ac7d97c80b", 45, 47),
        ]
    );

    // APKMetaData proto: path (field 1), then two APKEntry messages (field 2)
    // with md5 (1), dataOffset (2), dataSize (3); proto3 omits the zero offset.
    assert_eq!(
        hex(&metadata.encode_proto()),
        concat!(
            "0a08626173652e61706b",
            "12140a10d57095036749fca3b0e0af6e8d8fec6a182d",
            "12160a10c5877b5ab62f1816652282ac7d97c80b102d182f",
        )
    );
}

#[test]
fn central_directory_record_semantics_match_aosp() {
    let apk = fixture_apk();
    let (offset, size) = locate_central_directory(&apk).unwrap();
    assert_eq!((offset, size), (92, 117));

    let cd = &apk[offset..offset + size];
    let (consumed, first) = parse_central_directory_record(cd).unwrap();
    assert_eq!(consumed, 57);
    assert_eq!(first.data_offset, 0);
    // Stored entry: AOSP takes `uncompressed_size` before the local header pass.
    assert_eq!(first.data_size, 4);
    assert_eq!(first.md5_hex(), "d57095036749fca3b0e0af6e8d8fec6a");

    let (consumed, second) = parse_central_directory_record(&cd[57..]).unwrap();
    assert_eq!(consumed, 60);
    assert_eq!(second.data_offset, 45);
    assert_eq!(second.data_size, 3);

    // AOSP's loop stops on a record with a bad signature and keeps what it has.
    let mut partial = cd.to_vec();
    partial.extend_from_slice(&[0u8; 46]);
    let metadata = metadata_from_central_directory(&partial, "device.apk");
    assert_eq!(metadata.entries.len(), 2);

    let metadata = metadata_from_central_directory(&[0u8; 46], "device.apk");
    assert!(metadata.entries.is_empty());
}

#[test]
fn missing_or_out_of_bounds_eocd_is_an_error() {
    assert_eq!(
        extract_metadata_from_apk(b"not a zip at all", "x").unwrap_err(),
        FastDeployError::MissingEndOfCentralDirectory
    );

    let mut apk = vec![0u8; 22];
    apk[0..4].copy_from_slice(&0x0605_4B50u32.to_le_bytes());
    apk[12..16].copy_from_slice(&10u32.to_le_bytes()); // central directory size
    apk[16..20].copy_from_slice(&1000u32.to_le_bytes()); // offset past EOF
    assert_eq!(
        extract_metadata_from_apk(&apk, "x").unwrap_err(),
        FastDeployError::InvalidCentralDirectory
    );
}

#[test]
fn archive_truncated_before_the_central_directory_is_an_error() {
    let apk = fixture_apk();
    let truncated = &apk[..50];
    assert_eq!(
        extract_metadata_from_apk(truncated, "x").unwrap_err(),
        FastDeployError::MissingEndOfCentralDirectory
    );
    assert_eq!(
        calculate_local_file_entry_size(&[], 0, 0).unwrap_err(),
        FastDeployError::InvalidLocalHeader(0)
    );
}

#[test]
fn local_header_size_mismatch_is_detected() {
    let mut apk = fixture_apk();
    let (offset, _) = locate_central_directory(&apk).unwrap();
    // First CD record, `uncompressed_size` at +24 (stored entry): claim 5 bytes
    // while the local header still says 4.
    apk[offset + 24..offset + 28].copy_from_slice(&5u32.to_le_bytes());

    match extract_metadata_from_apk(&apk, "x").unwrap_err() {
        FastDeployError::DataSizeMismatch {
            offset: 0,
            cd_size: 5,
            local_size: 4,
        } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Local file header + 4 data bytes + optional data-descriptor signature.
fn entry_with_data_descriptor(with_signature: bool) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&0x0403_4B50u32.to_le_bytes()); // signature
    entry.extend_from_slice(&20u16.to_le_bytes()); // version_needed
    entry.extend_from_slice(&0x0008u16.to_le_bytes()); // gpb_flags: data descriptor
    entry.extend_from_slice(&0u16.to_le_bytes()); // compression_method: stored
    entry.extend_from_slice(&0u16.to_le_bytes()); // last_mod_time
    entry.extend_from_slice(&0u16.to_le_bytes()); // last_mod_date
    entry.extend_from_slice(&0u32.to_le_bytes()); // crc32
    entry.extend_from_slice(&0u32.to_le_bytes()); // compressed_size (in descriptor)
    entry.extend_from_slice(&0u32.to_le_bytes()); // uncompressed_size (in descriptor)
    entry.extend_from_slice(&3u16.to_le_bytes()); // file_name_length
    entry.extend_from_slice(&0u16.to_le_bytes()); // extra_field_length
    entry.extend_from_slice(b"a.b");
    entry.extend_from_slice(b"data");

    if with_signature {
        entry.extend_from_slice(&0x0807_4B50u32.to_le_bytes());
    }
    entry.extend_from_slice(&0u32.to_le_bytes()); // crc32
    entry.extend_from_slice(&4u32.to_le_bytes()); // compressed_size
    entry.extend_from_slice(&4u32.to_le_bytes()); // uncompressed_size
    entry
}

#[test]
fn data_descriptor_sizes_match_aosp() {
    // 30-byte header + 3-byte name + 4-byte data + 16-byte descriptor with the
    // optional 0x08074b50 signature, or 12 bytes without it.
    let with_signature = entry_with_data_descriptor(true);
    assert_eq!(
        calculate_local_file_entry_size(&with_signature, 0, 4).unwrap(),
        53
    );

    let without_signature = entry_with_data_descriptor(false);
    assert_eq!(
        calculate_local_file_entry_size(&without_signature, 0, 4).unwrap(),
        49
    );

    assert_eq!(
        calculate_local_file_entry_size(&with_signature, 0, 5).unwrap_err(),
        FastDeployError::DataSizeMismatch {
            offset: 0,
            cd_size: 5,
            local_size: 4,
        }
    );
    assert_eq!(
        calculate_local_file_entry_size(&with_signature, 0, 1 << 30).unwrap_err(),
        FastDeployError::InvalidDataDescriptor((1 << 30) + 33)
    );
}
