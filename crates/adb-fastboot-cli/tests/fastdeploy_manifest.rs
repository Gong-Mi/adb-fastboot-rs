//! Offline tests for the fastdeploy binary-XML / package-name helpers.
//!
//! AOSP: `client/fastdeploy.cpp:128-204` (`get_string_from_utf16`,
//! `get_package_name_from_apk`). Fixtures are built byte by byte so the tests
//! need no APK on disk and cover both string-pool encodings.

#[path = "../src/client/fastdeploy.rs"]
mod fastdeploy;

use std::io::Write;

use fastdeploy::{
    get_package_name_from_apk, get_string_from_utf16, parse_package_name, FastDeployError,
};

const NO_INDEX: u32 = 0xFFFF_FFFF;

fn u16v(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn u32v(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// `ResStringPool` chunk. `utf8` selects the UTF-8 flag and the UTF-8 entry
/// layout (two lengths + bytes); otherwise UTF-16 code units are stored.
fn string_pool(strings: &[&str], utf8: bool) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for string in strings {
        offsets.push(data.len() as u32);
        if utf8 {
            let bytes = string.as_bytes();
            let utf16_len = string.encode_utf16().count();
            assert!(
                utf16_len < 0x80 && bytes.len() < 0x80,
                "test string must use the short UTF-8 length form"
            );
            data.push(utf16_len as u8);
            data.push(bytes.len() as u8);
            data.extend_from_slice(bytes);
            data.push(0);
        } else {
            let units: Vec<u16> = string.encode_utf16().collect();
            assert!(units.len() < 0x8000, "test string must use the short UTF-16 length form");
            data.extend_from_slice(&u16v(units.len() as u16));
            for unit in units {
                data.extend_from_slice(&u16v(unit));
            }
            data.extend_from_slice(&u16v(0));
        }
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }

    let header_size: u16 = 28;
    let strings_start = header_size as usize + offsets.len() * 4;
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&u16v(0x0001)); // RES_STRING_POOL_TYPE
    chunk.extend_from_slice(&u16v(header_size));
    chunk.extend_from_slice(&u32v((strings_start + data.len()) as u32));
    chunk.extend_from_slice(&u32v(strings.len() as u32));
    chunk.extend_from_slice(&u32v(0)); // styleCount
    chunk.extend_from_slice(&u32v(if utf8 { 0x0000_0100 } else { 0 }));
    chunk.extend_from_slice(&u32v(strings_start as u32));
    chunk.extend_from_slice(&u32v(0)); // stylesStart
    for offset in offsets {
        chunk.extend_from_slice(&u32v(offset));
    }
    chunk.extend_from_slice(&data);
    chunk
}

struct TestAttr {
    name: u32,
    raw: u32,
    value_type: u8,
    data: u32,
}

fn string_attr(name: u32, value: u32) -> TestAttr {
    TestAttr {
        name,
        raw: value,
        value_type: 0x03,
        data: value,
    }
}

fn int_attr(name: u32, value: u32) -> TestAttr {
    TestAttr {
        name,
        raw: NO_INDEX,
        value_type: 0x10,
        data: value,
    }
}

/// `ResXMLTree_node` of type START_ELEMENT with a `ResXMLTree_attrExt`.
fn start_element(name: u32, attributes: &[TestAttr]) -> Vec<u8> {
    let header_size: u16 = 16;
    let size = 16 + 20 + 20 * attributes.len();
    let mut chunk = Vec::with_capacity(size);
    chunk.extend_from_slice(&u16v(0x0102));
    chunk.extend_from_slice(&u16v(header_size));
    chunk.extend_from_slice(&u32v(size as u32));
    chunk.extend_from_slice(&u32v(1)); // lineNumber
    chunk.extend_from_slice(&u32v(NO_INDEX)); // comment
    chunk.extend_from_slice(&u32v(NO_INDEX)); // ns
    chunk.extend_from_slice(&u32v(name));
    chunk.extend_from_slice(&u16v(20)); // attributeStart
    chunk.extend_from_slice(&u16v(20)); // attributeSize
    chunk.extend_from_slice(&u16v(attributes.len() as u16));
    chunk.extend_from_slice(&u16v(0)); // idIndex
    chunk.extend_from_slice(&u16v(0)); // classIndex
    chunk.extend_from_slice(&u16v(0)); // styleIndex
    for attribute in attributes {
        chunk.extend_from_slice(&u32v(NO_INDEX));
        chunk.extend_from_slice(&u32v(attribute.name));
        chunk.extend_from_slice(&u32v(attribute.raw));
        chunk.extend_from_slice(&u16v(8)); // Res_value.size
        chunk.push(0); // res0
        chunk.push(attribute.value_type);
        chunk.extend_from_slice(&u32v(attribute.data));
    }
    chunk
}

fn end_element(name: u32) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&u16v(0x0103));
    chunk.extend_from_slice(&u16v(16));
    chunk.extend_from_slice(&u32v(24));
    chunk.extend_from_slice(&u32v(1));
    chunk.extend_from_slice(&u32v(NO_INDEX));
    chunk.extend_from_slice(&u32v(NO_INDEX));
    chunk.extend_from_slice(&u32v(name));
    chunk
}

fn resource_map(ids: &[u32]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&u16v(0x0180));
    chunk.extend_from_slice(&u16v(8));
    chunk.extend_from_slice(&u32v(8 + 4 * ids.len() as u32));
    for id in ids {
        chunk.extend_from_slice(&u32v(*id));
    }
    chunk
}

fn xml_document(children: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = children.iter().map(Vec::len).sum();
    let mut document = Vec::with_capacity(8 + payload);
    document.extend_from_slice(&u16v(0x0003)); // RES_XML_TYPE
    document.extend_from_slice(&u16v(8));
    document.extend_from_slice(&u32v((8 + payload) as u32));
    for child in children {
        document.extend_from_slice(child);
    }
    document
}

fn namespace_chunk(chunk_type: u16) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&u16v(chunk_type));
    chunk.extend_from_slice(&u16v(16));
    chunk.extend_from_slice(&u32v(24));
    chunk.extend_from_slice(&u32v(1));
    chunk.extend_from_slice(&u32v(NO_INDEX));
    chunk.extend_from_slice(&u32v(0));
    chunk.extend_from_slice(&u32v(0));
    chunk
}

/// A manifest with a `package` string attribute and a typed `versionCode`.
fn manifest(strings: &[&str], utf8: bool) -> Vec<u8> {
    xml_document(&[
        namespace_chunk(0x0100), // START_NAMESPACE
        string_pool(strings, utf8),
        resource_map(&[0x0101_0003]),
        start_element(0, &[int_attr(3, 1), string_attr(1, 2)]),
        end_element(0),
        namespace_chunk(0x0101), // END_NAMESPACE
    ])
}

fn apk_with_manifest(manifest: &[u8], compression: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(compression);
    writer.start_file("AndroidManifest.xml", options).unwrap();
    writer.write_all(manifest).unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn utf16_helper_decodes_bmp_and_supplementary_characters() {
    assert_eq!(get_string_from_utf16(&[]), "");
    assert_eq!(get_string_from_utf16(&[0x61, 0x00, 0x62, 0x00]), "ab");

    let bmp: Vec<u8> = "例子".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(get_string_from_utf16(&bmp), "例子");

    let emoji: Vec<u8> = "😀".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(get_string_from_utf16(&emoji), "😀");
}

#[test]
fn utf16_helper_rejects_invalid_input_like_aosp() {
    // AOSP's `get_string_from_utf16` returns {} when `utf16_to_utf8_length`
    // reports an error, which is what an unpaired surrogate produces.
    assert_eq!(get_string_from_utf16(&[0x00, 0xD8]), "");
    assert_eq!(get_string_from_utf16(&[0x00, 0xDC]), "");
    // Not a whole UTF-16 code unit.
    assert_eq!(get_string_from_utf16(&[0x61]), "");
}

#[test]
fn utf8_string_pool_yields_package() {
    let manifest = manifest(
        &["manifest", "package", "com.example.app", "versionCode"],
        true,
    );
    assert_eq!(parse_package_name(&manifest).unwrap(), "com.example.app");
}

#[test]
fn utf16_string_pool_yields_package() {
    let manifest = manifest(
        &["manifest", "package", "com.example.app", "versionCode"],
        false,
    );
    assert_eq!(parse_package_name(&manifest).unwrap(), "com.example.app");
}

#[test]
fn both_pool_encodings_decode_non_ascii_values() {
    let strings = ["manifest", "package", "com.例子.app", "versionCode"];
    let utf8 = manifest(&strings, true);
    let utf16 = manifest(&strings, false);
    assert_eq!(parse_package_name(&utf8).unwrap(), "com.例子.app");
    assert_eq!(parse_package_name(&utf16).unwrap(), "com.例子.app");
}

#[test]
fn typed_string_value_is_accepted_without_raw_value() {
    let strings = ["manifest", "package", "com.example.typed"];
    let document = xml_document(&[
        string_pool(&strings, true),
        start_element(
            0,
            &[TestAttr {
                name: 1,
                raw: NO_INDEX,
                value_type: 0x03,
                data: 2,
            }],
        ),
    ]);
    assert_eq!(parse_package_name(&document).unwrap(), "com.example.typed");
}

#[test]
fn non_string_package_value_is_ignored() {
    // `ResXMLParser::getAttributeStringValue` returns nullptr for any type
    // other than TYPE_STRING, so AOSP keeps scanning and then fails.
    let strings = ["manifest", "package", "com.example.app"];
    let document = xml_document(&[
        string_pool(&strings, true),
        start_element(
            0,
            &[TestAttr {
                name: 1,
                raw: NO_INDEX,
                value_type: 0x10, // TYPE_INT_DEC
                data: 7,
            }],
        ),
    ]);
    assert_eq!(
        parse_package_name(&document).unwrap_err(),
        FastDeployError::MissingPackage
    );
}

#[test]
fn manifest_without_package_attribute_is_missing_package() {
    let strings = ["manifest", "versionCode"];
    let document = xml_document(&[
        string_pool(&strings, false),
        start_element(0, &[int_attr(1, 3)]),
    ]);
    assert_eq!(
        parse_package_name(&document).unwrap_err(),
        FastDeployError::MissingPackage
    );
}

#[test]
fn a_non_manifest_root_is_skipped() {
    // AOSP only inspects elements named "manifest"; an earlier element with a
    // `package` attribute must not win.
    let strings = ["application", "manifest", "package", "com.example.app"];
    let document = xml_document(&[
        string_pool(&strings, true),
        start_element(0, &[string_attr(2, 3)]),
        end_element(0),
        start_element(1, &[string_attr(2, 3)]),
    ]);
    assert_eq!(parse_package_name(&document).unwrap(), "com.example.app");
}

#[test]
fn corrupt_documents_are_rejected() {
    assert!(matches!(
        parse_package_name(&[]).unwrap_err(),
        FastDeployError::InvalidManifest(_)
    ));

    let mut wrong_type = manifest(&["manifest", "package", "x"], true);
    wrong_type[0] = 0x04;
    assert!(matches!(
        parse_package_name(&wrong_type).unwrap_err(),
        FastDeployError::InvalidManifest(_)
    ));

    let valid = manifest(&["manifest", "package", "com.example.app"], true);
    let truncated = &valid[..valid.len() - 4];
    assert!(matches!(
        parse_package_name(truncated).unwrap_err(),
        FastDeployError::InvalidManifest(_)
    ));

    // First string offset points outside the pool: the package lookup fails
    // instead of reading garbage. Pool starts right after the 8-byte header.
    let mut bad_offset = manifest(&["manifest", "package", "com.example.app"], true);
    bad_offset[8 + 28..8 + 32].copy_from_slice(&u32v(0xFFFF));
    assert!(matches!(
        parse_package_name(&bad_offset).unwrap_err(),
        FastDeployError::InvalidManifest(_)
    ));

    // A START_ELEMENT before any string pool cannot resolve names.
    let no_pool = xml_document(&[start_element(0, &[])]);
    assert!(matches!(
        parse_package_name(&no_pool).unwrap_err(),
        FastDeployError::InvalidManifest(_)
    ));
}

#[test]
fn package_name_is_read_from_a_stored_apk() {
    let manifest = manifest(
        &["manifest", "package", "com.example.app", "versionCode"],
        true,
    );
    let apk = apk_with_manifest(&manifest, zip::CompressionMethod::Stored);
    assert_eq!(get_package_name_from_apk(&apk).unwrap(), "com.example.app");
}

#[test]
fn package_name_is_read_from_a_deflated_apk() {
    let manifest = manifest(
        &["manifest", "package", "com.example.app", "versionCode"],
        false,
    );
    let apk = apk_with_manifest(&manifest, zip::CompressionMethod::Deflated);
    assert_eq!(get_package_name_from_apk(&apk).unwrap(), "com.example.app");
}

#[test]
fn apk_without_manifest_and_non_zip_are_errors() {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("classes.dex", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"dex\n035\0").unwrap();
    let apk = writer.finish().unwrap().into_inner();

    assert_eq!(
        get_package_name_from_apk(&apk).unwrap_err(),
        FastDeployError::MissingManifest
    );
    assert!(matches!(
        get_package_name_from_apk(b"not a zip").unwrap_err(),
        FastDeployError::Zip(_)
    ));
}
