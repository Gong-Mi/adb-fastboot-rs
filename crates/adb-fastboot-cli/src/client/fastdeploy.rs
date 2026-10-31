//! Fastdeploy APK metadata: the pure-computation part of AOSP's fastdeploy.
//!
//! AOSP source map (`vendor/adb`), with the exact lines this module mirrors:
//!
//! | Rust item | AOSP source |
//! | --- | --- |
//! | [`get_string_from_utf16`] | `client/fastdeploy.cpp:128-137` |
//! | [`get_package_name_from_apk`], [`parse_package_name`] | `client/fastdeploy.cpp:139-204` |
//! | [`extract_metadata_from_apk`] | `client/fastdeploy.cpp:219-270` (device half omitted) |
//! | [`metadata_from_central_directory`] | `fastdeploy/deploypatchgenerator/patch_utils.cpp:34-56` |
//! | [`parse_central_directory_record`] | `fastdeploy/deploypatchgenerator/apk_archive.cpp:209-289` |
//! | [`calculate_local_file_entry_size`] | `fastdeploy/deploypatchgenerator/apk_archive.cpp:291-417` |
//! | [`ApkMetaData::encode_proto`] | `fastdeploy/proto/ApkEntry.proto:9-25` |
//!
//! AOSP's `extract_metadata()` is mostly a device protocol: probe the agent,
//! run `deployagent dump 3 <package>`, parse `APKDump`, then feed the central
//! directory to `PatchUtils::GetDeviceAPKMetaData`. This module implements only
//! the parts that are pure functions of the APK bytes:
//!
//! * decompress and parse the binary `AndroidManifest.xml`, extract `package`;
//! * find the EOCD + central directory, and derive the per-entry metadata
//!   (MD5 of the central directory record, local header offset, data size);
//! * resolve the real data size from each local file header, exactly like
//!   `ApkArchive::CalculateLocalFileEntrySize`.
//!
//! Deliberately absent: the deploy agent and every shell round-trip,
//! `install_patch`/`stream_patch`, and bsdiff patch generation. Nothing in this
//! module touches a device or writes files.

use std::io::Read;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the pure fastdeploy helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FastDeployError {
    #[error("could not open APK as a zip archive: {0}")]
    Zip(String),
    #[error("could not find AndroidManifest.xml inside the APK")]
    MissingManifest,
    #[error("could not read AndroidManifest.xml: {0}")]
    ManifestRead(String),
    #[error("invalid binary XML: {0}")]
    InvalidManifest(&'static str),
    #[error("could not find package name tag in AndroidManifest.xml")]
    MissingPackage,
    #[error("unable to find End of Central Directory record")]
    MissingEndOfCentralDirectory,
    #[error("central directory is outside the APK")]
    InvalidCentralDirectory,
    #[error("invalid Local File Header at offset {0}")]
    InvalidLocalHeader(i64),
    #[error("error reading trailing data descriptor for offset {0}")]
    InvalidDataDescriptor(i64),
    #[error(
        "data sizes mismatch at offset {offset}, CDr: {cd_size} vs LHR/DD: {local_size}"
    )]
    DataSizeMismatch {
        offset: i64,
        cd_size: i64,
        local_size: i64,
    },
}

// ---------------------------------------------------------------------------
// UTF-16 -> UTF-8 (fastdeploy.cpp:128-137)
// ---------------------------------------------------------------------------

/// Convert little-endian UTF-16 bytes to a `String`.
///
/// Mirrors AOSP's `get_string_from_utf16`: it first asks `utf16_to_utf8_length`
/// for the output size, and returns an empty string when that reports an error
/// (unpaired surrogate) or zero. An odd byte count cannot be a valid UTF-16
/// sequence and is treated the same way. Supplementary-plane characters are
/// decoded from surrogate pairs.
pub fn get_string_from_utf16(input: &[u8]) -> String {
    utf16_to_string(input).unwrap_or_default()
}

fn utf16_to_string(input: &[u8]) -> Option<String> {
    if input.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = input
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    let mut out = String::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let unit = units[i];
        let code_point = if (0xD800..=0xDBFF).contains(&unit) {
            let low = *units.get(i + 1)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return None;
            }
            i += 2;
            0x1_0000 + (((unit as u32 - 0xD800) << 10) | (low as u32 - 0xDC00))
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return None;
        } else {
            i += 1;
            unit as u32
        };
        out.push(char::from_u32(code_point)?);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Binary AndroidManifest.xml (fastdeploy.cpp:139-204)
// ---------------------------------------------------------------------------

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

/// `ResStringPool_header::UTF8_FLAG`
const UTF8_FLAG: u32 = 0x0000_0100;
/// `Res_value::TYPE_STRING`
const TYPE_STRING: u8 = 0x03;
/// `ResStringPool::INDEX_NONE`
const INDEX_NONE: u32 = 0xFFFF_FFFF;

fn invalid_manifest(reason: &'static str) -> FastDeployError {
    FastDeployError::InvalidManifest(reason)
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Locate `AndroidManifest.xml` inside the APK and return its package name.
///
/// AOSP opens the APK path with `ZipFileRO` and reads the manifest entry
/// (`fastdeploy.cpp:139-158`). Here the APK is passed as bytes and the entry is
/// inflated with the `zip` crate; everything after the uncompress step is
/// [`parse_package_name`], which follows `ResXMLTree` traversal.
pub fn get_package_name_from_apk(apk: &[u8]) -> Result<String, FastDeployError> {
    // A manifest is a few KiB in practice; refuse absurd allocations from a
    // hostile zip header instead of trusting the declared uncompressed size.
    const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(apk))
        .map_err(|err| FastDeployError::Zip(err.to_string()))?;
    let mut entry = archive
        .by_name("AndroidManifest.xml")
        .map_err(|_| FastDeployError::MissingManifest)?;
    if entry.size() > MAX_MANIFEST_SIZE {
        return Err(FastDeployError::ManifestRead(format!(
            "AndroidManifest.xml is {} bytes, larger than the {} byte limit",
            entry.size(),
            MAX_MANIFEST_SIZE
        )));
    }
    let mut manifest = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut manifest)
        .map_err(|err| FastDeployError::ManifestRead(err.to_string()))?;
    parse_package_name(&manifest)
}

/// Parse a binary `AndroidManifest.xml` and return the `package` attribute of
/// the first `<manifest>` element that carries one.
///
/// This is the `ResXMLTree` loop from `fastdeploy.cpp:159-203`: walk chunks in
/// order, resolve element and attribute names through the string pool, and
/// return the first string-valued `package` attribute. Unknown chunk types are
/// skipped, like `ResXMLTree::next()` does.
pub fn parse_package_name(manifest: &[u8]) -> Result<String, FastDeployError> {
    // `ResXMLTree::setTo` expects a `ResXMLTree_header`: type 0x0003,
    // headerSize 0x0008, size covering the whole document. Read as a LE u32
    // the magic is 0x00080003.
    if manifest.len() < 8 {
        return Err(invalid_manifest("truncated binary XML header"));
    }
    if u16_at(manifest, 0) != Some(RES_XML_TYPE) {
        return Err(invalid_manifest(
            "not a binary XML document (expected RES_XML_TYPE 0x0003)",
        ));
    }
    let header_size = u16_at(manifest, 2).ok_or(invalid_manifest("truncated header"))? as usize;
    let document_size = u32_at(manifest, 4).ok_or(invalid_manifest("truncated header"))? as usize;
    if header_size < 8 {
        return Err(invalid_manifest("binary XML header is smaller than 8 bytes"));
    }
    if document_size < header_size || document_size > manifest.len() {
        return Err(invalid_manifest(
            "binary XML size field exceeds the input buffer",
        ));
    }
    let document = &manifest[..document_size];

    let mut pool: Option<StringPool<'_>> = None;
    let mut offset = header_size;
    while offset + 8 <= document.len() {
        let chunk_type =
            u16_at(document, offset).ok_or(invalid_manifest("truncated chunk header"))?;
        let chunk_header_size =
            u16_at(document, offset + 2).ok_or(invalid_manifest("truncated chunk header"))? as usize;
        let chunk_size =
            u32_at(document, offset + 4).ok_or(invalid_manifest("truncated chunk header"))? as usize;

        if chunk_size < 8 || chunk_header_size < 8 || chunk_header_size > chunk_size {
            return Err(invalid_manifest("malformed chunk header"));
        }
        let chunk_end = offset
            .checked_add(chunk_size)
            .ok_or(invalid_manifest("chunk size overflow"))?;
        if chunk_end > document.len() {
            return Err(invalid_manifest("chunk extends past the end of the document"));
        }
        let chunk = &document[offset..chunk_end];

        match chunk_type {
            RES_STRING_POOL_TYPE => {
                if pool.is_none() {
                    pool = Some(StringPool::parse(chunk, chunk_header_size)?);
                }
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                // Attribute resource IDs; this parser matches attributes by
                // name, so the map is skipped (same as `ResXMLTree`).
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool = pool.as_ref().ok_or(invalid_manifest(
                    "START_ELEMENT appeared before the string pool",
                ))?;
                if let Some(package) = package_from_start_element(chunk, chunk_header_size, pool)? {
                    return Ok(package);
                }
            }
            _ => {
                // END_ELEMENT, namespaces, CDATA and any future chunk types do
                // not affect the package name; skip by `chunk_size`.
            }
        }
        offset = chunk_end;
    }

    Err(FastDeployError::MissingPackage)
}

/// Read the `package` attribute out of a `ResXMLTree_node` of type START_ELEMENT.
fn package_from_start_element(
    chunk: &[u8],
    header_size: usize,
    pool: &StringPool<'_>,
) -> Result<Option<String>, FastDeployError> {
    // `ResXMLTree_node` is header (8) + lineNumber (4) + comment (4); the
    // `ResXMLTree_attrExt` follows the node header.
    const NODE_HEADER_SIZE: usize = 16;
    const ATTR_EXT_SIZE: usize = 20;
    const ATTR_SIZE: usize = 20;

    if header_size < NODE_HEADER_SIZE {
        return Err(invalid_manifest("START_ELEMENT node header too small"));
    }
    let ext = header_size;
    // ResXMLTree_attrExt: ns, name, attributeStart, attributeSize,
    // attributeCount, idIndex, classIndex, styleIndex.
    let element_name_index =
        u32_at(chunk, ext + 4).ok_or(invalid_manifest("truncated START_ELEMENT"))?;
    let attribute_start =
        u16_at(chunk, ext + 8).ok_or(invalid_manifest("truncated START_ELEMENT"))? as usize;
    let attribute_size =
        u16_at(chunk, ext + 10).ok_or(invalid_manifest("truncated START_ELEMENT"))? as usize;
    let attribute_count =
        u16_at(chunk, ext + 12).ok_or(invalid_manifest("truncated START_ELEMENT"))? as usize;

    if attribute_size < ATTR_SIZE {
        return Err(invalid_manifest("ResXMLTree_attribute is smaller than 20 bytes"));
    }
    if ext + ATTR_EXT_SIZE > chunk.len() {
        return Err(invalid_manifest("START_ELEMENT has no attribute extension"));
    }
    if pool.get(element_name_index)? != "manifest" {
        return Ok(None);
    }

    let attributes_begin = ext
        .checked_add(attribute_start)
        .ok_or(invalid_manifest("attribute offset overflow"))?;
    for index in 0..attribute_count {
        let attribute = attributes_begin
            .checked_add(index * attribute_size)
            .ok_or(invalid_manifest("attribute offset overflow"))?;
        let attribute_end = attribute
            .checked_add(ATTR_SIZE)
            .ok_or(invalid_manifest("attribute offset overflow"))?;
        if attribute_end > chunk.len() {
            return Err(invalid_manifest("attribute extends past the element chunk"));
        }

        // ResXMLTree_attribute: ns, name, rawValue, Res_value{size, res0,
        // dataType, data}.
        let name_index = u32_at(chunk, attribute + 4).unwrap();
        if pool.get(name_index)? != "package" {
            continue;
        }
        let raw_value = u32_at(chunk, attribute + 8).unwrap();
        let value = if raw_value != INDEX_NONE {
            pool.get(raw_value)?
        } else if chunk[attribute + 15] == TYPE_STRING {
            // `getAttributeStringValue` only accepts TYPE_STRING; other types
            // (references, integers, ...) yield nullptr in AOSP.
            pool.get(u32_at(chunk, attribute + 16).unwrap())?
        } else {
            continue;
        };
        return Ok(Some(value));
    }

    Ok(None)
}

/// A `ResStringPool` chunk: offsets array plus the string data region.
struct StringPool<'a> {
    chunk: &'a [u8],
    offsets: Vec<u32>,
    strings_start: usize,
    utf8: bool,
}

impl<'a> StringPool<'a> {
    fn parse(chunk: &'a [u8], header_size: usize) -> Result<Self, FastDeployError> {
        // ResStringPool_header: header (8), stringCount, styleCount, flags,
        // stringsStart, stylesStart.
        if header_size < 28 || chunk.len() < 28 {
            return Err(invalid_manifest("string pool header too small"));
        }
        let string_count = u32_at(chunk, 8).unwrap() as usize;
        let flags = u32_at(chunk, 16).unwrap();
        let strings_start = u32_at(chunk, 20).unwrap() as usize;

        let offsets_end = string_count
            .checked_mul(4)
            .and_then(|bytes| header_size.checked_add(bytes))
            .ok_or(invalid_manifest("string pool offset table overflow"))?;
        if offsets_end > chunk.len() {
            return Err(invalid_manifest(
                "string pool offset table extends past the chunk",
            ));
        }
        if strings_start > chunk.len() {
            return Err(invalid_manifest("string pool data starts past the chunk"));
        }

        let mut offsets = Vec::with_capacity(string_count.min(4096));
        for index in 0..string_count {
            offsets.push(u32_at(chunk, header_size + index * 4).unwrap());
        }

        Ok(Self {
            chunk,
            offsets,
            strings_start,
            utf8: flags & UTF8_FLAG != 0,
        })
    }

    fn get(&self, index: u32) -> Result<String, FastDeployError> {
        let offset = *self
            .offsets
            .get(index as usize)
            .ok_or(invalid_manifest("string index outside the string pool"))?;
        let position = self
            .strings_start
            .checked_add(offset as usize)
            .ok_or(invalid_manifest("string offset overflow"))?;
        if position >= self.chunk.len() {
            return Err(invalid_manifest("string offset is outside the string pool"));
        }
        if self.utf8 {
            self.get_utf8(position)
        } else {
            self.get_utf16(position)
        }
    }

    /// `ResStringPool::string8At`: two lengths (UTF-16 length, then byte
    /// length), each 1 byte or 2 bytes when the high bit is set.
    fn get_utf8(&self, position: usize) -> Result<String, FastDeployError> {
        let (_, first) = self.length8(position)?;
        let (byte_length, second) = self.length8(position + first)?;
        let start = position + first + second;
        let end = start
            .checked_add(byte_length)
            .ok_or(invalid_manifest("string length overflow"))?;
        if end > self.chunk.len() {
            return Err(invalid_manifest("UTF-8 string extends past the pool"));
        }
        // aapt emits modified UTF-8; for BMP text (all package names, all
        // attribute names) this is identical to UTF-8. Invalid sequences in
        // unrelated strings are replaced instead of failing the whole parse.
        Ok(String::from_utf8_lossy(&self.chunk[start..end]).into_owned())
    }

    fn length8(&self, position: usize) -> Result<(usize, usize), FastDeployError> {
        let first = *self
            .chunk
            .get(position)
            .ok_or(invalid_manifest("truncated UTF-8 string length"))?
            as usize;
        if first & 0x80 == 0 {
            return Ok((first, 1));
        }
        let second = *self
            .chunk
            .get(position + 1)
            .ok_or(invalid_manifest("truncated UTF-8 string length"))?
            as usize;
        Ok((((first & 0x7F) << 8) | second, 2))
    }

    /// `ResStringPool::stringAt` for a UTF-16 pool: a UTF-16 length (2 or 4
    /// bytes) followed by that many code units.
    fn get_utf16(&self, position: usize) -> Result<String, FastDeployError> {
        let first = u16_at(self.chunk, position)
            .ok_or(invalid_manifest("truncated UTF-16 string length"))?
            as usize;
        let (unit_count, length_bytes) = if first & 0x8000 == 0 {
            (first, 2)
        } else {
            let second = u16_at(self.chunk, position + 2)
                .ok_or(invalid_manifest("truncated UTF-16 string length"))?
                as usize;
            (((first & 0x7FFF) << 16) | second, 4)
        };
        let start = position + length_bytes;
        let byte_length = unit_count
            .checked_mul(2)
            .ok_or(invalid_manifest("string length overflow"))?;
        let end = start
            .checked_add(byte_length)
            .ok_or(invalid_manifest("string length overflow"))?;
        if end > self.chunk.len() {
            return Err(invalid_manifest("UTF-16 string extends past the pool"));
        }
        utf16_to_string(&self.chunk[start..end])
            .ok_or(invalid_manifest("invalid UTF-16 string in the pool"))
    }
}

// ---------------------------------------------------------------------------
// APK metadata (patch_utils.cpp:34-80, apk_archive.cpp:209-417)
// ---------------------------------------------------------------------------

const EOCD_SIGNATURE: u32 = 0x0605_4B50;
const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4B50;
const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4B50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4B50;
/// Fixed part of `CentralDirectoryRecord` (apk_archive.cpp:218-264).
const CD_RECORD_FIXED_SIZE: usize = 46;
/// Fixed part of `LocalFileHeader` (apk_archive.cpp:298-329).
const LOCAL_FILE_HEADER_SIZE: usize = 30;
/// `kGPBDDFlagMask`: the entry is followed by a data descriptor.
const GPB_DATA_DESCRIPTOR: u16 = 0x0008;
const COMPRESSION_STORED: u16 = 0;
/// EOCD is 22 bytes; its comment can add up to 65535 bytes.
const MAX_EOCD_SEARCH: usize = 65_557;

/// One `APKEntry` (ApkEntry.proto:16-20).
///
/// `md5` is the MD5 digest of this entry's *central directory record* (header,
/// name, extra field and comment), not of the file contents: that is what
/// `ApkArchive::ParseCentralDirectoryRecord` computes at
/// `apk_archive.cpp:280-282`. `data_offset` is the local file header offset and
/// `data_size` is the full local entry size once
/// [`calculate_local_file_entry_size`] has run, matching
/// `PatchUtils::GetHostAPKMetaData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkEntryMeta {
    pub md5: [u8; 16],
    pub data_offset: i64,
    pub data_size: i64,
}

impl ApkEntryMeta {
    /// Lowercase hex rendering of [`Self::md5`], for logs and test assertions.
    pub fn md5_hex(&self) -> String {
        let mut out = String::with_capacity(32);
        for byte in self.md5 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// `APKMetaData` (ApkEntry.proto:22-25).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApkMetaData {
    pub absolute_path: String,
    pub entries: Vec<ApkEntryMeta>,
}

impl ApkMetaData {
    /// Encode this value as the protobuf `APKMetaData` message, field numbers
    /// and wire types taken from `fastdeploy/proto/ApkEntry.proto`.
    ///
    /// proto3 default values are omitted, like the generated C++ serializer.
    /// Negative `int64` values would use the 10-byte two's-complement varint;
    /// real offsets and sizes are non-negative.
    pub fn encode_proto(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.absolute_path.is_empty() {
            out.push(0x0A); // field 1, length-delimited
            encode_varint(self.absolute_path.len() as u64, &mut out);
            out.extend_from_slice(self.absolute_path.as_bytes());
        }
        for entry in &self.entries {
            let mut payload = Vec::with_capacity(24);
            payload.push(0x0A); // APKEntry.md5, field 1, length-delimited
            payload.push(16); // MD5_DIGEST_LENGTH
            payload.extend_from_slice(&entry.md5);
            if entry.data_offset != 0 {
                payload.push(0x10); // field 2, varint
                encode_varint(entry.data_offset as u64, &mut payload);
            }
            if entry.data_size != 0 {
                payload.push(0x18); // field 3, varint
                encode_varint(entry.data_size as u64, &mut payload);
            }
            out.push(0x12); // field 2, length-delimited
            encode_varint(payload.len() as u64, &mut out);
            out.extend_from_slice(&payload);
        }
        out
    }
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Compute `APKMetaData` for a local APK, the way
/// `PatchUtils::GetHostAPKMetaData` does (`patch_utils.cpp:58-80`):
/// read the central directory, derive each entry's MD5/offset/size, then
/// replace `data_size` with the size of the whole local file entry.
///
/// AOSP does this in two passes because it also collects the signing block for
/// the device; the signing block is not part of `APKMetaData`, so it is not
/// reproduced here.
pub fn extract_metadata_from_apk(
    apk: &[u8],
    absolute_path: &str,
) -> Result<ApkMetaData, FastDeployError> {
    let (offset, size) = locate_central_directory(apk)?;
    let mut metadata = metadata_from_central_directory(&apk[offset..offset + size], absolute_path);
    for entry in &mut metadata.entries {
        entry.data_size =
            calculate_local_file_entry_size(apk, entry.data_offset, entry.data_size)?;
    }
    Ok(metadata)
}

/// Find the central directory from the End of Central Directory record.
///
/// Mirrors `ApkArchive::FindEndOfCDRecord` + `FindCDRecord`
/// (`apk_archive.cpp:108-174`): scan backwards (at most 65557 bytes) for
/// `0x06054b50`, then take `crSize`/`offsetToCdHeader` from it. Unlike AOSP,
/// the resulting range is bounds-checked instead of reading past the buffer.
pub fn locate_central_directory(apk: &[u8]) -> Result<(usize, usize), FastDeployError> {
    const EOCD_MIN_SIZE: usize = 22;
    if apk.len() < EOCD_MIN_SIZE {
        return Err(FastDeployError::MissingEndOfCentralDirectory);
    }

    let search_floor = apk.len().saturating_sub(MAX_EOCD_SEARCH);
    let mut record = None;
    let mut cursor = apk.len() - EOCD_MIN_SIZE;
    loop {
        if u32_at(apk, cursor) == Some(EOCD_SIGNATURE) {
            record = Some(cursor);
            break;
        }
        if cursor == search_floor {
            break;
        }
        cursor -= 1;
    }
    let record = record.ok_or(FastDeployError::MissingEndOfCentralDirectory)?;

    // ecdr_t: signature (4), disk numbers (8), entries (4), crSize at +12,
    // offsetToCdHeader at +16, commentSize at +20.
    let size = u32_at(apk, record + 12).unwrap() as usize;
    let offset = u32_at(apk, record + 16).unwrap() as usize;
    let end = offset
        .checked_add(size)
        .ok_or(FastDeployError::InvalidCentralDirectory)?;
    if end > apk.len() {
        return Err(FastDeployError::InvalidCentralDirectory);
    }
    Ok((offset, size))
}

/// Build `APKMetaData` from the raw central directory bytes, exactly like
/// `PatchUtils::GetDeviceAPKMetaData` (`patch_utils.cpp:34-56`).
///
/// AOSP's loop stops as soon as `ApkArchive::ParseCentralDirectoryRecord`
/// returns 0 (short record or bad signature) and keeps the entries parsed so
/// far; this function does the same, so a truncated tail yields a partial list
/// rather than an error.
pub fn metadata_from_central_directory(cd: &[u8], absolute_path: &str) -> ApkMetaData {
    let mut metadata = ApkMetaData {
        absolute_path: absolute_path.to_string(),
        entries: Vec::new(),
    };
    let mut offset = 0;
    while offset < cd.len() {
        match parse_central_directory_record(&cd[offset..]) {
            Some((consumed, entry)) => {
                metadata.entries.push(entry);
                offset += consumed;
            }
            None => break,
        }
    }
    metadata
}

/// Parse one `CentralDirectoryRecord` (`apk_archive.cpp:209-289`).
///
/// Returns the number of bytes consumed and the entry: MD5 over the entire
/// record (fixed header + file name + extra field + comment), the local file
/// header offset, and the data size (`uncompressed_size` when stored,
/// `compressed_size` otherwise).
pub fn parse_central_directory_record(record: &[u8]) -> Option<(usize, ApkEntryMeta)> {
    if record.len() < CD_RECORD_FIXED_SIZE {
        return None;
    }
    if u32_at(record, 0)? != CENTRAL_DIRECTORY_SIGNATURE {
        return None;
    }

    let compression_method = u16_at(record, 10)?;
    let compressed_size = u32_at(record, 20)? as i64;
    let uncompressed_size = u32_at(record, 24)? as i64;
    let file_name_length = u16_at(record, 28)? as usize;
    let extra_field_length = u16_at(record, 30)? as usize;
    let comment_length = u16_at(record, 32)? as usize;

    let total = CD_RECORD_FIXED_SIZE
        .checked_add(file_name_length)?
        .checked_add(extra_field_length)?
        .checked_add(comment_length)?;
    // AOSP trusts these lengths and would read out of bounds; refuse instead.
    if total > record.len() {
        return None;
    }

    let md5 = md5_digest(&record[..total]);
    let data_offset = u32_at(record, 42)? as i64;
    let data_size = if compression_method == COMPRESSION_STORED {
        uncompressed_size
    } else {
        compressed_size
    };

    Some((
        total,
        ApkEntryMeta {
            md5,
            data_offset,
            data_size,
        },
    ))
}

/// Size of the whole local file entry: fixed header, file name, extra field,
/// entry data, and the optional trailing data descriptor.
///
/// Port of `ApkArchive::CalculateLocalFileEntrySize`
/// (`apk_archive.cpp:291-417`), including the `kGPBDDFlagMask` handling and the
/// optional `0x08074b50` data descriptor signature. AOSP also verifies that the
/// local header/descriptor size equals the central directory size and exits(1)
/// on mismatch; here that is [`FastDeployError::DataSizeMismatch`].
pub fn calculate_local_file_entry_size(
    apk: &[u8],
    local_file_header_offset: i64,
    data_size: i64,
) -> Result<i64, FastDeployError> {
    let offset = usize::try_from(local_file_header_offset)
        .map_err(|_| FastDeployError::InvalidLocalHeader(local_file_header_offset))?;
    let header_end = offset
        .checked_add(LOCAL_FILE_HEADER_SIZE)
        .ok_or(FastDeployError::InvalidLocalHeader(local_file_header_offset))?;
    if header_end > apk.len() {
        return Err(FastDeployError::InvalidLocalHeader(local_file_header_offset));
    }
    if u32_at(apk, offset) != Some(LOCAL_FILE_HEADER_SIGNATURE) {
        return Err(FastDeployError::InvalidLocalHeader(local_file_header_offset));
    }

    // LocalFileHeader: signature (4), version (2), gpb_flags at +6,
    // compression_method at +8, crc at +14, compressed_size at +18,
    // uncompressed_size at +22, name/extra lengths at +26/+28.
    let flags = u16_at(apk, offset + 6).unwrap();
    let compression_method = u16_at(apk, offset + 8).unwrap();
    let compressed_size = u32_at(apk, offset + 18).unwrap() as i64;
    let uncompressed_size = u32_at(apk, offset + 22).unwrap() as i64;
    let file_name_length = u16_at(apk, offset + 26).unwrap() as i64;
    let extra_field_length = u16_at(apk, offset + 28).unwrap() as i64;

    let payload_offset = local_file_header_offset
        .checked_add(LOCAL_FILE_HEADER_SIZE as i64)
        .and_then(|value| value.checked_add(file_name_length))
        .and_then(|value| value.checked_add(extra_field_length))
        .and_then(|value| value.checked_add(data_size))
        .ok_or(FastDeployError::InvalidLocalHeader(local_file_header_offset))?;

    let mut descriptor_size = 0i64;
    let local_data_size = if flags & GPB_DATA_DESCRIPTOR != 0 {
        // DataDescriptor: crc32, compressed_size, uncompressed_size, preceded
        // by an optional 0x08074b50 signature.
        let mut descriptor = payload_offset;
        let position = usize::try_from(descriptor)
            .map_err(|_| FastDeployError::InvalidDataDescriptor(payload_offset))?;
        if position + 4 > apk.len() {
            return Err(FastDeployError::InvalidDataDescriptor(payload_offset));
        }
        if u32_at(apk, position) == Some(DATA_DESCRIPTOR_SIGNATURE) {
            descriptor += 4;
            descriptor_size += 4;
        }
        let position = usize::try_from(descriptor)
            .map_err(|_| FastDeployError::InvalidDataDescriptor(payload_offset))?;
        if position + 12 > apk.len() {
            return Err(FastDeployError::InvalidDataDescriptor(payload_offset));
        }
        let descriptor_compressed = u32_at(apk, position + 4).unwrap() as i64;
        let descriptor_uncompressed = u32_at(apk, position + 8).unwrap() as i64;
        descriptor_size += 12;
        if compression_method == COMPRESSION_STORED {
            descriptor_uncompressed
        } else {
            descriptor_compressed
        }
    } else if compression_method == COMPRESSION_STORED {
        uncompressed_size
    } else {
        compressed_size
    };

    if local_data_size != data_size {
        return Err(FastDeployError::DataSizeMismatch {
            offset: local_file_header_offset,
            cd_size: data_size,
            local_size: local_data_size,
        });
    }

    Ok(LOCAL_FILE_HEADER_SIZE as i64
        + file_name_length
        + extra_field_length
        + data_size
        + descriptor_size)
}

// ---------------------------------------------------------------------------
// MD5 (OpenSSL MD5 in apk_archive.cpp; RFC 1321 here)
// ---------------------------------------------------------------------------

/// MD5 digest (RFC 1321).
///
/// `ApkArchive::ParseCentralDirectoryRecord` calls OpenSSL's `MD5`; the crate
/// has no MD5 dependency and the dependency set is out of scope for this slice,
/// so the algorithm is implemented here and checked against RFC 1321 test
/// vectors.
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6,
        10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const TABLE: [u32; 64] = [
        0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613,
        0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193,
        0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D,
        0x02441453, 0xD8A1E681, 0xE7D3FBC8, 0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
        0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122,
        0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
        0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665, 0xF4292244,
        0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB,
        0xEB86D391,
    ];

    let mut state: [u32; 4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
    let bit_length = (data.len() as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_le_bytes());

    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = state;
        for round in 0..64 {
            let (function, word_index) = match round / 16 {
                0 => ((b & c) | (!b & d), round),
                1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                2 => (b ^ c ^ d, (3 * round + 5) % 16),
                _ => (c ^ (b | !d), (7 * round) % 16),
            };
            let sum = a
                .wrapping_add(function)
                .wrapping_add(TABLE[round])
                .wrapping_add(words[word_index]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(SHIFTS[round]));
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}
