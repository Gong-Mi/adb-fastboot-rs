use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

pub const VENDOR_BOOT_MAGIC: [u8; 8] = *b"VNDRBOOT";
pub const VENDOR_BOOT_PAGE_SIZE: usize = 4096;
pub const VENDOR_BOOT_NAME_SIZE: usize = 16;
pub const VENDOR_BOOT_CMDLINE_SIZE: usize = 2048;
pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_BOARD_ID_SIZE: usize = 16;
pub const VENDOR_RAMDISK_TABLE_ENTRY_SIZE: usize = 4 + 4 + 4 + VENDOR_RAMDISK_NAME_SIZE + 4 * VENDOR_RAMDISK_BOARD_ID_SIZE;
pub const VENDOR_BOOT_HEADER_V3_SIZE: usize = 2112;
pub const VENDOR_BOOT_HEADER_V4_SIZE: usize = 2128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorBootVersion {
    V3,
    V4,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VendorBootError {
    #[error("vendor_boot is too short: expected at least {expected} bytes, got {got}")]
    BufferTooShort { expected: usize, got: usize },
    #[error("invalid vendor_boot magic")]
    InvalidMagic,
    #[error("unsupported vendor_boot header version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid vendor_boot page size {0}")]
    InvalidPageSize(u32),
    #[error("invalid vendor_boot header_size {actual}, expected {expected}")]
    InvalidHeaderSize { actual: u32, expected: u32 },
    #[error("unsupported vendor ramdisk table entry size {0}")]
    UnsupportedTableEntrySize(u32),
    #[error("vendor ramdisk table size {size} does not equal {entries} entries")]
    InvalidTableSize { size: u32, entries: u64 },
    #[error("vendor_boot section {section} exceeds image: offset {offset}, size {size}, image {image}")]
    SectionBounds { section: &'static str, offset: usize, size: usize, image: usize },
    #[error("vendor ramdisk entry {index} exceeds ramdisk: offset {offset}, size {size}, ramdisk {ramdisk}")]
    RamdiskEntryOutOfBounds { index: usize, offset: u32, size: u32, ramdisk: u32 },
    #[error("duplicate vendor ramdisk name {name:?}")]
    DuplicateRamdiskName { name: String },
    #[error("vendor ramdisk name is not valid UTF-8 at entry {index}")]
    InvalidRamdiskName { index: usize },
    #[error("arithmetic overflow while calculating vendor_boot layout")]
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorBootHeader {
    pub version: VendorBootVersion,
    pub page_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub vendor_ramdisk_size: u32,
    pub cmdline: String,
    pub tags_addr: u32,
    pub name: String,
    pub header_size: u32,
    pub dtb_size: u32,
    pub dtb_addr: u64,
    pub vendor_ramdisk_table_size: u32,
    pub vendor_ramdisk_table_entry_num: u32,
    pub vendor_ramdisk_table_entry_size: u32,
    pub bootconfig_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRamdiskTableEntry {
    pub ramdisk_size: u32,
    pub ramdisk_offset: u32,
    pub ramdisk_type: u32,
    pub ramdisk_name: String,
    pub board_id: [u32; VENDOR_RAMDISK_BOARD_ID_SIZE],
}

impl VendorRamdiskTableEntry {
    pub fn new(name: &[u8], ramdisk_size: u32, ramdisk_type: u32) -> Self {
        Self {
            ramdisk_size,
            ramdisk_offset: 0,
            ramdisk_type,
            ramdisk_name: String::from_utf8_lossy(name).into_owned(),
            board_id: [0; VENDOR_RAMDISK_BOARD_ID_SIZE],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorBootSectionOffsets {
    pub header: usize,
    pub ramdisk: usize,
    pub dtb: usize,
    pub table: usize,
    pub bootconfig: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorBootImage<'a> {
    pub header: VendorBootHeader,
    pub data: &'a [u8],
    entries: Vec<VendorRamdiskTableEntry>,
    offsets: VendorBootSectionOffsets,
}

impl<'a> VendorBootImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, VendorBootError> {
        if data.len() < VENDOR_BOOT_HEADER_V3_SIZE {
            return Err(VendorBootError::BufferTooShort { expected: VENDOR_BOOT_HEADER_V3_SIZE, got: data.len() });
        }
        if data[..8] != VENDOR_BOOT_MAGIC {
            return Err(VendorBootError::InvalidMagic);
        }
        let raw_version = u32_at(data, 8);
        let version = match raw_version {
            3 => VendorBootVersion::V3,
            4 => VendorBootVersion::V4,
            other => return Err(VendorBootError::UnsupportedVersion(other)),
        };
        let header_len = match version { VendorBootVersion::V3 => VENDOR_BOOT_HEADER_V3_SIZE, VendorBootVersion::V4 => VENDOR_BOOT_HEADER_V4_SIZE };
        if data.len() < header_len { return Err(VendorBootError::BufferTooShort { expected: header_len, got: data.len() }); }
        let page_size = u32_at(data, 12);
        if page_size == 0 { return Err(VendorBootError::InvalidPageSize(page_size)); }
        let header_size = u32_at(data, 2096);
        if header_size != header_len as u32 { return Err(VendorBootError::InvalidHeaderSize { actual: header_size, expected: header_len as u32 }); }
        let header = VendorBootHeader {
            version, page_size, kernel_addr: u32_at(data, 16), ramdisk_addr: u32_at(data, 20),
            vendor_ramdisk_size: u32_at(data, 24), cmdline: fixed_string(&data[28..2076]),
            tags_addr: u32_at(data, 2076), name: fixed_string(&data[2080..2096]), header_size,
            dtb_size: u32_at(data, 2100), dtb_addr: u64_at(data, 2104),
            vendor_ramdisk_table_size: if version == VendorBootVersion::V4 { u32_at(data, 2112) } else { 0 },
            vendor_ramdisk_table_entry_num: if version == VendorBootVersion::V4 { u32_at(data, 2116) } else { 0 },
            vendor_ramdisk_table_entry_size: if version == VendorBootVersion::V4 { u32_at(data, 2120) } else { 0 },
            bootconfig_size: if version == VendorBootVersion::V4 { u32_at(data, 2124) } else { 0 },
        };
        let offsets = section_offsets_for(&header)?;
        ensure_section(data, "header", 0, offsets.ramdisk)?;
        ensure_section(data, "vendor ramdisk", offsets.ramdisk, offsets.dtb - offsets.ramdisk)?;
        ensure_section(data, "dtb", offsets.dtb, offsets.table - offsets.dtb)?;
        if version == VendorBootVersion::V4 {
            ensure_section(data, "vendor ramdisk table", offsets.table, offsets.bootconfig - offsets.table)?;
            ensure_section(data, "bootconfig", offsets.bootconfig, offsets.end - offsets.bootconfig)?;
            if header.vendor_ramdisk_table_entry_size != VENDOR_RAMDISK_TABLE_ENTRY_SIZE as u32 {
                return Err(VendorBootError::UnsupportedTableEntrySize(header.vendor_ramdisk_table_entry_size));
            }
            let expected = (header.vendor_ramdisk_table_entry_num as u64)
                .checked_mul(header.vendor_ramdisk_table_entry_size as u64).ok_or(VendorBootError::ArithmeticOverflow)?;
            if expected != header.vendor_ramdisk_table_size as u64 {
                return Err(VendorBootError::InvalidTableSize { size: header.vendor_ramdisk_table_size, entries: expected });
            }
        }
        let mut entries = Vec::new();
        let table_bytes = if version == VendorBootVersion::V4 { header.vendor_ramdisk_table_entry_num as usize } else { 0 };
        for index in 0..table_bytes {
            let start = offsets.table + index * VENDOR_RAMDISK_TABLE_ENTRY_SIZE;
            let entry = parse_entry(&data[start..start + VENDOR_RAMDISK_TABLE_ENTRY_SIZE], index)?;
            let end = entry.ramdisk_offset.checked_add(entry.ramdisk_size).ok_or(VendorBootError::ArithmeticOverflow)?;
            if end > header.vendor_ramdisk_size {
                return Err(VendorBootError::RamdiskEntryOutOfBounds { index, offset: entry.ramdisk_offset, size: entry.ramdisk_size, ramdisk: header.vendor_ramdisk_size });
            }
            if entries.iter().any(|old: &VendorRamdiskTableEntry| old.ramdisk_name == entry.ramdisk_name) {
                return Err(VendorBootError::DuplicateRamdiskName { name: entry.ramdisk_name });
            }
            entries.push(entry);
        }
        Ok(Self { header, data, entries, offsets })
    }

    pub fn entries(&self) -> &[VendorRamdiskTableEntry] { &self.entries }
    pub fn section_offsets(&self) -> Result<VendorBootSectionOffsets, VendorBootError> { Ok(self.offsets) }
    pub fn ramdisk(&self) -> &'a [u8] { &self.data[self.offsets.ramdisk..self.offsets.ramdisk + self.header.vendor_ramdisk_size as usize] }
    pub fn dtb(&self) -> &'a [u8] { &self.data[self.offsets.dtb..self.offsets.dtb + self.header.dtb_size as usize] }
    pub fn bootconfig(&self) -> &'a [u8] { &self.data[self.offsets.bootconfig..self.offsets.bootconfig + self.header.bootconfig_size as usize] }
}

fn section_offsets_for(h: &VendorBootHeader) -> Result<VendorBootSectionOffsets, VendorBootError> {
    let page = h.page_size as usize;
    let align = |n: usize| n.checked_add(page - 1).map(|v| v / page * page).ok_or(VendorBootError::ArithmeticOverflow);
    let header = align(h.header_size as usize)?;
    let ramdisk = header;
    let dtb = ramdisk.checked_add(align(h.vendor_ramdisk_size as usize)?).ok_or(VendorBootError::ArithmeticOverflow)?;
    let table = dtb.checked_add(align(h.dtb_size as usize)?).ok_or(VendorBootError::ArithmeticOverflow)?;
    let bootconfig = table.checked_add(align(h.vendor_ramdisk_table_size as usize)?).ok_or(VendorBootError::ArithmeticOverflow)?;
    let end = bootconfig.checked_add(align(h.bootconfig_size as usize)?).ok_or(VendorBootError::ArithmeticOverflow)?;
    Ok(VendorBootSectionOffsets { header, ramdisk, dtb, table, bootconfig, end })
}

fn ensure_section(data: &[u8], section: &'static str, offset: usize, size: usize) -> Result<(), VendorBootError> {
    let end = offset.checked_add(size).ok_or(VendorBootError::ArithmeticOverflow)?;
    if end > data.len() { return Err(VendorBootError::SectionBounds { section, offset, size, image: data.len() }); }
    Ok(())
}

fn parse_entry(data: &[u8], index: usize) -> Result<VendorRamdiskTableEntry, VendorBootError> {
    let mut name_bytes = &data[12..44];
    if let Some(end) = name_bytes.iter().position(|&b| b == 0) { name_bytes = &name_bytes[..end]; }
    let name = std::str::from_utf8(name_bytes).map_err(|_| VendorBootError::InvalidRamdiskName { index })?.to_owned();
    let mut board_id = [0u32; VENDOR_RAMDISK_BOARD_ID_SIZE];
    for (i, word) in board_id.iter_mut().enumerate() { *word = u32_at(data, 44 + i * 4); }
    Ok(VendorRamdiskTableEntry { ramdisk_size: u32_at(data, 0), ramdisk_offset: u32_at(data, 4), ramdisk_type: u32_at(data, 8), ramdisk_name: name, board_id })
}

fn fixed_string(data: &[u8]) -> String { let end = data.iter().position(|&b| b == 0).unwrap_or(data.len()); String::from_utf8_lossy(&data[..end]).into_owned() }
fn u32_at(data: &[u8], offset: usize) -> u32 { LittleEndian::read_u32(&data[offset..offset + 4]) }
fn u64_at(data: &[u8], offset: usize) -> u64 { LittleEndian::read_u64(&data[offset..offset + 8]) }

#[cfg(test)]
fn build_vendor_boot_v4_for_test(ramdisk: &[u8], dtb: &[u8], bootconfig: &[u8], entries: &[VendorRamdiskTableEntry]) -> Vec<u8> {
    let page = 4096usize;
    let table_size = entries.len() * VENDOR_RAMDISK_TABLE_ENTRY_SIZE;
    let mut image = vec![0u8; page];
    image[..8].copy_from_slice(&VENDOR_BOOT_MAGIC);
    image[8..12].copy_from_slice(&4u32.to_le_bytes());
    image[12..16].copy_from_slice(&(page as u32).to_le_bytes());
    image[24..28].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
    image[2096..2100].copy_from_slice(&(VENDOR_BOOT_HEADER_V4_SIZE as u32).to_le_bytes());
    image[2100..2104].copy_from_slice(&(dtb.len() as u32).to_le_bytes());
    image[2112..2116].copy_from_slice(&(table_size as u32).to_le_bytes());
    image[2116..2120].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    image[2120..2124].copy_from_slice(&(VENDOR_RAMDISK_TABLE_ENTRY_SIZE as u32).to_le_bytes());
    image[2124..2128].copy_from_slice(&(bootconfig.len() as u32).to_le_bytes());
    for section in [ramdisk, dtb] { image.extend_from_slice(section); image.resize((image.len() + page - 1) / page * page, 0); }
    for entry in entries {
        let mut raw = [0u8; VENDOR_RAMDISK_TABLE_ENTRY_SIZE];
        raw[..4].copy_from_slice(&entry.ramdisk_size.to_le_bytes()); raw[4..8].copy_from_slice(&entry.ramdisk_offset.to_le_bytes()); raw[8..12].copy_from_slice(&entry.ramdisk_type.to_le_bytes());
        let name = entry.ramdisk_name.as_bytes(); raw[12..12 + name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
        for (i, word) in entry.board_id.iter().enumerate() { raw[44 + i * 4..48 + i * 4].copy_from_slice(&word.to_le_bytes()); }
        image.extend_from_slice(&raw);
    }
    image.resize((image.len() + page - 1) / page * page, 0); image.extend_from_slice(bootconfig); image.resize((image.len() + page - 1) / page * page, 0); image
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v4_layout_and_table_roundtrip() {
        let entries = vec![VendorRamdiskTableEntry::new(b"platform", 3, 1), VendorRamdiskTableEntry::new(b"recovery", 5, 2)];
        let image = build_vendor_boot_v4_for_test(b"ramdisk", b"dtb", b"bootconfig", &entries);
        let parsed = VendorBootImage::parse(&image).unwrap();
        assert_eq!(parsed.header.version, VendorBootVersion::V4); assert_eq!(parsed.header.vendor_ramdisk_size, 7); assert_eq!(parsed.entries(), entries.as_slice());
        assert_eq!(parsed.ramdisk(), b"ramdisk"); assert_eq!(parsed.dtb(), b"dtb"); assert_eq!(parsed.bootconfig(), b"bootconfig"); assert_eq!(parsed.section_offsets().unwrap().table, 12288);
    }
    #[test]
    fn rejects_duplicate_names_and_out_of_bounds_entries() {
        let entries = vec![VendorRamdiskTableEntry::new(b"same", 3, 0), VendorRamdiskTableEntry::new(b"same", 4, 0)];
        let image = build_vendor_boot_v4_for_test(b"ramdisk", b"", b"", &entries); assert!(matches!(VendorBootImage::parse(&image), Err(VendorBootError::DuplicateRamdiskName { .. })));
        let mut image = build_vendor_boot_v4_for_test(b"ramdisk", b"", b"", &[VendorRamdiskTableEntry::new(b"one", 99, 0)]); image[8192..8196].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(VendorBootImage::parse(&image), Err(VendorBootError::RamdiskEntryOutOfBounds { .. })));
    }
    #[test]
    fn rejects_unsupported_entry_size_and_zero_page_size() {
        let mut image = build_vendor_boot_v4_for_test(b"ramdisk", b"", b"", &[VendorRamdiskTableEntry::new(b"one", 7, 0)]); image[2120..2124].copy_from_slice(&32u32.to_le_bytes());
        assert!(matches!(VendorBootImage::parse(&image), Err(VendorBootError::UnsupportedTableEntrySize(32)))); image[2120..2124].copy_from_slice(&64u32.to_le_bytes()); image[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(VendorBootImage::parse(&image), Err(VendorBootError::InvalidPageSize(0))));
    }
}
