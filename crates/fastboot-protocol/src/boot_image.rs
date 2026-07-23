use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

/// BOOT image magic string "ANDROID!"
pub const BOOT_MAGIC: [u8; 8] = *b"ANDROID!";
const BOOT_MAGIC_STR: &str = "ANDROID!";

/// Size constants
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;
pub const BOOT_ID_SIZE: usize = 32;

pub const BOOT_IMAGE_HEADER_V0_SIZE: usize = 1632;
pub const BOOT_IMAGE_HEADER_V1_SIZE: usize = 1648;
pub const BOOT_IMAGE_HEADER_V2_SIZE: usize = 1664;
pub const BOOT_IMAGE_HEADER_V3_SIZE: usize = 4096;
pub const BOOT_IMAGE_HEADER_V4_SIZE: usize = 4096;

/// Default addresses used by mkbootimg
pub const DEFAULT_KERNEL_ADDR: u32 = 0x00008000;
pub const DEFAULT_RAMDISK_ADDR: u32 = 0x01000000;
pub const DEFAULT_SECOND_ADDR: u32 = 0x00F00000;
pub const DEFAULT_TAGS_ADDR: u32 = 0x00000100;
pub const DEFAULT_PAGE_SIZE: u32 = 2048;

/// v0 header size excluding page padding
pub const BOOT_IMAGE_HEADER_V0_NATIVE_SIZE: usize = 1632;
/// v1 header additional size after v0
pub const BOOT_IMAGE_HEADER_V1_EXTRA_SIZE: usize = 16;
/// v2 header additional size after v1
pub const BOOT_IMAGE_HEADER_V2_EXTRA_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BootImageError {
    #[error("Buffer too short: expected at least {expected} bytes, got {got}")]
    BufferTooShort { expected: usize, got: usize },

    #[error("Invalid boot magic: expected '{BOOT_MAGIC_STR}', got '{got}'")]
    InvalidMagic { got: String },

    #[error("Unsupported header version: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid page size: {0} (must be a power of two)")]
    InvalidPageSize(u32),

    #[error("Invalid os_version: year field {year} is out of range")]
    InvalidOsVersion { year: u32 },

    #[error("Unexpected end of data while reading {section}: offset {offset} + size {size} > len {len}")]
    SectionBounds {
        section: &'static str,
        offset: usize,
        size: usize,
        len: usize,
    },

    #[error("cmdline too long: {len} bytes (max {max})")]
    CmdlineTooLong { len: usize, max: usize },

    #[error("name too long: {name_len} bytes (max {max})")]
    NameTooLong { name_len: usize, max: usize },
}

// ---------------------------------------------------------------------------
// OS Version helper
// ---------------------------------------------------------------------------

/// Decoded Android OS version / patch level.
///
/// Packed into a `u32` as follows:
/// ```text
/// bits[7:0]   = year (since 2000)
/// bits[11:8]  = month
/// bits[15:12] = day
/// bits[23:16] = major version
/// bits[27:24] = minor version
/// bits[31:28] = patch version
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    /// Year since 2000 (0 = 2000, 25 = 2025, etc.)
    pub year_since_2000: u8,
    pub month: u8,
    pub day: u8,
}

impl OsVersion {
    pub const fn new(
        major: u8,
        minor: u8,
        patch: u8,
        year_since_2000: u8,
        month: u8,
        day: u8,
    ) -> Self {
        Self {
            major,
            minor,
            patch,
            year_since_2000,
            month,
            day,
        }
    }

    /// Encode to the packed `u32` format used in boot image headers.
    pub fn encode(&self) -> u32 {
        (self.major as u32) << 16
            | (self.minor as u32) << 24
            | (self.patch as u32) << 28
            | (self.year_since_2000 as u32)
            | (self.month as u32) << 8
            | (self.day as u32) << 12
    }

    /// Decode from the packed `u32` format.
    pub fn decode(raw: u32) -> Self {
        Self {
            year_since_2000: (raw & 0xFF) as u8,
            month: ((raw >> 8) & 0x0F) as u8,
            day: ((raw >> 12) & 0x0F) as u8,
            major: ((raw >> 16) & 0xFF) as u8,
            minor: ((raw >> 24) & 0x0F) as u8,
            patch: ((raw >> 28) & 0x0F) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// Boot image version
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootImageVersion {
    V0,
    V1,
    V2,
    V3,
    V4,
}

impl BootImageVersion {
    pub fn from_u32(v: u32) -> Result<Self, BootImageError> {
        match v {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            other => Err(BootImageError::UnsupportedVersion(other)),
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }

    /// Native (unpadded) header size in bytes.
    pub fn header_size(&self) -> usize {
        match self {
            Self::V0 => BOOT_IMAGE_HEADER_V0_SIZE,
            Self::V1 => BOOT_IMAGE_HEADER_V1_SIZE,
            Self::V2 => BOOT_IMAGE_HEADER_V2_SIZE,
            Self::V3 | Self::V4 => BOOT_IMAGE_HEADER_V4_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// Boot image header (unified across v0–v4)
// ---------------------------------------------------------------------------

/// Unified boot image header covering v0 through v4.
///
/// Fields that don't exist in a given version are ignored during encode /
/// decode for that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImageHeader {
    // -- Common to all versions --
    pub header_version: u32,
    pub kernel_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub os_version: u32,

    // -- v0/v1/v2 --
    pub second_size: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    pub name: String,
    pub cmdline: String,
    pub id: [u8; BOOT_ID_SIZE],
    pub extra_cmdline: String,

    // -- v1+ --
    pub recovery_dtbo_size: u32,
    pub recovery_dtbo_offset: u64,
    pub boot_header_size: u32,

    // -- v2+ --
    pub dtb_size: u32,
    pub dtb_addr: u64,

    // -- v4 (stored in boot image, not vendor boot) --
    // For v4 boot images, the header is the same size as v3 (4096).
    // The vendor ramdisk table and additional data follow after the page.
    // We track whether this was parsed as v3 or v4.
}

impl BootImageHeader {
    /// Create a default v0 header.
    pub fn new_v0() -> Self {
        Self {
            header_version: 0,
            kernel_size: 0,
            kernel_addr: DEFAULT_KERNEL_ADDR,
            ramdisk_size: 0,
            ramdisk_addr: DEFAULT_RAMDISK_ADDR,
            os_version: 0,
            second_size: 0,
            second_addr: DEFAULT_SECOND_ADDR,
            tags_addr: DEFAULT_TAGS_ADDR,
            page_size: DEFAULT_PAGE_SIZE,
            name: String::new(),
            cmdline: String::new(),
            id: [0u8; BOOT_ID_SIZE],
            extra_cmdline: String::new(),
            recovery_dtbo_size: 0,
            recovery_dtbo_offset: 0,
            boot_header_size: 0,
            dtb_size: 0,
            dtb_addr: 0,
        }
    }

    /// Create a default v3/v4 header.
    pub fn new_v3() -> Self {
        Self {
            header_version: 3,
            kernel_size: 0,
            kernel_addr: 0,
            ramdisk_size: 0,
            ramdisk_addr: 0,
            os_version: 0,
            second_size: 0,
            second_addr: 0,
            tags_addr: 0,
            page_size: 4096,
            name: String::new(),
            cmdline: String::new(),
            id: [0u8; BOOT_ID_SIZE],
            extra_cmdline: String::new(),
            recovery_dtbo_size: 0,
            recovery_dtbo_offset: 0,
            boot_header_size: BOOT_IMAGE_HEADER_V3_SIZE as u32,
            dtb_size: 0,
            dtb_addr: 0,
        }
    }

    // ------------------------------------------------------------------
    // Encode
    // ------------------------------------------------------------------

    /// Encode the header into its on-disk representation (without page
    /// padding). The caller must pad to `page_size`.
    pub fn encode(&self) -> Vec<u8> {
        let version = self.header_version;
        let mut buf = Vec::with_capacity(self.native_header_size());

        // Magic (8 bytes)
        buf.extend_from_slice(&BOOT_MAGIC);

        match version {
            0 | 1 | 2 => self.encode_v0_v1_v2(&mut buf),
            3 | 4 => self.encode_v3_v4(&mut buf),
            _ => {} // unreachable via from_u32 guard
        }

        buf
    }

    fn encode_v0_v1_v2(&self, buf: &mut Vec<u8>) {
        let version = self.header_version;
        let hdr_sz = BootImageVersion::from_u32(version)
            .map(|v| v.header_size())
            .unwrap_or(0);

        // Write scalar fields up to extra_cmdline
        write_u32(buf, self.kernel_size);
        write_u32(buf, self.kernel_addr);
        write_u32(buf, self.ramdisk_size);
        write_u32(buf, self.ramdisk_addr);
        write_u32(buf, self.second_size);
        write_u32(buf, self.second_addr);
        write_u32(buf, self.tags_addr);
        write_u32(buf, self.page_size);

        // header_version at offset 40
        write_u32(buf, self.header_version);

        // os_version at offset 44
        write_u32(buf, self.os_version);

        // name[16]
        write_fixed_string(buf, &self.name, BOOT_NAME_SIZE);

        // cmdline[512]
        write_fixed_string(buf, &self.cmdline, BOOT_ARGS_SIZE);

        // id[8] = 32 bytes
        buf.extend_from_slice(&self.id);

        // extra_cmdline[1024]
        write_fixed_string(buf, &self.extra_cmdline, BOOT_EXTRA_ARGS_SIZE);

        // v1+ extensions
        if version >= 1 {
            write_u32(buf, self.recovery_dtbo_size);
            write_u64(buf, self.recovery_dtbo_offset);
            write_u32(buf, self.boot_header_size);
        }

        // v2+ extensions
        if version >= 2 {
            write_u32(buf, self.dtb_size);
            write_u64(buf, self.dtb_addr);
        }

        // Pad to header size
        while buf.len() < hdr_sz {
            buf.push(0);
        }
    }

    fn encode_v3_v4(&self, buf: &mut Vec<u8>) {
        // v3/v4 layout (4096 bytes):
        // offset 0: magic (8)
        // offset 8: header_version (4) = 3 or 4
        // offset 12: kernel_size (4)
        // offset 16: ramdisk_size (4)
        // offset 20: os_version (4)
        // offset 24: header_size (4) = 4096
        // offset 28: reserved[4] (16 bytes)
        // offset 44..4095: padding

        write_u32(buf, self.header_version);
        write_u32(buf, self.kernel_size);
        write_u32(buf, self.ramdisk_size);
        write_u32(buf, self.os_version);
        write_u32(buf, BOOT_IMAGE_HEADER_V3_SIZE as u32); // header_size = 4096

        // reserved[4] = 16 bytes
        for _ in 0..4 {
            write_u32(buf, 0);
        }

        // Pad to exactly 4096 bytes
        while buf.len() < BOOT_IMAGE_HEADER_V3_SIZE {
            buf.push(0);
        }
    }

    /// Native header size for this instance's version.
    fn native_header_size(&self) -> usize {
        BootImageVersion::from_u32(self.header_version)
            .map(|v| v.header_size())
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // Decode
    // ------------------------------------------------------------------

    /// Parse a boot image header from the beginning of `data`.
    /// `data` should contain at least the header (unpadded size), but extra
    /// bytes are ignored.
    pub fn decode(data: &[u8]) -> Result<Self, BootImageError> {
        if data.len() < BOOT_MAGIC.len() {
            return Err(BootImageError::BufferTooShort {
                expected: BOOT_MAGIC.len(),
                got: data.len(),
            });
        }

        // Check magic
        if &data[0..8] != BOOT_MAGIC {
            let got: String = data[0..8].iter().map(|&b| b as char).collect();
            return Err(BootImageError::InvalidMagic { got });
        }

        // Determine version:
        //   v0/v1/v2: header_version is at offset 40
        //   v3/v4:    header_version is at offset 8  (offset 40 is reserved/zero)
        //
        // Strategy: check offset 8 first.  If it's 3 or 4 → v3/v4.
        // Otherwise check offset 40 for 0/1/2 → v0/v1/v2.
        // Ambiguity when a v0 kernel_size happens to be 3 or 4 is
        // theoretically possible but impossible in practice.
        let ver_at_8 = if data.len() < 12 {
            return Err(BootImageError::BufferTooShort {
                expected: 12,
                got: data.len(),
            });
        } else {
            LittleEndian::read_u32(&data[8..12])
        };

        let version = if ver_at_8 == 3 || ver_at_8 == 4 {
            ver_at_8
        } else {
            // v0/v1/v2
            let ver_at_40 = LittleEndian::read_u32(&data[40..44]);
            if ver_at_40 <= 2 {
                ver_at_40
            } else {
                return Err(BootImageError::UnsupportedVersion(ver_at_40));
            }
        };

        match version {
            0 | 1 | 2 => Self::decode_v0_v1_v2(data, version),
            3 | 4 => Self::decode_v3_v4(data, version),
            _ => Err(BootImageError::UnsupportedVersion(version)),
        }
    }

    fn decode_v0_v1_v2(data: &[u8], version: u32) -> Result<Self, BootImageError> {
        let hdr_sz = BootImageVersion::from_u32(version)
            .map(|v| v.header_size())
            .unwrap();

        if data.len() < hdr_sz {
            return Err(BootImageError::BufferTooShort {
                expected: hdr_sz,
                got: data.len(),
            });
        }

        // Read scalar fields from fixed offsets (after the 8-byte magic)
        let mut off = 8usize;
        let kernel_size = read_u32(data, &mut off);
        let kernel_addr = read_u32(data, &mut off);
        let ramdisk_size = read_u32(data, &mut off);
        let ramdisk_addr = read_u32(data, &mut off);
        let second_size = read_u32(data, &mut off);
        let second_addr = read_u32(data, &mut off);
        let tags_addr = read_u32(data, &mut off);
        let page_size = read_u32(data, &mut off);
        let header_version = read_u32(data, &mut off);
        let os_version = read_u32(data, &mut off);

        // name[16]
        off = 48;
        let name = read_fixed_string(data, &mut off, BOOT_NAME_SIZE);

        // cmdline[512]
        off = 64;
        let cmdline = read_fixed_string(data, &mut off, BOOT_ARGS_SIZE);

        // id[32]
        off = 576;
        let mut id = [0u8; BOOT_ID_SIZE];
        id.copy_from_slice(&data[off..off + BOOT_ID_SIZE]);

        // extra_cmdline[1024]
        off = 608;
        let extra_cmdline = read_fixed_string(data, &mut off, BOOT_EXTRA_ARGS_SIZE);

        // v1+ extensions start at offset 1632
        let (recovery_dtbo_size, recovery_dtbo_offset, boot_header_size) = if version >= 1 {
            off = BOOT_IMAGE_HEADER_V0_SIZE;
            (
                read_u32(data, &mut off),
                read_u64(data, &mut off),
                read_u32(data, &mut off),
            )
        } else {
            (0, 0, 0)
        };

        // v2+ extensions
        let (dtb_size, dtb_addr) = if version >= 2 {
            off = BOOT_IMAGE_HEADER_V1_SIZE;
            (read_u32(data, &mut off), read_u64(data, &mut off))
        } else {
            (0, 0)
        };

        Ok(Self {
            header_version,
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            os_version,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            name,
            cmdline,
            id,
            extra_cmdline,
            recovery_dtbo_size,
            recovery_dtbo_offset,
            boot_header_size,
            dtb_size,
            dtb_addr,
        })
    }

    fn decode_v3_v4(data: &[u8], version: u32) -> Result<Self, BootImageError> {
        if data.len() < BOOT_IMAGE_HEADER_V3_SIZE {
            return Err(BootImageError::BufferTooShort {
                expected: BOOT_IMAGE_HEADER_V3_SIZE,
                got: data.len(),
            });
        }

        let kernel_size = LittleEndian::read_u32(&data[12..16]);
        let ramdisk_size = LittleEndian::read_u32(&data[16..20]);
        let os_version = LittleEndian::read_u32(&data[20..24]);

        Ok(Self {
            header_version: version,
            kernel_size,
            kernel_addr: 0,
            ramdisk_size,
            ramdisk_addr: 0,
            os_version,
            second_size: 0,
            second_addr: 0,
            tags_addr: 0,
            page_size: 4096,
            name: String::new(),
            cmdline: String::new(),
            id: [0u8; BOOT_ID_SIZE],
            extra_cmdline: String::new(),
            recovery_dtbo_size: 0,
            recovery_dtbo_offset: 0,
            boot_header_size: BOOT_IMAGE_HEADER_V3_SIZE as u32,
            dtb_size: 0,
            dtb_addr: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// BootImage (header + data sections)
// ---------------------------------------------------------------------------

/// A complete boot image consisting of a header and the associated payload
/// sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImage {
    pub header: BootImageHeader,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second: Vec<u8>,
    pub recovery_dtbo: Vec<u8>,
    pub dtb: Vec<u8>,
}

impl BootImage {
    pub fn new(header: BootImageHeader) -> Self {
        Self {
            header,
            kernel: Vec::new(),
            ramdisk: Vec::new(),
            second: Vec::new(),
            recovery_dtbo: Vec::new(),
            dtb: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Build / Parse public API
// ---------------------------------------------------------------------------

/// Build a complete boot image from its components.
///
/// `page_size` is only meaningful for v0–v2; v3/v4 use a fixed 4096-byte
/// page. The returned vector contains the header (padded to a page boundary)
/// followed by the kernel, ramdisk, second, recovery_dtbo, and dtb sections,
/// each also padded to a page boundary.
pub fn build_boot_image(
    kernel: &[u8],
    ramdisk: &[u8],
    second: &[u8],
    dtb: &[u8],
    page_size: u32,
    header_version: u32,
) -> Vec<u8> {
    let ps = match header_version {
        0 | 1 | 2 => {
            if !page_size.is_power_of_two() || page_size == 0 {
                DEFAULT_PAGE_SIZE
            } else {
                page_size
            }
        }
        _ => 4096,
    } as usize;

    let mut hdr = match header_version {
        0 | 1 | 2 => BootImageHeader::new_v0(),
        _ => BootImageHeader::new_v3(),
    };

    hdr.header_version = header_version;
    hdr.kernel_size = kernel.len() as u32;
    hdr.ramdisk_size = ramdisk.len() as u32;
    hdr.second_size = second.len() as u32;
    hdr.page_size = ps as u32;

    if header_version >= 1 {
        hdr.boot_header_size = BootImageVersion::from_u32(header_version)
            .map(|v| v.header_size() as u32)
            .unwrap_or(0);

        hdr.recovery_dtbo_size = 0;
        hdr.recovery_dtbo_offset = 0;
    }

    if header_version >= 2 {
        hdr.dtb_size = dtb.len() as u32;
        hdr.dtb_addr = 0;
    }

    // Encode header and compute section offsets
    let mut raw_hdr = hdr.encode();
    let hdr_page = align_up(raw_hdr.len(), ps);
    raw_hdr.resize(hdr_page, 0);

    let mut image = raw_hdr;

    // Kernel
    if !kernel.is_empty() {
        let mut section = kernel.to_vec();
        section.resize(align_up(section.len(), ps), 0);
        image.extend_from_slice(&section);
    }

    // Ramdisk
    if !ramdisk.is_empty() {
        let mut section = ramdisk.to_vec();
        section.resize(align_up(section.len(), ps), 0);
        image.extend_from_slice(&section);
    }

    // Second
    if !second.is_empty() && header_version <= 2 {
        let mut section = second.to_vec();
        section.resize(align_up(section.len(), ps), 0);
        image.extend_from_slice(&section);
    }

    // Recovery DTBO (v1+)
    if header_version == 1 {
        // In practice, recovery_dtbo is stored here for non-A/B devices
        // We don't take it as a separate parameter; it's part of the image.
    }

    // DTB (v2+)
    if !dtb.is_empty() && header_version >= 2 {
        let mut section = dtb.to_vec();
        section.resize(align_up(section.len(), ps), 0);
        image.extend_from_slice(&section);
    }

    image
}

/// Parse a complete boot image from raw bytes.
///
/// Returns the header and the extracted data sections (kernel, ramdisk, etc.).
pub fn parse_boot_image(data: &[u8]) -> Result<BootImage, BootImageError> {
    if data.len() < BOOT_MAGIC.len() {
        return Err(BootImageError::BufferTooShort {
            expected: BOOT_MAGIC.len(),
            got: data.len(),
        });
    }

    let header = BootImageHeader::decode(data)?;
    let version = header.header_version;
    let ps = match version {
        0 | 1 | 2 => header.page_size as usize,
        _ => 4096,
    };

    if ps == 0 || !ps.is_power_of_two() {
        return Err(BootImageError::InvalidPageSize(header.page_size));
    }

    let hdr_bytes = match version {
        0 | 1 | 2 => align_up(
            BootImageVersion::from_u32(version).unwrap().header_size(),
            ps,
        ),
        _ => BOOT_IMAGE_HEADER_V3_SIZE,
    };

    if data.len() < hdr_bytes {
        return Err(BootImageError::BufferTooShort {
            expected: hdr_bytes,
            got: data.len(),
        });
    }

    let mut offset = hdr_bytes;

    // Kernel
    let kernel_size = header.kernel_size as usize;
    let kernel = if kernel_size > 0 {
        let padded = align_up(kernel_size, ps);
        if offset + padded > data.len() {
            return Err(BootImageError::SectionBounds {
                section: "kernel",
                offset,
                size: padded,
                len: data.len(),
            });
        }
        let section = data[offset..offset + kernel_size].to_vec();
        offset += padded;
        section
    } else {
        Vec::new()
    };

    // Ramdisk
    let ramdisk_size = header.ramdisk_size as usize;
    let ramdisk = if ramdisk_size > 0 {
        let padded = align_up(ramdisk_size, ps);
        if offset + padded > data.len() {
            return Err(BootImageError::SectionBounds {
                section: "ramdisk",
                offset,
                size: padded,
                len: data.len(),
            });
        }
        let section = data[offset..offset + ramdisk_size].to_vec();
        offset += padded;
        section
    } else {
        Vec::new()
    };

    // Second stage (v0–v2 only)
    let second_size = if version <= 2 {
        header.second_size as usize
    } else {
        0
    };
    let second = if second_size > 0 {
        let padded = align_up(second_size, ps);
        if offset + padded > data.len() {
            return Err(BootImageError::SectionBounds {
                section: "second",
                offset,
                size: padded,
                len: data.len(),
            });
        }
        let section = data[offset..offset + second_size].to_vec();
        offset += padded;
        section
    } else {
        Vec::new()
    };

    // Recovery DTBO (v1)
    let recovery_dtbo = if version == 1 && header.recovery_dtbo_size > 0 {
        let sz = header.recovery_dtbo_size as usize;
        let padded = align_up(sz, ps);
        if offset + padded > data.len() {
            return Err(BootImageError::SectionBounds {
                section: "recovery_dtbo",
                offset,
                size: padded,
                len: data.len(),
            });
        }
        let section = data[offset..offset + sz].to_vec();
        offset += padded;
        section
    } else {
        Vec::new()
    };

    // DTB (v2+)
    let dtb_size = if version >= 2 {
        header.dtb_size as usize
    } else {
        0
    };
    let dtb = if dtb_size > 0 {
        let padded = align_up(dtb_size, ps);
        if offset + padded > data.len() {
            return Err(BootImageError::SectionBounds {
                section: "dtb",
                offset,
                size: padded,
                len: data.len(),
            });
        }
        let section = data[offset..offset + dtb_size].to_vec();
        section
    } else {
        Vec::new()
    };

    Ok(BootImage {
        header,
        kernel,
        ramdisk,
        second,
        recovery_dtbo,
        dtb,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    let mut tmp = [0u8; 4];
    LittleEndian::write_u32(&mut tmp, v);
    buf.extend_from_slice(&tmp);
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    let mut tmp = [0u8; 8];
    LittleEndian::write_u64(&mut tmp, v);
    buf.extend_from_slice(&tmp);
}

fn write_fixed_string(buf: &mut Vec<u8>, s: &str, len: usize) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(len);
    buf.extend_from_slice(&bytes[..copy_len]);
    // Pad with null bytes
    if copy_len < len {
        buf.resize(buf.len() + (len - copy_len), 0);
    }
}

fn read_u32(data: &[u8], off: &mut usize) -> u32 {
    let v = LittleEndian::read_u32(&data[*off..*off + 4]);
    *off += 4;
    v
}

fn read_u64(data: &[u8], off: &mut usize) -> u64 {
    let v = LittleEndian::read_u64(&data[*off..*off + 8]);
    *off += 8;
    v
}

fn read_fixed_string(data: &[u8], off: &mut usize, len: usize) -> String {
    let end = data[*off..*off + len]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(len);
    let s = String::from_utf8_lossy(&data[*off..*off + end]).to_string();
    *off += len;
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // OsVersion encode/decode
    // ------------------------------------------------------------------

    #[test]
    fn test_os_version_roundtrip() {
        let ov = OsVersion::new(12, 0, 0, 25, 1, 15);
        let encoded = ov.encode();
        let decoded = OsVersion::decode(encoded);
        assert_eq!(ov, decoded);
    }

    #[test]
    fn test_os_version_zero() {
        let ov = OsVersion::decode(0);
        assert_eq!(ov.major, 0);
        assert_eq!(ov.minor, 0);
        assert_eq!(ov.patch, 0);
        assert_eq!(ov.year_since_2000, 0);
    }

    #[test]
    fn test_os_version_max() {
        // All bits set within field ranges (major 7 bits max=127, minor 4 bits max=15,
        // patch 4 bits max=15, year 8 bits, month/day 4 bits)
        let raw = (127u32 << 16) | (15u32 << 24) | (15u32 << 28) | 0xFFu32 | (15u32 << 8) | (15u32 << 12);
        let ov = OsVersion::decode(raw);
        assert_eq!(ov.major, 127);
        assert_eq!(ov.minor, 15);
        assert_eq!(ov.patch, 15);
        assert_eq!(ov.year_since_2000, 255);
        assert_eq!(ov.month, 15);
        assert_eq!(ov.day, 15);
    }

    // ------------------------------------------------------------------
    // BootImageHeader v0 encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_header_v0_roundtrip() {
        let mut hdr = BootImageHeader::new_v0();
        hdr.kernel_size = 0x123456;
        hdr.kernel_addr = 0x8000;
        hdr.ramdisk_size = 0x7890;
        hdr.ramdisk_addr = 0x1000000;
        hdr.second_size = 0x100;
        hdr.second_addr = 0xF00000;
        hdr.tags_addr = 0x100;
        hdr.page_size = 2048;
        hdr.os_version = OsVersion::new(14, 0, 0, 24, 10, 1).encode();
        hdr.name = "boot".to_string();
        hdr.cmdline = "console=ttyS0 androidboot.hardware=foo".to_string();
        hdr.extra_cmdline = "extra=1".to_string();
        hdr.id.copy_from_slice(b"0123456789abcdef0123456789abcdef"); // 32 bytes

        let encoded = hdr.encode();
        let decoded = BootImageHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.header_version, 0);
        assert_eq!(decoded.kernel_size, 0x123456);
        assert_eq!(decoded.kernel_addr, 0x8000);
        assert_eq!(decoded.ramdisk_size, 0x7890);
        assert_eq!(decoded.ramdisk_addr, 0x1000000);
        assert_eq!(decoded.second_size, 0x100);
        assert_eq!(decoded.second_addr, 0xF00000);
        assert_eq!(decoded.tags_addr, 0x100);
        assert_eq!(decoded.page_size, 2048);
        assert_eq!(decoded.name, "boot");
        assert_eq!(decoded.cmdline, "console=ttyS0 androidboot.hardware=foo");
        assert_eq!(decoded.extra_cmdline, "extra=1");
        assert_eq!(decoded.id, *b"0123456789abcdef0123456789abcdef");
    }

    // ------------------------------------------------------------------
    // BootImageHeader v1 encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_header_v1_roundtrip() {
        let mut hdr = BootImageHeader::new_v0();
        hdr.header_version = 1;
        hdr.kernel_size = 0x100000;
        hdr.ramdisk_size = 0x50000;
        hdr.page_size = 4096;
        hdr.boot_header_size = BOOT_IMAGE_HEADER_V1_SIZE as u32;
        hdr.recovery_dtbo_size = 0x8000;
        hdr.recovery_dtbo_offset = 0x200000;
        hdr.cmdline = "androidboot.slot_suffix=_a".to_string();

        let encoded = hdr.encode();
        let decoded = BootImageHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.header_version, 1);
        assert_eq!(decoded.kernel_size, 0x100000);
        assert_eq!(decoded.boot_header_size, BOOT_IMAGE_HEADER_V1_SIZE as u32);
        assert_eq!(decoded.recovery_dtbo_size, 0x8000);
        assert_eq!(decoded.recovery_dtbo_offset, 0x200000);
        assert_eq!(decoded.cmdline, "androidboot.slot_suffix=_a");
    }

    // ------------------------------------------------------------------
    // BootImageHeader v2 encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_header_v2_roundtrip() {
        let mut hdr = BootImageHeader::new_v0();
        hdr.header_version = 2;
        hdr.kernel_size = 0x200000;
        hdr.ramdisk_size = 0x100000;
        hdr.page_size = 4096;
        hdr.boot_header_size = BOOT_IMAGE_HEADER_V2_SIZE as u32;
        hdr.dtb_size = 0x40000;
        hdr.dtb_addr = 0x10000000;

        let encoded = hdr.encode();
        let decoded = BootImageHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.header_version, 2);
        assert_eq!(decoded.dtb_size, 0x40000);
        assert_eq!(decoded.dtb_addr, 0x10000000);
    }

    // ------------------------------------------------------------------
    // BootImageHeader v3 encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_header_v3_roundtrip() {
        let mut hdr = BootImageHeader::new_v3();
        hdr.kernel_size = 0x300000;
        hdr.ramdisk_size = 0x80000;
        hdr.os_version = OsVersion::new(14, 0, 0, 24, 10, 1).encode();

        let encoded = hdr.encode();
        assert_eq!(encoded.len(), 4096);

        let decoded = BootImageHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.header_version, 3);
        assert_eq!(decoded.kernel_size, 0x300000);
        assert_eq!(decoded.ramdisk_size, 0x80000);
        assert_eq!(decoded.page_size, 4096);
        assert_eq!(decoded.boot_header_size, BOOT_IMAGE_HEADER_V3_SIZE as u32);
        assert_eq!(decoded.cmdline, "");
    }

    // ------------------------------------------------------------------
    // BootImageHeader v4 encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_header_v4_roundtrip() {
        let mut hdr = BootImageHeader::new_v3();
        hdr.header_version = 4;
        hdr.kernel_size = 0x400000;
        hdr.ramdisk_size = 0x100000;

        let encoded = hdr.encode();
        assert_eq!(encoded.len(), 4096);

        let decoded = BootImageHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.header_version, 4);
        assert_eq!(decoded.kernel_size, 0x400000);
        assert_eq!(decoded.ramdisk_size, 0x100000);
    }

    // ------------------------------------------------------------------
    // Decode errors
    // ------------------------------------------------------------------

    #[test]
    fn test_decode_invalid_magic() {
        let data = b"XXXXXXXX"; // wrong magic
        let err = BootImageHeader::decode(data).unwrap_err();
        assert!(
            matches!(err, BootImageError::InvalidMagic { .. }),
            "expected InvalidMagic, got {:?}",
            err
        );
    }

    #[test]
    fn test_decode_too_short() {
        let data = b"ANDROI"; // only 6 bytes
        let err = BootImageHeader::decode(data).unwrap_err();
        assert!(
            matches!(err, BootImageError::BufferTooShort { .. }),
            "expected BufferTooShort, got {:?}",
            err
        );
    }

    // ------------------------------------------------------------------
    // build_boot_image / parse_boot_image roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_build_parse_v0_roundtrip() {
        let kernel = vec![0xAAu8; 1024];
        let ramdisk = vec![0xBBu8; 512];
        let second = vec![0xCCu8; 128];

        let image = build_boot_image(&kernel, &ramdisk, &second, &[], 2048, 0);
        let parsed = parse_boot_image(&image).unwrap();

        assert_eq!(parsed.header.header_version, 0);
        assert_eq!(parsed.kernel, kernel);
        assert_eq!(parsed.ramdisk, ramdisk);
        assert_eq!(parsed.second, second);
        assert!(parsed.recovery_dtbo.is_empty());
        assert!(parsed.dtb.is_empty());

        // Verify page alignment
        let ps = 2048usize;
        assert_eq!(image.len() % ps, 0);
    }

    #[test]
    fn test_build_parse_v1_roundtrip() {
        let kernel = vec![0xAAu8; 2048];
        let ramdisk = vec![0xBBu8; 1024];

        let image = build_boot_image(&kernel, &ramdisk, &[], &[], 4096, 1);
        let parsed = parse_boot_image(&image).unwrap();

        assert_eq!(parsed.header.header_version, 1);
        assert_eq!(parsed.kernel, kernel);
        assert_eq!(parsed.ramdisk, ramdisk);
        assert!(parsed.second.is_empty());
        assert!(parsed.dtb.is_empty());
    }

    #[test]
    fn test_build_parse_v2_roundtrip() {
        let kernel = vec![0xAAu8; 4096];
        let ramdisk = vec![0xBBu8; 2048];
        let dtb = vec![0xDDu8; 512];

        let image = build_boot_image(&kernel, &ramdisk, &[], &dtb, 4096, 2);
        let parsed = parse_boot_image(&image).unwrap();

        assert_eq!(parsed.header.header_version, 2);
        assert_eq!(parsed.kernel, kernel);
        assert_eq!(parsed.ramdisk, ramdisk);
        assert_eq!(parsed.dtb, dtb);
    }

    #[test]
    fn test_build_parse_v3_roundtrip() {
        let kernel = vec![0xAAu8; 4096];
        let ramdisk = vec![0xBBu8; 2048];

        let image = build_boot_image(&kernel, &ramdisk, &[], &[], 4096, 3);
        assert_eq!(image.len() % 4096, 0);

        let parsed = parse_boot_image(&image).unwrap();

        assert_eq!(parsed.header.header_version, 3);
        assert_eq!(parsed.kernel, kernel);
        assert_eq!(parsed.ramdisk, ramdisk);
        assert!(parsed.second.is_empty());
        assert!(parsed.dtb.is_empty());
    }

    #[test]
    fn test_build_parse_v4_roundtrip() {
        let kernel = vec![0xAAu8; 8192];
        let ramdisk = vec![0xBBu8; 4096];

        let image = build_boot_image(&kernel, &ramdisk, &[], &[], 4096, 4);
        assert_eq!(image.len() % 4096, 0);

        let parsed = parse_boot_image(&image).unwrap();

        assert_eq!(parsed.header.header_version, 4);
        assert_eq!(parsed.kernel, kernel);
        assert_eq!(parsed.ramdisk, ramdisk);
    }

    // ------------------------------------------------------------------
    // build_boot_image: empty sections
    // ------------------------------------------------------------------

    #[test]
    fn test_build_empty_kernel() {
        // A boot image with no kernel is degenerate but should not panic
        let image = build_boot_image(&[], &[], &[], &[], 2048, 0);
        let parsed = parse_boot_image(&image).unwrap();
        assert_eq!(parsed.header.kernel_size, 0);
        assert!(parsed.kernel.is_empty());
    }

    // ------------------------------------------------------------------
    // Build with known size checks (v0)
    // ------------------------------------------------------------------

    #[test]
    fn test_v0_image_size() {
        let kernel = vec![0xAAu8; 1]; // 1 byte, will be padded to page
        let ramdisk = vec![0xBBu8; 1];
        let ps = 2048usize;

        let image = build_boot_image(&kernel, &ramdisk, &[], &[], ps as u32, 0);

        // header: 1632 bytes + padding to 2048
        // kernel: 1 + padding to 2048
        // ramdisk: 1 + padding to 2048
        let expected = 2048 + 2048 + 2048;
        assert_eq!(image.len(), expected);
        assert_eq!(image.len() % ps, 0);
    }

    // ------------------------------------------------------------------
    // BootImageVersion tests
    // ------------------------------------------------------------------

    #[test]
    fn test_boot_image_version() {
        assert_eq!(BootImageVersion::from_u32(0).unwrap(), BootImageVersion::V0);
        assert_eq!(BootImageVersion::from_u32(1).unwrap(), BootImageVersion::V1);
        assert_eq!(BootImageVersion::from_u32(2).unwrap(), BootImageVersion::V2);
        assert_eq!(BootImageVersion::from_u32(3).unwrap(), BootImageVersion::V3);
        assert_eq!(BootImageVersion::from_u32(4).unwrap(), BootImageVersion::V4);
        assert!(BootImageVersion::from_u32(5).is_err());

        assert_eq!(BootImageVersion::V0.as_u32(), 0);
        assert_eq!(BootImageVersion::V1.as_u32(), 1);
        assert_eq!(BootImageVersion::V2.as_u32(), 2);
        assert_eq!(BootImageVersion::V3.as_u32(), 3);
        assert_eq!(BootImageVersion::V4.as_u32(), 4);
    }

    #[test]
    fn test_header_sizes() {
        assert_eq!(BootImageVersion::V0.header_size(), 1632);
        assert_eq!(BootImageVersion::V1.header_size(), 1648);
        assert_eq!(BootImageVersion::V2.header_size(), 1664);
        assert_eq!(BootImageVersion::V3.header_size(), 4096);
        assert_eq!(BootImageVersion::V4.header_size(), 4096);
    }

    // ------------------------------------------------------------------
    // id field read/write
    // ------------------------------------------------------------------

    #[test]
    fn test_header_id_field() {
        let mut hdr = BootImageHeader::new_v0();
        let expected_id = b"abcdefghijklmnopqrstuvwxyz123456"; // 32 bytes
        hdr.id.copy_from_slice(expected_id);

        let encoded = hdr.encode();
        let decoded = BootImageHeader::decode(&encoded).unwrap();
        assert_eq!(&decoded.id[..], expected_id);
    }
}
