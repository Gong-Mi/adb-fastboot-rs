use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use clap::{Parser, Subcommand};
use fastboot_protocol::{FastbootTcpTransport, FastbootTransport};
#[cfg(feature = "usb")]
use fastboot_protocol::usb_android::UsbfsFastbootDevice;
use zip::ZipArchive;

/// AOSP-mirror global options that affect flash/update orchestration.
///
/// Constructed once in `main()` from the CLI flags and threaded through
/// every command that needs them.  Field names match the AOSP C++ globals
/// (`g_disable_verity`, etc.) for traceability.
#[derive(Debug, Clone, Copy, Default)]
struct GlobalOptions {
    /// `--disable-verity`: set bit 0 in vbmeta flags.
    disable_verity: bool,
    /// `--disable-verification`: set bit 1 in vbmeta flags.
    disable_verification: bool,
    /// `--verbose` / `-v`.
    verbose: bool,
}

impl GlobalOptions {
    /// True when either vbmeta flag needs patching.
    fn needs_vbmeta_patch(&self) -> bool {
        self.disable_verity || self.disable_verification
    }
}

/// AOSP `AVB_MAGIC` = "AVB0" (4 bytes).
const AVB_MAGIC: &[u8; 4] = b"AVB0";
/// AOSP `AVB_FOOTER_MAGIC` = "AVBf" (4 bytes).
const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
const AVB_FOOTER_SIZE: usize = 64;
const VBMETA_HEADER_SIZE: usize = 256;
/// AvbVBMetaImageHeader.flags is BE u32 at 120; bits 0/1 are in byte 123.
const VBMETA_FLAGS_LSB_OFFSET: usize = 123;

/// Rewrite flags using Android 17's packed AvbFooter/AvbVBMetaImageHeader
/// layouts (external/avb ba2dec4b, core fastboot.cpp:rewrite_vbmeta_buffer).
/// No flags or no recognized AVB structure preserves the existing raw-image
/// behavior. Recognized but truncated/inconsistent structures return an error.
/// This checks structural bounds, NOT signatures, algorithms or key trust.
fn patch_vbmeta_flags(data: &[u8], opts: &GlobalOptions) -> Result<Option<Vec<u8>>, String> {
    if !opts.needs_vbmeta_patch() {
        return Ok(None);
    }
    let error = || "invalid AVB/vbmeta structure: truncated or overflowing field/range".to_string();
    let read_u32 = |bytes: &[u8], offset: usize| -> Result<u32, String> {
        let end = offset.checked_add(4).ok_or_else(error)?;
        let field = bytes.get(offset..end).ok_or_else(error)?;
        Ok(u32::from_be_bytes(field.try_into().map_err(|_| error())?))
    };
    let read_u64 = |bytes: &[u8], offset: usize| -> Result<u64, String> {
        let end = offset.checked_add(8).ok_or_else(error)?;
        let field = bytes.get(offset..end).ok_or_else(error)?;
        Ok(u64::from_be_bytes(field.try_into().map_err(|_| error())?))
    };
    let native = |value: u64| usize::try_from(value).map_err(|_| error());

    let footer_start = data.len().checked_sub(AVB_FOOTER_SIZE);
    let footer = footer_start.and_then(|start| data.get(start..));
    let (vbmeta_offset, vbmeta_end) = match footer {
        Some(footer) if footer.starts_with(AVB_FOOTER_MAGIC) => {
            // Packed footer: major=4, minor=8, original_size=12,
            // vbmeta_offset=20, vbmeta_size=28, reserved=36. In particular,
            // [8..16] is NOT the offset. libavb accepts major <= 1 and any minor.
            if read_u32(footer, 4)? > 1 {
                return Err("unsupported AVB footer major version".to_string());
            }
            let original_size = native(read_u64(footer, 12)?)?;
            let offset = native(read_u64(footer, 20)?)?;
            let size = native(read_u64(footer, 28)?)?;
            let end = offset.checked_add(size).ok_or_else(error)?;
            let start = footer_start.ok_or_else(error)?;
            if original_size > offset || size < VBMETA_HEADER_SIZE || end > start {
                return Err(error());
            }
            data.get(offset..end).ok_or_else(error)?;
            (offset, end)
        }
        _ if data.starts_with(AVB_MAGIC) => (0, data.len()),
        _ => return Ok(None),
    };
    let header_end = vbmeta_offset
        .checked_add(VBMETA_HEADER_SIZE)
        .ok_or_else(error)?;
    if header_end > vbmeta_end {
        return Err(error());
    }
    let header = data.get(vbmeta_offset..header_end).ok_or_else(error)?;
    if !header.starts_with(AVB_MAGIC) {
        return Err("invalid AVB/vbmeta structure: footer does not point to AVB0".to_string());
    }

    // Header + auth + aux must be present; all relative ranges must fit their
    // own block. Reject corrupt sizes without authenticating/re-signing data.
    let auth_size = native(read_u64(header, 12)?)?;
    let aux_size = native(read_u64(header, 20)?)?;
    if auth_size % 64 != 0 || aux_size % 64 != 0 {
        return Err("invalid AVB/vbmeta structure: unaligned auth/aux block".to_string());
    }
    let end = header_end
        .checked_add(auth_size)
        .and_then(|end| end.checked_add(aux_size))
        .ok_or_else(error)?;
    if end > vbmeta_end {
        return Err(error());
    }
    data.get(vbmeta_offset..end).ok_or_else(error)?;
    for (offset_field, size_field, block_size) in [
        (32, 40, auth_size), // hash
        (48, 56, auth_size), // signature
        (64, 72, aux_size),  // public key
        (80, 88, aux_size),  // public key metadata
        (96, 104, aux_size), // descriptors
    ] {
        let offset = native(read_u64(header, offset_field)?)?;
        let size = native(read_u64(header, size_field)?)?;
        if offset.checked_add(size).ok_or_else(error)? > block_size {
            return Err(error());
        }
    }

    let flags_byte = vbmeta_offset
        .checked_add(VBMETA_FLAGS_LSB_OFFSET)
        .ok_or_else(error)?;
    let mut patched = data.to_vec();
    let flags = patched.get_mut(flags_byte).ok_or_else(error)?;
    if opts.disable_verity {
        *flags |= 0x01;
    }
    if opts.disable_verification {
        *flags |= 0x02;
    }
    Ok(Some(patched))
}


/// Returns true when `partition` is a vbmeta partition (AOSP
/// `is_vbmeta_partition()`).
fn is_vbmeta_partition(partition: &str) -> bool {
    partition.ends_with("vbmeta")
        || partition.ends_with("vbmeta_a")
        || partition.ends_with("vbmeta_b")
}

/// Verbose log helper — prints only when `--verbose` is active.
macro_rules! vlog {
    ($opts:expr, $($arg:tt)*) => {
        if $opts.verbose { eprintln!($($arg)*); }
    };
}


#[derive(Parser)]
#[command(name = "fastboot-rs", author, version, about = "Rust Fastboot Command-Line Interface")]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    /// Force USB serial selection (rejects explicit TCP/UDP targets).
    #[arg(long, global = true)]
    usb: bool,

    /// Use a concrete SLOT for partition commands (`all` and `other` are not supported).
    #[arg(id = "global_slot", long = "slot", global = true, value_parser = parse_slot_value)]
    slot: Option<String>,

    /// Not supported: automatic slot activation; rejected before any I/O.
    /// Use the explicit set_active SLOT command separately.
    #[arg(long, global = true, num_args = 0..=1, default_missing_value = "")]
    set_active: Option<String>,

    /// Not supported: AOSP --skip-reboot (flash/update currently do not auto-reboot).
    #[arg(long, global = true)]
    skip_reboot: bool,

    /// Not supported: AOSP secondary-slot policy; rejected before any I/O.
    #[arg(long, global = true)]
    skip_secondary: bool,

    /// Not supported: AOSP --force requirement override; rejected before any I/O.
    #[arg(long, global = true)]
    force: bool,

    /// Sets disable-verity flag when flashing vbmeta (AOSP --disable-verity).
    #[arg(long, global = true)]
    disable_verity: bool,

    /// Sets disable-verification flag when flashing vbmeta (AOSP --disable-verification).
    #[arg(long, global = true)]
    disable_verification: bool,

    /// Verbose output (AOSP --verbose / -v).
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// Not supported: AOSP --unbuffered; rejected before any I/O.
    #[arg(long, global = true)]
    unbuffered: bool,

    #[command(subcommand)]
    command: Commands,
}

fn parse_slot_value(s: &str) -> Result<String, String> {
    fastboot_protocol::SlotSelection::parse(Some(s))
        .map(|_| s.to_string())
        .map_err(|error| error.to_string())
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_str, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_max_download_size(val: &str) -> Option<usize> {
    let s = val.trim();
    if s.is_empty() {
        return None;
    }

    let s_lower = s.to_lowercase();
    let (num_str, multiplier): (&str, usize) = if s_lower.ends_with("gb") || s_lower.ends_with("g") {
        let len = if s_lower.ends_with("gb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024 * 1024 * 1024)
    } else if s_lower.ends_with("mb") || s_lower.ends_with("m") {
        let len = if s_lower.ends_with("mb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024 * 1024)
    } else if s_lower.ends_with("kb") || s_lower.ends_with("k") {
        let len = if s_lower.ends_with("kb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024)
    } else if s_lower.ends_with("b") && !s_lower.starts_with("0x") && !s.chars().all(|c| c.is_ascii_hexdigit()) {
        (&s[..s.len() - 1], 1)
    } else {
        (s, 1)
    };

    let num_str = num_str.trim();
    if num_str.is_empty() {
        return None;
    }

    let base_val = if let Some(hex_str) = num_str.strip_prefix("0x").or_else(|| num_str.strip_prefix("0X")) {
        usize::from_str_radix(hex_str, 16).ok()?
    } else if let Ok(n) = num_str.parse::<usize>() {
        n
    } else {
        usize::from_str_radix(num_str, 16).ok()?
    };

    base_val.checked_mul(multiplier)
}

#[derive(Subcommand)]
enum Commands {
    /// List connected fastboot devices
    Devices {
        /// Show long listing with device properties/details
        #[arg(short = 'l', long)]
        long: bool,
    },
    /// Validate and persist a TCP or UDP Fastboot network target.
    Connect {
        /// Network serial in AOSP form: tcp:HOST:PORT or udp:HOST:PORT.
        target: String,
    },
    /// Remove one persisted network target, or all targets when omitted.
    Disconnect {
        /// Optional network serial in AOSP form: tcp:HOST:PORT or udp:HOST:PORT.
        target: Option<String>,
    },
    /// Get variable value from bootloader
    Getvar {
        variable: String,
    },
    /// Set the active A/B slot (AOSP CLI spelling: set_active SLOT; wire: set_active:SLOT)
    #[command(name = "set_active", visible_alias = "set-active")]
    SetActive {
        slot: String,
    },
    /// Flash partition with image. If FILE is not specified, looks up ANDROID_PRODUCT_OUT
    /// environment variable (AOSP-style) to find <ANDROID_PRODUCT_OUT>/<partition>.img
    Flash {
        partition: String,
        file: Option<String>,
    },
    /// Wipe super partition using super_empty image (AOSP CLI: wipe-super [SUPER_EMPTY])
    #[command(name = "wipe-super", visible_alias = "wipe_super")]
    WipeSuper {
        /// Optional path to super_empty.img. If omitted, derives <ANDROID_PRODUCT_OUT>/super_empty.img
        image: Option<String>,
    },
    /// Package kernel/ramdisk as boot image and flash to partition (AOSP flash:raw).
    /// Usage: flash:raw <partition> <kernel> [ramdisk [second]]
    #[command(name = "flash:raw")]
    FlashRaw {
        partition: String,
        kernel: String,
        /// Optional ramdisk image file
        ramdisk: Option<String>,
        /// Optional second boot image file
        second: Option<String>,
    },
    /// Erase partition
    Erase {
        partition: String,
    },
    /// Reboot device
    #[command(name = "reboot")]
    Reboot {
        target: Option<String>,
    },
    /// Reboot into the bootloader (AOSP fastboot alias).
    #[command(name = "reboot-bootloader")]
    RebootBootloader,
    /// Reboot into recovery (AOSP fastboot alias).
    #[command(name = "reboot-recovery")]
    RebootRecovery,
    /// Reboot into fastbootd (AOSP fastboot alias).
    #[command(name = "reboot-fastboot")]
    RebootFastboot,
    /// Send OEM command
    Oem {
        #[arg(required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Create dynamic logical partition
    CreateLogicalPartition {
        partition: String,
        #[arg(value_parser = parse_u64)]
        size: u64,
    },
    /// Delete dynamic logical partition
    DeleteLogicalPartition {
        partition: String,
    },
    /// Resize dynamic logical partition
    ResizeLogicalPartition {
        partition: String,
        #[arg(value_parser = parse_u64)]
        size: u64,
    },
    /// Download and boot a kernel image with optional ramdisk
    Boot {
        kernel: String,
        ramdisk: Option<String>,
        second: Option<String>,
    },
    /// Fetch a partition image to a local file (AOSP fetch PARTITION OUT_FILE).
    /// With no range, queries partition-size and max-fetch-size and fetches in chunks.
    Fetch {
        partition: String,
        out_file: String,

        /// Starting byte offset (decimal or 0x-prefixed hexadecimal).
        #[arg(long, value_parser = parse_u64)]
        offset: Option<u64>,
        /// Number of bytes to fetch (requires --offset).
        #[arg(long, value_parser = parse_u64)]
        size: Option<u64>,
    },
    /// Continue booting after flash operations (re-send to device)
    Continue,
    /// Install a 256-byte bootloader signature.
    Signature {
        file: String,
    },
    /// Send a snapshot update command (cancel or merge).
    SnapshotUpdate {
        #[arg(value_parser = ["cancel", "merge"])]
        action: Option<String>,
    },
    /// Shut down the device (sends reboot-shutdown)
    Shutdown,
    /// Format a partition (sends format:<partition> or format:<partition_type>:<partition>)
    Format {
        partition: String,
        #[arg(long)]
        partition_type: Option<String>,
    },
    /// Read staged data from the device into OUT_FILE (sends get_staged)
    GetStaged {
        /// Destination file for the staged bytes.
        out_file: String,
    },
    /// Stage data onto the device for a subsequent command (reverse of get_staged).
    /// Reads from FILE and sends download:DATA with streamed chunks.
    Stage {
        /// Path to the file to stage.
        #[arg(required = true)]
        file: Option<String>,
    },
    /// Send flashing command to bootloader (e.g. lock, unlock, close, lock_critical, unlock_critical)
    Flashing {
        #[arg(value_parser = ["unlock", "lock", "unlock_critical", "lock_critical", "get_unlock_ability"])]
        action: String,
    },
    /// GSI command; AOSP forwards every positional argument as a colon-separated wire command.
    Gsi {
        #[arg(required = true, num_args = 1..)]
        action: Vec<String>,
    },
    /// Flash all partitions from an update.zip package
    Update {
        /// Path to the update.zip file
        zip_file: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FastbootTarget {
    Usb(Option<String>),
    Tcp(String),
    Udp(String),
}

impl FastbootTarget {
    fn label(&self) -> String {
        match self {
            Self::Usb(Some(serial)) => serial.clone(),
            Self::Usb(None) => "USB (unique device required)".into(),
            Self::Tcp(address) => address.clone(),
            Self::Udp(address) => format!("udp:{address}"),
        }
    }
}

// Freeze target identity once, before opening any device. Explicit -s wins
// over ANDROID_SERIAL; absent selection never invents a loopback endpoint.
fn resolve_target(
    usb: bool,
    serial: Option<&str>,
    environment_serial: Option<&str>,
) -> Result<FastbootTarget, String> {
    let serial = serial.or(environment_serial.filter(|value| !value.is_empty()));
    let Some(serial) = serial else { return Ok(FastbootTarget::Usb(None)); };
    if serial.is_empty() { return Err("empty Fastboot serial is not a target".into()); }
    if serial.starts_with("usb:") || serial.starts_with('/') {
        return Err(format!("USB path selectors are not supported; use the exact device serial: {serial}"));
    }
    if let Some(address) = serial.strip_prefix("tcp:") {
        if usb { return Err("--usb conflicts with an explicit TCP target".into()); }
        return Ok(FastbootTarget::Tcp(normalize_network_address(address, true)?));
    }
    if let Some(address) = serial.strip_prefix("udp:") {
        if usb { return Err("--usb conflicts with an explicit UDP target".into()); }
        return Ok(FastbootTarget::Udp(normalize_network_address(address, true)?));
    }
    if usb { return Ok(FastbootTarget::Usb(Some(serial.into()))); }
    if serial.contains(':') {
        // Preserve the existing host:port loopback extension, not arbitrary
        // strings converted to host:5554. --usb keeps literal serial semantics.
        return Ok(FastbootTarget::Tcp(normalize_network_address(serial, false)?));
    }
    Ok(FastbootTarget::Usb(Some(serial.into())))
}

fn normalize_network_address(address: &str, allow_default_port: bool) -> Result<String, String> {
    if address.is_empty() || address.chars().any(char::is_whitespace) {
        return Err(format!("invalid network address '{address}'"));
    }
    let (host, port) = if let Some(bracketed) = address.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']')
            .ok_or_else(|| format!("invalid bracketed network address '{address}'"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() { return Err(format!("invalid IPv6 target '{address}'")); }
        let port = if suffix.is_empty() && allow_default_port { "5554" } else {
            suffix.strip_prefix(':').ok_or_else(|| format!("invalid network address '{address}'"))?
        };
        (format!("[{host}]"), port)
    } else if allow_default_port && address.parse::<std::net::Ipv6Addr>().is_ok() {
        (format!("[{address}]"), "5554")
    } else if let Some((host, port)) = address.rsplit_once(':') {
        if host.contains(':') { return Err(format!("invalid network address '{address}'")); }
        (host.to_string(), port)
    } else if allow_default_port {
        (address.to_string(), "5554")
    } else {
        return Err(format!("network target needs host:port: '{address}'"));
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(format!("invalid network address '{address}'"));
    }
    Ok(format!("{host}:{port}"))
}

/// Parse the network serial form accepted by AOSP `fastboot connect`.
///
/// AOSP `ParseNetworkSerial` accepts only `tcp:` and `udp:` prefixes, then
/// validates a host and port. This CLI returns the protocol and the transport
/// address without its protocol prefix.
fn parse_network_target(serial: &str) -> Result<(&str, String), String> {
    let (protocol, address) = if let Some(address) = serial.strip_prefix("tcp:") {
        ("tcp", address)
    } else if let Some(address) = serial.strip_prefix("udp:") {
        ("udp", address)
    } else {
        return Err(format!(
            "protocol prefix ('tcp:' or 'udp:') is missing: {serial}"
        ));
    };

    Ok((protocol, normalize_network_address(address, true)?))
}

/// AOSP ConnectedDevicesStorage uses `$HOME/.fastboot/devices` and stores a
/// sorted set, one serial per line (fastboot.cpp:468-474; storage.cpp:26-52).
fn connected_devices_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(std::path::PathBuf::from(home).join(".fastboot/devices"))
}

fn read_connected_devices(
    path: &std::path::Path,
) -> std::io::Result<std::collections::BTreeSet<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents.lines().map(str::to_owned).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(error) => Err(error),
    }
}

fn write_connected_devices(
    path: &std::path::Path,
    devices: &std::collections::BTreeSet<String>,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("devices path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let contents = devices.iter().cloned().collect::<Vec<_>>().join("\n");
    std::fs::write(path, format!("{contents}\n"))
}

fn store_connected_device(path: &std::path::Path, serial: &str) -> std::io::Result<()> {
    let mut devices = read_connected_devices(path)?;
    devices.insert(serial.to_string());
    write_connected_devices(path, &devices)
}

fn remove_connected_device(path: &std::path::Path, serial: Option<&str>) -> std::io::Result<()> {
    if let Some(serial) = serial {
        let mut devices = read_connected_devices(path)?;
        devices.remove(serial);
        if devices.is_empty() {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        } else {
            write_connected_devices(path, &devices)
        }
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(feature = "usb")]
type UsbFastbootTransport = fastboot_protocol::FastbootUsbTransport<fastboot_protocol::usb_android::UsbfsFastbootDevice>;

enum FastbootConnection {
    Tcp(FastbootTcpTransport),
    Udp(fastboot_protocol::FastbootUdpTransport),
    #[cfg(feature = "usb")]
    Usb(UsbFastbootTransport),
}

impl std::io::Read for FastbootConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.read(buf),
            Self::Udp(transport) => transport.read(buf),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.read(buf),
        }
    }
}

impl std::io::Write for FastbootConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.write(buf),
            Self::Udp(transport) => transport.write(buf),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(transport) => transport.flush(),
            Self::Udp(transport) => transport.flush(),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.flush(),
        }
    }
}

// Keep response dispatch transport-aware even inside T: FastbootTransport helpers.
impl FastbootTransport for FastbootConnection {
    fn send_cmd(&mut self, cmd: &str) -> Result<(), fastboot_protocol::FastbootTransportError> {
        match self {
            Self::Tcp(transport) => transport.send_cmd(cmd),
            Self::Udp(transport) => transport.send_cmd(cmd),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.send_cmd(cmd),
        }
    }

    fn recv_response_with_info(
        &mut self,
        info_logs: &mut Vec<String>,
    ) -> Result<fastboot_protocol::FastbootResponse, fastboot_protocol::FastbootTransportError> {
        match self {
            Self::Tcp(transport) => transport.recv_response_with_info(info_logs),
            Self::Udp(transport) => transport.recv_response_with_info(info_logs),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.recv_response_with_info(info_logs),
        }
    }
}

fn require_terminal_okay(
    response: &fastboot_protocol::FastbootResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    match response {
        fastboot_protocol::FastbootResponse::Okay(_) => Ok(()),
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            Err(format!("remote failure: {reason}").into())
        }
        other => Err(format!("unexpected terminal response: {other:?}").into()),
    }
}

fn open_transport(
    target: &FastbootTarget,
    timeout: Duration,
) -> Result<FastbootConnection, Box<dyn std::error::Error>> {
    match target {
        FastbootTarget::Usb(serial) => {
            #[cfg(feature = "usb")]
            {
                let device = match serial {
                    Some(serial) => UsbfsFastbootDevice::open_by_serial(serial),
                    None => UsbfsFastbootDevice::open_first(),
                }.map_err(|error| format!("failed to open Fastboot USB target {}: {error}", target.label()))?;
                fastboot_protocol::FastbootUsbTransport::new(device)
                    .map(FastbootConnection::Usb).map_err(|error| error.into())
            }
            #[cfg(not(feature = "usb"))]
            {
                let _ = (serial, timeout);
                Err("USB support is not enabled; rebuild with `--features usb`".into())
            }
        }
        FastbootTarget::Tcp(address) => FastbootTcpTransport::connect_timeout(address, timeout)
            .map(FastbootConnection::Tcp).map_err(|error| error.into()),
        FastbootTarget::Udp(address) => fastboot_protocol::FastbootUdpTransport::connect_timeout(address, timeout)
            .map(FastbootConnection::Udp).map_err(|error| error.into()),
    }
}

/// 读取文件全部字节，出错时 exit(1)。
fn read_file_bytes(path: &str) -> Vec<u8> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法打开文件 '{}': {}", path, e);
            std::process::exit(1);
        }
    };
    let mut data = Vec::new();
    if let Err(e) = f.read_to_end(&mut data) {
        eprintln!("[fastboot-rs] 错误: 读取文件 '{}' 失败: {}", path, e);
        std::process::exit(1);
    }
    if data.is_empty() {
        eprintln!("[fastboot-rs] 错误: 文件 '{}' 为空", path);
        std::process::exit(1);
    }
    data
}

/// 下载内存中的 payload 并发送 boot 命令。
fn download_and_boot_payload<T: FastbootTransport>(
    transport: &mut T,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = payload.len();
    if file_size > u32::MAX as usize {
        eprintln!(
            "[fastboot-rs] 错误: payload 大小 ({}) 超过 u32 上限 ({}); 协议限制",
            file_size,
            u32::MAX
        );
        std::process::exit(1);
    }

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
            limit, limit
        );
    }

    // Step 1: 发送 download 命令
    let download_cmd = fastboot_protocol::download(file_size as u32);
    transport.send_cmd(&download_cmd)?;
    let dl_resp = transport.recv_response()?;
    match dl_resp {
        fastboot_protocol::FastbootResponse::Data(expected_len) => {
            if expected_len != file_size as u32 {
                eprintln!(
                    "[fastboot-rs] 错误: 设备请求 {} 字节，但 payload 为 {} 字节",
                    expected_len, file_size
                );
                std::process::exit(1);
            }
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            eprintln!("[fastboot-rs] download 失败: {}", reason);
            std::process::exit(1);
        }
        other => {
            eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
            std::process::exit(1);
        }
    }

    // Step 2: 分块发送 payload
    let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
    println!(
        "[fastboot-rs] 发送 payload ({} 字节, 分块大小: {} 字节)...",
        file_size, chunk_size
    );
    let mut offset = 0usize;
    while offset < file_size {
        let to_send = (file_size - offset).min(chunk_size);
        let chunk = &payload[offset..offset + to_send];
        if let Err(e) = transport.write_all(chunk) {
            eprintln!(
                "[fastboot-rs] 错误: 写入 transport 失败 at offset {}: {}",
                offset, e
            );
            std::process::exit(1);
        }
        offset += to_send;
    }
    transport.flush()?;

    // Step 3: 读取 payload 发送完成后的 OKAY/FAIL
    let post_dl_resp = transport.recv_response()?;
    require_terminal_okay(&post_dl_resp)?;
    println!("[fastboot-rs] Download 完成: {:?}", post_dl_resp);

    // Step 4: 发送 boot 命令
    println!("[fastboot-rs] 发送 boot 命令...");
    transport.send_cmd("boot")?;

    Ok(())
}

/// 下载内存中的 payload 并发送 flash 命令到指定分区。
fn download_and_flash_payload<T: FastbootTransport>(
    transport: &mut T,
    payload: &[u8],
    partition: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = payload.len();
    if file_size > u32::MAX as usize {
        eprintln!(
            "[fastboot-rs] 错误: payload 大小 ({}) 超过 u32 上限 ({}); 协议限制",
            file_size,
            u32::MAX
        );
        std::process::exit(1);
    }

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
            limit, limit
        );
    }

    // Step 1: 发送 download 命令
    let download_cmd = fastboot_protocol::download(file_size as u32);
    transport.send_cmd(&download_cmd)?;
    let dl_resp = transport.recv_response()?;
    match dl_resp {
        fastboot_protocol::FastbootResponse::Data(expected_len) => {
            if expected_len != file_size as u32 {
                eprintln!(
                    "[fastboot-rs] 错误: 设备请求 {} 字节，但 payload 为 {} 字节",
                    expected_len, file_size
                );
                std::process::exit(1);
            }
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            eprintln!("[fastboot-rs] download 失败: {}", reason);
            std::process::exit(1);
        }
        other => {
            eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
            std::process::exit(1);
        }
    }

    // Step 2: 分块发送 payload
    let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
    println!(
        "[fastboot-rs] 发送 boot image payload ({} 字节, 分块大小: {} 字节)...",
        file_size, chunk_size
    );
    let mut offset = 0usize;
    while offset < file_size {
        let to_send = (file_size - offset).min(chunk_size);
        let chunk = &payload[offset..offset + to_send];
        if let Err(e) = transport.write_all(chunk) {
            eprintln!(
                "[fastboot-rs] 错误: 写入 transport 失败 at offset {}: {}",
                offset, e
            );
            std::process::exit(1);
        }
        offset += to_send;
    }
    transport.flush()?;

    // Step 3: 读取 payload 发送完成后的 OKAY/FAIL
    let post_dl_resp = transport.recv_response()?;
    require_terminal_okay(&post_dl_resp)?;
    println!("[fastboot-rs] Download 完成: {:?}", post_dl_resp);

    // Step 4: 发送 flash 命令到指定分区
    println!("[fastboot-rs] 发送 flash:{} 命令...", partition);
    let flash_cmd = fastboot_protocol::flash(partition);
    transport.send_cmd(&flash_cmd)?;

    Ok(())
}

/// Boot is confirmed only by a terminal OKAY, not DATA or an I/O error.
fn handle_boot_response(
    mut transport: FastbootConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = transport.recv_response()?;
    require_terminal_okay(&response)?;
    println!("[fastboot-rs] Boot OK: {:?}", response);
    if wait_for_disconnect(transport, Duration::from_secs(5)) {
        println!("[fastboot-rs] 设备已断开 — boot 确认");
    } else {
        eprintln!("[fastboot-rs] 警告: 设备未在 5s 内断开 (boot 可能仍在进行)");
    }
    Ok(())
}


fn getvar_value(
    transport: &mut FastbootConnection,
    variable: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    transport.send_cmd(&fastboot_protocol::getvar(variable))?;
    match recv_and_print_info(transport)? {
        fastboot_protocol::FastbootResponse::Okay(value) => Ok(value),
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            Err(format!("getvar:{variable} failed: {reason}").into())
        }
        response => Err(format!("unexpected getvar:{variable} response: {response:?}").into()),
    }
}

fn fetch_to_file(
    transport: &mut FastbootConnection,
    partition: &str,
    out_file: &str,
    offset: Option<u64>,
    size: Option<u64>,
    slot: &fastboot_protocol::SlotSelection,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    if size.is_some() && offset.is_none() {
        return Err("fetch size requires an offset".into());
    }
    let partition = slot.partition_name(partition)?;
    let max_fetch_size = parse_max_download_size(&getvar_value(transport, "max-fetch-size")?)
        .ok_or("device returned an invalid max-fetch-size")? as u64;
    if max_fetch_size == 0 {
        return Err("device returned zero max-fetch-size".into());
    }

    let (start, total) = match (offset, size) {
        (Some(offset), Some(size)) => (offset, size),
        (Some(offset), None) => (offset, max_fetch_size),
        (None, None) => {
            let partition_size = parse_max_download_size(&getvar_value(
                transport,
                &format!("partition-size:{partition}"),
            )?)
            .ok_or("device returned an invalid partition-size")? as u64;
            (0, partition_size)
        }
        _ => unreachable!(),
    };
    if total == 0 {
        return Err("fetch range has zero size".into());
    }

    let mut output = File::create(out_file)?;
    if let (Some(offset), None) = (offset, size) {
        let command = fastboot_protocol::fetch(&partition, Some(offset), None);
        transport.send_cmd(&command)?;
        let data_size = match recv_data_response(transport, "fetch")? {
            fastboot_protocol::FastbootResponse::Data(size) if size > 0 => size as usize,
            fastboot_protocol::FastbootResponse::Data(_) => return Err("fetch returned zero bytes".into()),
            _ => unreachable!("recv_data_response only returns DATA"),
        };
        let mut remaining = data_size;
        let mut buffer = [0u8; 1024 * 1024];
        while remaining > 0 {
            let read_size = remaining.min(buffer.len());
            transport.read_exact(&mut buffer[..read_size])?;
            output.write_all(&buffer[..read_size])?;
            remaining -= read_size;
        }
        output.sync_data()?;
        let response = transport.recv_response()?;
        require_terminal_okay(&response)?;
        return Ok(response);
    }
    let mut current_offset = start;
    let mut remaining = total;
    let mut final_response = fastboot_protocol::FastbootResponse::Okay(String::new());
    while remaining > 0 {
        let chunk_size = remaining.min(max_fetch_size);
        let command = fastboot_protocol::fetch(&partition, Some(current_offset), Some(chunk_size));
        transport.send_cmd(&command)?;
        let response = recv_data_response(transport, "fetch")?;
        let data_size = match response {
            fastboot_protocol::FastbootResponse::Data(size) if size > 0 => size as u64,
            fastboot_protocol::FastbootResponse::Data(_) => return Err("fetch returned zero bytes".into()),
            _ => unreachable!("recv_data_response only returns DATA"),
        };
        if data_size > chunk_size {
            return Err(format!("fetch returned {data_size} bytes, requested {chunk_size}").into());
        }
        let mut left = data_size as usize;
        let mut buffer = [0u8; 1024 * 1024];
        while left > 0 {
            let read_size = left.min(buffer.len());
            transport.read_exact(&mut buffer[..read_size])?;
            output.write_all(&buffer[..read_size])?;
            left -= read_size;
        }
        output.sync_data()?;
        final_response = transport.recv_response()?;
        require_terminal_okay(&final_response)?;
        if data_size != chunk_size {
            return Err(format!("fetch returned {data_size} bytes, requested {chunk_size}").into());
        }
        current_offset += chunk_size;
        remaining -= chunk_size;
    }
    Ok(final_response)
}

/// Read the DATA status for commands whose response is followed by a byte payload.
/// AOSP FastBootDriver::RunAndReadBuffer accepts INFO/TEXT packets before DATA and
/// then reads exactly the advertised number of bytes. Keep that framing separate from
/// the payload consumer so fetch and get_staged cannot accidentally treat INFO as DATA.
fn recv_data_response(
    transport: &mut FastbootConnection,
    operation: &str,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    let mut info_logs = Vec::new();
    let response = transport.recv_response_with_info(&mut info_logs)?;
    for info in info_logs {
        println!("[fastboot-rs] INFO {}", info);
    }
    match response {
        fastboot_protocol::FastbootResponse::Data(size) => {
            Ok(fastboot_protocol::FastbootResponse::Data(size))
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            Err(format!("{operation} failed: {reason}").into())
        }
        other => Err(format!("unexpected {operation} response: {other:?}").into()),
    }
}

fn recv_and_print_info(
    transport: &mut FastbootConnection,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    let mut info_logs = Vec::new();
    let response = transport.recv_response_with_info(&mut info_logs)?;
    for info in info_logs {
        println!("[fastboot-rs] INFO {}", info);
    }
    require_terminal_okay(&response)?;
    Ok(response)
}

/// 发送 reboot 命令后，等待设备断开连接。
///
/// 通过在线程中执行阻塞读取来检测连接断开：
/// - 如果读取返回错误 → 设备已断开 → reboot 成功
/// - 如果读取返回数据（不应发生）或超时 → 返回 false
///
/// 注意：此函数获取 transport 的所有权，因为我们需要将其移入线程。
fn wait_for_disconnect(transport: FastbootConnection, timeout: Duration) -> bool {
    let (tx, rx) = mpsc::channel::<bool>();

    thread::spawn(move || {
        let mut t = transport;
        let mut buf = [0u8; 1];
        // 阻塞读取；设备重启时 TCP 连接会 RST，read 立即返回错误
        let result = Read::read(&mut t, &mut buf);
        let _ = tx.send(result.is_err());
    });

    match rx.recv_timeout(timeout) {
        Ok(true) => true,   // read 返回错误 → 设备断开
        Ok(false) => false, // read 返回了数据（异常）
        Err(mpsc::RecvTimeoutError::Timeout) => false,   // 超时，设备未断开
        Err(mpsc::RecvTimeoutError::Disconnected) => false, // 线程 panic 等异常
    }
}

fn run_reboot(
    connection_target: &FastbootTarget,
    target: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = open_transport(connection_target, Duration::from_secs(3))?;
    let cmd = fastboot_protocol::reboot(target);
    transport.send_cmd(&cmd)?;

    // A rebooting device may close the connection before returning a status.
    match transport.recv_response() {
        Ok(response) => {
            require_terminal_okay(&response)?;
            println!("[fastboot-rs] Reboot response: {:?}", response);
        }
        Err(error) => eprintln!(
            "[fastboot-rs] Warning: Could not read reboot response (device may be disconnecting): {}",
            error
        ),
    }

    if wait_for_disconnect(transport, Duration::from_secs(5)) {
        println!("[fastboot-rs] Device disconnected — reboot confirmed");
    } else {
        eprintln!(
            "[fastboot-rs] Warning: Device did not disconnect within 5s timeout (reboot may still be in progress)"
        );
    }
    Ok(())
}

/// Mandatory update queries never turn FAIL, DATA, or I/O errors into a value.
fn update_getvar<T: FastbootTransport>(
    transport: &mut T,
    variable: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    transport.send_cmd(&format!("getvar:{variable}"))?;
    let response = transport.recv_response()?;
    require_terminal_okay(&response).map_err(|error| format!("getvar:{variable}: {error}"))?;
    match response {
        fastboot_protocol::FastbootResponse::Okay(value) => Ok(value),
        _ => unreachable!("terminal OKAY was checked"),
    }
}

/// Check the supported android-info grammar before planning any writes.
/// AOSP require/reject, board alias, product guards, alternatives and trailing
/// wildcard are supported; legacy `require inverse`/`or` remain accepted.
/// Unsupported/malformed lines fail closed instead of silently removing a gate.
fn check_android_info<T: FastbootTransport>(
    transport: &mut T,
    data: &str,
) -> Result<std::collections::HashSet<String>, Box<dyn std::error::Error>> {
    let mut requirements = Vec::new();
    for line in data.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (mut left, right) = line
            .split_once('=')
            .ok_or_else(|| format!("unsupported android-info.txt requirement: {line}"))?;
        left = left.trim();
        let mut invert = false;
        let mut product = None;
        if let Some(rest) = left.strip_prefix("require-for-product:") {
            let (guard, variable) = rest
                .trim()
                .split_once(char::is_whitespace)
                .ok_or_else(|| format!("malformed product requirement: {line}"))?;
            product = Some(guard.to_string());
            left = variable.trim();
        } else if let Some(rest) = left.strip_prefix("require inverse ") {
            invert = true;
            left = rest.trim();
        } else if let Some(rest) = left.strip_prefix("require ") {
            left = rest.trim();
        } else if let Some(rest) = left.strip_prefix("reject ") {
            invert = true;
            left = rest.trim();
        }
        if left.is_empty() || left.chars().any(char::is_whitespace) || left == "force" {
            return Err(format!("unsupported android-info.txt requirement: {line}").into());
        }
        let options: Vec<String> = right
            .replace(" or ", "|")
            .split('|')
            .map(|value| value.trim().to_string())
            .collect();
        if options.iter().any(String::is_empty) {
            return Err(format!("empty android-info.txt requirement value: {line}").into());
        }
        let variable = if left == "board" { "product" } else { left };
        requirements.push((variable.to_string(), options, invert, product));
    }

    let mut required_images = std::collections::HashSet::new();
    for (variable, options, invert, product) in requirements {
        if let Some(product) = product {
            if update_getvar(transport, "product")? != product {
                continue; // explicit product guard, not a failed mandatory query
            }
        }
        if variable == "partition-exists" {
            if invert
                || options.len() != 1
                || !AOSP_IMAGES.iter().any(|entry| entry.0 == options[0])
            {
                return Err(
                    format!("unsupported required partition: {}", options.join("|")).into(),
                );
            }
            let has_slot = update_getvar(transport, &format!("has-slot:{}", options[0]))?;
            if has_slot != "yes" && has_slot != "no" {
                return Err(format!("device lacks required partition: {}", options[0]).into());
            }
            required_images.insert(options[0].clone());
        } else {
            let actual = update_getvar(transport, &variable)?;
            let matches = options.iter().any(|option| {
                option
                    .strip_suffix('*')
                    .map_or(actual.trim() == option, |prefix| {
                        actual.trim().starts_with(prefix)
                    })
            });
            if matches == invert {
                return Err(
                    format!("android-info.txt requirement not met: {variable}={actual}").into(),
                );
            }
        }
    }
    Ok(required_images)
}

/// AOSP 兼容的分区镜像列表及刷写顺序。
///
/// 每一项：(分区名, zip内文件名, 是否可选)
/// 按此顺序刷写，仅刷写 zip 中存在的镜像。
const AOSP_IMAGES: &[(&str, &str, bool)] = &[
    ("boot",           "boot.img",           false),
    ("bootloader",     "bootloader.img",     true),
    ("init_boot",      "init_boot.img",      true),
    ("dtbo",           "dtbo.img",           true),
    ("dts",            "dt.img",             true),
    ("odm",            "odm.img",            true),
    ("odm_dlkm",       "odm_dlkm.img",       true),
    ("product",        "product.img",        true),
    ("pvmfw",          "pvmfw.img",          true),
    ("radio",          "radio.img",          true),
    ("recovery",       "recovery.img",       true),
    ("super",          "super.img",          true),
    ("system",         "system.img",         false),
    ("system_dlkm",    "system_dlkm.img",    true),
    ("system_ext",     "system_ext.img",     true),
    ("userdata",       "userdata.img",       true),
    ("vbmeta",         "vbmeta.img",         true),
    ("vbmeta_system",  "vbmeta_system.img",  true),
    ("vbmeta_vendor",  "vbmeta_vendor.img",  true),
    ("vendor",         "vendor.img",         true),
    ("vendor_boot",    "vendor_boot.img",    true),
    ("vendor_dlkm",    "vendor_dlkm.img",    true),
    ("vendor_kernel_boot", "vendor_kernel_boot.img", true),
    ("cache",          "cache.img",          true),
];

struct UpdateImage {
    partition: &'static str,
    image_name: &'static str,
    wire_partition: String,
    size: u64,
    // Freeze the exact converted bytes; never repeat a fallible vbmeta transform
    // after an earlier image has been flashed. Only selected transforms are kept.
    prepared_data: Option<Vec<u8>>,
}

/// Freeze required-image presence/readability and every partition/slot decision
/// before the first download. Only one entry is decompressed at a time.
fn prepare_update_images<T: FastbootTransport>(
    transport: &mut T,
    archive: &mut ZipArchive<File>,
    required: &std::collections::HashSet<String>,
    slot: &fastboot_protocol::SlotSelection,
    max_download_size: Option<usize>,
    gopts: &GlobalOptions,
) -> Result<Vec<UpdateImage>, Box<dyn std::error::Error>> {
    let mut names = std::collections::HashSet::new();
    for name in archive.file_names() {
        if !names.insert(name.to_string()) {
            return Err(format!("duplicate update ZIP entry: {name}").into());
        }
    }
    let mut images = Vec::new();
    for &(partition, image_name, optional) in AOSP_IMAGES {
        if !names.contains(image_name) {
            if !optional || required.contains(partition) {
                return Err(
                    format!("required image '{image_name}' missing from update ZIP").into(),
                );
            }
            continue;
        }
        let mut entry = archive.by_name(image_name)?;
        let size = entry.size();
        if size == 0 || size > u32::MAX as u64 || entry.is_dir() {
            return Err(format!("invalid update image '{image_name}' size: {size}").into());
        }
        // Read to EOF now: CRC, sparse parsing, or split-planning errors in a
        // later image must not be discovered after an earlier partition write.
        // The temporary buffer is released for each entry, not retained for the ZIP.
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        if data.len() as u64 != size {
            return Err(format!("truncated update image '{image_name}'").into());
        }
        let freeze_data = is_vbmeta_partition(partition) && gopts.needs_vbmeta_patch();
        if freeze_data {
            if let Some(patched) = patch_vbmeta_flags(&data, gopts)
                .map_err(|error| format!("update image '{image_name}': {error}"))?
            {
                data = patched;
            }
        }
        let sparse = if data.starts_with(&fastboot_protocol::SPARSE_HEADER_MAGIC.to_le_bytes()) {
            Some(fastboot_protocol::SparseFile::from_bytes(&data)?)
        } else {
            None
        };
        if let Some(limit) = max_download_size.filter(|limit| *limit > 0 && size > *limit as u64) {
            let sparse =
                sparse.unwrap_or_else(|| fastboot_protocol::SparseFile::from_raw(&data, 4096));
            sparse.split(limit)?;
        }
        images.push(UpdateImage {
            partition,
            image_name,
            wire_partition: partition.to_string(),
            size,
            prepared_data: if freeze_data { Some(data) } else { None },
        });
    }
    let mut selected_slot = match slot {
        fastboot_protocol::SlotSelection::Named(name) => Some(name.clone()),
        fastboot_protocol::SlotSelection::Current => None,
        _ => return Err("update --slot=all/other is not supported".into()),
    };
    for image in &mut images {
        match update_getvar(transport, &format!("has-slot:{}", image.partition))?.as_str() {
            "no" => {}
            "yes" => {
                if selected_slot.is_none() {
                    let current = update_getvar(transport, "current-slot")?;
                    match fastboot_protocol::SlotSelection::parse(Some(&current))? {
                        fastboot_protocol::SlotSelection::Named(name) => selected_slot = Some(name),
                        _ => return Err("device returned no concrete current-slot".into()),
                    }
                }
                image.wire_partition =
                    format!("{}_{}", image.partition, selected_slot.as_ref().unwrap());
            }
            value => {
                return Err(format!("invalid has-slot:{} value: {value}", image.partition).into())
            }
        }
    }
    Ok(images)
}

/// Execute the bounded legacy update image-list path (not AOSP's full task planner).
fn do_update<T: FastbootTransport>(
    transport: &mut T,
    zip_path: &str,
    gopts: &GlobalOptions,
    slot: &fastboot_protocol::SlotSelection,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: 打开 update.zip ---
    let zip_file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法打开 update.zip '{zip_path}': {e}");
            std::process::exit(1);
        }
    };

    let mut archive = match ZipArchive::new(zip_file) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法解析 zip 文件 '{zip_path}': {e}");
            std::process::exit(1);
        }
    };

    println!("[fastboot-rs] 已打开 update.zip ({} 个条目)", archive.len());

    // --- Step 2: 读取并检查 android-info.txt ---
    let android_info = match archive.by_name("android-info.txt") {
        Ok(mut entry) => {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            println!("[fastboot-rs] android-info.txt 大小: {} 字节", contents.len());
            contents
        }
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法读取 android-info.txt: {e}");
            std::process::exit(1);
        }
    };

    // 显示设备信息 (AOSP DumpInfo 风格)
    println!("[fastboot-rs] --------------------------------------------");
    for &var in &["version-bootloader", "version-baseband", "serialno"] {
        let query = format!("getvar:{var}");
        if transport.send_cmd(&query).is_ok() {
            if let Ok(resp) = transport.recv_response() {
                if let fastboot_protocol::FastbootResponse::Okay(val) = resp {
                    println!("[fastboot-rs] {var}: {val}");
                }
            }
        }
    }
    println!("[fastboot-rs] --------------------------------------------");

    // 检查兼容性
    let required = check_android_info(transport, &android_info)?;
    println!("[fastboot-rs] 设备兼容性检查通过");

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {limit} bytes ({limit:#x})"
        );
    }

    let images = prepare_update_images(transport, &mut archive, &required, slot, max_download_size, gopts)?;
    // Every selected image and partition/slot query passed before any download.
    println!("[fastboot-rs] 开始刷写分区镜像...\n");
    for image in images {
        let partition = image.partition;
        let img_name = image.image_name;
        let partition_with_slot = image.wire_partition;
        println!("[fastboot-rs] >>> 刷写 {img_name} -> 分区 {partition}");

        // Selected vbmeta transforms were executed and frozen during preflight.
        let image_data = if let Some(data) = image.prepared_data {
            data
        } else {
            let mut entry = archive.by_name(img_name)?;
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            data
        };

        let file_size = image_data.len();
        if file_size as u64 != image.size {
            return Err(format!("update image changed after preflight: {img_name}").into());
        }
        if file_size == 0 {
            eprintln!("[fastboot-rs] 错误: 镜像 '{img_name}' 为空");
            std::process::exit(1);
        }
        if file_size > u32::MAX as usize {
            eprintln!(
                "[fastboot-rs] 错误: 镜像 '{img_name}' 大小 ({file_size}) 超过 u32 上限"
            );
            std::process::exit(1);
        }

        println!(
            "[fastboot-rs]   {img_name}: {file_size} 字节"
        );

        let need_split = match max_download_size {
            Some(limit) if limit > 0 && file_size > limit => true,
            _ => false,
        };

        if need_split {
            // 需要做 sparse split
            let limit = max_download_size.unwrap();

            let is_sparse = file_size >= 28
                && u32::from_le_bytes(image_data[..4].try_into().unwrap())
                    == fastboot_protocol::SPARSE_HEADER_MAGIC;

            let sparse_file = if is_sparse {
                match fastboot_protocol::SparseFile::from_bytes(&image_data) {
                    Ok(sf) => sf,
                    Err(e) => {
                        eprintln!(
                            "[fastboot-rs] 错误: 解析 sparse 文件 '{img_name}' 失败: {e}"
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                fastboot_protocol::SparseFile::from_raw(&image_data, 4096)
            };

            let splits = match sparse_file.split(limit) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 分割镜像 '{img_name}' 失败: {e}"
                    );
                    std::process::exit(1);
                }
            };

            println!(
                "[fastboot-rs]   {img_name}: 大小超过 max-download-size，分割为 {} 个 sparse chunk",
                splits.len()
            );

            for (idx, split_file) in splits.iter().enumerate() {
                let payload = split_file.encode();
                println!(
                    "[fastboot-rs]   发送 chunk {}/{} ({} 字节)...",
                    idx + 1,
                    splits.len(),
                    payload.len()
                );

                // download
                let dl_cmd = fastboot_protocol::download(payload.len() as u32);
                transport.send_cmd(&dl_cmd)?;
                let dl_resp = transport.recv_response()?;
                match dl_resp {
                    fastboot_protocol::FastbootResponse::Data(expected) => {
                        if expected != payload.len() as u32 {
                            eprintln!(
                                "[fastboot-rs] 错误: 设备请求 {expected} 字节，但 chunk 为 {} 字节",
                                payload.len()
                            );
                            std::process::exit(1);
                        }
                    }
                    fastboot_protocol::FastbootResponse::Fail(reason) => {
                        eprintln!(
                            "[fastboot-rs] download 失败 (chunk {}/{}): {reason}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                    other => {
                        eprintln!(
                            "[fastboot-rs] 意外的 download 响应 (chunk {}/{}): {other:?}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                }

                // 发送 payload
                transport.write_all(&payload)?;
                transport.flush()?;

                let post_resp = transport.recv_response()?;
                require_terminal_okay(&post_resp)?;

                // flash
                let flash_cmd = fastboot_protocol::flash(&partition_with_slot);
                transport.send_cmd(&flash_cmd)?;
                let flash_resp = transport.recv_response()?;
                require_terminal_okay(&flash_resp)?;
                match &flash_resp {
                    fastboot_protocol::FastbootResponse::Okay(val) => {
                        println!(
                            "[fastboot-rs]   {img_name} chunk {}/{} OK: {val}",
                            idx + 1,
                            splits.len()
                        );
                    }
                    fastboot_protocol::FastbootResponse::Fail(reason) => {
                        eprintln!(
                            "[fastboot-rs] 错误: 刷写 {img_name} chunk {}/{} 失败: {reason}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                    other => {
                        println!(
                            "[fastboot-rs]   {img_name} chunk {}/{} 响应: {other:?}",
                            idx + 1,
                            splits.len()
                        );
                    }
                }
            }
        } else {
            // 不需要 split：直接 download + flash
            let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
            let download_cmd = fastboot_protocol::download(file_size as u32);
            transport.send_cmd(&download_cmd)?;
            let dl_resp = transport.recv_response()?;
            match dl_resp {
                fastboot_protocol::FastbootResponse::Data(expected) => {
                    if expected != file_size as u32 {
                        eprintln!(
                            "[fastboot-rs] 错误: 设备请求 {expected} 字节，但镜像为 {file_size} 字节"
                        );
                        std::process::exit(1);
                    }
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] download 失败 ({img_name}): {reason}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("[fastboot-rs] 意外的 download 响应 ({img_name}): {other:?}");
                    std::process::exit(1);
                }
            }

            // 分块发送 payload
            let mut offset = 0usize;
            while offset < file_size {
                let to_send = (file_size - offset).min(chunk_size);
                let chunk = &image_data[offset..offset + to_send];
                transport.write_all(chunk)?;
                offset += to_send;
            }
            transport.flush()?;

            let post_resp = transport.recv_response()?;
            require_terminal_okay(&post_resp)?;

            // 发送 flash 命令
            let flash_cmd = fastboot_protocol::flash(&partition_with_slot);
            transport.send_cmd(&flash_cmd)?;
            let flash_resp = transport.recv_response()?;
            require_terminal_okay(&flash_resp)?;
            match &flash_resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs]   {img_name} -> {partition_with_slot} OK: {val}");
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 刷写 {img_name} -> {partition_with_slot} 失败: {reason}"
                    );
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs]   {img_name} -> {partition_with_slot} 响应: {other:?}");
                }
            }
        }
    }

    println!("\n[fastboot-rs] 所有分区已刷写完成。");
    Ok(())
}

/// Helper to handle download and flashing of an image file to a specified partition over fastboot transport.
fn flash_image_file<T: FastbootTransport>(
    transport: &mut T,
    partition_label: &str,
    wire_partition: &str,
    image_path: &std::path::Path,
    gopts: &GlobalOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    vlog!(gopts, "[fastboot-rs] flash_image_file: partition={partition_label} wire={wire_partition} path={}", image_path.display());

    let mut image_file = match File::open(image_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening image file '{}': {}", image_path.display(), e);
            std::process::exit(1);
        }
    };

    let file_size = match image_file.metadata() {
        Ok(m) => m.len() as usize,
        Err(e) => {
            eprintln!("Error reading metadata for '{}': {}", image_path.display(), e);
            std::process::exit(1);
        }
    };

    if file_size == 0 {
        eprintln!("Error: image file '{}' is empty", image_path.display());
        std::process::exit(1);
    }

    if file_size > u32::MAX as usize {
        eprintln!(
            "Error: image file '{}' size ({}) exceeds u32 max ({}); protocol limit",
            image_path.display(),
            file_size,
            u32::MAX
        );
        std::process::exit(1);
    }

    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => parse_max_download_size(&val),
            _ => None,
        },
        _ => None,
    };

    if let Some(limit) = max_download_size {
        println!("[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})", limit, limit);
    }

    let need_split = match max_download_size {
        Some(limit) => limit > 0 && file_size > limit,
        None => false,
    };

    if need_split {
        let image_data = match std::fs::read(image_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading image file '{}': {}", image_path.display(), e);
                std::process::exit(1);
            }
        };

        // AOSP SetVbmetaFlags: patch disable-verity/verification bits
        // before flashing vbmeta partitions.
        let image_data = if is_vbmeta_partition(partition_label) {
            match patch_vbmeta_flags(&image_data, gopts)? {
                Some(patched) => {
                    vlog!(gopts, "[fastboot-rs] vbmeta flags patched ({} bytes)", patched.len());
                    patched
                }
                None => image_data,
            }
        } else {
            image_data
        };

        let limit = max_download_size.unwrap();
        println!(
            "[fastboot-rs] Image size ({} bytes) exceeds max-download-size ({} bytes). Splitting image into sparse chunks...",
            image_data.len(),
            limit
        );

        let is_sparse = image_data.len() >= 28
            && u32::from_le_bytes(image_data[0..4].try_into().unwrap()) == fastboot_protocol::SPARSE_HEADER_MAGIC;

        let sparse_file = if is_sparse {
            match fastboot_protocol::SparseFile::from_bytes(&image_data) {
                Ok(sf) => sf,
                Err(e) => {
                    eprintln!("Error parsing sparse file: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            fastboot_protocol::SparseFile::from_raw(&image_data, 4096)
        };

        let splits = match sparse_file.split(limit) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error splitting image: {}", e);
                std::process::exit(1);
            }
        };

        println!("[fastboot-rs] Split into {} sparse chunk file(s)", splits.len());

        for (idx, split_file) in splits.iter().enumerate() {
            let payload = split_file.encode();
            println!(
                "[fastboot-rs] Sending split chunk {}/{} ({} bytes)...",
                idx + 1,
                splits.len(),
                payload.len()
            );

            let download_cmd = fastboot_protocol::download(payload.len() as u32);
            transport.send_cmd(&download_cmd)?;
            let dl_resp = transport.recv_response()?;
            match dl_resp {
                fastboot_protocol::FastbootResponse::Data(expected_len) => {
                    if expected_len != payload.len() as u32 {
                        eprintln!(
                            "Error: Device requested {} bytes, but chunk payload is {} bytes",
                            expected_len,
                            payload.len()
                        );
                        std::process::exit(1);
                    }
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("Error download failed for chunk {}: {}", idx + 1, reason);
                    std::process::exit(1);
                }
                other => {
                    eprintln!("Unexpected download response for chunk {}: {:?}", idx + 1, other);
                    std::process::exit(1);
                }
            }

            transport.write_all(&payload)?;
            transport.flush()?;

            let post_dl_resp = transport.recv_response()?;
            require_terminal_okay(&post_dl_resp)?;

            let flash_cmd = fastboot_protocol::flash(wire_partition);
            transport.send_cmd(&flash_cmd)?;
            let flash_resp = transport.recv_response()?;
            require_terminal_okay(&flash_resp)?;
            println!(
                "[fastboot-rs] Flash response for split chunk {}/{}: {:?}",
                idx + 1,
                splits.len(),
                flash_resp
            );
        }
    } else {
        let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);

        // AOSP SetVbmetaFlags: for vbmeta partitions, read the whole image
        // into memory so we can patch the flags byte before sending.
        let vbmeta_patched: Option<Vec<u8>> = if is_vbmeta_partition(partition_label) && gopts.needs_vbmeta_patch() {
            let data = match std::fs::read(image_path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error reading image file '{}': {}", image_path.display(), e);
                    std::process::exit(1);
                }
            };
            match patch_vbmeta_flags(&data, gopts)? {
                Some(patched) => {
                    vlog!(gopts, "[fastboot-rs] vbmeta flags patched ({} bytes)", patched.len());
                    Some(patched)
                }
                None => None,
            }
        } else {
            None
        };

        let effective_size = vbmeta_patched.as_ref().map_or(file_size, |p| p.len());

        println!(
            "[fastboot-rs] Flashing partition '{}' with image '{}' ({} bytes, chunk size: {} bytes)",
            partition_label,
            image_path.display(),
            effective_size,
            chunk_size
        );

        let download_cmd = fastboot_protocol::download(effective_size as u32);
        transport.send_cmd(&download_cmd)?;
        let dl_resp = transport.recv_response()?;
        match dl_resp {
            fastboot_protocol::FastbootResponse::Data(expected_len) => {
                if expected_len != effective_size as u32 {
                    eprintln!("Error: Device requested {} bytes, but local file is {} bytes", expected_len, effective_size);
                    std::process::exit(1);
                }
            }
            fastboot_protocol::FastbootResponse::Fail(reason) => {
                eprintln!("Error download failed: {}", reason);
                std::process::exit(1);
            }
            other => {
                eprintln!("Unexpected download response: {:?}", other);
                std::process::exit(1);
            }
        }

        println!("[fastboot-rs] Sending image payload in chunks ({} bytes total)...", effective_size);

        if let Some(ref patched_data) = vbmeta_patched {
            // Send patched vbmeta data from memory.
            let mut offset = 0usize;
            while offset < patched_data.len() {
                let to_send = (patched_data.len() - offset).min(chunk_size);
                if let Err(e) = transport.write_all(&patched_data[offset..offset + to_send]) {
                    eprintln!("Error writing patched vbmeta to transport at offset {offset}: {e}");
                    std::process::exit(1);
                }
                offset += to_send;
            }
        } else {
            // Stream from file as before.
            let mut buffer = vec![0u8; chunk_size];
            let mut remaining = file_size;
            let mut chunk_index = 0u64;

            while remaining > 0 {
                let to_read = remaining.min(chunk_size);
                if let Err(e) = image_file.read_exact(&mut buffer[..to_read]) {
                    eprintln!("Error reading from '{}' at offset {}: {}", image_path.display(), file_size - remaining, e);
                    std::process::exit(1);
                }
                if let Err(e) = transport.write_all(&buffer[..to_read]) {
                    eprintln!(
                        "Error writing to transport at chunk {} (offset {}): {}",
                        chunk_index,
                        file_size - remaining,
                        e
                    );
                    std::process::exit(1);
                }
                remaining -= to_read;
                chunk_index += 1;
            }
        }
        transport.flush()?;

        let post_dl_resp = transport.recv_response()?;
        require_terminal_okay(&post_dl_resp)?;

        let flash_cmd = fastboot_protocol::flash(wire_partition);
        transport.send_cmd(&flash_cmd)?;
        let flash_resp = transport.recv_response()?;
        require_terminal_okay(&flash_resp)?;
        println!("[fastboot-rs] Flash response for partition '{}': {:?}", partition_label, flash_resp);
    }

    Ok(())
}

/// Parsed compatibility flags must never silently promise missing orchestration.
/// Keep this gate before target opening, local-file reads, and storage operations.
fn validate_supported_options(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    for (requested, option) in [
        (cli.set_active.is_some(), "--set-active"),
        (cli.skip_secondary, "--skip-secondary"),
        (cli.force, "--force"),
        (cli.unbuffered, "--unbuffered"),
    ] {
        if requested {
            return Err(format!("{option} is not supported; refusing before any I/O").into());
        }
    }
    if cli.skip_reboot {
        return Err("--skip-reboot is not supported; flash/update currently do not automatically reboot; refusing before any I/O".into());
    }
    if matches!(cli.slot.as_deref(), Some("all" | "other")) {
        return Err("--slot=all/other is not supported; refusing before any I/O".into());
    }
    if cli.slot.is_some()
        && !matches!(
            cli.command,
            Commands::Flash { .. }
                | Commands::WipeSuper { .. }
                | Commands::FlashRaw { .. }
                | Commands::Erase { .. }
                | Commands::Format { .. }
                | Commands::Fetch { .. }
                | Commands::Update { .. }
        )
    {
        return Err("--slot is not supported for this command; refusing before any I/O".into());
    }
    if (cli.disable_verity || cli.disable_verification)
        && !matches!(
            cli.command,
            Commands::Flash { .. } | Commands::WipeSuper { .. } | Commands::Update { .. }
        )
    {
        return Err("--disable-verity/--disable-verification are not supported for this command; refusing before any I/O".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    validate_supported_options(&cli)?;
    let environment_serial = std::env::var("ANDROID_SERIAL").ok();
    let connection_target = match &cli.command {
        // connect has its own explicit positional target; disconnect is a
        // local storage operation and must not validate/open an unrelated device.
        Commands::Connect { target } => resolve_target(cli.usb, Some(target), None)?,
        Commands::Disconnect { .. } => FastbootTarget::Usb(None),
        _ => resolve_target(cli.usb, cli.serial.as_deref(), environment_serial.as_deref())?,
    };
    let addr = connection_target.label();
    let use_usb = matches!(connection_target, FastbootTarget::Usb(_));
    let slot_selection = fastboot_protocol::SlotSelection::parse(cli.slot.as_deref())?;

    // AOSP-mirror global options, constructed once and threaded through.
    let gopts = GlobalOptions {
        disable_verity: cli.disable_verity,
        disable_verification: cli.disable_verification,
        verbose: cli.verbose,
    };
    if gopts.verbose {
        eprintln!("[fastboot-rs] verbose mode enabled");
        eprintln!("[fastboot-rs] global options: {gopts:?}");
    }

    match cli.command {
        Commands::Connect { target } => {
            parse_network_target(&target)?;
            open_transport(&connection_target, Duration::from_secs(3))?;
            store_connected_device(&connected_devices_path()?, &target)?;
            println!("connected to {target}");
        }
        Commands::Disconnect { target } => {
            if let Some(target) = target.as_deref() {
                parse_network_target(target)?;
            }
            remove_connected_device(&connected_devices_path()?, target.as_deref())?;
            match target {
                Some(target) => println!("disconnected {target}"),
                None => println!("disconnected all devices"),
            }
        }
        Commands::Devices { long } => {
            println!("List of fastboot devices (fastboot-rs pure rust protocol)");
            if use_usb {
                #[cfg(feature = "usb")]
                {
                    match UsbfsFastbootDevice::enumerate() {
                        Ok(devices) => {
                            if devices.is_empty() {
                                println!("no devices found");
                            }
                            for device in &devices {
                                let serial = device.serial.as_deref().unwrap_or("????????");
                                if long {
                                    println!("{}\tfastboot usb:{}-{}", serial, device.bus_number, device.address);
                                } else {
                                    println!("{}\tfastboot", serial);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error enumerating fastboot USB devices: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(feature = "usb"))]
                {
                    let _ = addr;
                    eprintln!("USB support is not enabled; rebuild with `--features usb`");
                    std::process::exit(1);
                }
            } else {
                match open_transport(&connection_target, Duration::from_secs(2)) {
                    Ok(mut transport) => {
                        let mut details = String::new();
                        if long {
                            if let Ok(_) = transport.send_cmd("getvar:product") {
                                if let Ok(fastboot_protocol::FastbootResponse::Okay(val)) = transport.recv_response() {
                                    details.push_str(&format!(" product:{}", val));
                                }
                            }
                        }
                        if let Ok(_) = transport.send_cmd("getvar:version") {
                            if let Ok(resp) = transport.recv_response() {
                                println!("{}\tfastboot ({:?}){}", addr, resp, details);
                            } else {
                                println!("{}\tfastboot{}", addr, details);
                            }
                        } else {
                            println!("{}\tfastboot{}", addr, details);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Getvar { variable } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("getvar:{}", variable);
            transport.send_cmd(&cmd)?;
            if variable == "all" {
                // AOSP-compatible output for getvar all:
                //   (bootloader) key: value
                //   ...
                //   Finished. Total time: X.XXXs
                let start = std::time::Instant::now();
                let mut info_logs = Vec::new();
                let response = transport.recv_response_with_info(&mut info_logs)?;
                for info in info_logs {
                    println!("(bootloader) {}", info);
                }
                require_terminal_okay(&response)?;
                let elapsed = start.elapsed();
                println!("Finished. Total time: {:.3}s", elapsed.as_secs_f64());
            } else {
                let resp = recv_and_print_info(&mut transport)?;
                println!("[fastboot-rs] Response: {:?}", resp);
            }
        }
        Commands::SetActive { slot } => {
            if slot.is_empty() {
                return Err("set_active requires a non-empty SLOT".into());
            }
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            // AOSP fastboot's SetActive() sends the protocol command set_active:SLOT.
            transport.send_cmd(&format!("set_active:{}", slot))?;
            let resp = recv_and_print_info(&mut transport)?;
            println!("[fastboot-rs] Set active slot '{}' response: {:?}", slot, resp);
        }
        Commands::Flash { partition, file } => {
            let wire_partition = slot_selection.partition_name(&partition)?;
            let image_path = match fastboot_protocol::resolve_image_path(
                &partition,
                file.as_deref(),
                std::env::var("ANDROID_PRODUCT_OUT").ok().as_deref(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] Connected to fastboot target {}", addr);

            flash_image_file(&mut transport, &partition, &wire_partition, &image_path, &gopts)?;
        }
        Commands::WipeSuper { image } => {
            let wire_partition = slot_selection.partition_name("super")?;
            let image_path = match fastboot_protocol::resolve_super_empty_path(
                image.as_deref(),
                std::env::var("ANDROID_PRODUCT_OUT").ok().as_deref(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] Connected to fastboot target {}", addr);

            println!("[fastboot-rs] Wiping super partition using image '{}'", image_path.display());
            flash_image_file(&mut transport, "super", &wire_partition, &image_path, &gopts)?;
        }
        Commands::Erase { partition } => {
            let wire_partition = slot_selection.partition_name(&partition)?;
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("erase:{}", wire_partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            require_terminal_okay(&resp)?;
            println!("[fastboot-rs] Erase response: {:?}", resp);
        }
        Commands::Reboot { target } => run_reboot(&connection_target, target.as_deref())?,
        Commands::RebootBootloader => run_reboot(&connection_target, Some("bootloader"))?,
        Commands::RebootRecovery => run_reboot(&connection_target, Some("recovery"))?,
        Commands::RebootFastboot => run_reboot(&connection_target, Some("fastboot"))?,
        Commands::Oem { command } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("oem {}", command.join(" "));
            transport.send_cmd(&cmd)?;
            let resp = recv_and_print_info(&mut transport)?;
            println!("[fastboot-rs] OEM response: {:?}", resp);
        }
        Commands::CreateLogicalPartition { partition, size } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::create_logical_partition(&partition, size);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            require_terminal_okay(&resp)?;
            println!("[fastboot-rs] Create logical partition response: {:?}", resp);
        }
        Commands::DeleteLogicalPartition { partition } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::delete_logical_partition(&partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            require_terminal_okay(&resp)?;
            println!("[fastboot-rs] Delete logical partition response: {:?}", resp);
        }
        Commands::ResizeLogicalPartition { partition, size } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::resize_logical_partition(&partition, size);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            require_terminal_okay(&resp)?;
            println!("[fastboot-rs] Resize logical partition response: {:?}", resp);
        }
        Commands::Boot { kernel, ramdisk, second } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {}", addr);

            let boot_payload: Vec<u8>;

            if let Some(ramdisk_path) = &ramdisk {
                // --- 有 ramdisk: 打包为 boot image ---
                println!(
                    "[fastboot-rs] 打包 boot image (kernel={}, ramdisk={})",
                    kernel, ramdisk_path
                );

                // 读取 kernel
                let kernel_data = read_file_bytes(&kernel);
                // 读取 ramdisk
                let ramdisk_data = read_file_bytes(ramdisk_path);

                // 检查 kernel 是否已经是完整 boot image
                if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                    println!(
                        "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                    );
                    boot_payload = kernel_data;
                } else {
                    let second_bytes = second.as_ref().map(|p| read_file_bytes(p));
                    let second_data = second_bytes.as_deref().unwrap_or(&[]);
                    println!(
                        "[fastboot-rs] 构建 boot image (header v4, page_size=4096)..."
                    );
                    boot_payload = fastboot_protocol::boot_image::BootImageBuilder::new()
                        .kernel(kernel_data)
                        .ramdisk(ramdisk_data)
                        .second(second_data.to_vec())
                        .build();
                    println!(
                        "[fastboot-rs] boot image 构建完成: {} 字节",
                        boot_payload.len()
                    );
                }

                if let Some(ref s) = second {
                    println!("[fastboot-rs] second 已打包: {}", s);
                }
            } else {
                // --- 无 ramdisk: 检查 kernel 是否为完整 boot image ---
                let kernel_data = read_file_bytes(&kernel);
                if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                    println!(
                        "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                    );
                    boot_payload = kernel_data;
                } else {
                    println!(
                        "[fastboot-rs] 无 ramdisk，使用 BootImageBuilder 构建 boot image..."
                    );
                    let second_bytes = second.as_ref().map(|p| read_file_bytes(p));
                    let second_data = second_bytes.as_deref().unwrap_or(&[]);
                    boot_payload = fastboot_protocol::boot_image::BootImageBuilder::new()
                        .kernel(kernel_data)
                        .second(second_data.to_vec())
                        .build();
                }
            }

            // --- 公共流程: download boot_payload + boot ---
            download_and_boot_payload(&mut transport, &boot_payload)?;
            return handle_boot_response(transport);
        }
        Commands::FlashRaw {
            partition,
            kernel,
            ramdisk,
            second,
        } => {
            let wire_partition = slot_selection.partition_name(&partition)?;
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {}", addr);

            // 读取 kernel
            let kernel_data = read_file_bytes(&kernel);

            let boot_payload: Vec<u8> = if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                println!(
                    "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                );
                kernel_data
            } else {
                // 读取可选 ramdisk
                let ramdisk_data = match &ramdisk {
                    Some(path) => read_file_bytes(path),
                    None => Vec::new(),
                };
                // 读取可选 second
                let second_data = match &second {
                    Some(path) => read_file_bytes(path),
                    None => Vec::new(),
                };

                println!(
                    "[fastboot-rs] 构建 boot image (kernel={}, ramdisk={}字节, second={}字节, header v4, page_size=4096)...",
                    kernel,
                    ramdisk_data.len(),
                    second_data.len(),
                );

                let built = fastboot_protocol::boot_image::build_boot_image(
                    &kernel_data,
                    &ramdisk_data,
                    &second_data,
                    &[], // dtb — 暂不提供
                    4096,
                    4,
                );
                println!(
                    "[fastboot-rs] boot image 构建完成: {} 字节",
                    built.len()
                );
                built
            };

            // download + flash 流程
            download_and_flash_payload(&mut transport, &boot_payload, &wire_partition)?;

            // 读取 flash 响应
            let flash_resp = transport.recv_response()?;
            require_terminal_okay(&flash_resp)?;
            match &flash_resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!(
                        "[fastboot-rs] 成功刷写分区 '{}': {}",
                        partition, val
                    );
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 刷写分区 '{}' 失败: {}",
                        partition, reason
                    );
                    std::process::exit(1);
                }
                other => {
                    println!(
                        "[fastboot-rs] 刷写分区 '{}' 响应: {:?}",
                        partition, other
                    );
                }
            }
        }
        Commands::Fetch { partition, out_file, offset, size } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let resp = fetch_to_file(
                &mut transport,
                &partition,
                &out_file,
                offset,
                size,
                &slot_selection,
            )?;
            println!(
                "[fastboot-rs] Fetched partition '{}' to '{}': {:?}",
                partition, out_file, resp
            );
        }
        Commands::Continue => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("continue")?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Continue OK: {}", val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Continue FAIL: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Continue response: {:?}", other);
                }
            }
        }
        Commands::Signature { file } => {
            let signature = read_file_bytes(&file);
            if signature.len() != 256 {
                return Err(format!(
                    "signature must be 256 bytes (got {})",
                    signature.len()
                )
                .into());
            }
            let mut transport = open_transport(&connection_target, Duration::from_secs(3))?;
            transport.send_cmd(&fastboot_protocol::download(256))?;
            match transport.recv_response()? {
                fastboot_protocol::FastbootResponse::Data(size) if size == 256 => {}
                response => {
                    return Err(format!("signature download rejected: {:?}", response).into());
                }
            }
            transport.write_all(&signature)?;
            transport.flush()?;
            match transport.recv_response()? {
                fastboot_protocol::FastbootResponse::Okay(_) => {}
                response => return Err(format!("signature payload rejected: {:?}", response).into()),
            }
            transport.send_cmd(&fastboot_protocol::signature())?;
            let response = recv_and_print_info(&mut transport)?;
            match response {
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    return Err(format!("signature installation failed: {reason}").into());
                }
                other => println!("[fastboot-rs] Signature response: {:?}", other),
            }
        }
        Commands::SnapshotUpdate { action } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::snapshot_update(action.as_deref());
            transport.send_cmd(&cmd)?;
            let response = recv_and_print_info(&mut transport)?;
            match response {
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    return Err(format!("{} failed: {}", cmd, reason).into());
                }
                other => println!("[fastboot-rs] Snapshot update response: {:?}", other),
            }
        }
        Commands::Format { partition, partition_type } => {
            let wire_partition = slot_selection.partition_name(&partition)?;
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = match &partition_type {
                Some(pt) => format!("format:{}:{}", pt, wire_partition),
                None => format!("format:{}", wire_partition),
            };
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Format OK: {}", val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Format FAIL: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Format response: {:?}", other);
                }
            }
        }
        Commands::GetStaged { out_file } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("get_staged")?;
            let data_size = match recv_data_response(&mut transport, "get_staged")? {
                fastboot_protocol::FastbootResponse::Data(size) if size > 0 => size as usize,
                fastboot_protocol::FastbootResponse::Data(_) => {
                    return Err("get_staged failed: device returned zero bytes".into());
                }
                _ => unreachable!("recv_data_response only returns DATA"),
            };
            let mut output = File::create(&out_file)?;
            let mut remaining = data_size;
            let mut buffer = [0u8; 1024 * 1024];
            while remaining > 0 {
                let chunk_size = remaining.min(buffer.len());
                transport.read_exact(&mut buffer[..chunk_size])?;
                output.write_all(&buffer[..chunk_size])?;
                remaining -= chunk_size;
            }
            output.sync_all()?;
            let final_resp = transport.recv_response()?;
            match final_resp {
                fastboot_protocol::FastbootResponse::Okay(msg) => {
                    println!("[fastboot-rs] GetStaged wrote {} bytes to '{}': {}", data_size, out_file, msg);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    return Err(format!("get_staged failed after receiving data: {reason}").into());
                }
                other => return Err(format!("unexpected get_staged final response: {other:?}").into()),
            }
        }
        Commands::Stage { file } => {
            // 准备数据源：打开文件或读取 stdin
            let (mut data_source, file_size): (Box<dyn std::io::Read>, usize) = match file {
                Some(ref path) => {
                    let file = match File::open(path) {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("[fastboot-rs] 错误: 无法打开文件 '{}': {}", path, e);
                            std::process::exit(1);
                        }
                    };
                    let size = match file.metadata() {
                        Ok(m) => m.len() as usize,
                        Err(e) => {
                            eprintln!("[fastboot-rs] 错误: 无法读取文件元数据 '{}': {}", path, e);
                            std::process::exit(1);
                        }
                    };
                    if size == 0 {
                        eprintln!("[fastboot-rs] 错误: 文件 '{}' 为空", path);
                        std::process::exit(1);
                    }
                    if size > u32::MAX as usize {
                        eprintln!(
                            "[fastboot-rs] 错误: 文件 '{}' 大小 ({}) 超过 u32 上限 ({}); 协议限制",
                            path,
                            size,
                            u32::MAX
                        );
                        std::process::exit(1);
                    }
                    (Box::new(file) as Box<dyn std::io::Read>, size)
                }
                None => {
                    // 从 stdin 读取全部数据（需要提前知道大小才能发送 download 命令）
                    let mut buf = Vec::new();
                    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                        eprintln!("[fastboot-rs] 错误: 读取 stdin 失败: {}", e);
                        std::process::exit(1);
                    }
                    if buf.is_empty() {
                        eprintln!("[fastboot-rs] 错误: stdin 无数据");
                        std::process::exit(1);
                    }
                    if buf.len() > u32::MAX as usize {
                        eprintln!(
                            "[fastboot-rs] 错误: stdin 数据大小 ({}) 超过 u32 上限 ({}); 协议限制",
                            buf.len(),
                            u32::MAX
                        );
                        std::process::exit(1);
                    }
                    let size = buf.len();
                    (Box::new(std::io::Cursor::new(buf)) as Box<dyn std::io::Read>, size)
                }
            };

            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!(
                "[fastboot-rs] 已连接至 {}，开始 stage {} 字节数据...",
                addr, file_size
            );

            // Step 1: 获取 max-download-size
            let max_download_size = match transport.send_cmd("getvar:max-download-size") {
                Ok(_) => match transport.recv_response() {
                    Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                        parse_max_download_size(&val)
                    }
                    _ => None,
                },
                _ => None,
            };

            let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024); // 默认 16MB
            if let Some(limit) = max_download_size {
                println!(
                    "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
                    limit, limit
                );
            }
            println!(
                "[fastboot-rs] 发送 download 命令 ({} bytes, 分块大小: {} bytes)...",
                file_size, chunk_size
            );

            // Step 2: 发送 download 命令
            let download_cmd = fastboot_protocol::download(file_size as u32);
            transport.send_cmd(&download_cmd)?;
            let dl_resp = transport.recv_response()?;
            match dl_resp {
                fastboot_protocol::FastbootResponse::Data(expected_len) => {
                    if expected_len != file_size as u32 {
                        eprintln!(
                            "[fastboot-rs] 错误: 设备请求 {} 字节，但本地数据为 {} 字节",
                            expected_len, file_size
                        );
                        std::process::exit(1);
                    }
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] download 失败: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
                    std::process::exit(1);
                }
            }

            // Step 3: 分块发送 DATA payload
            println!("[fastboot-rs] 分块发送 payload...");
            let mut buffer = vec![0u8; chunk_size];
            let mut remaining = file_size;
            let mut chunk_index = 0u64;

            while remaining > 0 {
                let to_read = remaining.min(chunk_size);
                if let Err(e) = data_source.read_exact(&mut buffer[..to_read]) {
                    eprintln!(
                        "[fastboot-rs] 错误: 读取数据失败 at offset {}: {}",
                        file_size - remaining,
                        e
                    );
                    std::process::exit(1);
                }
                if let Err(e) = transport.write_all(&buffer[..to_read]) {
                    eprintln!(
                        "[fastboot-rs] 错误: 写入 transport 失败 at chunk {} (offset {}): {}",
                        chunk_index,
                        file_size - remaining,
                        e
                    );
                    std::process::exit(1);
                }
                remaining -= to_read;
                chunk_index += 1;
            }
            transport.flush()?;

            // Step 4: only OKAY completes the accepted download.
            let final_resp = transport.recv_response()?;
            require_terminal_okay(&final_resp)?;
            match &final_resp {
                fastboot_protocol::FastbootResponse::Okay(msg) => {
                    println!("[fastboot-rs] Stage 成功: {}", msg);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Stage 失败: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Stage 响应: {:?}", other);
                }
            }
        }
        Commands::Shutdown => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("reboot-shutdown")?;
            let resp = transport.recv_response();
            match &resp {
                Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                    println!("[fastboot-rs] Shutdown OK: {}", val);
                }
                Ok(fastboot_protocol::FastbootResponse::Fail(reason)) => {
                    eprintln!("[fastboot-rs] Shutdown FAIL: {}", reason);
                    std::process::exit(1);
                }
                Ok(other) => {
                    println!("[fastboot-rs] Shutdown response: {:?}", other);
                }
                Err(e) => {
                    // 设备可能已经断开（断电），读不到响应也是正常的
                    eprintln!(
                        "[fastboot-rs] Warning: Could not read shutdown response \
                         (device may be powering off): {}",
                        e
                    );
                }
            }
            let disconnected = wait_for_disconnect(transport, Duration::from_secs(5));
            if disconnected {
                println!("[fastboot-rs] Device disconnected — shutdown confirmed");
            } else {
                eprintln!(
                    "[fastboot-rs] Warning: Device did not disconnect within 5s timeout \
                     (shutdown may still be in progress)"
                );
            }
        }
        Commands::Flashing { action } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("flashing:{}", action);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Flashing '{}' 成功: {}", action, val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Flashing '{}' 失败: {}", action, reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Flashing '{}' 响应: {:?}", action, other);
                }
            }
        }
        Commands::Update { zip_file } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {e}");
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {addr}");
            do_update(&mut transport, &zip_file, &gopts, &slot_selection)?;
        }
        Commands::Gsi { action } => {
            let mut transport = match open_transport(&connection_target, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let command = format!("gsi:{}", action.join(":"));
            transport.send_cmd(&command)?;
            let response = recv_and_print_info(&mut transport)?;
            if let fastboot_protocol::FastbootResponse::Fail(reason) = response {
                return Err(format!("{command} failed: {reason}").into());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn target_explicit_usb_serial_survives_cli_resolution() {
        assert_eq!(resolve_target(true, Some("B"), None).unwrap(), FastbootTarget::Usb(Some("B".into())));
        assert_eq!(resolve_target(false, Some("B"), None).unwrap(), FastbootTarget::Usb(Some("B".into())));
    }

    #[test]
    fn target_no_serial_is_usb_not_implicit_loopback() {
        assert_eq!(resolve_target(false, None, None).unwrap(), FastbootTarget::Usb(None));
    }

    #[test]
    fn target_environment_serial_and_cli_precedence() {
        assert_eq!(resolve_target(false, None, Some("B")).unwrap(), FastbootTarget::Usb(Some("B".into())));
        assert_eq!(resolve_target(false, Some("A"), Some("B")).unwrap(), FastbootTarget::Usb(Some("A".into())));
    }

    #[test]
    fn target_standard_network_prefixes_and_legacy_endpoint() {
        assert_eq!(resolve_target(false, Some("tcp:127.0.0.1:1234"), None).unwrap(), FastbootTarget::Tcp("127.0.0.1:1234".into()));
        assert_eq!(resolve_target(false, Some("udp:127.0.0.1:1234"), None).unwrap(), FastbootTarget::Udp("127.0.0.1:1234".into()));
        assert_eq!(resolve_target(false, Some("127.0.0.1:1234"), None).unwrap(), FastbootTarget::Tcp("127.0.0.1:1234".into()));
    }

    #[test]
    fn target_network_defaults_ipv6_and_literal_usb_serial_are_preserved() {
        for (source, expected) in [("tcp:localhost", "localhost:5554"), ("tcp:[::1]", "[::1]:5554"), ("tcp:[::1]:1234", "[::1]:1234"), ("tcp:::1", "[::1]:5554")] {
            assert_eq!(resolve_target(false, Some(source), None).unwrap(), FastbootTarget::Tcp(expected.into()));
        }
        assert_eq!(resolve_target(true, Some("serial:literal"), None).unwrap(), FastbootTarget::Usb(Some("serial:literal".into())));
        assert_eq!(resolve_target(false, None, Some("")).unwrap(), FastbootTarget::Usb(None));
    }

    #[test]
    fn target_conflicts_and_unsupported_usb_paths_fail_before_open() {
        for serial in ["tcp:127.0.0.1:1234", "udp:127.0.0.1:1234"] {
            assert!(resolve_target(true, Some(serial), None).is_err());
        }
        for serial in ["", "usb:1-2", "/dev/bus/usb/001/002", "tcp:", "tcp:host:bad"] {
            assert!(resolve_target(false, Some(serial), None).is_err(), "{serial}");
        }
    }

    #[test]
    fn help_exposes_global_usb_opt_in() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--usb"));
        assert!(help.contains("devices"));
        assert!(help.contains("getvar"));
    }

    #[test]
    #[cfg(not(feature = "usb"))]
    fn usb_mode_reports_feature_requirement_without_touching_tcp() {
        let error = match open_transport(&FastbootTarget::Usb(None), Duration::from_secs(1)) {
            Ok(_) => panic!("USB mode must fail clearly when the optional feature is disabled"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("USB support is not enabled"));
        assert!(error.contains("--features usb"));
    }

    #[test]
    fn cli_accepts_usb_before_and_after_subcommand() {
        for args in [
            ["fastboot-rs", "--usb", "getvar", "version"],
            ["fastboot-rs", "getvar", "version", "--usb"],
        ] {
            let cli = Cli::try_parse_from(args).expect("--usb should be a global option");
            assert!(cli.usb);
            assert!(matches!(cli.command, Commands::Getvar { ref variable } if variable == "version"));
        }
    }

    #[test]
    fn cli_accepts_global_aosp_slot_options() {
        let cli = Cli::try_parse_from([
            "fastboot-rs", "--slot", "b", "--set-active=b", "erase", "userdata",
        ])
        .expect("global slot options should parse before a command");
        assert_eq!(cli.slot.as_deref(), Some("b"));
        assert_eq!(cli.set_active.as_deref(), Some("b"));

        let cli = Cli::try_parse_from(["fastboot-rs", "getvar", "all", "--slot", "other"])
            .expect("global slot option should parse after a command");
        assert_eq!(cli.slot.as_deref(), Some("other"));
    }

    #[test]
    fn cli_rejects_malformed_slot_values() {
        for value in ["_a", "A", "a1", ""] {
            let cli = Cli::try_parse_from(["fastboot-rs", "--slot", value, "erase", "userdata"]);
            assert!(cli.is_err(), "slot value {value:?} must be rejected");
        }
    }

    #[test]
    fn test_parse_max_download_size() {
        assert_eq!(parse_max_download_size("0x20000000"), Some(536870912));
        assert_eq!(parse_max_download_size("0X04000000"), Some(67108864));
        assert_eq!(parse_max_download_size("536870912"), Some(536870912));
        assert_eq!(parse_max_download_size("  0x100000 \n"), Some(1048576));
        assert_eq!(parse_max_download_size("invalid"), None);
        assert_eq!(parse_max_download_size(""), None);
    }

    #[test]
    fn test_parse_max_download_size_suffixes() {
        assert_eq!(parse_max_download_size("512MB"), Some(536870912));
        assert_eq!(parse_max_download_size("1024K"), Some(1048576));
        assert_eq!(parse_max_download_size("1GB"), Some(1073741824));
        assert_eq!(parse_max_download_size("256M"), Some(268435456));
        assert_eq!(parse_max_download_size("1024kb"), Some(1048576));
        assert_eq!(parse_max_download_size("512 mb"), Some(536870912));
        assert_eq!(parse_max_download_size("0x200MB"), Some(536870912));
    }

    #[test]
    fn test_boot_accepts_kernel_and_optional_ramdisk_second() {
        // 验证 CLI 参数解析：kernel 为必选，ramdisk/second 为可选（positional args）
        let cli = Cli::try_parse_from([
            "fastboot-rs",
            "boot",
            "boot.img",
            "ramdisk.img",
            "second.img",
        ])
        .expect("boot with all positional args should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "boot.img");
                assert_eq!(ramdisk.as_deref(), Some("ramdisk.img"));
                assert_eq!(second.as_deref(), Some("second.img"));
            }
            _ => panic!("expected Boot command"),
        }

        // kernel + ramdisk
        let cli = Cli::try_parse_from(["fastboot-rs", "boot", "kernel.img", "ramdisk.img"])
            .expect("boot with kernel and ramdisk should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "kernel.img");
                assert_eq!(ramdisk.as_deref(), Some("ramdisk.img"));
                assert!(second.is_none());
            }
            _ => panic!("expected Boot command"),
        }

        // 仅 kernel 参数
        let cli = Cli::try_parse_from(["fastboot-rs", "boot", "kernel.img"])
            .expect("boot with kernel only should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "kernel.img");
                assert!(ramdisk.is_none());
                assert!(second.is_none());
            }
            _ => panic!("expected Boot command"),
        }
    }

    #[test]
    fn fetch_range_command_is_aosp_formatted() {
        assert_eq!(
            fastboot_protocol::fetch("boot", Some(0), Some(5)),
            "fetch:boot:0x00000000:0x00000005"
        );
    }

    #[test]
    fn get_staged_requires_a_destination_file_like_aosp_cli() {
        let cli = Cli::try_parse_from(["fastboot-rs", "get-staged", "staged.bin"])
            .expect("AOSP get_staged takes an output file");
        assert!(matches!(
            cli.command,
            Commands::GetStaged { ref out_file } if out_file == "staged.bin"
        ));
    }

    #[test]
    fn aosp_reboot_variant_commands_parse_without_a_target_argument() {
        for (name, expected) in [
            ("reboot-bootloader", "bootloader"),
            ("reboot-recovery", "recovery"),
            ("reboot-fastboot", "fastboot"),
        ] {
            let cli = Cli::try_parse_from(["fastboot-rs", name])
                .expect("AOSP reboot variant should parse");
            let actual = match cli.command {
                Commands::RebootBootloader => "bootloader",
                Commands::RebootRecovery => "recovery",
                Commands::RebootFastboot => "fastboot",
                _ => panic!("expected a reboot variant"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn signature_requires_a_file() {
        assert!(Cli::try_parse_from(["fastboot-rs", "signature"]).is_err());
        assert!(Cli::try_parse_from(["fastboot-rs", "signature", "sig.bin"]).is_ok());
    }

    #[test]
    fn snapshot_update_accepts_only_aosp_actions() {
        assert!(Cli::try_parse_from(["fastboot-rs", "snapshot-update"]).is_ok());
        assert!(Cli::try_parse_from(["fastboot-rs", "snapshot-update", "cancel"]).is_ok());
        assert!(Cli::try_parse_from(["fastboot-rs", "snapshot-update", "merge"]).is_ok());
        assert!(Cli::try_parse_from(["fastboot-rs", "snapshot-update", "bad"]).is_err());
    }

    #[test]
    fn aosp_stage_requires_an_input_file() {
        assert!(Cli::try_parse_from(["fastboot-rs", "stage"]).is_err());
    }

    #[test]
    fn gsi_accepts_multiple_aosp_command_arguments() {
        let cli = Cli::try_parse_from(["fastboot-rs", "gsi", "wipe", "vendor", "extra"])
            .expect("AOSP forwards every gsi argument as a colon-separated command");
        assert!(matches!(
            cli.command,
            Commands::Gsi { ref action } if action == &["wipe", "vendor", "extra"]
        ));
    }

    #[test]
    fn flashing_rejects_unknown_action_and_oem_requires_a_command() {
        assert!(Cli::try_parse_from(["fastboot-rs", "flashing", "unlock"]).is_ok());
        assert!(Cli::try_parse_from(["fastboot-rs", "flashing", "unknown"]).is_err());
        assert!(Cli::try_parse_from(["fastboot-rs", "oem"]).is_err());
    }

    #[test]
    fn connected_device_storage_is_sorted_deduplicated_and_removable() {
        let root = std::env::temp_dir().join(format!(
            "fastboot-rs-connected-devices-{}",
            std::process::id()
        ));
        let devices_path = root.join(".fastboot/devices");
        let _ = std::fs::remove_dir_all(&root);

        store_connected_device(&devices_path, "tcp:127.0.0.1:5554").unwrap();
        store_connected_device(&devices_path, "udp:127.0.0.1:5555").unwrap();
        store_connected_device(&devices_path, "tcp:127.0.0.1:5554").unwrap();
        assert_eq!(
            std::fs::read_to_string(&devices_path).unwrap(),
            "tcp:127.0.0.1:5554\nudp:127.0.0.1:5555\n"
        );

        remove_connected_device(&devices_path, Some("tcp:127.0.0.1:5554")).unwrap();
        assert_eq!(std::fs::read_to_string(&devices_path).unwrap(), "udp:127.0.0.1:5555\n");

        remove_connected_device(&devices_path, None).unwrap();
        assert!(!devices_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    // ------------------------------------------------------------------
    // AOSP global options (--skip-reboot, --force, --disable-verity, etc.)
    // ------------------------------------------------------------------

    #[test]
    fn cli_accepts_aosp_global_flash_options() {
        let cli = Cli::try_parse_from([
            "fastboot-rs",
            "--skip-reboot",
            "--skip-secondary",
            "--force",
            "--disable-verity",
            "--disable-verification",
            "-v",
            "getvar", "unlocked",
        ])
        .expect("all AOSP global options should parse");
        assert!(cli.skip_reboot);
        assert!(cli.skip_secondary);
        assert!(cli.force);
        assert!(cli.disable_verity);
        assert!(cli.disable_verification);
        assert!(cli.verbose);
    }

    #[test]
    fn global_options_default_to_false() {
        let cli = Cli::try_parse_from(["fastboot-rs", "getvar", "unlocked"]).unwrap();
        assert!(!cli.skip_reboot);
        assert!(!cli.skip_secondary);
        assert!(!cli.force);
        assert!(!cli.disable_verity);
        assert!(!cli.disable_verification);
        assert!(!cli.verbose);
    }

    #[test]
    fn global_options_work_after_subcommand() {
        // AOSP getopt_long allows options anywhere on the command line.
        let cli = Cli::try_parse_from([
            "fastboot-rs", "flash", "boot", "--skip-reboot", "--force",
        ])
        .expect("global flags after subcommand should parse");
        assert!(cli.skip_reboot);
        assert!(cli.force);
        assert!(matches!(cli.command, Commands::Flash { .. }));
    }

    // ------------------------------------------------------------------
    // vbmeta flag patching (AOSP SetVbmetaFlags)
    // ------------------------------------------------------------------

    /// Build a minimal 256-byte vbmeta image with AVB0 magic at offset 0.
    fn fake_vbmeta() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"AVB0");
        // flags field at offset 120..124 (BE u32), LSB at 123
        data
    }

    #[test]
    fn patch_vbmeta_sets_verity_bit() {
        let data = fake_vbmeta();
        let opts = GlobalOptions { disable_verity: true, ..Default::default() };
        let patched = patch_vbmeta_flags(&data, &opts).expect("valid structure").expect("should patch");
        assert_eq!(patched[123] & 0x01, 0x01, "bit 0 = disable-verity");
        assert_eq!(patched[123] & 0x02, 0x00, "bit 1 unchanged");
    }

    #[test]
    fn patch_vbmeta_sets_verification_bit() {
        let data = fake_vbmeta();
        let opts = GlobalOptions { disable_verification: true, ..Default::default() };
        let patched = patch_vbmeta_flags(&data, &opts).expect("valid structure").expect("should patch");
        assert_eq!(patched[123] & 0x02, 0x02, "bit 1 = disable-verification");
        assert_eq!(patched[123] & 0x01, 0x00, "bit 0 unchanged");
    }

    #[test]
    fn patch_vbmeta_sets_both_bits() {
        let data = fake_vbmeta();
        let opts = GlobalOptions { disable_verity: true, disable_verification: true, ..Default::default() };
        let patched = patch_vbmeta_flags(&data, &opts).expect("valid structure").expect("should patch");
        assert_eq!(patched[123] & 0x03, 0x03, "both bits set");
    }

    #[test]
    fn patch_vbmeta_noop_without_flags() {
        let data = fake_vbmeta();
        let opts = GlobalOptions::default();
        assert!(patch_vbmeta_flags(&data, &opts).expect("unrecognized or unchanged").is_none(), "no flags → None");
    }

    #[test]
    fn patch_vbmeta_rejects_short_buffer() {
        let data = vec![0u8; 100];
        let opts = GlobalOptions { disable_verity: true, ..Default::default() };
        assert!(patch_vbmeta_flags(&data, &opts).expect("unrecognized or unchanged").is_none(), "too short → None");
    }

    #[test]
    fn patch_vbmeta_rejects_missing_magic() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"XXXX"); // wrong magic
        let opts = GlobalOptions { disable_verity: true, ..Default::default() };
        assert!(patch_vbmeta_flags(&data, &opts).expect("unrecognized or unchanged").is_none(), "no AVB0 → None");
    }

    #[test]
    fn patch_vbmeta_via_avb_footer() {
        // Simulate a boot image: 512 bytes of payload + AVB footer at end.
        // vbmeta lives at offset 256 inside the image.
        let mut data = vec![0u8; 512 + AVB_FOOTER_SIZE];
        // Place AVB0 magic at offset 256
        data[256..260].copy_from_slice(b"AVB0");
        // Build footer at the end
        let footer_start = data.len() - AVB_FOOTER_SIZE;
        data[footer_start..footer_start + 4].copy_from_slice(b"AVBf");
        // Packed AvbFooter: major=4, original_size=12, offset=20, size=28.
        data[footer_start + 4..footer_start + 8].copy_from_slice(&1u32.to_be_bytes());
        data[footer_start + 12..footer_start + 20].copy_from_slice(&128u64.to_be_bytes());
        data[footer_start + 20..footer_start + 28].copy_from_slice(&256u64.to_be_bytes());
        data[footer_start + 28..footer_start + 36].copy_from_slice(&256u64.to_be_bytes());

        let opts = GlobalOptions { disable_verity: true, disable_verification: true, ..Default::default() };
        let patched = patch_vbmeta_flags(&data, &opts).expect("valid structure").expect("should patch via footer");
        // flags LSB at 256 + 123 = 379
        assert_eq!(patched[379] & 0x03, 0x03, "both bits set via footer path");
    }

    #[test]
    fn is_vbmeta_partition_matches_aosp() {
        // AOSP: EndsWith(partition, "vbmeta") || EndsWith("vbmeta_a") || EndsWith("vbmeta_b")
        assert!(is_vbmeta_partition("vbmeta"));
        assert!(is_vbmeta_partition("vbmeta_a"));
        assert!(is_vbmeta_partition("vbmeta_b"));
        // vbmeta_system / vbmeta_vendor do NOT end with "vbmeta" — AOSP
        // patches them via the flash path's partition-name check, not
        // is_vbmeta_partition().
        assert!(!is_vbmeta_partition("vbmeta_system"));
        assert!(!is_vbmeta_partition("vbmeta_vendor"));
        assert!(!is_vbmeta_partition("boot"));
        assert!(!is_vbmeta_partition("system"));
    }
}
