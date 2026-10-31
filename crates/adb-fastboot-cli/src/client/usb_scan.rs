//! USB hotplug scanning with injectable roots — pure logic, no ioctls.
//!
//! AOSP source: `vendor/adb/client/usb_linux.cpp` (Android 17 main).
//!
//! This slice reproduces the *discovery* half of the Linux USB backend: the
//! periodic walk of `/dev/bus/usb`, the "known device" set, descriptor-derived
//! interface matching, and the add/remove difference that
//! `device_poll_thread()` turns into transport registrations.  Driving a real
//! usbfs node (open/ioctl/claim/reap) is deliberately out of scope: that lives
//! in [`adb_protocol::usb_android`] and is not reachable without hardware.
//!
//! Anchors in `client/usb_linux.cpp`:
//!
//! | AOSP | lines | reproduced here |
//! | --- | --- | --- |
//! | `contains_non_digit()` | 115-120 | [`is_decimal_name`] |
//! | `is_known_device()` | 103-113 | [`HotplugTracker::is_known_device`] |
//! | `process_usb_device()` | 153-312 | [`probe_device`] |
//! | ADB interface test | 221-223 | [`classify_interface`] + two-endpoint rule |
//! | serial read + `Trim` | 546-557 | [`read_serial`] |
//! | `register_device()` dedupe | 572-578 | [`HotplugTracker::register_device`] |
//! | `scan_usb_devices()` | 622-651 | [`scan_usb_devices`] |
//! | `device_poll_thread()` | 653-719 | [`HotplugTracker::tick`] + [`PollThread`] |
//!
//! `is_adb_interface()` itself is in `client/transport_usb.cpp:170-179`
//! (class `0xff`/subclass `0x42`/protocol `0x01`, plus the DbC fallback
//! `0xdc`/`0x02`/`0x01`).  Fastboot uses the same vendor class with protocol
//! `0x03` (`fastboot/protocol/usb.h`).
//!
//! ## Why sysfs, and why injectable roots
//!
//! AOSP reads the descriptor blob straight off the usbfs file descriptor.  An
//! offline test can only fake that by opening a file, which would make the
//! parse depend on the fake blob layout rather than on the scan semantics.
//! Instead the scan consumes the sysfs projection of the same descriptors
//! (`idVendor`, `idProduct`, `busnum`, `devnum`, `serial`, and one directory
//! per interface with `bInterfaceClass`/`bInterfaceSubClass`/
//! `bInterfaceProtocol`/`bNumEndpoints`), which is exactly how the scan maps a
//! device node to a device name in AOSP (`usb_linux.cpp:280-291` resolves
//! `/sys/dev/char/<maj>:<min>` to `usb:<name>`, and `register_device()` then
//! reads `/sys/bus/usb/devices/<name>/serial` at 546-557).  Both roots are
//! constructor parameters, so tests build a throwaway tree and never touch
//! `/dev/bus/usb`.
//!
//! ## Failure policy
//!
//! A scan never panics.  Unreadable nodes, missing sysfs entries and broken
//! attributes become [`SkippedEntry`] values; a device that is *known* but
//! cannot be re-identified stays registered (AOSP keeps the `usb_handle` while
//! the node exists — removal only happens on an explicit remove event,
//! `usb_linux.cpp:706-714`).  Removal therefore requires a *complete* scan.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Interface class triples
// ---------------------------------------------------------------------------

/// `ADB_CLASS` (`adb.h:194`).
pub const ADB_CLASS: u8 = 0xff;
/// `ADB_SUBCLASS` (`adb.h:195`).
pub const ADB_SUBCLASS: u8 = 0x42;
/// `ADB_PROTOCOL` (`adb.h:196`).
pub const ADB_PROTOCOL: u8 = 0x01;
/// `ADB_DBC_CLASS` (`adb.h:198`) — Debug Bridge over USB-C Debug Class.
pub const ADB_DBC_CLASS: u8 = 0xdc;
/// `ADB_DBC_SUBCLASS` (`adb.h:199`).
pub const ADB_DBC_SUBCLASS: u8 = 0x02;
/// Fastboot vendor class (same as ADB).
pub const FASTBOOT_CLASS: u8 = 0xff;
/// Fastboot vendor subclass (same as ADB).
pub const FASTBOOT_SUBCLASS: u8 = 0x42;
/// Fastboot protocol selector — the only triple element that differs from ADB.
pub const FASTBOOT_PROTOCOL: u8 = 0x03;

/// Which host-side protocol an interface speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsbInterfaceKind {
    /// `adb` (includes the DbC fallback triple).
    Adb,
    /// `fastboot`.
    Fastboot,
}

impl UsbInterfaceKind {
    /// Lower-case name, matching the subcommand that would use the device.
    pub fn as_str(self) -> &'static str {
        match self {
            UsbInterfaceKind::Adb => "adb",
            UsbInterfaceKind::Fastboot => "fastboot",
        }
    }
}

impl fmt::Display for UsbInterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify one interface triple.
///
/// ADB follows `is_adb_interface()` (`client/transport_usb.cpp:170-179`)
/// byte-for-byte, including the DbC branch.  Fastboot is the same vendor
/// class/subclass with protocol `0x03`; it is checked second so an ADB triple
/// can never be mistaken for fastboot.
pub fn classify_interface(class: u8, subclass: u8, protocol: u8) -> Option<UsbInterfaceKind> {
    if protocol == ADB_PROTOCOL
        && ((class == ADB_CLASS && subclass == ADB_SUBCLASS)
            || (class == ADB_DBC_CLASS && subclass == ADB_DBC_SUBCLASS))
    {
        return Some(UsbInterfaceKind::Adb);
    }
    if class == FASTBOOT_CLASS
        && subclass == FASTBOOT_SUBCLASS
        && protocol == FASTBOOT_PROTOCOL
    {
        return Some(UsbInterfaceKind::Fastboot);
    }
    None
}

// ---------------------------------------------------------------------------
// Roots
// ---------------------------------------------------------------------------

/// Filesystem roots the scan reads.
///
/// Production uses `/dev/bus/usb` and `/sys/bus/usb/devices`; tests point both
/// at a temporary tree.  Only these two roots are ever consulted, so a fake
/// tree is fully self-contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRoots {
    dev_usb: PathBuf,
    sysfs_devices: PathBuf,
}

impl ScanRoots {
    /// The real host roots (`usb_linux.cpp:626`, `:548`).
    pub fn production() -> Self {
        Self {
            dev_usb: PathBuf::from("/dev/bus/usb"),
            sysfs_devices: PathBuf::from("/sys/bus/usb/devices"),
        }
    }

    /// Explicit roots — the injection point used by tests.
    pub fn new(dev_usb: impl Into<PathBuf>, sysfs_devices: impl Into<PathBuf>) -> Self {
        Self {
            dev_usb: dev_usb.into(),
            sysfs_devices: sysfs_devices.into(),
        }
    }

    /// Directory holding `<bus>/<addr>` device nodes.
    pub fn dev_usb(&self) -> &Path {
        &self.dev_usb
    }

    /// Directory holding `busnum`/`devnum`/`serial`/interface attribute dirs.
    pub fn sysfs_devices(&self) -> &Path {
        &self.sysfs_devices
    }
}

// ---------------------------------------------------------------------------
// Scanned records
// ---------------------------------------------------------------------------

/// One interface of a USB device, as projected by sysfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbInterface {
    /// sysfs directory name, e.g. `1-2:1.0`.
    pub name: String,
    /// `bInterfaceNumber`.
    pub number: u8,
    /// `bInterfaceClass`.
    pub class: u8,
    /// `bInterfaceSubClass`.
    pub subclass: u8,
    /// `bInterfaceProtocol`.
    pub protocol: u8,
    /// `bNumEndpoints`.
    pub num_endpoints: u8,
}

impl UsbInterface {
    /// ADB/fastboot classification of this interface's triple.
    pub fn kind(&self) -> Option<UsbInterfaceKind> {
        classify_interface(self.class, self.subclass, self.protocol)
    }
}

/// A device the scan could identify as ADB or fastboot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedDevice {
    /// usbfs node path, e.g. `/dev/bus/usb/001/002` (rooted at
    /// [`ScanRoots::dev_usb`] when the roots are injected).
    pub dev_name: String,
    /// sysfs device directory name, e.g. `1-2`.
    pub sysfs_name: String,
    /// `usb:<sysfs_name>` — the AOSP `dev_path` form (`usb_linux.cpp:288`).
    pub dev_path: String,
    /// `busnum`.
    pub bus_number: u8,
    /// `devnum`.
    pub address: u8,
    /// `idVendor`, if readable.
    pub vendor_id: Option<u16>,
    /// `idProduct`, if readable.
    pub product_id: Option<u16>,
    /// `serial`, trimmed; `None` when unreadable or empty (`usb_linux.cpp:546-557`
    /// explicitly treats a missing serial as acceptable).
    pub serial: Option<String>,
    /// Every interface the device reported, in sysfs order.
    pub interfaces: Vec<UsbInterface>,
    /// Protocol this device is usable for (ADB wins over fastboot).
    pub kind: UsbInterfaceKind,
}

impl ScannedDevice {
    /// The ADB interface selected for transport setup, if any.
    pub fn adb_interface(&self) -> Option<&UsbInterface> {
        self.interfaces
            .iter()
            .find(|i| i.kind() == Some(UsbInterfaceKind::Adb) && i.num_endpoints == 2)
    }

    /// The fastboot interface selected for transport setup, if any.
    pub fn fastboot_interface(&self) -> Option<&UsbInterface> {
        self.interfaces
            .iter()
            .find(|i| i.kind() == Some(UsbInterfaceKind::Fastboot))
    }
}

/// Why one device node was not turned into a [`ScannedDevice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The node could not be stat'ed (missing, or `EACCES` from the
    /// udev-chmod race documented at `usb_linux.cpp:122-151`).
    DeviceNodeUnreadable,
    /// No sysfs directory under [`ScanRoots::sysfs_devices`] has a matching
    /// `busnum`/`devnum` pair.
    SysfsDeviceNotFound,
    /// An interface attribute exists but could not be read.
    SysfsAttributeUnreadable { attribute: String },
    /// No interface matched ADB or fastboot.
    NoMatchingInterface,
    /// An ADB triple was present but `bNumEndpoints != 2`; AOSP rejects that
    /// interface (`usb_linux.cpp:221`).
    AdbInterfaceWithoutTwoEndpoints { interface: String },
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::DeviceNodeUnreadable => f.write_str("device node unreadable"),
            SkipReason::SysfsDeviceNotFound => f.write_str("no matching sysfs device"),
            SkipReason::SysfsAttributeUnreadable { attribute } => {
                write!(f, "sysfs attribute unreadable: {attribute}")
            }
            SkipReason::NoMatchingInterface => f.write_str("no ADB or fastboot interface"),
            SkipReason::AdbInterfaceWithoutTwoEndpoints { interface } => {
                write!(f, "ADB interface {interface} does not have 2 endpoints")
            }
        }
    }
}

/// One skipped device node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// The node path that was skipped.
    pub dev_name: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Result of one full directory walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Identified ADB/fastboot devices, sorted by node path.
    pub devices: Vec<ScannedDevice>,
    /// Nodes that were reached but not identified.
    pub skipped: Vec<SkippedEntry>,
    /// Every all-digit node seen in the walk, identified or not.  This is the
    /// authority for "still present" in [`HotplugTracker::tick`].
    pub present_dev_nodes: Vec<String>,
    /// Set when the bus root itself could not be read.
    pub root_error: Option<String>,
    /// `true` only when every directory in the walk was readable.  An
    /// incomplete scan must not be read as "these devices are gone".
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Walk `<dev_usb>/<digits>/<digits>` and identify every device.
///
/// Mirrors `scan_usb_devices()` (`usb_linux.cpp:622-651`): non-numeric entries
/// are ignored, an unreadable subdirectory is skipped, and a missing bus root
/// is a warning (here [`ScanReport::root_error`]) rather than a panic.
pub fn scan_usb_devices(roots: &ScanRoots) -> ScanReport {
    let mut report = ScanReport::default();

    let bus_entries = match fs::read_dir(roots.dev_usb()) {
        Ok(entries) => entries,
        Err(e) => {
            report.complete = false;
            report.root_error = Some(format!("{}: {e}", roots.dev_usb().display()));
            return report;
        }
    };
    report.complete = true;

    let mut buses: Vec<(String, PathBuf)> = Vec::new();
    for entry in bus_entries {
        match entry {
            Ok(entry) => {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if !is_decimal_name(&name) {
                    continue;
                }
                let path = entry.path();
                if path.is_dir() {
                    buses.push((name, path));
                }
            }
            Err(_) => report.complete = false,
        }
    }
    buses.sort_by(|a, b| a.0.cmp(&b.0));

    for (bus_name, bus_path) in buses {
        let dev_entries = match fs::read_dir(&bus_path) {
            Ok(entries) => entries,
            Err(_) => {
                // AOSP `continue`s here (`usb_linux.cpp:639-641`); we must also
                // remember that the walk is incomplete so nothing is unregistered.
                report.complete = false;
                continue;
            }
        };

        let mut devs: Vec<(String, PathBuf)> = Vec::new();
        for entry in dev_entries {
            match entry {
                Ok(entry) => {
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if !is_decimal_name(&name) {
                        continue;
                    }
                    devs.push((name, entry.path()));
                }
                Err(_) => report.complete = false,
            }
        }
        devs.sort_by(|a, b| a.0.cmp(&b.0));

        for (addr_name, node_path) in devs {
            let dev_name = node_path.to_string_lossy().into_owned();
            // Present even if identification fails: the node exists.
            report.present_dev_nodes.push(dev_name.clone());

            let Ok(bus_number) = bus_name.parse::<u8>() else {
                report.skipped.push(SkippedEntry {
                    dev_name,
                    reason: SkipReason::DeviceNodeUnreadable,
                });
                continue;
            };
            let Ok(address) = addr_name.parse::<u8>() else {
                report.skipped.push(SkippedEntry {
                    dev_name,
                    reason: SkipReason::DeviceNodeUnreadable,
                });
                continue;
            };

            match probe_device(roots, &dev_name, bus_number, address) {
                Ok(device) => report.devices.push(device),
                Err(reason) => report.skipped.push(SkippedEntry { dev_name, reason }),
            }
        }
    }

    report
}

/// AOSP `contains_non_digit()` (`usb_linux.cpp:115-120`), inverted.
fn is_decimal_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())
}

/// Resolve one node into a [`ScannedDevice`].
///
/// This is the injectable counterpart of `process_usb_device()`
/// (`usb_linux.cpp:153-312`): dedupe is handled by the caller, descriptor
/// parsing is replaced by the sysfs projection, and every failure is a
/// [`SkipReason`].
pub fn probe_device(
    roots: &ScanRoots,
    dev_name: &str,
    bus_number: u8,
    address: u8,
) -> Result<ScannedDevice, SkipReason> {
    // AOSP opens the node and retries EACCES three times (`usb_linux.cpp:128-151`).
    // The scan slice cannot read descriptors from the node, but it must still
    // notice an inaccessible node instead of inventing a device.
    fs::metadata(dev_name).map_err(|_| SkipReason::DeviceNodeUnreadable)?;

    let (sysfs_name, sysfs_dir) = find_sysfs_device(roots, bus_number, address)
        .ok_or(SkipReason::SysfsDeviceNotFound)?;

    let vendor_id = read_hex(&sysfs_dir.join("idVendor"))
        .ok()
        .and_then(|v| u16::try_from(v).ok());
    let product_id = read_hex(&sysfs_dir.join("idProduct"))
        .ok()
        .and_then(|v| u16::try_from(v).ok());
    let serial = read_serial(&sysfs_dir);

    let interfaces = read_interfaces(&sysfs_dir)?;

    let mut adb: Option<&UsbInterface> = None;
    let mut adb_bad_endpoints: Option<String> = None;
    let mut fastboot: Option<&UsbInterface> = None;

    for iface in &interfaces {
        match iface.kind() {
            Some(UsbInterfaceKind::Adb) => {
                // `usb_linux.cpp:221`: an ADB-looking interface is only usable
                // when it exposes exactly two endpoints (bulk IN + bulk OUT).
                if iface.num_endpoints == 2 {
                    if adb.is_none() {
                        adb = Some(iface);
                    }
                } else if adb_bad_endpoints.is_none() {
                    adb_bad_endpoints = Some(iface.name.clone());
                }
            }
            Some(UsbInterfaceKind::Fastboot) => {
                if fastboot.is_none() {
                    fastboot = Some(iface);
                }
            }
            None => {}
        }
    }

    let kind = match (adb, fastboot) {
        (Some(_), _) => UsbInterfaceKind::Adb,
        (None, Some(_)) => UsbInterfaceKind::Fastboot,
        (None, None) => {
            return Err(match adb_bad_endpoints {
                Some(interface) => SkipReason::AdbInterfaceWithoutTwoEndpoints { interface },
                None => SkipReason::NoMatchingInterface,
            })
        }
    };

    Ok(ScannedDevice {
        dev_name: dev_name.to_owned(),
        dev_path: format!("usb:{sysfs_name}"),
        sysfs_name,
        bus_number,
        address,
        vendor_id,
        product_id,
        serial,
        interfaces,
        kind,
    })
}

/// Find the sysfs directory whose `busnum`/`devnum` match the node.
///
/// AOSP derives the name from the character device's
/// `/sys/dev/char/<major>:<minor>` link (`usb_linux.cpp:280-291`); reading
/// `busnum`/`devnum` is the portable equivalent and works identically on a
/// fake tree.  Interface directories (names containing `:`) are not devices.
fn find_sysfs_device(roots: &ScanRoots, bus_number: u8, address: u8) -> Option<(String, PathBuf)> {
    let entries = fs::read_dir(roots.sysfs_devices()).ok()?;
    let mut candidates: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            if name.contains(':') {
                return None;
            }
            Some((name, entry.path()))
        })
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    let want_bus = u32::from(bus_number);
    let want_addr = u32::from(address);
    candidates.into_iter().find(|(_, path)| {
        read_decimal(&path.join("busnum")) == Some(want_bus)
            && read_decimal(&path.join("devnum")) == Some(want_addr)
    })
}

/// Read `serial` the way `register_device()` does (`usb_linux.cpp:546-557`):
/// an unreadable or empty value is not an error.
fn read_serial(sysfs_dir: &Path) -> Option<String> {
    let serial = fs::read_to_string(sysfs_dir.join("serial")).ok()?;
    let serial = serial.trim();
    if serial.is_empty() {
        None
    } else {
        Some(serial.to_owned())
    }
}

/// Read every interface directory of one device.
///
/// A single broken interface does not discard the device: it is recorded in
/// the returned error only when no interface could be read at all.
fn read_interfaces(sysfs_dir: &Path) -> Result<Vec<UsbInterface>, SkipReason> {
    let entries = fs::read_dir(sysfs_dir).map_err(|_| SkipReason::SysfsAttributeUnreadable {
        attribute: "bInterfaceClass".to_owned(),
    })?;

    let mut dirs: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            if !name.contains(':') {
                return None;
            }
            Some((name, entry.path()))
        })
        .collect();
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut interfaces = Vec::new();
    let mut broken: Option<String> = None;

    for (name, dir) in dirs {
        let class = match read_hex(&dir.join("bInterfaceClass")) {
            Ok(v) => v as u8,
            Err(_) => {
                broken.get_or_insert("bInterfaceClass".to_owned());
                continue;
            }
        };
        let subclass = match read_hex(&dir.join("bInterfaceSubClass")) {
            Ok(v) => v as u8,
            Err(_) => {
                broken.get_or_insert("bInterfaceSubClass".to_owned());
                continue;
            }
        };
        let protocol = match read_hex(&dir.join("bInterfaceProtocol")) {
            Ok(v) => v as u8,
            Err(_) => {
                broken.get_or_insert("bInterfaceProtocol".to_owned());
                continue;
            }
        };
        let num_endpoints = match read_hex(&dir.join("bNumEndpoints")) {
            Ok(v) => v as u8,
            Err(_) => {
                broken.get_or_insert("bNumEndpoints".to_owned());
                continue;
            }
        };
        let number = read_hex(&dir.join("bInterfaceNumber"))
            .map(|v| v as u8)
            .unwrap_or_else(|_| interface_number_from_name(&name));

        interfaces.push(UsbInterface {
            name,
            number,
            class,
            subclass,
            protocol,
            num_endpoints,
        });
    }

    if interfaces.is_empty() {
        if let Some(attribute) = broken {
            return Err(SkipReason::SysfsAttributeUnreadable { attribute });
        }
    }
    Ok(interfaces)
}

/// Fallback interface number from `1-2:1.3` → `3`.
fn interface_number_from_name(name: &str) -> u8 {
    name.rsplit('.')
        .next()
        .and_then(|n| n.parse::<u8>().ok())
        .unwrap_or(0)
}

fn read_trimmed(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn read_decimal(path: &Path) -> Option<u32> {
    read_trimmed(path).ok()?.parse::<u32>().ok()
}

/// sysfs prints `idVendor`, `bInterfaceClass`, `bNumEndpoints`, … as hex.
fn read_hex(path: &Path) -> io::Result<u32> {
    let raw = read_trimmed(path)?;
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(&raw);
    u32::from_str_radix(digits, 16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

// ---------------------------------------------------------------------------
// Known-device set and diffing
// ---------------------------------------------------------------------------

/// One add/remove transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotplugEvent {
    /// A node that was not known became usable.
    Added(ScannedDevice),
    /// A known node disappeared.
    Removed(ScannedDevice),
}

/// Result of one [`HotplugTracker::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tick {
    /// Monotonic tick counter (1-based).
    pub generation: u64,
    /// Devices registered by this tick.
    pub added: Vec<ScannedDevice>,
    /// Devices unregistered because their node vanished.
    pub removed: Vec<ScannedDevice>,
    /// Names of known devices that are still present (including devices that
    /// could not be re-identified this round).
    pub kept: Vec<String>,
    /// Nodes skipped during this scan.
    pub skipped: Vec<SkippedEntry>,
    /// Set when the bus root could not be read at all.
    pub root_error: Option<String>,
    /// Whether the scan was complete.  Removals are only applied when `true`.
    pub complete: bool,
}

impl Tick {
    /// Added events followed by removed events.
    pub fn events(&self) -> Vec<HotplugEvent> {
        self.added
            .iter()
            .cloned()
            .map(HotplugEvent::Added)
            .chain(self.removed.iter().cloned().map(HotplugEvent::Removed))
            .collect()
    }
}

/// Outcome of processing a single node (`process_usb_device()` equivalent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Already in the known set (`usb_linux.cpp:158-161`).
    AlreadyKnown,
    /// Newly registered.
    Added(ScannedDevice),
    /// Not identified; nothing registered.
    Skipped(SkippedEntry),
    /// The node does not exist (e.g. an unplug event raced the scan).
    NotPresent,
}

/// The known-device set plus the scan roots it diffs.
///
/// AOSP keeps `g_usb_handles` under a mutex and marks handles alive inside
/// `is_known_device()` (`usb_linux.cpp:103-113`); the same state is kept here,
/// but the "still alive" decision is made from the node list of a *complete*
/// scan, so a transient `EACCES` cannot unregister a working device.
#[derive(Debug)]
pub struct HotplugTracker {
    roots: ScanRoots,
    known: BTreeMap<String, KnownDevice>,
    generation: u64,
    scans: u64,
}

#[derive(Debug)]
struct KnownDevice {
    device: ScannedDevice,
    last_seen: u64,
    added_at: u64,
}

impl HotplugTracker {
    /// Create a tracker over the given roots.
    pub fn new(roots: ScanRoots) -> Self {
        Self {
            roots,
            known: BTreeMap::new(),
            generation: 0,
            scans: 0,
        }
    }

    /// Roots this tracker scans.
    pub fn roots(&self) -> &ScanRoots {
        &self.roots
    }

    /// AOSP `is_known_device()`: look the node up and mark it alive.
    ///
    /// Returns `true` when the node is already registered.
    pub fn is_known_device(&mut self, dev_name: &str) -> bool {
        match self.known.get_mut(dev_name) {
            Some(known) => {
                known.last_seen = self.generation;
                true
            }
            None => false,
        }
    }

    /// AOSP `register_device()` dedupe (`usb_linux.cpp:572-578`).
    ///
    /// Returns `false` when the node was already known; the stored record is
    /// refreshed either way so a re-scan picks up a new serial or interface set.
    pub fn register_device(&mut self, device: ScannedDevice) -> bool {
        match self.known.get_mut(&device.dev_name) {
            Some(known) => {
                known.device = device;
                known.last_seen = self.generation;
                false
            }
            None => {
                let dev_name = device.dev_name.clone();
                self.known.insert(
                    dev_name,
                    KnownDevice {
                        device,
                        last_seen: self.generation,
                        added_at: self.generation,
                    },
                );
                true
            }
        }
    }

    /// Process one node, as a netlink `add` event would (`usb_linux.cpp:700-703`).
    ///
    /// The argument may be an absolute node path or a `<bus>/<addr>` suffix
    /// relative to [`ScanRoots::dev_usb`].
    pub fn process_usb_device(&mut self, dev_name: &str) -> ProcessOutcome {
        let node = self.normalize_dev_name(dev_name);
        if self.is_known_device(&node) {
            return ProcessOutcome::AlreadyKnown;
        }
        let Some((bus_number, address)) = bus_addr_from_node(&self.roots, &node) else {
            return ProcessOutcome::NotPresent;
        };
        if fs::metadata(&node).is_err() {
            return ProcessOutcome::NotPresent;
        }
        match probe_device(&self.roots, &node, bus_number, address) {
            Ok(device) => {
                self.register_device(device.clone());
                ProcessOutcome::Added(device)
            }
            Err(reason) => ProcessOutcome::Skipped(SkippedEntry {
                dev_name: node,
                reason,
            }),
        }
    }

    /// One poll iteration: scan, register new devices, unregister vanished ones.
    ///
    /// This is the testable core of `device_poll_thread()`: the initial scan
    /// (`usb_linux.cpp:658`) and every netlink add/remove (`:700-716`) collapse
    /// into a single diff over the same directory walk.
    pub fn tick(&mut self) -> Tick {
        self.generation += 1;
        self.scans += 1;
        let generation = self.generation;

        let report = scan_usb_devices(&self.roots);
        let present: BTreeSet<String> = report.present_dev_nodes.iter().cloned().collect();

        let mut added = Vec::new();
        for device in report.devices {
            match self.known.get_mut(&device.dev_name) {
                Some(known) => {
                    known.device = device;
                    known.last_seen = generation;
                }
                None => {
                    let dev_name = device.dev_name.clone();
                    self.known.insert(
                        dev_name,
                        KnownDevice {
                            device: device.clone(),
                            last_seen: generation,
                            added_at: generation,
                        },
                    );
                    added.push(device);
                }
            }
        }

        let mut removed = Vec::new();
        if report.complete {
            let gone: Vec<String> = self
                .known
                .keys()
                .filter(|name| !present.contains(*name))
                .cloned()
                .collect();
            for name in gone {
                if let Some(known) = self.known.remove(&name) {
                    removed.push(known.device);
                }
            }
        }

        Tick {
            generation,
            added,
            removed,
            kept: self.known.keys().cloned().collect(),
            skipped: report.skipped,
            root_error: report.root_error,
            complete: report.complete,
        }
    }

    /// [`Self::tick`] plus an event callback, in scan order.
    pub fn tick_with<F>(&mut self, mut on_event: F) -> Tick
    where
        F: FnMut(&HotplugEvent),
    {
        let tick = self.tick();
        for event in tick.events() {
            on_event(&event);
        }
        tick
    }

    /// Number of registered devices.
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// Registered devices, sorted by node name.
    pub fn known_devices(&self) -> impl Iterator<Item = &ScannedDevice> {
        self.known.values().map(|k| &k.device)
    }

    /// Recorded device for a node, if known.
    pub fn known(&self, dev_name: &str) -> Option<&ScannedDevice> {
        self.known.get(dev_name).map(|k| &k.device)
    }

    /// Tick generation of a known device (`None` if unknown).
    pub fn added_at(&self, dev_name: &str) -> Option<u64> {
        self.known.get(dev_name).map(|k| k.added_at)
    }

    /// Current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of ticks executed.
    pub fn scans(&self) -> u64 {
        self.scans
    }

    fn normalize_dev_name(&self, dev_name: &str) -> String {
        let path = Path::new(dev_name);
        if path.is_absolute() {
            path.to_string_lossy().into_owned()
        } else {
            self.roots.dev_usb().join(path).to_string_lossy().into_owned()
        }
    }
}

/// Extract `(bus, addr)` from the last two path components when both are
/// numeric, matching the `/dev/bus/usb/<bus>/<addr>` layout.
fn bus_addr_from_node(roots: &ScanRoots, node: &str) -> Option<(u8, u8)> {
    let path = Path::new(node);
    if !path.starts_with(roots.dev_usb()) {
        return None;
    }
    let addr = path.file_name()?.to_str()?;
    let bus = path.parent()?.file_name()?.to_str()?;
    if !is_decimal_name(addr) || !is_decimal_name(bus) {
        return None;
    }
    Some((bus.parse().ok()?, addr.parse().ok()?))
}

// ---------------------------------------------------------------------------
// Thin thread shell (not exercised by offline tests)
// ---------------------------------------------------------------------------

/// Polling loop around [`HotplugTracker::tick`].
///
/// `device_poll_thread()` blocks on netlink (`usb_linux.cpp:674-717`); this
/// port has no netlink socket, so the wrapper polls on an interval instead.
/// The wrapper is intentionally thin: every decision lives in `tick`.
pub struct PollThread {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PollThread {
    /// Spawn the polling loop.  `on_event` runs on the polling thread.
    pub fn spawn<F>(
        tracker: Arc<Mutex<HotplugTracker>>,
        interval: Duration,
        mut on_event: F,
    ) -> Self
    where
        F: FnMut(HotplugEvent) + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let slice = interval.min(Duration::from_millis(50));
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                let events = {
                    let mut tracker = match tracker.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    tracker.tick().events()
                };
                for event in events {
                    on_event(event);
                }
                let mut slept = Duration::ZERO;
                while slept < interval && !stop_flag.load(Ordering::Relaxed) {
                    thread::sleep(slice);
                    slept += slice;
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Ask the loop to stop and join it.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PollThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
