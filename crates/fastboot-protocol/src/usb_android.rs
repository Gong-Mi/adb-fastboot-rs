//! Pure Rust Android/Linux usbfs backend for Fastboot.
//!
//! No external native dependencies: only `open`, `read`, `ioctl` from the
//! Linux usbfs layer.  This backend does not use `rusb` at all.
//!
//! Device discovery iterates `/dev/bus/usb/<bus>/<addr>`, reads raw USB
//! descriptors via `read(fd, buf, size)`, and parses them with
//! [`parse_fastboot_interface_descriptors`].
//!
//! Serial numbers are read from `/sys/bus/usb/devices/<name>/serial`.
//!
//! Fastboot uses interface class ff/42/03 and does **not** require zero-length
//! packets (ZLP).  Bulk reads/writes follow AOSP's chunking: 16 KiB read cap,
//! 256 KiB write cap.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read as _};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::time::Duration;

use crate::usb::{
    BulkIo, UsbDescriptor, UsbEndpointDirection, UsbEndpointInfo, UsbTransportError,
};

// ---------------------------------------------------------------------------
// Ioctl helpers — computed from the kernel `_IO`/`_IOR`/`_IOWR` macros.
// Type byte is 'U' (0x55). Size argument is the Rust struct size on
// AArch64 (page 4 / 4 byte scalar → zero padding; 8 byte pointer → 8‑byte
// alignment).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const IOC_NONE: u32 = 0;
const IOC_READ: u32 = 2;
#[allow(dead_code)]
const IOC_WRITE: u32 = 1;
const IOC_READWRITE: u32 = 3;

#[inline(always)]
const fn ioc(dir: u32, typ: u8, nr: u8, size: usize) -> u32 {
    (dir << 30) | ((size as u32) << 16) | ((typ as u32) << 8) | (nr as u32)
}

#[inline(always)]
const fn _io(typ: u8, nr: u8) -> u32 {
    ioc(IOC_NONE, typ, nr, 0)
}
#[inline(always)]
const fn _ior(typ: u8, nr: u8, size: usize) -> u32 {
    ioc(IOC_READ, typ, nr, size)
}
#[inline(always)]
const fn _iowr(typ: u8, nr: u8, size: usize) -> u32 {
    ioc(IOC_READWRITE, typ, nr, size)
}

const T: u8 = b'U'; // USBDEVFS magic

// ---- struct layouts (AArch64) --------------------------------------------

/// Matches `struct usbdevfs_bulktransfer` in `<linux/usbdevice_fs.h>`.
#[repr(C)]
struct UsbdevfsBulkTransfer {
    ep: u32,
    len: u32,
    timeout: u32,
    _pad: u32,       // padding so that `data` is 8‑byte aligned
    data: *mut u8,
}

const _: () = assert!(std::mem::size_of::<UsbdevfsBulkTransfer>() == 24);

/// Matches `struct usbdevfs_setinterface`.
#[repr(C)]
struct UsbdevfsSetInterface {
    interface: u32,
    altsetting: u32,
}

const _: () = assert!(std::mem::size_of::<UsbdevfsSetInterface>() == 8);

/// Matches `struct usbdevfs_disconnect_claim`.
#[repr(C)]
struct UsbdevfsDisconnectClaim {
    interface: u32,
    flags: u32,
    driver: [u8; 256],
}

// ---- ioctl numbers -------------------------------------------------------

const USBDEVFS_BULK: u32 = _iowr(T, 2, std::mem::size_of::<UsbdevfsBulkTransfer>());
const USBDEVFS_SETINTERFACE: u32 = _ior(T, 4, std::mem::size_of::<UsbdevfsSetInterface>());
const USBDEVFS_DISCONNECT_CLAIM: u32 =
    _ior(T, 27, std::mem::size_of::<UsbdevfsDisconnectClaim>());
const USBDEVFS_CLAIMINTERFACE: u32 = _ior(T, 15, 4);
#[allow(dead_code)]
const USBDEVFS_RELEASEINTERFACE: u32 = _ior(T, 16, 4);
#[allow(dead_code)]
const USBDEVFS_RESET: u32 = _io(T, 20);
#[allow(dead_code)]
const USBDEVFS_CLEAR_HALT: u32 = _ior(T, 21, 4);

// ---- ioctl wrappers ------------------------------------------------------

unsafe fn usbdevfs_ioctl<T>(fd: RawFd, request: u32, arg: *mut T) -> io::Result<i32> {
    #[cfg(target_os = "android")]
    let req: libc::c_int = request as libc::c_int;
    #[cfg(not(target_os = "android"))]
    let req: libc::c_ulong = request as libc::c_ulong;
    let rc = libc::ioctl(fd, req, arg);
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

unsafe fn usbdevfs_ioctl_val(fd: RawFd, request: u32, val: u32) -> io::Result<i32> {
    let v = val as libc::c_int;
    #[cfg(target_os = "android")]
    let req: libc::c_int = request as libc::c_int;
    #[cfg(not(target_os = "android"))]
    let req: libc::c_ulong = request as libc::c_ulong;
    let rc = libc::ioctl(fd, req, &v as *const libc::c_int);
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

// ---------------------------------------------------------------------------
// Raw sysfs device path helpers
// ---------------------------------------------------------------------------

/// Read a sysfs attribute file into a trimmed String.
fn read_sysfs_attr(dir: &std::path::Path, attr: &str) -> Option<String> {
    let path = dir.join(attr);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

// ---------------------------------------------------------------------------
// Fastboot-specific descriptor parser (ff/42/03)
// ---------------------------------------------------------------------------

const INTERFACE_DESCRIPTOR: u8 = 0x04;
const ENDPOINT_DESCRIPTOR: u8 = 0x05;
const BULK_TRANSFER_TYPE: u8 = 0x02;
const USB_DIRECTION_IN: u8 = 0x80;

/// Parse raw active-configuration USB descriptors and return the first
/// complete Fastboot (ff/42/03) interface with bulk IN and OUT endpoints.
///
/// This follows the same pattern as `parse_adb_interface_descriptors` from
/// `adb-protocol`, but targets protocol=0x03 (Fastboot) instead of 0x01 (ADB).
fn parse_fastboot_interface_descriptors(
    descriptors: &[u8],
) -> Result<UsbDescriptor, UsbTransportError> {
    let mut offset = 0;
    let mut candidate: Option<(
        u8,               // interface_number
        u8,               // alternate_setting
        Option<(u8, u16)>, // bulk_in (address, max_packet_size)
        Option<(u8, u16)>, // bulk_out (address, max_packet_size)
        Option<u16>,       // consistent max_packet_size across endpoints
    )> = None;

    while offset < descriptors.len() {
        if descriptors.len() - offset < 2 {
            return Err(UsbTransportError::InvalidDescriptor {
                reason: "descriptor header is truncated".into(),
            });
        }
        let length = descriptors[offset] as usize;
        if length < 2 || offset + length > descriptors.len() {
            return Err(UsbTransportError::InvalidDescriptor {
                reason: "invalid descriptor length".into(),
            });
        }
        let desc = &descriptors[offset..offset + length];
        match desc[1] {
            INTERFACE_DESCRIPTOR => {
                if length < 9 {
                    return Err(UsbTransportError::InvalidDescriptor {
                        reason: "interface descriptor shorter than 9 bytes".into(),
                    });
                }
                // If we already have a candidate that's complete, emit it.
                if let Some((num, alt, in_ep, out_ep, _ps)) = candidate.take() {
                    if let (Some(in_ep), Some(out_ep)) = (in_ep, out_ep) {
                        return Ok(build_descriptor(num, alt, in_ep, out_ep));
                    }
                    // Incomplete candidate — discard and continue scanning.
                }
                // Check for Fastboot interface (ff/42/03).
                if desc[5] == 0xff && desc[6] == 0x42 && desc[7] == 0x03 {
                    candidate = Some((desc[2], desc[3], None, None, None));
                }
            }
            ENDPOINT_DESCRIPTOR => {
                if length < 7 {
                    return Err(UsbTransportError::InvalidDescriptor {
                        reason: "endpoint descriptor shorter than 7 bytes".into(),
                    });
                }
                if let Some((num, _alt, ref mut in_ep, ref mut out_ep, ref mut ps)) = candidate {
                    let address = desc[2];
                    let attributes = desc[3] & 0x03;
                    if attributes == BULK_TRANSFER_TYPE {
                        let size = u16::from_le_bytes([desc[4], desc[5]]);
                        if size == 0 {
                            return Err(UsbTransportError::InvalidDescriptor {
                                reason: format!(
                                    "interface {} has zero bulk endpoint packet size",
                                    num
                                ),
                            });
                        }
                        if let Some(prev) = *ps {
                            if prev != size {
                                return Err(UsbTransportError::InvalidDescriptor {
                                    reason: format!(
                                        "interface {} has inconsistent bulk endpoint packet sizes",
                                        num
                                    ),
                                });
                            }
                        } else {
                            *ps = Some(size);
                        }
                        if address & USB_DIRECTION_IN != 0 {
                            if in_ep.is_none() {
                                *in_ep = Some((address, size));
                            }
                        } else if out_ep.is_none() {
                            *out_ep = Some((address, size));
                        }
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }

    // Final candidate check after finishing descriptor walking.
    if let Some((num, alt, in_ep, out_ep, _ps)) = candidate {
        if let (Some(in_ep), Some(out_ep)) = (in_ep, out_ep) {
            return Ok(build_descriptor(num, alt, in_ep, out_ep));
        }
    }
    Err(UsbTransportError::NoDevice)
}

fn build_descriptor(
    interface_number: u8,
    alternate_setting: u8,
    in_ep: (u8, u16),
    out_ep: (u8, u16),
) -> UsbDescriptor {
    UsbDescriptor {
        interface_number,
        alternate_setting,
        interface_class: 0xff,
        interface_subclass: 0x42,
        interface_protocol: 0x03,
        bulk_in: Some(UsbEndpointInfo {
            address: in_ep.0,
            direction: UsbEndpointDirection::In,
            max_packet_size: in_ep.1,
        }),
        bulk_out: Some(UsbEndpointInfo {
            address: out_ep.0,
            direction: UsbEndpointDirection::Out,
            max_packet_size: out_ep.1,
        }),
    }
}

// ---------------------------------------------------------------------------
// UsbfsFastbootDevice — pure Rust usbfs Fastboot backend
// ---------------------------------------------------------------------------

/// A USB Fastboot device opened directly via the Linux usbfs interface.
///
/// No `rusb` or `libusb` is involved — device access goes through `open()` +
/// `ioctl()` against `/dev/bus/usb/...`.
pub struct UsbfsFastbootDevice {
    fd: File,
    descriptor: UsbDescriptor,
    serial: Option<String>,
    bus_number: u8,
    address: u8,
    timeout: Duration,
}

impl std::fmt::Debug for UsbfsFastbootDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbfsFastbootDevice")
            .field("bus_number", &self.bus_number)
            .field("address", &self.address)
            .field("serial", &self.serial)
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

impl UsbfsFastbootDevice {
    /// Try to open the first Fastboot USB device found.
    pub fn open_first() -> Result<Self, UsbAndroidError> {
        let candidates = Self::enumerate()?;
        match candidates.len() {
            0 => Err(UsbAndroidError::NoDevice),
            _ => candidates.into_iter().next().unwrap().open(),
        }
    }

    /// Open by a specific serial number string.
    pub fn open_by_serial(serial: &str) -> Result<Self, UsbAndroidError> {
        let candidates = Self::enumerate()?;
        for cand in &candidates {
            if cand.serial.as_deref() == Some(serial) {
                return cand.clone().open();
            }
        }
        Err(UsbAndroidError::NoDevice)
    }

    /// Open by a specific bus:address tuple.
    pub fn open_by_bus_address(
        bus_number: u8,
        address: u8,
    ) -> Result<Self, UsbAndroidError> {
        let dev_path = format!("/dev/bus/usb/{:03}/{:03}", bus_number, address);
        let mut device = Self::open_device_node(&dev_path, bus_number, address)?;
        device.serial = Self::read_serial_from_sysfs(bus_number, address);
        Ok(device)
    }

    /// Enumerate all Fastboot-capable devices visible on usbfs.
    pub fn enumerate() -> Result<Vec<FastbootDeviceCandidate>, UsbAndroidError> {
        let mut candidates = Vec::new();
        let bus_dir = std::path::Path::new("/dev/bus/usb");
        let bus_dir_entries = match fs::read_dir(bus_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(UsbAndroidError::PermissionDenied);
            }
            Err(_) => return Err(UsbAndroidError::NoDevice),
        };

        for bus_entry in bus_dir_entries.flatten() {
            let bus_path = bus_entry.path();
            if !bus_path.is_dir() {
                continue;
            }
            let bus_name = match bus_path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };
            let bus_number: u8 = match bus_name.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let dev_entries = match fs::read_dir(&bus_path) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for dev_entry in dev_entries.flatten() {
                let dev_path = dev_entry.path();
                let addr_name = match dev_path.file_name().and_then(|n| n.to_str()) {
                    Some(name) => name,
                    None => continue,
                };
                let address: u8 = match addr_name.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                let dev_fd = match fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&dev_path)
                {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                // Read raw descriptors from the usbfs device node.
                let mut raw_buf = [0u8; 4096];
                let n = match (&dev_fd).read(&mut raw_buf) {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };

                // Try to parse a Fastboot interface from the raw descriptors.
                match parse_fastboot_interface_descriptors(&raw_buf[..n]) {
                    Ok(descriptor) => {
                        let serial = Self::read_serial_from_sysfs(bus_number, address);
                        candidates.push(FastbootDeviceCandidate {
                            bus_number,
                            address,
                            serial,
                            descriptor,
                        });
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(candidates)
    }

    /// Open a specific device node and claim the Fastboot interface.
    fn open_device_node(
        path: &str,
        bus_number: u8,
        address: u8,
    ) -> Result<Self, UsbAndroidError> {
        let dev_fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .or_else(|_| {
                // Fall back to read-only if O_RDWR fails (AOSP compatibility).
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
            })?;

        let fd = dev_fd.as_raw_fd();

        // Read descriptors again to get endpoint info.
        let mut raw_buf = [0u8; 4096];
        let n = (&dev_fd).read(&mut raw_buf)?;
        let descriptor = parse_fastboot_interface_descriptors(&raw_buf[..n])
            .map_err(|e| UsbAndroidError::Descriptor(e))?;

        // Validate the descriptor before claiming.
        descriptor
            .validate()
            .map_err(|e| UsbAndroidError::Descriptor(e))?;

        // Claim interface using disconnect-claim (unbinds kernel drivers first).
        let mut disc = UsbdevfsDisconnectClaim {
            interface: descriptor.interface_number as u32,
            flags: 0,
            driver: [0u8; 256],
        };
        let disc_rc =
            unsafe { usbdevfs_ioctl(fd, USBDEVFS_DISCONNECT_CLAIM, &mut disc as *mut _) };
        if disc_rc.is_err() {
            // Fallback: direct claim.
            unsafe {
                usbdevfs_ioctl_val(
                    fd,
                    USBDEVFS_CLAIMINTERFACE,
                    descriptor.interface_number as u32,
                )?;
            }
        }

        // Set alternate setting if non-zero (Fastboot often uses alternate).
        if descriptor.alternate_setting != 0 {
            let mut si = UsbdevfsSetInterface {
                interface: descriptor.interface_number as u32,
                altsetting: descriptor.alternate_setting as u32,
            };
            unsafe { usbdevfs_ioctl(fd, USBDEVFS_SETINTERFACE, &mut si as *mut _)? };
        }

        Ok(Self {
            fd: dev_fd,
            descriptor,
            serial: Self::read_serial_from_sysfs(bus_number, address),
            bus_number,
            address,
            timeout: Duration::from_secs(10),
        })
    }

    /// Read the serial number from sysfs.
    fn read_serial_from_sysfs(bus: u8, addr: u8) -> Option<String> {
        let sysfs_dir = std::path::Path::new("/sys/bus/usb/devices");
        let dir_entries = fs::read_dir(sysfs_dir).ok()?;

        for entry in dir_entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path.file_name()?.to_str()?;
            // Skip interfaces (e.g. "1-1:1.0") and host controllers (e.g. "usb1").
            if file_name.contains(':') || file_name.starts_with("usb") {
                continue;
            }
            let e_bus = read_sysfs_attr(&entry_path, "busnum")?;
            let e_dev = read_sysfs_attr(&entry_path, "devnum")?;
            if e_bus == bus.to_string() && e_dev == addr.to_string() {
                return read_sysfs_attr(&entry_path, "serial");
            }
        }
        None
    }

    /// Set the I/O timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Bus number.
    pub fn bus_number(&self) -> u8 {
        self.bus_number
    }
    /// Device address on the bus.
    pub fn address(&self) -> u8 {
        self.address
    }
    /// Serial number string, if available.
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Construct the existing `Read`/`Write` transport boundary over usbfs.
    pub fn open_transport() -> Result<super::FastbootUsbTransport<Self>, UsbTransportError> {
        let dev = Self::open_first().map_err(|e| UsbTransportError::Backend {
            operation: "open",
            message: e.to_string(),
        })?;
        super::FastbootUsbTransport::new(dev)
    }
}

// ---------------------------------------------------------------------------
// BulkIo implementation — no ZLP, short read/write allowed per AOSP
// ---------------------------------------------------------------------------

// One implementation builds the real ioctl request and interprets its result.
// Tests replace only the syscall, below BulkIo; descriptor/length/timeout and
// the production backend-to-Read/Write adapter paths remain unchanged.
impl UsbfsFastbootDevice {
    fn bulk_read_with<F>(
        &mut self,
        endpoint: UsbEndpointInfo,
        buf: &mut [u8],
        mut ioctl: F,
    ) -> Result<usize, UsbTransportError>
    where
        F: FnMut(RawFd, &mut UsbdevfsBulkTransfer) -> io::Result<i32>,
    {
        if endpoint.direction != UsbEndpointDirection::In {
            return Err(UsbTransportError::InvalidDescriptor {
                reason: "bulk read endpoint is not IN".into(),
            });
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let timeout_ms = self.timeout.as_millis().min(u32::MAX as u128) as u32;
        let len = buf.len().min(16 * 1024); // AOSP read cap: 16 KiB
        let mut bulk = UsbdevfsBulkTransfer {
            ep: endpoint.address as u32,
            len: len as u32,
            timeout: timeout_ms,
            _pad: 0,
            data: buf.as_mut_ptr(),
        };
        let rc = ioctl(self.fd.as_raw_fd(), &mut bulk);
        match rc {
            Ok(count) => checked_bulk_count(count, len),
            Err(e) => Err(map_io_error(e)),
        }
    }

    fn bulk_write_with<F>(
        &mut self,
        endpoint: UsbEndpointInfo,
        buf: &[u8],
        mut ioctl: F,
    ) -> Result<usize, UsbTransportError>
    where
        F: FnMut(RawFd, &mut UsbdevfsBulkTransfer) -> io::Result<i32>,
    {
        if endpoint.direction != UsbEndpointDirection::Out {
            return Err(UsbTransportError::InvalidDescriptor {
                reason: "bulk write endpoint is not OUT".into(),
            });
        }
        if buf.is_empty() {
            return Ok(0);
        }
        // USBDEVFS_BULK needs a mutable pointer even for writes.
        let timeout_ms = self.timeout.as_millis().min(u32::MAX as u128) as u32;
        let chunk_len = buf.len().min(256 * 1024); // AOSP write cap: 256 KiB
        let mut buf_copy = buf[..chunk_len].to_vec();
        let mut bulk = UsbdevfsBulkTransfer {
            ep: endpoint.address as u32,
            len: buf_copy.len() as u32,
            timeout: timeout_ms,
            _pad: 0,
            data: buf_copy.as_mut_ptr(),
        };
        let rc = ioctl(self.fd.as_raw_fd(), &mut bulk);
        match rc {
            Ok(count) => checked_bulk_count(count, chunk_len),
            Err(e) => Err(map_io_error(e)),
        }
    }
}

// USBDEVFS_BULK returns the actual byte count. The struct's len is the
// requested capacity, not an output count (AOSP usb_linux.cpp Read/Write).
fn checked_bulk_count(count: i32, capacity: usize) -> Result<usize, UsbTransportError> {
    let received = usize::try_from(count).map_err(|_| UsbTransportError::Backend {
        operation: "bulk transfer",
        message: format!("usbfs returned negative byte count {count}"),
    })?;
    if received > capacity {
        return Err(UsbTransportError::InvalidTransfer { received, capacity });
    }
    Ok(received)
}

impl BulkIo for UsbfsFastbootDevice {
    fn descriptor(&self) -> &UsbDescriptor {
        &self.descriptor
    }

    fn bulk_read(
        &mut self,
        endpoint: UsbEndpointInfo,
        buf: &mut [u8],
    ) -> Result<usize, UsbTransportError> {
        self.bulk_read_with(endpoint, buf, |fd, bulk| unsafe {
            usbdevfs_ioctl(fd, USBDEVFS_BULK, bulk as *mut _)
        })
    }

    fn bulk_write(
        &mut self,
        endpoint: UsbEndpointInfo,
        buf: &[u8],
    ) -> Result<usize, UsbTransportError> {
        self.bulk_write_with(endpoint, buf, |fd, bulk| unsafe {
            usbdevfs_ioctl(fd, USBDEVFS_BULK, bulk as *mut _)
        })
    }
}

// ---------------------------------------------------------------------------
// FastbootDeviceCandidate
// ---------------------------------------------------------------------------

/// A candidate Fastboot device discovered on the usbfs.
#[derive(Clone, Debug)]
pub struct FastbootDeviceCandidate {
    pub bus_number: u8,
    pub address: u8,
    pub serial: Option<String>,
    #[allow(dead_code)]
    pub(crate) descriptor: UsbDescriptor,
}

impl FastbootDeviceCandidate {
    /// Open this candidate and return a fully‑claimed `UsbfsFastbootDevice`.
    pub fn open(self) -> Result<UsbfsFastbootDevice, UsbAndroidError> {
        let dev_path = format!("/dev/bus/usb/{:03}/{:03}", self.bus_number, self.address);
        UsbfsFastbootDevice::open_device_node(&dev_path, self.bus_number, self.address)
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UsbAndroidError {
    #[error("USB Fastboot device not found")]
    NoDevice,
    #[error("USB permission denied")]
    PermissionDenied,
    #[error("USB descriptor parse error: {0}")]
    Descriptor(#[from] UsbTransportError),
    #[error("USB I/O error: {0}")]
    Io(#[from] io::Error),
}

fn map_io_error(e: io::Error) -> UsbTransportError {
    match e.kind() {
        ErrorKind::PermissionDenied => UsbTransportError::PermissionDenied {
            operation: "bulk transfer",
        },
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UsbTransportError::Timeout {
            operation: "bulk transfer",
        },
        ErrorKind::NotConnected => UsbTransportError::NoDevice,
        ErrorKind::NotFound => UsbTransportError::NoDevice,
        _ => UsbTransportError::Backend {
            operation: "bulk transfer",
            message: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests — syscall injection covers the production request/count boundary;
// physical USB access and kernel/device behaviour remain separate evidence.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bulk_syscall_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{Read, Write};

    fn device() -> UsbfsFastbootDevice {
        UsbfsFastbootDevice {
            // Merely hold a valid fd. Every transfer below replaces the syscall,
            // so these tests never enumerate, claim, or access a USB device.
            fd: File::open("/dev/null").unwrap(),
            descriptor: build_descriptor(2, 1, (0x81, 512), (0x02, 512)),
            serial: Some("injected-only".into()),
            bus_number: 0,
            address: 0,
            timeout: Duration::from_millis(123),
        }
    }

    #[test]
    fn bulk_read_uses_syscall_count_and_preserves_unread_bytes() {
        let mut device = device();
        let endpoint = device.descriptor.bulk_in.unwrap();
        let mut buf = [0xa5; 64];
        let n = device.bulk_read_with(endpoint, &mut buf, |_, request| {
            assert_eq!(request.ep, 0x81);
            assert_eq!(request.len, 64);
            assert_eq!(request.timeout, 123);
            unsafe { std::ptr::copy_nonoverlapping(b"abc".as_ptr(), request.data, 3) };
            // usbfs leaves the requested length intact and returns the actual n.
            Ok(3)
        }).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"abc");
        assert!(buf[n..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn bulk_write_uses_syscall_count_not_request_length() {
        let mut device = device();
        let endpoint = device.descriptor.bulk_out.unwrap();
        let n = device.bulk_write_with(endpoint, b"abcdef", |_, request| {
            assert_eq!(request.ep, 0x02);
            assert_eq!(request.len, 6);
            assert_eq!(request.timeout, 123);
            let data = unsafe { std::slice::from_raw_parts(request.data, request.len as usize) };
            assert_eq!(data, b"abcdef");
            Ok(2)
        }).unwrap();
        assert_eq!(n, 2);
    }

    struct InjectedBackend {
        device: UsbfsFastbootDevice,
        write_results: VecDeque<Result<i32, i32>>,
        requests: Vec<Vec<u8>>,
        accepted: Vec<u8>,
        reads: VecDeque<Vec<u8>>,
    }

    impl InjectedBackend {
        fn writes(results: impl IntoIterator<Item = Result<i32, i32>>) -> Self {
            Self {
                device: device(), write_results: results.into_iter().collect(),
                requests: Vec::new(), accepted: Vec::new(), reads: VecDeque::new(),
            }
        }
    }

    impl BulkIo for InjectedBackend {
        fn descriptor(&self) -> &UsbDescriptor { &self.device.descriptor }

        fn bulk_read(&mut self, endpoint: UsbEndpointInfo, buf: &mut [u8]) -> Result<usize, UsbTransportError> {
            let bytes = self.reads.pop_front().unwrap_or_default();
            self.device.bulk_read_with(endpoint, buf, |_, request| {
                assert!(bytes.len() <= request.len as usize);
                unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), request.data, bytes.len()) };
                Ok(bytes.len() as i32)
            })
        }

        fn bulk_write(&mut self, endpoint: UsbEndpointInfo, buf: &[u8]) -> Result<usize, UsbTransportError> {
            let outcome = self.write_results.pop_front().expect("unexpected extra ioctl");
            let requests = &mut self.requests;
            let accepted = &mut self.accepted;
            self.device.bulk_write_with(endpoint, buf, |_, request| {
                let bytes = unsafe { std::slice::from_raw_parts(request.data, request.len as usize) };
                requests.push(bytes.to_vec());
                match outcome {
                    Ok(n) => {
                        if n >= 0 && n as usize <= bytes.len() { accepted.extend_from_slice(&bytes[..n as usize]); }
                        Ok(n)
                    }
                    Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                }
            })
        }
    }

    #[test]
    fn adapter_retries_only_unwritten_suffix_using_real_backend_count_logic() {
        let backend = InjectedBackend::writes([Ok(2), Ok(1), Ok(3)]);
        let mut transport = crate::FastbootUsbTransport::new(backend).unwrap();
        transport.write_all(b"abcdef").unwrap();
        let backend = transport.into_inner();
        assert_eq!(backend.requests, [b"abcdef".to_vec(), b"cdef".to_vec(), b"def".to_vec()]);
        assert_eq!(backend.accepted, b"abcdef");
        assert!(backend.write_results.is_empty());
    }

    #[test]
    fn adapter_zero_write_and_error_after_partial_write_fail_without_extra_io() {
        for outcome in [Ok(0), Err(libc::EIO), Err(libc::ETIMEDOUT), Err(libc::ENODEV), Err(libc::EINTR)] {
            let backend = InjectedBackend::writes([Ok(2), outcome, Ok(4)]);
            let mut transport = crate::FastbootUsbTransport::new(backend).unwrap();
            let error = transport.write_all(b"abcdef").unwrap_err();
            if outcome == Ok(0) { assert_eq!(error.kind(), io::ErrorKind::WriteZero); }
            let backend = transport.into_inner();
            assert_eq!(backend.accepted, b"ab");
            assert_eq!(backend.requests, [b"abcdef".to_vec(), b"cdef".to_vec()]);
            assert_eq!(backend.write_results.len(), 1, "no next transfer after failure");
        }
    }

    #[test]
    fn adapter_short_read_then_zero_is_eof_not_fabricated_data() {
        let mut backend = InjectedBackend::writes([]);
        backend.reads.push_back(b"abc".to_vec());
        backend.reads.push_back(Vec::new());
        let mut transport = crate::FastbootUsbTransport::new(backend).unwrap();
        let mut bytes = [0xa5; 8];
        assert_eq!(transport.read(&mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"abc");
        assert_eq!(&bytes[3..], &[0xa5; 5]);
        assert_eq!(transport.read_exact(&mut bytes).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn syscall_count_is_bounded_by_capped_request_not_caller_buffer() {
        let mut device = device();
        let in_ep = device.descriptor.bulk_in.unwrap();
        let out_ep = device.descriptor.bulk_out.unwrap();
        let mut bytes = vec![0; 32 * 1024];
        let error = device.bulk_read_with(in_ep, &mut bytes, |_, request| {
            assert_eq!(request.len, 16 * 1024);
            Ok(16 * 1024 + 1)
        }).unwrap_err();
        assert_eq!(error, UsbTransportError::InvalidTransfer { received: 16 * 1024 + 1, capacity: 16 * 1024 });
        let error = device.bulk_write_with(out_ep, &vec![0; 512 * 1024], |_, request| {
            assert_eq!(request.len, 256 * 1024);
            Ok(256 * 1024 + 1)
        }).unwrap_err();
        assert_eq!(error, UsbTransportError::InvalidTransfer { received: 256 * 1024 + 1, capacity: 256 * 1024 });
    }

    #[test]
    fn empty_transfers_and_wrong_direction_never_call_ioctl() {
        let mut device = device();
        let in_ep = device.descriptor.bulk_in.unwrap();
        let out_ep = device.descriptor.bulk_out.unwrap();
        assert_eq!(device.bulk_read_with(in_ep, &mut [], |_, _| panic!("empty read ioctl")).unwrap(), 0);
        assert_eq!(device.bulk_write_with(out_ep, &[], |_, _| panic!("empty write ioctl")).unwrap(), 0);
        assert!(device.bulk_read_with(out_ep, &mut [0; 8], |_, _| panic!("wrong-direction ioctl")).is_err());
        assert!(device.bulk_write_with(in_ep, b"data", |_, _| panic!("wrong-direction ioctl")).is_err());
    }

    #[test]
    fn syscall_errors_propagate_without_inventing_a_success_count() {
        let mut device = device();
        let in_ep = device.descriptor.bulk_in.unwrap();
        let out_ep = device.descriptor.bulk_out.unwrap();
        for errno in [libc::EACCES, libc::ETIMEDOUT, libc::EAGAIN, libc::ENODEV, libc::EINTR, libc::EIO] {
            assert!(device.bulk_read_with(in_ep, &mut [0; 64], |_, _| Err(io::Error::from_raw_os_error(errno))).is_err());
            assert!(device.bulk_write_with(out_ep, b"payload", |_, _| Err(io::Error::from_raw_os_error(errno))).is_err());
        }
        assert!(device.bulk_read_with(in_ep, &mut [0; 64], |_, _| Ok(-1)).is_err());
        assert!(device.bulk_write_with(out_ep, b"payload", |_, _| Ok(-1)).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usbdevfs_bulktransfer_layout() {
        assert_eq!(std::mem::size_of::<UsbdevfsBulkTransfer>(), 24);
        assert_eq!(std::mem::align_of::<UsbdevfsBulkTransfer>(), 8);
    }

    #[test]
    fn usbdevfs_setinterface_layout() {
        assert_eq!(std::mem::size_of::<UsbdevfsSetInterface>(), 8);
    }

    #[test]
    fn ioctl_constants_are_well_formed() {
        assert!(USBDEVFS_BULK != 0);
        assert!(USBDEVFS_SETINTERFACE != 0);
        assert!(USBDEVFS_CLAIMINTERFACE != 0);
        assert!(USBDEVFS_RELEASEINTERFACE != 0);
        assert!(USBDEVFS_RESET != 0);
        assert!(USBDEVFS_CLEAR_HALT != 0);
    }

    /// A valid Fastboot (ff/42/03) descriptor blob with bulk IN and OUT.
    fn fastboot_descriptor_bytes() -> Vec<u8> {
        vec![
            9, 0x04, 2, 1, 2, 0xff, 0x42, 0x03, 0, // interface
            7, 0x05, 0x81, 0x02, 0x00, 0x02, 0, // bulk IN  (0x81, 512)
            7, 0x05, 0x02, 0x02, 0x00, 0x02, 0, // bulk OUT (0x02, 512)
        ]
    }

    #[test]
    fn parses_fastboot_descriptor() {
        let desc = parse_fastboot_interface_descriptors(&fastboot_descriptor_bytes()).unwrap();
        assert_eq!(desc.interface_number, 2);
        assert_eq!(desc.alternate_setting, 1);
        assert_eq!(desc.interface_class, 0xff);
        assert_eq!(desc.interface_subclass, 0x42);
        assert_eq!(desc.interface_protocol, 0x03);
        assert_eq!(desc.bulk_in.unwrap().address, 0x81);
        assert_eq!(desc.bulk_out.unwrap().address, 0x02);
        assert!(desc.validate().is_ok());
    }

    #[test]
    fn rejects_non_fastboot_descriptor() {
        // Same class/subclass but wrong protocol (0x01 = ADB, not Fastboot).
        let raw = vec![
            9, 0x04, 0, 0, 2, 0xff, 0x42, 0x01, 0,
            7, 0x05, 0x81, 0x02, 0x40, 0, 0,
            7, 0x05, 0x02, 0x02, 0x40, 0, 0,
        ];
        assert!(parse_fastboot_interface_descriptors(&raw).is_err());
    }

    #[test]
    fn rejects_incomplete_descriptor() {
        // Interface with ff/42/03 but only one bulk endpoint.
        // (missing OUT — our parser will never emit a one-endpoint descriptor)
        let raw = vec![
            9, 0x04, 0, 0, 1, 0xff, 0x42, 0x03, 0,
            7, 0x05, 0x81, 0x02, 0x40, 0, 0,
        ];
        assert!(parse_fastboot_interface_descriptors(&raw).is_err());
    }

    #[test]
    fn validates_complete_candidate_descriptor() {
        let desc = parse_fastboot_interface_descriptors(&fastboot_descriptor_bytes()).unwrap();
        assert!(desc.validate().is_ok());
    }

    #[test]
    fn candidate_selects_correct_descriptor_among_multiple() {
        // Two interfaces: first non-Fastboot, second Fastboot.
        let raw = vec![
            // Non-Fastboot interface (0xff/0x00/0x00)
            9, 0x04, 0, 0, 2, 0xff, 0x00, 0x00, 0,
            7, 0x05, 0x81, 0x02, 0x40, 0, 0,
            7, 0x05, 0x02, 0x02, 0x40, 0, 0,
            // Fastboot interface (0xff/0x42/0x03)
            9, 0x04, 1, 0, 2, 0xff, 0x42, 0x03, 0,
            7, 0x05, 0x83, 0x02, 0x00, 0x02, 0,
            7, 0x05, 0x04, 0x02, 0x00, 0x02, 0,
        ];
        let desc = parse_fastboot_interface_descriptors(&raw).unwrap();
        assert_eq!(desc.interface_number, 1);
        assert_eq!(desc.bulk_in.unwrap().address, 0x83);
        assert_eq!(desc.bulk_out.unwrap().address, 0x04);
    }
}
