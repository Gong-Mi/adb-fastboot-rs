//! Pure Rust Android/Linux usbfs backend for ADB.
//!
//! No external native dependencies: only `open`, `read`, `write`, `ioctl`,
//! `lseek`, `close`, and `getpagegroups` from the Android / Linux usbfs layer.
//!
//! Device discovery iterates `/dev/bus/usb/<bus>/<addr>`, reads raw USB
//! descriptors via `read(fd, buf, size)`, and parses them with the
//! backend‑neutral [`parse_adb_interface_descriptors`].
//!
//! Serial numbers are read from `/sys/bus/usb/devices/<name>/serial`.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read as _};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::time::Duration;

use crate::usb::{
    parse_adb_interface_descriptors, UsbEndpointInfo, UsbTransport,
    UsbTransportError,
};
// (transport trait not used here – adapter is in usb.rs)

// ---------------------------------------------------------------------------
// Ioctl helpers — computed from the kernel `_IO`/`_IOR`/`_IOWR` macros.
// Type byte is 'U' (0x55). Size argument is the Rust struct size on
// AArch64 (page 4 / 4 byte scalar → zero padding; 8 byte pointer → 8‑byte
// alignment).
// ---------------------------------------------------------------------------

const IOC_READ: u32 = 2;
const IOC_READWRITE: u32 = 3;

#[inline(always)]
const fn ioc(dir: u32, typ: u8, nr: u8, size: usize) -> u32 {
    (dir << 30) | ((size as u32) << 16) | ((typ as u32) << 8) | (nr as u32)
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



// ---- ioctl numbers -------------------------------------------------------

const USBDEVFS_BULK: u32 = _iowr(T, 2, std::mem::size_of::<UsbdevfsBulkTransfer>());
/// Matches `struct usbdevfs_disconnect_claim`.
#[repr(C)]
struct UsbdevfsDisconnectClaim {
    interface: u32,
    flags: u32,
    driver: [u8; 256],
}

const USBDEVFS_DISCONNECT_CLAIM: u32 = _ior(T, 27, std::mem::size_of::<UsbdevfsDisconnectClaim>());
const USBDEVFS_CLAIMINTERFACE: u32 = _ior(T, 15, 4);

// ---- ioctl numbers -------------------------------------------------------

unsafe fn usbdevfs_ioctl<T>(fd: RawFd, request: u32, arg: *mut T) -> io::Result<i32> {
    let rc = libc::ioctl(fd, request as libc::c_int, arg);
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

unsafe fn usbdevfs_ioctl_val(fd: RawFd, request: u32, val: u32) -> io::Result<i32> {
    let v = val as libc::c_int;
    let rc = libc::ioctl(fd, request as libc::c_int, &v as *const libc::c_int);
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

// ---------------------------------------------------------------------------
// Raw sysfs device path helpers (following AOSP's pattern)
// ---------------------------------------------------------------------------

/// Read a sysfs attribute file into a trimmed String.
fn read_sysfs_attr(dir: &std::path::Path, attr: &str) -> Option<String> {
    let path = dir.join(attr);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

// ---------------------------------------------------------------------------
// UsbfsAdbDevice – pure Rust usbfs ADB backend
// ---------------------------------------------------------------------------

/// A USB ADB device opened directly via the Linux usbfs interface.
///
/// No `rusb` or `libusb` is involved — device access goes through `open()` +
/// `ioctl()` against `/dev/bus/usb/...`.
pub struct UsbfsAdbDevice {
    fd: File,
    endpoints: UsbEndpointInfo,
    serial: Option<String>,
    bus_number: u8,
    address: u8,
    timeout: Duration,
}

impl std::fmt::Debug for UsbfsAdbDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbfsAdbDevice")
            .field("bus_number", &self.bus_number)
            .field("address", &self.address)
            .field("serial", &self.serial)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

impl UsbfsAdbDevice {
    /// Try to open the first ADB USB device found.
    pub fn open_first() -> Result<Self, UsbAndroidError> {
        let candidates = Self::enumerate()?;
        match candidates.len() {
            0 => Err(UsbAndroidError::NoDevice),
            1 => candidates.into_iter().next().unwrap().open(),
            _ => {
                // If there's exactly one that was accessible for reading
                // descriptors, try it.
                candidates.into_iter().next().unwrap().open()
            }
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
    pub fn open_by_bus_address(bus_number: u8, address: u8) -> Result<Self, UsbAndroidError> {
        let dev_path = format!("/dev/bus/usb/{:03}/{:03}", bus_number, address);
        let mut device = Self::open_device_node(&dev_path, bus_number, address)?;
        device.serial = Self::read_serial_from_sysfs(bus_number, address);
        Ok(device)
    }

    /// Enumerate all ADB-capable devices visible on usbfs.
    pub fn enumerate() -> Result<Vec<DeviceCandidate>, UsbAndroidError> {
        let mut candidates = Vec::new();
        let bus_dir = std::path::Path::new("/dev/bus/usb");
        let bus_dir_entries = match fs::read_dir(bus_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(UsbAndroidError::PermissionDenied)
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

                // Try to parse an ADB interface from the raw descriptors.
                match parse_adb_interface_descriptors(&raw_buf[..n]) {
                    Ok(_) => {
                        let serial = Self::read_serial_from_sysfs(bus_number, address);
                        candidates.push(DeviceCandidate {
                            bus_number,
                            address,
                            serial,
                        });
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(candidates)
    }

    /// Open a specific device node and claim the ADB interface.
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
        let endpoints = parse_adb_interface_descriptors(&raw_buf[..n])
            .map_err(|e| UsbAndroidError::Descriptor(e))?;

        // Claim interface. AOSP also does a driver-detach step, but the
        // simple claim ioctl works on most Android/Linux configurations
        // when the device is not bound to a kernel driver already.
        // Use USBDEVFS_DISCONNECT_CLAIM to unbind kernel drivers first.
        let mut disc = UsbdevfsDisconnectClaim {
            interface: endpoints.interface_number as u32,
            flags: 0,
            driver: [0u8; 256],
        };
        let disc_rc = unsafe { usbdevfs_ioctl(fd, USBDEVFS_DISCONNECT_CLAIM, &mut disc as *mut _) };
        if disc_rc.is_err() {
            // Fallback: direct claim
            unsafe { usbdevfs_ioctl_val(fd, USBDEVFS_CLAIMINTERFACE, endpoints.interface_number as u32)?; }
        }

        Ok(Self {
            fd: dev_fd,
            endpoints,
            serial: Self::read_serial_from_sysfs(bus_number, address),
            bus_number,
            address,
            timeout: Duration::from_secs(10),
        })
    }

    /// Read the serial number from sysfs.
    fn read_serial_from_sysfs(bus: u8, addr: u8) -> Option<String> {
        // The sysfs device path pattern for usbfs is not trivial.
        // AOSP scans /sys/bus/usb/devices and matches busnum+devnum.
        // As a simpler first approach, try common patterns.
        let sysfs_dir = std::path::Path::new("/sys/bus/usb/devices");
        let dir_entries = fs::read_dir(sysfs_dir).ok()?;

        for entry in dir_entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path.file_name()?.to_str()?;
            // Skip interfaces (e.g. "1-1:1.0") and host controllers (e.g. "usb1").
            if file_name.contains(':') || file_name.starts_with("usb") {
                continue;
            }
            // Check busnum and devnum.
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
    pub fn bus_number(&self) -> u8 { self.bus_number }
    /// Device address on the bus.
    pub fn address(&self) -> u8 { self.address }
    /// Serial number string, if available.
    pub fn serial(&self) -> Option<&str> { self.serial.as_deref() }
}

impl UsbTransport for UsbfsAdbDevice {
    fn endpoint_info(&self) -> UsbEndpointInfo {
        self.endpoints
    }

    fn bulk_read(&mut self, endpoint: u8, buffer: &mut [u8]) -> Result<usize, UsbTransportError> {
        let timeout_ms = self.timeout.as_millis().min(u32::MAX as u128) as u32;
        let mut bulk = UsbdevfsBulkTransfer {
            ep: endpoint as u32,
            len: buffer.len() as u32,
            timeout: timeout_ms,
            _pad: 0,
            data: buffer.as_mut_ptr(),
        };
        let rc = unsafe { usbdevfs_ioctl(self.fd.as_raw_fd(), USBDEVFS_BULK, &mut bulk as *mut _) };
        match rc {
            Ok(_) => Ok(bulk.len as usize),
            Err(e) => Err(map_io_error(e)),
        }
    }

    fn bulk_write(&mut self, endpoint: u8, buffer: &[u8]) -> Result<usize, UsbTransportError> {
        // USBDEVFS_BULK needs a mutable pointer even for writes.
        let timeout_ms = self.timeout.as_millis().min(u32::MAX as u128) as u32;
        let mut buf_copy = buffer.to_vec();
        let mut bulk = UsbdevfsBulkTransfer {
            ep: endpoint as u32,
            len: buf_copy.len() as u32,
            timeout: timeout_ms,
            _pad: 0,
            data: buf_copy.as_mut_ptr(),
        };
        let rc = unsafe { usbdevfs_ioctl(self.fd.as_raw_fd(), USBDEVFS_BULK, &mut bulk as *mut _) };
        match rc {
            Ok(_) => Ok(bulk.len as usize),
            Err(e) => Err(map_io_error(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceCandidate
// ---------------------------------------------------------------------------

/// A candidate ADB device discovered on the usbfs.
#[derive(Clone, Debug)]
pub struct DeviceCandidate {
    pub bus_number: u8,
    pub address: u8,
    pub serial: Option<String>,
}

impl DeviceCandidate {
    /// Open this candidate and return a fully‑claimed `UsbfsAdbDevice`.
    pub fn open(self) -> Result<UsbfsAdbDevice, UsbAndroidError> {
        let dev_path = format!("/dev/bus/usb/{:03}/{:03}", self.bus_number, self.address);
        UsbfsAdbDevice::open_device_node(&dev_path, self.bus_number, self.address)
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UsbAndroidError {
    #[error("USB device not found")]
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
        ErrorKind::PermissionDenied => UsbTransportError::PermissionDenied,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UsbTransportError::Timeout,
        ErrorKind::NotConnected => UsbTransportError::Disconnected,
        ErrorKind::NotFound => UsbTransportError::NoDevice,
        _ => UsbTransportError::Io(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests (mock / compilation tests only – requires real hardware for usbfs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usbdevfs_bulktransfer_layout() {
        assert_eq!(std::mem::size_of::<UsbdevfsBulkTransfer>(), 24);
        assert_eq!(std::mem::align_of::<UsbdevfsBulkTransfer>(), 8);
    }

    #[test]
    fn ioctl_constants_are_well_formed() {
        assert!(USBDEVFS_BULK != 0);
        assert!(USBDEVFS_CLAIMINTERFACE != 0);
        assert!(USBDEVFS_DISCONNECT_CLAIM != 0);
    }
}
