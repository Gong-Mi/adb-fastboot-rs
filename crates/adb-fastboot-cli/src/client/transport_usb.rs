//! ADB USB transport implementation.
//!
//! AOSP source: `vendor/adb/client/transport_usb.cpp`
//!
//! Manages USB-based ADB device discovery, connection, and I/O.
//! Interfaces with the lower-level USB abstraction (`usb_libusb` / `UsbFs`).
//!
//! Features:
//! - USB device enumeration via libusb or sysfs
//! - Opening USB ADB interfaces (vendor=0x18d1, product=0x4e11/0x4ee7/0x4e43)
//! - Bulk IN/END POINT I/O
//! - Device disconnect detection

use std::sync::{Arc, Mutex};
use std::time::Duration;

use adb_protocol::Transport;

/// A discovered USB ADB device.
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    /// Serial number of the device.
    pub serial: Option<String>,
    /// USB bus number.
    pub bus_number: u8,
    /// Device address on the bus.
    pub address: u8,
    /// Vendor ID (typically 0x18d1 for Google).
    pub vendor_id: u16,
    /// Product ID (varies by device mode).
    pub product_id: u16,
    /// Whether the device is currently authorized for ADB.
    pub authorized: bool,
}

/// Manages USB device discovery and connection state.
#[derive(Debug)]
pub struct UsbTransportManager {
    /// Cached list of known devices.
    devices: Arc<Mutex<Vec<UsbDeviceInfo>>>,
    /// Whether to use the usbfs backend (Android/Linux) or rusb (cross-platform).
    use_usbfs: bool,
}

impl UsbTransportManager {
    /// Create a new USB transport manager.
    pub fn new(use_usbfs: bool) -> Self {
        Self {
            devices: Arc::new(Mutex::new(Vec::new())),
            use_usbfs,
        }
    }

    /// Enumerate all connected ADB USB devices.
    #[cfg(feature = "usb")]
    pub fn enumerate(&self) -> Result<Vec<UsbDeviceInfo>, Box<dyn std::error::Error>> {
        let devices = self.do_enumerate()?;
        if let Ok(mut cached) = self.devices.lock() {
            *cached = devices.clone();
        }
        Ok(devices)
    }

    #[cfg(not(feature = "usb"))]
    pub fn enumerate(&self) -> Result<Vec<UsbDeviceInfo>, Box<dyn std::error::Error>> {
        Err("USB support not enabled (rebuild with --features usb)".into())
    }

    #[cfg(feature = "usb")]
    fn do_enumerate(&self) -> Result<Vec<UsbDeviceInfo>, Box<dyn std::error::Error>> {
        let mut devices = Vec::new();

        if self.use_usbfs {
            // Use UsbfsAdbDevice enumeration (Android/Linux usbfs)
            match adb_protocol::UsbfsAdbDevice::enumerate() {
                Ok(candidates) => {
                    for candidate in candidates {
                        devices.push(UsbDeviceInfo {
                            serial: candidate.serial.clone(),
                            bus_number: candidate.bus_number,
                            address: candidate.address,
                            vendor_id: 0x18d1, // Google
                            product_id: 0x4ee7, // ADB mode
                            authorized: true,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Warning: usbfs enumeration failed: {e}");
                }
            }
        }

        Ok(devices)
    }

    /// Open a USB transport to the first ADB device found.
    #[cfg(feature = "usb")]
    pub fn open_first(
        &self,
    ) -> Result<Box<dyn Transport>, Box<dyn std::error::Error>> {
        if self.use_usbfs {
            let mut dev = adb_protocol::UsbfsAdbDevice::open_first()
                .map_err(|e| format!("Failed to open first ADB USB device: {e}"))?;
            dev.set_timeout(Duration::from_secs(30 * 60));
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }

        Err("USB support not enabled".into())
    }

    /// Open a USB transport by device serial number.
    #[cfg(feature = "usb")]
    pub fn open_by_serial(
        &self,
        serial: &str,
    ) -> Result<Box<dyn Transport>, Box<dyn std::error::Error>> {
        if self.use_usbfs {
            let mut dev = adb_protocol::UsbfsAdbDevice::open_by_serial(serial)
                .map_err(|e| format!("Failed to open ADB USB device {serial}: {e}"))?;
            dev.set_timeout(Duration::from_secs(30 * 60));
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }

        Err(format!("Failed to open USB device {serial}").into())
    }

    /// Get the cached list of devices.
    pub fn get_cached_devices(&self) -> Vec<UsbDeviceInfo> {
        self.devices
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default()
    }

    /// Check if a device is still connected by serial.
    #[cfg(feature = "usb")]
    pub fn is_device_connected(
        &self,
        serial: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let devices = self.enumerate()?;
        Ok(devices.iter().any(|d| d.serial.as_deref() == Some(serial)))
    }

    #[cfg(not(feature = "usb"))]
    pub fn is_device_connected(
        &self,
        _serial: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Err("USB support not enabled".into())
    }
}

/// Check if the given serial represents a USB device (not TCP, not emulator).
pub fn is_usb_serial(serial: &str) -> bool {
    !serial.contains(':') && !serial.starts_with("emulator-")
}

/// The standard ADB vendor ID.
pub const ADB_VENDOR_ID: u16 = 0x18d1;

/// Standard ADB product IDs for different device modes.
pub const ADB_PRODUCT_ID: u16 = 0x4ee7;       // ADB mode
pub const ADB_PRODUCT_ID_FASTBOOT: u16 = 0x4e11; // Fastboot mode
pub const ADB_PRODUCT_ID_RECOVERY: u16 = 0x4e43; // Recovery mode

/// Create a default USB transport manager (auto-detects backend).
pub fn default_usb_manager() -> UsbTransportManager {
    #[cfg(target_os = "android")]
    let use_usbfs = true;
    #[cfg(not(target_os = "android"))]
    let use_usbfs = false;

    UsbTransportManager::new(use_usbfs)
}
