//! libusb-based ADB USB backend.
//!
//! AOSP source: `vendor/adb/client/usb_libusb.cpp`
//!
//! Pure userspace USB I/O using libusb (via the `rusb` crate).
//! Alternative to the Linux-sysfs USB backend.
//!
//! Features:
//! - Cross-platform USB ADB access (Linux, macOS, Windows, Android)
//! - Device enumeration by vid:pid (18d1:4ee7 etc.)
//! - Bulk transfer I/O
//! - Hotplug callback support
//!
//! Related AOSP files:
//! - `vendor/adb/client/usb_libusb10.cpp` — libusb 1.0 backend


#[cfg(feature = "usb-rusb")]
use std::time::Duration;
#[cfg(feature = "usb-rusb")]
use adb_protocol::{RusbUsbTransport, UsbTransportAdapter};

/// The libusb-based ADB USB transport.
///
/// Wraps `adb_protocol::usb::RusbUsbTransport` which provides a full
/// libusb backend via the `rusb` crate. This module exists as a
/// convenience layer for the client to provide a clean API.
///
/// Only available when the `usb` feature is enabled on `adb-protocol`
/// (which forwards to `adb-protocol/usb-rusb`).

/// Result of a USB device open operation.
#[derive(Debug)]
pub struct UsbLibusbDevice {
    /// Whether the device was successfully opened.
    pub is_open: bool,
    /// Bus number.
    pub bus: u8,
    /// Device address.
    pub address: u8,
    /// Serial number, if available.
    pub serial: Option<String>,
}

/// Enumerate ADB devices using the rusb/libusb backend.
///
/// Returns a list of discovered ADB device identifiers.
#[cfg(feature = "usb-rusb")]
pub fn enumerate_libusb_devices() -> Result<Vec<UsbLibusbDevice>, Box<dyn std::error::Error>> {
    let candidates = RusbUsbTransport::enumerate_candidates()
        .map_err(|e| format!("libusb enumeration failed: {e}"))?;

    Ok(candidates
        .into_iter()
        .map(|c| UsbLibusbDevice {
            is_open: false,
            bus: c.bus_number,
            address: c.address,
            serial: c.serial.clone(),
        })
        .collect())
}

/// Open the first ADB device found via libusb.
///
/// Returns a boxed `Transport` ready for ADB protocol communication.
#[cfg(feature = "usb-rusb")]
pub fn open_first_libusb() -> Result<Box<dyn adb_protocol::Transport>, Box<dyn std::error::Error>> {
    let rusb = RusbUsbTransport::open_first()
        .map_err(|e| format!("Failed to open first USB device via libusb: {e}"))?;
    let adapter = UsbTransportAdapter::new(rusb);
    Ok(Box::new(adapter))
}

/// Open an ADB device by serial number via libusb.
///
/// Returns a boxed `Transport` ready for ADB protocol communication.
#[cfg(feature = "usb-rusb")]
pub fn open_libusb_by_serial(
    serial: &str,
) -> Result<Box<dyn adb_protocol::Transport>, Box<dyn std::error::Error>> {
    let rusb = RusbUsbTransport::open_by_serial(serial)
        .map_err(|e| format!("Failed to open USB device {serial} via libusb: {e}"))?;
    let adapter = UsbTransportAdapter::new(rusb);
    Ok(Box::new(adapter))
}

/// Open an ADB device by bus number and address via libusb.
#[cfg(feature = "usb-rusb")]
pub fn open_libusb_by_bus_address(
    bus: u8,
    address: u8,
) -> Result<Box<dyn adb_protocol::Transport>, Box<dyn std::error::Error>> {
    let rusb = RusbUsbTransport::open_by_bus_address(bus, address)
        .map_err(|e| format!("Failed to open USB device at bus {bus} address {address}: {e}"))?;
    let adapter = UsbTransportAdapter::new(rusb);
    Ok(Box::new(adapter))
}

/// Check if libusb backend is available on this platform.
///
/// Returns true if the `usb` feature is enabled (which activates
/// the `adb-protocol/usb-rusb` backend).
pub fn is_libusb_available() -> bool {
    #[cfg(feature = "usb-rusb")]
    {
        true
    }
    #[cfg(not(feature = "usb-rusb"))]
    {
        false
    }
}

/// Error type for libusb operations.
#[derive(Debug, thiserror::Error)]
pub enum LibusbError {
    #[error("libusb not available (feature not enabled)")]
    NotAvailable,
    #[error("libusb error: {0}")]
    Other(String),
}

/// Non-feature-gated helper: returns error when usb feature is not available.
#[cfg(not(feature = "usb-rusb"))]
pub fn enumerate_libusb_devices() -> Result<Vec<UsbLibusbDevice>, Box<dyn std::error::Error>> {
    Err("USB support not enabled. Rebuild with --features usb".into())
}

#[cfg(not(feature = "usb-rusb"))]
pub fn open_first_libusb() -> Result<Box<dyn adb_protocol::Transport>, Box<dyn std::error::Error>> {
    Err("USB support not enabled. Rebuild with --features usb".into())
}

#[cfg(not(feature = "usb-rusb"))]
pub fn open_libusb_by_serial(
    _serial: &str,
) -> Result<Box<dyn adb_protocol::Transport>, Box<dyn std::error::Error>> {
    Err("USB support not enabled. Rebuild with --features usb".into())
}

/// Set the I/O timeout for a device opened via libusb.
#[cfg(feature = "usb-rusb")]
pub fn set_libusb_timeout(
    transport: &mut dyn adb_protocol::Transport,
    _timeout: Duration,
) {
    // The timeout is set during device creation via open_first/open_by_serial.
    // For existing transports, we'd need to downcast to RusbUsbTransport.
    // This is a no-op for now; timeout is configured at open time.
    let _ = transport;
}
