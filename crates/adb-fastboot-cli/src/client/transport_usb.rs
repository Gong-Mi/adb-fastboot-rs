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
//!
//! TODO: Implement USB transport layer wrapping adb_protocol::usb::UsbfsAdbDevice.
//! TODO: Implement device enumeration and hotplug detection.
//! TODO: Handle USB permission issues on Android/Linux.
