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
//!
//! TODO: Implement USB backend using `rusb` crate.
//! TODO: Handle device enumeration, opening, and bulk I/O.
//! TODO: Integrate with transport.rs for cross-platform USB support.
//! TODO: Add `libusb` feature gate (conditional compilation).
