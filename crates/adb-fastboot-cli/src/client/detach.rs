//! ADB detach command: disconnect from a device without killing the server.
//!
//! AOSP source: `vendor/adb/client/detach.cpp`
//!
//! Handles:
//! - `adb detach <serial>` — detach a specific device from the ADB server
//! - Disconnects the transport without affecting other devices
//!
//! TODO: Implement the detach protocol: sends host:detach request to the ADB server.
//! TODO: Validate serial format before sending the request.
