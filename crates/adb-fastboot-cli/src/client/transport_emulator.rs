//! ADB transport for Android emulator connections.
//!
//! AOSP source: `vendor/adb/client/transport_emulator.cpp`
//!
//! Handles:
//! - Connecting to Android Virtual Device (AVD) emulators via local TCP ports
//! - Emulator auto-discovery via emulator console (qemu) protocol
//! - Port management for emulator instances (5554, 5555, ...)
//!
//! TODO: Implement emulator transport: connect to emulator serial ports.
//! TODO: Implement emulator auto-discovery (probe serial ports 5554-5584).
//! TODO: Handle emulator-specific quirks (no USB, limited auth).
