//! Client-side ADB protocol helpers.
//!
//! Maps to AOSP `vendor/adb/client/`:
//! - adb_client.cpp        → transport, protocol, host_command
//! - auth.cpp              → auth
//! - commandline.cpp       → dispatch (in main_adb.rs)
//! - file_sync_client.cpp  → sync (push/pull)
//! - mdns_utils.cpp / mdns_tracker.cpp → mdns
//! - console.cpp           → console
//! - adb_install.cpp       → adb_install
//! - adb_wifi.cpp          → adb_wifi
//! - bugreport.cpp         → bugreport
//! - detach.cpp            → detach
//! - discovered_services.cpp → discovered_services
//! - incremental_adb_install.cpp → incremental
//! - line_printer.cpp      → line_printer
//! - transport_emulator.cpp → transport_emulator
//! - transport_usb.cpp     → transport_usb
//! - usb_libusb.cpp / usb_libusb10.cpp → usb_libusb

pub mod auth;
pub mod transport;
pub mod protocol;
pub mod shell;
pub mod exec_out;
pub mod server_cmds;
pub mod host_command;
pub mod mdns;
pub mod console;
pub mod adb_install;
pub mod adb_wifi;
pub mod bugreport;
pub mod detach;
pub mod discovered_services;
pub mod incremental;
pub mod line_printer;
pub mod transport_emulator;
pub mod transport_mdns;
pub mod transport_usb;
pub mod file_sync;
pub mod usb_libusb;
