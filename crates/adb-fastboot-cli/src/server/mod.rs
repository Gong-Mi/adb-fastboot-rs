//! ADB Server — maps to AOSP `vendor/adb/` (top-level .cpp files).
#![allow(dead_code)]
//!
//! Module structure mirrors AOSP source layout:
//! - runner.rs  → adb.cpp (run_server, launch_server)
//! - handler.rs → sockets.cpp (smart socket, handle_client)
//! - models.rs  → transport.cpp types (TransportRegistry, atransport)
//! - bridge.rs  → smart socket connect_to_remote bridge logic
//! - forward.rs → adb_listeners.cpp (forward/reverse)
//! - types.rs   → types.cpp (IOVector block I/O)
//! - apacket_reader.rs → apacket_reader.cpp (ADB packet assembly)
//! - watcher.rs → USB device watcher (usb.cpp)
//! - adb_utils.rs → adb_utils.cpp (file/path helpers, shell escaping, logging)

pub mod adb_io;
pub mod adb_mdns;
pub mod adb_trace;
pub mod adb_utils;
pub mod apacket_reader;
pub mod bridge;
pub mod fdevent;
pub mod forward;
pub mod handler;
pub mod models;
pub mod mdns_backend;
pub mod runner;
pub mod services;
pub mod smart_socket;
pub mod socket_spec;
pub mod sysdeps_posix_network;
pub mod sysdeps_unix;
pub mod transport;
pub mod transport_fd;
pub mod types;
pub mod watcher;

// Re-export all items for backward compatibility within the crate.
pub(crate) use runner::*;
