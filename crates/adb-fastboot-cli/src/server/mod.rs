//! ADB Server — maps to AOSP `vendor/adb/` (top-level .cpp files).
//!
//! Module structure mirrors AOSP source layout:
//! - runner.rs  → adb.cpp (run_server, launch_server)
//! - handler.rs → sockets.cpp (smart socket, handle_client)
//! - models.rs  → transport.cpp types (TransportRegistry, atransport)
//! - bridge.rs  → smart socket connect_to_remote bridge logic
//! - forward.rs → adb_listeners.cpp (forward/reverse)
//! - watcher.rs → USB device watcher (usb.cpp)
//! - adb_utils.rs → adb_utils.cpp (file/path helpers, shell escaping, logging

pub mod adb_utils;
pub mod bridge;
pub mod forward;
pub mod services;
pub mod handler;
pub mod models;
pub mod runner;
pub mod transport;
pub mod watcher;

// Re-export all items for backward compatibility within the crate.
pub(crate) use adb_utils::*;
pub(crate) use bridge::*;
pub(crate) use forward::*;
pub(crate) use services::*;
pub(crate) use handler::*;
pub(crate) use models::*;
pub(crate) use runner::*;
pub(crate) use transport::*;
pub(crate) use watcher::*;
