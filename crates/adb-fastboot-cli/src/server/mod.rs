//! ADB Server — maps to AOSP `vendor/adb/` (top-level .cpp files).
//!
//! Module structure mirrors AOSP source layout:
//! - server.rs / old.rs  → adb.cpp (run_server, launch_server)
//! - handler.rs          → sockets.cpp (smart socket, handle_client)
//! - models.rs           → transport.cpp types (TransportRegistry, atransport)
//! - bridge.rs           → smart socket connect_to_remote bridge logic  
//! - forward.rs          → adb_listeners.cpp (forward/reverse)
//! - watcher.rs          → USB device watcher (usb.cpp)

// Include the old monolithic server.rs content until it's fully split.
// Each function group will be migrated to its own sub-module.
#[path = "old.rs"]
mod old;

// Re-export all public items from old.rs for backward compatibility.
pub use old::*;

pub mod runner;
pub mod handler;
pub mod models;
pub mod bridge;
pub mod forward;
pub mod watcher;
