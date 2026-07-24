//! Client-side ADB protocol helpers.
//!
//! Maps to AOSP `vendor/adb/client/`:
//! - adb_client.cpp  → transport, protocol, host_command
//! - auth.cpp        → auth
//! - commandline.cpp → dispatch (in main_adb.rs)
//! - file_sync_client.cpp → sync (push/pull)

pub mod auth;
pub mod transport;
pub mod protocol;
pub mod shell;
pub mod exec_out;
pub mod server_cmds;
pub mod host_command;
