//! Incremental ADB installation (adb install —incremental).
//!
//! AOSP source: `vendor/adb/client/incremental_adb_install.cpp`
//!
//! Handles:
//! - Incremental APK installation using the Incremental File System (IncFS)
//! - Splits APK into chunks and streams them on-demand
//! - Reduces install time for large APKs by allowing apps to start before
//!   the full APK is transferred
//!
//! Related AOSP files:
//! - `vendor/adb/client/incremental_server.cpp`
//! - `vendor/adb/client/incremental_install.cpp`
//!
//! TODO: Implement IncFS incremental installation protocol.
//! TODO: Handle chunked APK streaming and on-demand loading.
//! TODO: Support `--incremental` flag in adb install.
