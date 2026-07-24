//! Environment utilities, mirroring AOSP `vendor/adb/sysdeps/env.cpp`.

use std::path::PathBuf;

/// Returns the ADB home directory (~/.android).
pub fn adb_home_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".android")
}

/// Returns the default ADB key path (~/.android/adbkey).
pub fn adb_private_key_path() -> PathBuf {
    adb_home_dir().join("adbkey")
}

/// Returns the default ADB public key path (~/.android/adbkey.pub).
pub fn adb_public_key_path() -> PathBuf {
    adb_home_dir().join("adbkey.pub")
}
