//! ADB system dependencies, mirroring AOSP `vendor/adb/sysdeps/`.
pub mod env;
#[cfg(unix)]
pub mod errno;
