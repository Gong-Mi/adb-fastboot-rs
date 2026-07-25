//! Environment utilities, mirroring AOSP `vendor/adb/sysdeps/env.cpp`.
//!
//! Provides:
//! - `getenv` — read environment variables (AOSP `os_getenv`)
//! - `get_home_directory` — home directory path (AOSP `GetHomeDirectory`)
//! - `get_tmp_directory` — temp directory path (AOSP `GetTempDirectory`)

use std::path::PathBuf;

/// Read an environment variable by name.
///
/// Mirrors AOSP `os_getenv` in `vendor/adb/sysdeps/env.cpp`.
/// Returns `None` if the variable is not set or contains non-UTF-8 data.
///
/// # Example
/// ```
/// use adb_protocol::sysdeps::env::getenv;
/// let path = getenv("PATH");
/// assert!(path.is_some());
/// ```
pub fn getenv(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Returns the current user's home directory path.
///
/// Mirrors AOSP's `GetHomeDirectory` in `vendor/adb/sysdeps/env.cpp`.
/// Falls back to `/tmp` if `HOME` / `USERPROFILE` is not set.
pub fn get_home_directory() -> String {
    if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE")
            .unwrap_or_else(|_| std::env::var("HOMEDRIVE")
                .map(|d| d + &std::env::var("HOMEPATH").unwrap_or_else(|_| "\\".into()))
                .unwrap_or_else(|_| "/tmp".into()))
    } else {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
    }
}

/// Returns a temporary directory path suitable for ADB temporary files.
///
/// Mirrors AOSP's `GetTempDirectory` in `vendor/adb/sysdeps/env.cpp`.
/// Checks `TMPDIR`, `TMP`, `TEMP` in order, falling back to `/tmp` on Unix
/// or `%TEMP%` on Windows.
pub fn get_tmp_directory() -> String {
    // Android typically sets TMPDIR; on desktop Unix TMP is common.
    getenv("TMPDIR")
        .or_else(|| getenv("TMP"))
        .or_else(|| getenv("TEMP"))
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                "C:\\Windows\\Temp".into()
            } else {
                "/tmp".into()
            }
        })
}

// ---------------------------------------------------------------------------
// Existing helpers (unchanged)
// ---------------------------------------------------------------------------

/// Returns the ADB home directory (~/.android).
pub fn adb_home_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(get_home_directory()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getenv_found() {
        // PATH should always be set
        let path = getenv("PATH");
        assert!(path.is_some(), "PATH should be set");
        assert!(!path.unwrap().is_empty());
    }

    #[test]
    fn test_getenv_not_found() {
        let result = getenv("__ADB_TEST_ENV_VAR_THAT_DOES_NOT_EXIST__");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_home_directory() {
        let home = get_home_directory();
        assert!(!home.is_empty(), "home directory should not be empty");
    }

    #[test]
    fn test_get_tmp_directory() {
        let tmp = get_tmp_directory();
        assert!(!tmp.is_empty(), "tmp directory should not be empty");
    }
}
