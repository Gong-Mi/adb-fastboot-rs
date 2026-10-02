//! ADB trace/logging — bitmask-based per-tag tracing, device log file.
//!
//! Mirrors AOSP `vendor/adb/adb_trace.cpp`.

use std::sync::atomic::{AtomicU32, Ordering};

/// ADB trace tags (bit positions). Mirrors AOSP `adb_trace.h` `AdbTrace` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdbTrace {
    Adb = 0,
    Sockets = 1,
    Packets = 2,
    Rwx = 3,
    Usb = 4,
    Sync = 5,
    Sysdeps = 6,
    Transport = 7,
    Jdwp = 8,
    Services = 9,
    Auth = 10,
    Fdevent = 11,
    Shell = 12,
    Incremental = 13,
    Mdns = 14,
    MdnsStack = 15,
}

static TRACE_MASK: AtomicU32 = AtomicU32::new(0);

/// Global trace mask bits, indexed by `AdbTrace`.
pub fn trace_mask() -> u32 {
    TRACE_MASK.load(Ordering::Relaxed)
}

/// Number of trace tags in `AdbTrace` enum (AOSP: `AdbTrace::NUM_TRACES`).
pub const NUM_TRACES: usize = 16;

/// AOSP `get_trace_setting()` (adb_trace.cpp:92-102): returns `ADB_TRACE` env var.
pub fn get_trace_setting() -> String {
    std::env::var("ADB_TRACE").unwrap_or_default()
}

/// Enable a specific trace tag (AOSP: `adb_trace_enable()`).
pub fn adb_trace_enable(tag: AdbTrace) {
    TRACE_MASK.fetch_or(1 << (tag as u32), Ordering::Relaxed);
}

/// Enable all traces.
pub fn adb_trace_enable_all() {
    TRACE_MASK.store(!0u32, Ordering::Relaxed);
}

/// Check if a specific trace tag is enabled.
pub fn adb_trace_is_enabled(tag: AdbTrace) -> bool {
    (TRACE_MASK.load(Ordering::Relaxed) & (1 << (tag as u32))) != 0
}

/// Parse `ADB_TRACE` env var into trace mask (AOSP: `setup_trace_mask()`).
pub fn setup_trace_from_env() {
    let setting = get_trace_setting();
    if setting.is_empty() {
        return;
    }

    let mut mask = 0u32;
    for elem in setting.split(&[',', ' '][..]).filter(|s| !s.is_empty()) {
        let bit = match elem {
            "1" | "all" => { mask = !0u32; break; }
            "adb" => Some(AdbTrace::Adb),
            "sockets" => Some(AdbTrace::Sockets),
            "packets" => Some(AdbTrace::Packets),
            "rwx" => Some(AdbTrace::Rwx),
            "usb" => Some(AdbTrace::Usb),
            "sync" => Some(AdbTrace::Sync),
            "sysdeps" => Some(AdbTrace::Sysdeps),
            "transport" => Some(AdbTrace::Transport),
            "jdwp" => Some(AdbTrace::Jdwp),
            "services" => Some(AdbTrace::Services),
            "auth" => Some(AdbTrace::Auth),
            "fdevent" => Some(AdbTrace::Fdevent),
            "shell" => Some(AdbTrace::Shell),
            "incremental" => Some(AdbTrace::Incremental),
            "mdns" => Some(AdbTrace::Mdns),
            "mdns-stack" => Some(AdbTrace::MdnsStack),
            _ => { eprintln!("adb: Unknown trace flag: {}", elem); continue; }
        };
        if let Some(tag) = bit {
            mask |= 1 << (tag as u32);
        }
    }
    TRACE_MASK.store(mask, Ordering::Relaxed);
}

/// AOSP `setup_trace_mask()` (adb_trace.cpp:110-168).
pub fn setup_trace_mask() {
    setup_trace_from_env();
}

/// Redirect stdout/stderr to a timestamped log file (AOSP: `start_device_log()`).
pub fn start_device_log() {
    let pid = std::process::id();
    let mut now: libc::time_t = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::time(&mut now);
        libc::localtime_r(&now, &mut tm);
    }
    let log_path = format!(
        "/data/adb/adb-{:04}-{:02}-{:02}-{:02}-{:02}-{:02}-{}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        pid,
    );

    let c_path = std::ffi::CString::new(log_path.as_str()).unwrap();
    let fd = unsafe { libc::open(
        c_path.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
        0o640,
    ) };
    if fd < 0 {
        return;
    }

    unsafe {
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
        libc::close(fd);
    }
    eprintln!("--- adb starting (pid {}) ---", pid);
}

/// VLOG-style conditional trace macro.
#[macro_export]
macro_rules! vlog {
    ($tag:expr, $($arg:tt)*) => {
        if $crate::server::adb_trace::adb_trace_is_enabled($tag) {
            eprintln!("[adb] {}: {}", stringify!($tag), format!($($arg)*));
        }
    };
}

/// Trace log at ADB level.
#[macro_export]
macro_rules! vlog_adb { ($($arg:tt)*) => { $crate::vlog!($crate::server::adb_trace::AdbTrace::Adb, $($arg)*) } }

/// AOSP `adb_trace_init()` (adb_trace.cpp:170-202): initialize logging,
/// read trace mask from environment, and emit trace banner if ADB trace enabled.
pub fn adb_trace_init() {
    setup_trace_mask();
    if adb_trace_is_enabled(AdbTrace::Adb) {
        crate::vlog_adb!("Android Debug Bridge (trace initialized)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_tags_have_unique_bits() {
        assert_eq!(AdbTrace::Adb as u32, 0);
        assert_eq!(AdbTrace::Sockets as u32, 1);
        assert_eq!(AdbTrace::MdnsStack as u32, 15);
    }

    #[test]
    fn test_enable_and_check() {
        TRACE_MASK.store(0, Ordering::Relaxed);
        assert!(!adb_trace_is_enabled(AdbTrace::Usb));
        adb_trace_enable(AdbTrace::Usb);
        assert!(adb_trace_is_enabled(AdbTrace::Usb));
        assert!(!adb_trace_is_enabled(AdbTrace::Auth));
    }

    #[test]
    fn test_enable_all() {
        TRACE_MASK.store(0, Ordering::Relaxed);
        adb_trace_enable_all();
        assert!(adb_trace_is_enabled(AdbTrace::Adb));
        assert!(adb_trace_is_enabled(AdbTrace::MdnsStack));
    }

    /// ADB_TRACE is process-global; tests that touch it must serialize.
    static TRACE_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_setup_from_env_empty() {
        let _guard = TRACE_ENV_MUTEX.lock().unwrap();
        // No ADB_TRACE set → mask stays 0
        unsafe { std::env::remove_var("ADB_TRACE"); }
        TRACE_MASK.store(0, Ordering::Relaxed);
        setup_trace_from_env();
        assert_eq!(trace_mask(), 0);
    }

    #[test]
    fn test_setup_from_env_parses_tags() {
        let _guard = TRACE_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("ADB_TRACE", "usb,transport,shell"); }
        TRACE_MASK.store(0, Ordering::Relaxed);
        setup_trace_from_env();
        assert!(adb_trace_is_enabled(AdbTrace::Usb));
        assert!(adb_trace_is_enabled(AdbTrace::Transport));
        assert!(adb_trace_is_enabled(AdbTrace::Shell));
        assert!(!adb_trace_is_enabled(AdbTrace::Auth));
        unsafe { std::env::remove_var("ADB_TRACE"); }
    }

    #[test]
    fn test_setup_from_env_all() {
        let _guard = TRACE_ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("ADB_TRACE", "all"); }
        TRACE_MASK.store(0, Ordering::Relaxed);
        setup_trace_from_env();
        assert_eq!(trace_mask(), !0u32);
        unsafe { std::env::remove_var("ADB_TRACE"); }
    }

    #[test]
    fn test_get_trace_setting_and_trace_init() {
        let _guard = TRACE_ENV_MUTEX.lock().unwrap();
        assert_eq!(NUM_TRACES, 16);

        unsafe { std::env::set_var("ADB_TRACE", "adb,sync"); }
        assert_eq!(get_trace_setting(), "adb,sync");

        TRACE_MASK.store(0, Ordering::Relaxed);
        adb_trace_init();
        assert!(adb_trace_is_enabled(AdbTrace::Adb));
        assert!(adb_trace_is_enabled(AdbTrace::Sync));
        assert!(!adb_trace_is_enabled(AdbTrace::Usb));
        unsafe { std::env::remove_var("ADB_TRACE"); }
    }
}
