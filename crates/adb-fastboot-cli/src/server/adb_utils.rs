//! ADB utility functions — file/path helpers, shell argument escaping, logging macros.
//!
//! Mirrors AOSP `vendor/adb/adb_utils.cpp` / `adb_utils.h`.

use std::fs;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use adb_protocol::header::AdbMessageHeader;

// ---------------------------------------------------------------------------
// ADB home / config directory
// ---------------------------------------------------------------------------

/// Returns the ADB home directory (`~/.android`).
pub fn adb_home_dir() -> PathBuf {
    adb_protocol::sysdeps::env::adb_home_dir()
}

/// Returns the ADB Android directory path, creating it if needed.
pub fn adb_get_android_dir_path() -> PathBuf {
    let user_dir = adb_home_dir();
    let android_dir = user_dir.join(".android");
    if !android_dir.is_dir() {
        let _ = mkdirs(&android_dir);
    }
    android_dir
}

// ---------------------------------------------------------------------------
// Path / file utilities (AOSP: directory_exists, getcwd, mkdirs, dump_hex, ...)
// ---------------------------------------------------------------------------

pub fn file_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_file()
}

pub fn dir_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

pub fn path_join(base: impl AsRef<Path>, component: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join(component)
}

pub fn is_path_absolute(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_absolute()
}

pub fn get_env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub fn canonicalize_or(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref()
        .canonicalize()
        .unwrap_or_else(|_| path.as_ref().to_path_buf())
}

/// Redirect stdin to /dev/null (AOSP: `close_stdin()`).
pub fn close_stdin() {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if fd >= 0 {
        unsafe {
            libc::dup2(fd, libc::STDIN_FILENO);
            libc::close(fd);
        }
    }
}

/// Get current working directory (AOSP: `getcwd(std::string*)`).
pub fn getcwd() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Recursively create a directory hierarchy (AOSP: `mkdirs()`).
pub fn mkdirs(path: impl AsRef<Path>) -> bool {
    fs::create_dir_all(path.as_ref()).is_ok()
}

/// Hex dump of binary data, truncated to 16 bytes with ASCII sidebar (AOSP: `dump_hex()`).
pub fn dump_hex(data: &[u8]) -> String {
    let truncate_len = 16usize;
    let truncated = data.len() > truncate_len;
    let byte_count = data.len().min(truncate_len);

    let mut line = String::new();
    for &b in &data[..byte_count] {
        line.push_str(&format!("{:02x}", b));
    }
    line.push(' ');
    for &b in &data[..byte_count] {
        line.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
    }
    if truncated {
        line.push_str(" [truncated]");
    }
    line
}

/// Format an ADB message header as a human-readable string (AOSP: `dump_header()`).
pub fn dump_header(msg: &AdbMessageHeader) -> String {
    let cmd_bytes = msg.command.to_le_bytes();
    let cmd_str: String = cmd_bytes
        .iter()
        .take_while(|&&b| b.is_ascii_graphic())
        .map(|&b| b as char)
        .collect();
    let cmd_display = if cmd_str.len() == 4 { cmd_str } else { format!("{:08x}", msg.command) };

    let arg0 = if msg.arg0 < 256 {
        format!("{}", msg.arg0)
    } else {
        format!("0x{:x}", msg.arg0)
    };
    let arg1 = if msg.arg1 < 256 {
        format!("{}", msg.arg1)
    } else {
        format!("0x{:x}", msg.arg1)
    };

    format!("[{}] arg0={} arg1={} (len={}) ", cmd_display, arg0, arg1, msg.data_length)
}

/// Format a complete packet dump (AOSP: `dump_packet()`).
pub fn dump_packet(name: &str, func: &str, header: &AdbMessageHeader, payload: &[u8]) -> String {
    format!("{}: {}: {}{}", name, func, dump_header(header), dump_hex(payload))
}

/// Format errno message (AOSP: `perror_str()`).
pub fn perror_str(msg: &str) -> String {
    let errno = std::io::Error::last_os_error();
    format!("{}: {}", msg, errno)
}

/// Set or clear `O_NONBLOCK` on a file descriptor (AOSP: `set_file_block_mode()`).
pub fn set_file_block_mode(fd: RawFd, block: bool) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags == -1 {
        return false;
    }
    let new_flags = if block { flags & !libc::O_NONBLOCK } else { flags | libc::O_NONBLOCK };
    unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) == 0 }
}

/// Validate forward target specifications (AOSP: `forward_targets_are_valid()`).
pub fn forward_targets_are_valid(source: &str, dest: &str) -> Result<(), String> {
    if let Some(port_str) = source.strip_prefix("tcp:") {
        let port: i32 = port_str.parse().map_err(|_| format!("Invalid source port: '{}'", port_str))?;
        if port < 0 {
            return Err(format!("Invalid source port: '{}'", port_str));
        }
    }
    if let Some(port_str) = dest.strip_prefix("tcp:") {
        let port: i32 = port_str.parse().map_err(|_| format!("Invalid destination port: '{}'", port_str))?;
        if port <= 0 {
            return Err(format!("Invalid destination port: '{}'", port_str));
        }
    }
    Ok(())
}

/// Get the ADB log file path (AOSP: `GetLogFilePath()`).
pub fn get_log_file_path() -> PathBuf {
    if let Ok(path) = std::env::var("ANDROID_ADB_LOG_PATH") {
        return PathBuf::from(path);
    }
    let tmp_dir = get_env_or("TMPDIR", "/tmp");
    PathBuf::from(format!("{}/adb.{}.log", tmp_dir, unsafe { libc::getuid() }))
}

// ---------------------------------------------------------------------------
// Shell argument escaping (AOSP: escape_arg, implemented as QuoteArgument)
// ---------------------------------------------------------------------------

pub fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub fn escape_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len());
    for ch in arg.chars() {
        match ch {
            ' ' | '\t' | '\n' | '\r' | '\\' | '\'' | '"' | '|' | '&' | ';'
            | '(' | ')' | '<' | '>' | '`' | '$' | '*' | '?' | '[' | ']'
            | '#' | '~' | '!' | '{' | '}' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn quote_args(args: &[&str]) -> String {
    args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Logging macros (AOSP: adb_trace.h → VLOG, LOG(ERROR), ...)
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {
        {
            let _level = std::env::var("ADB_LOG").unwrap_or_default();
            if _level == "verbose" || _level == "debug" || _level == "trace" {
                eprintln!("[adb] {}", format!($($arg)*));
            }
        }
    };
}

#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {
        eprintln!("[adb] error: {}", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        eprintln!("[adb] warning: {}", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! info_log {
    ($($arg:tt)*) => {
        eprintln!("[adb] info: {}", format!($($arg)*));
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::constants::A_OKAY;

    #[test]
    fn test_adb_home_dir() {
        let dir = adb_home_dir();
        assert!(dir.to_string_lossy().contains(".android"));
    }

    #[test]
    fn test_file_and_dir_exists() {
        let this = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("server").join("adb_utils.rs");
        assert!(file_exists(&this));
        assert!(!dir_exists(&this));
        assert!(dir_exists(this.parent().unwrap()));
    }

    #[test]
    fn test_mkdirs() {
        let tmp = std::env::temp_dir().join("adb_test_mkdirs").join("a").join("b");
        let r = mkdirs(&tmp);
        assert!(r);
        assert!(tmp.is_dir());
        let _ = fs::remove_dir_all(tmp.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn test_dump_hex() {
        let s = dump_hex(b"hello");
        assert!(s.contains("68656c6c6f"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_dump_header() {
        let h = AdbMessageHeader::new(A_OKAY, 42, 0, b"test");
        let s = dump_header(&h);
        assert!(s.contains("OKAY"));
        assert!(s.contains("arg0=42"));
    }

    #[test]
    fn test_set_file_block_mode_fails_on_bad_fd() {
        assert!(!set_file_block_mode(-1, true));
    }

    #[test]
    fn test_forward_targets_valid() {
        assert!(forward_targets_are_valid("tcp:0", "tcp:5555").is_ok());
        assert!(forward_targets_are_valid("tcp:-1", "tcp:5555").is_err());
        assert!(forward_targets_are_valid("tcp:0", "tcp:0").is_err());
        assert!(forward_targets_are_valid("local:/tmp/sock", "tcp:5555").is_ok());
    }

    #[test]
    fn test_get_log_file_path() {
        let p = get_log_file_path();
        assert!(p.to_string_lossy().contains("adb."));
        assert!(p.to_string_lossy().ends_with(".log"));
    }

    #[test]
    fn test_getcwd() {
        let cwd = getcwd();
        assert!(cwd.is_some());
        assert!(!cwd.unwrap().is_empty());
    }

    // Shell escaping tests
    #[test]
    fn test_quote_arg_simple() {
        assert_eq!(quote_arg("hello"), "hello");
        assert_eq!(quote_arg("foo_bar"), "foo_bar");
    }
    #[test]
    fn test_quote_arg_spaces() {
        assert_eq!(quote_arg("hello world"), "'hello world'");
    }
    #[test]
    fn test_quote_arg_embedded_quote() {
        assert_eq!(quote_arg("it's"), "'it'\\''s'");
    }
    #[test]
    fn test_quote_arg_empty() {
        assert_eq!(quote_arg(""), "''");
    }
    #[test]
    fn test_escape_arg() {
        assert_eq!(escape_arg("hello"), "hello");
        assert_eq!(escape_arg("hello world"), r"hello\ world");
        assert_eq!(escape_arg("a$b"), r"a\$b");
    }
    #[test]
    fn test_quote_args() {
        assert_eq!(quote_args(&["adb", "shell", "echo hello"]), "adb shell 'echo hello'");
    }
}
