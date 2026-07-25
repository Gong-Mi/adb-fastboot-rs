//! ADB utility functions — file/path helpers, shell argument escaping, logging macros.
//!
//! Mirrors AOSP `vendor/adb/adb_utils.cpp` / `adb_utils.h`.
//!
//! Provided functions:
//!
//! - `adb_home_dir()` / `adb_get_android_dir_path()` — ADB config directory
//! - `file_exists`, `dir_exists`, `path_join` — path utilities
//! - `quote_arg`, `escape_arg`, `quote_args` — shell argument escaping
//! - Logging macros: `verbose!`, `error_log!`, `warn_log!`, `info_log!`

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// ADB home / config directory
// ---------------------------------------------------------------------------

/// Returns the ADB home directory (`~/.android`).
///
/// Delegates to `adb_protocol::sysdeps::env::adb_home_dir()`.
pub fn adb_home_dir() -> PathBuf {
    adb_protocol::sysdeps::env::adb_home_dir()
}

/// Returns the ADB Android directory path.
///
/// On standard systems this is the same as `adb_home_dir()`.
/// On Android the adbd shell typically uses `/data/local/tmp/.android`
/// rather than the HOME-based path, so this function checks that
/// alternative first.
pub fn adb_get_android_dir_path() -> PathBuf {
    #[cfg(target_os = "android")]
    {
        let alt = PathBuf::from("/data/local/tmp/.android");
        if alt.is_dir() {
            return alt;
        }
    }
    adb_home_dir()
}

// ---------------------------------------------------------------------------
// Path / file utilities
// ---------------------------------------------------------------------------

/// Returns `true` if a regular file exists at `path`.
pub fn file_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_file()
}

/// Returns `true` if a directory exists at `path`.
pub fn dir_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

/// Join two path components.
///
/// Convenience wrapper around `Path::join` matching AOSP's `PathJoin`.
pub fn path_join(base: impl AsRef<Path>, component: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join(component)
}

/// Returns `true` if `path` is absolute.
pub fn is_path_absolute(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_absolute()
}

/// Read a `key` environment variable, returning `default` if unset.
pub fn get_env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Resolve `path` to its canonical (absolute, symlink-resolved) form.
/// Returns `path` unchanged on failure.
pub fn canonicalize_or(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref()
        .canonicalize()
        .unwrap_or_else(|_| path.as_ref().to_path_buf())
}

// ---------------------------------------------------------------------------
// Shell argument escaping
// ---------------------------------------------------------------------------

/// Quote a single argument for POSIX shell.
///
/// If the argument contains only "safe" characters (alphanumerics plus
/// `_`, `-`, `.`, `:`, `/`), it is returned as-is.  Otherwise it is
/// wrapped in single quotes, with embedded single quotes escaped per
/// POSIX rules (`'` → `'\''`).
///
/// Mirrors AOSP `QuoteArgument()` in `vendor/adb/adb_utils.cpp`.
pub fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    // Safe characters — no escaping needed.
    if arg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
    {
        return arg.to_string();
    }
    // Single-quote wrapping; handle embedded quotes with '\'' sequence.
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

/// Escape shell metacharacters in a string with backslash prefix.
///
/// Unlike `quote_arg` which wraps the whole string in quotes, this
/// escapes each special character individually so the result can be
/// embedded inside an already-quoted string.
///
/// Escaped characters: space, tab, newline, carriage return, `\`, `'`,
/// `"`, `|`, `&`, `;`, `(`, `)`, `<`, `>`, `` ` ``, `$`, `*`, `?`,
/// `[`, `]`, `#`, `~`, `!`, `{`, `}`.
pub fn escape_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len());
    for ch in arg.chars() {
        match ch {
            ' '
            | '\t'
            | '\n'
            | '\r'
            | '\\'
            | '\''
            | '"'
            | '|'
            | '&'
            | ';'
            | '('
            | ')'
            | '<'
            | '>'
            | '`'
            | '$'
            | '*'
            | '?'
            | '['
            | ']'
            | '#'
            | '~'
            | '!'
            | '{'
            | '}' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Join multiple arguments into a single shell-safe command string.
///
/// Each argument is quoted with `quote_arg` and joined with spaces.
pub fn quote_args(args: &[&str]) -> String {
    args.iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Logging macros
// ---------------------------------------------------------------------------

/// Log a verbose message to stderr, prefixed with `[adb]`.
///
/// Only emits output when the `ADB_LOG` environment variable is set to
/// `verbose`, `debug`, or `trace`.
///
/// # Examples
///
/// ```ignore
/// verbose!("scanning USB devices");
/// verbose!("transport {} connected", serial);
/// ```
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

/// Log an error message to stderr, prefixed with `[adb] error:`.
///
/// # Examples
///
/// ```ignore
/// error_log!("failed to open device: {}", err);
/// ```
#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {
        eprintln!("[adb] error: {}", format!($($arg)*));
    };
}

/// Log a warning message to stderr, prefixed with `[adb] warning:`.
///
/// # Examples
///
/// ```ignore
/// warn_log!("USB device disconnected unexpectedly");
/// ```
#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        eprintln!("[adb] warning: {}", format!($($arg)*));
    };
}

/// Log an informational message to stderr, prefixed with `[adb] info:`.
///
/// # Examples
///
/// ```ignore
/// info_log!("ADB server started on port {}", port);
/// ```
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

    // -- Path utilities ------------------------------------------------------

    #[test]
    fn test_adb_home_dir_returns_dot_android() {
        let dir = adb_home_dir();
        assert!(dir.to_string_lossy().contains(".android"));
    }

    #[test]
    fn test_file_exists_and_dir_exists() {
        // This file itself should exist.
        let this_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("server")
            .join("adb_utils.rs");
        assert!(file_exists(&this_file));
        assert!(!dir_exists(&this_file));

        let parent = this_file.parent().unwrap();
        assert!(dir_exists(parent));
    }

    #[test]
    fn test_path_join() {
        let joined = path_join("/home/user", ".android");
        assert_eq!(joined, PathBuf::from("/home/user/.android"));
    }

    #[test]
    fn test_is_path_absolute() {
        assert!(is_path_absolute("/tmp"));
        assert!(!is_path_absolute("relative/path"));
    }

    #[test]
    fn test_get_env_or() {
        // Should return the value if set, or default if not.
        let val = get_env_or("PATH", "fallback");
        assert!(!val.is_empty());
        let val = get_env_or("__DOES_NOT_EXIST_12345__", "fallback");
        assert_eq!(val, "fallback");
    }

    // -- Shell argument escaping --------------------------------------------

    #[test]
    fn test_quote_arg_simple() {
        // Safe characters — returned as-is.
        assert_eq!(quote_arg("hello"), "hello");
        assert_eq!(quote_arg("foo_bar"), "foo_bar");
        assert_eq!(quote_arg("abc123"), "abc123");
    }

    #[test]
    fn test_quote_arg_spaces() {
        assert_eq!(quote_arg("hello world"), "'hello world'");
        assert_eq!(quote_arg("  "), "'  '");
    }

    #[test]
    fn test_quote_arg_embedded_quote() {
        // POSIX: single quote inside single quotes → '\''
        assert_eq!(quote_arg("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_quote_arg_empty() {
        assert_eq!(quote_arg(""), "''");
    }

    #[test]
    fn test_escape_arg() {
        // No-op for safe strings
        assert_eq!(escape_arg("hello"), "hello");

        // Space → backslash-space
        assert_eq!(escape_arg("hello world"), r"hello\ world");

        // Multiple special chars
        assert_eq!(escape_arg("a$b"), r"a\$b");
        assert_eq!(escape_arg("a'b"), r"a\'b");
    }

    #[test]
    fn test_quote_args() {
        let result = quote_args(&["adb", "shell", "echo hello"]);
        assert_eq!(result, "adb shell 'echo hello'");
    }
}
