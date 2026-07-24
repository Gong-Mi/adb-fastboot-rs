//! Line-based progress printer for ADB operations.
//!
//! AOSP source: `vendor/adb/client/line_printer.cpp`
//!
//! Provides a line-oriented progress display for operations like:
//! - `adb install` (APK push progress)
//! - `adb sync` (file sync progress)
//! - `adb backup` (backup stream progress)
//!
//! Features:
//! - Overwrites the current line for in-place progress updates
//! - Falls back to newline-separated output when not connected to a TTY
//! - Supports progress bar rendering
//!
//! TODO: Implement LinePrinter with terminal-aware output (stderr with \r).
//! TODO: Support progress bar rendering with percentage and ETA.
//! TODO: Handle non-TTY fallback (newline-separated output).
