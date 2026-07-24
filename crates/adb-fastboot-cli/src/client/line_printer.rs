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

use std::io::Write;
use std::time::Instant;

/// A line-based progress printer for ADB operations.
///
/// When connected to a terminal, it uses `\r` to overwrite the current
/// line with an updated progress percentage and optional speed/ETA.
/// When not connected to a terminal, it prints a new line for each update.
#[derive(Debug)]
pub struct LinePrinter {
    /// Total size in bytes (for progress calculation).
    total: u64,
    /// Whether we've been told to show a progress bar.
    show_bar: bool,
    /// Whether connected to a TTY.
    is_tty: bool,
    /// Width of the progress bar in characters.
    bar_width: usize,
    /// Last update time (for speed calculation).
    last_update: Option<Instant>,
    /// Last reported progress value.
    last_value: u64,
    /// Whether we've printed anything (for initial newline).
    started: bool,
    /// Start time (for ETA).
    start_time: Instant,
    /// Cumulative bytes processed.
    cumulative: u64,
    /// Whether to print to stderr (true) or stdout.
    use_stderr: bool,
}

impl LinePrinter {
    /// Create a new line printer with default settings.
    pub fn new() -> Self {
        let is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) != 0 };
        Self {
            total: 0,
            show_bar: true,
            is_tty,
            bar_width: 40,
            last_update: None,
            last_value: 0,
            started: false,
            start_time: Instant::now(),
            cumulative: 0,
            use_stderr: true,
        }
    }

    /// Set whether to show a progress bar or just text.
    pub fn set_show_bar(&mut self, show: bool) {
        self.show_bar = show;
    }

    /// Set the maximum value (total bytes).
    pub fn set_max(&mut self, total: u64) {
        self.total = total;
        self.start_time = Instant::now();
        self.cumulative = 0;
    }

    /// Update the progress with current value.
    pub fn update(&mut self, current: u64) {
        self.cumulative = current;
        self.last_value = current;
        self.last_update = Some(Instant::now());
        self.render();
    }

    /// Advance progress by `delta` bytes from the last known position.
    pub fn advance(&mut self, delta: u64) {
        self.cumulative += delta;
        self.last_value = self.cumulative;
        self.last_update = Some(Instant::now());
        self.render();
    }

    /// Print a plain text line (progress message, not bar).
    pub fn println(&mut self, msg: &str) {
        let out: Box<dyn Write> = if self.use_stderr {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };
        let mut out = out;
        if self.is_tty && self.started {
            // Clear current progress line first
            let _ = write!(out, "\r{}\r", " ".repeat(80));
        }
        let _ = writeln!(out, "{msg}");
        let _ = out.flush();
        self.started = true;
    }

    /// Finish the progress display (print newline).
    pub fn finish(&mut self) {
        let out: Box<dyn Write> = if self.use_stderr {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };
        let mut out = out;
        if self.is_tty {
            let _ = writeln!(out);
        } else {
            let elapsed = self.start_time.elapsed();
            let total = self.cumulative;
            let speed = if elapsed.as_secs() > 0 {
                total / elapsed.as_secs() as u64
            } else {
                total
            };
            let _ = writeln!(
                out,
                "{} bytes transferred in {:.1}s ({}/s)",
                total,
                elapsed.as_secs_f64(),
                format_size(speed)
            );
        }
        let _ = out.flush();
        self.started = false;
    }

    /// Render the current progress line.
    fn render(&mut self) {
        let out: Box<dyn Write> = if self.use_stderr {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };
        let mut out = out;

        if self.is_tty {
            // TTY mode: overwrite current line with \r
            let current = self.cumulative;
            let elapsed = self.start_time.elapsed();

            if self.show_bar && self.total > 0 {
                let pct = (current as f64 / self.total as f64 * 100.0).min(100.0);
                let filled = ((pct / 100.0) * self.bar_width as f64) as usize;
                let empty = self.bar_width.saturating_sub(filled);

                let bar: String = if filled > 0 {
                    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
                } else {
                    "░".repeat(self.bar_width)
                };

                let speed = if elapsed.as_secs_f64() > 0.0 {
                    current as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                let eta = if speed > 0.0 && current < self.total {
                    let remaining = (self.total - current) as f64 / speed;
                    format!(" ETA {:>4}s", remaining as u64)
                } else {
                    String::new()
                };

                let _ = write!(
                    out,
                    "\r{bar} {:5.1}% {:>8}/s{eta}  ",
                    pct,
                    format_size(speed as u64)
                );
            } else {
                // Plain text progress
                let speed = if elapsed.as_secs_f64() > 0.0 {
                    current as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };
                let _ = write!(
                    out,
                    "\r{:>8} bytes ({:>8}/s)   ",
                    format_size(current),
                    format_size(speed as u64),
                );
            }
        } else {
            // Non-TTY: print new line
            let current = self.cumulative;
            if self.total > 0 {
                let pct = (current as f64 / self.total as f64 * 100.0).min(100.0);
                let _ = writeln!(
                    out,
                    "{} / {} ({:.1}%)",
                    format_size(current),
                    format_size(self.total),
                    pct
                );
            } else {
                let _ = writeln!(out, "{} bytes", format_size(current));
            }
        }
        let _ = out.flush();
        self.started = true;
    }
}

impl Default for LinePrinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a byte count as a human-readable size string.
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let unit_idx = ((bytes as f64).log10() / 3.0) as usize;
    let unit_idx = unit_idx.min(UNITS.len() - 1);
    let value = bytes as f64 / 1000u64.pow(unit_idx as u32) as f64;
    format!("{:.1} {}", value, UNITS[unit_idx])
}

/// Print a one-line message with optional leading newline.
pub fn print_line(msg: &str) {
    eprintln!("{msg}");
}

/// Print a simple progress percentage without a stored `LinePrinter`.
pub fn print_progress(current: u64, total: u64) {
    if total == 0 {
        eprint!("\r{} bytes   ", format_size(current));
    } else {
        let pct = (current as f64 / total as f64 * 100.0).min(100.0);
        eprint!("\r{:.1}%   ", pct);
    }
    let _ = std::io::stderr().flush();
}

/// Print a final done message with elapsed time.
pub fn print_done(elapsed: std::time::Duration) {
    eprintln!("\rDone in {:.1}s", elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(500), "500.0 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1_500_000), "1.5 MB");
        assert_eq!(format_size(2_500_000_000), "2.5 GB");
    }
}
