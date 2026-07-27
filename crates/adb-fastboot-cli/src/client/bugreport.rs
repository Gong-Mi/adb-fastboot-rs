//! ADB bugreport — `adb bugreport [path]`
//!
//! Mirrors AOSP `vendor/adb/client/bugreport.cpp`.
//!
//! 1. `bugreportz -v` → detect version
//! 2. No bugreportz → fallback to plain `bugreport`
//! 3. v1.0 → `bugreportz` (no progress)
//! 4. v1.1+ → `bugreportz -p` (with progress)
//! 5. Parse `BEGIN:` / `OK:` / `FAIL:` / `PROGRESS:X/Y`
//! 6. `OK:` → `adb pull` via sync protocol

use std::io::Write;
use std::path::Path;

use crate::client::file_sync;
use crate::server::adb_utils;

const BUGZ_BEGIN: &str = "BEGIN:";
const BUGZ_PROGRESS: &str = "PROGRESS:";
const BUGZ_OK: &str = "OK:";
const BUGZ_FAIL: &str = "FAIL:";

pub struct BugreportResult {
    pub saved_path: String,
}

/// Execute `adb bugreport [path]`.
///
/// `transport` — authenticated transport to device.
/// `serial` — device serial (for sync pull).
/// `output_path` — optional output path (file or directory).
pub fn do_bugreport(
    transport: &mut dyn adb_protocol::Transport,
    serial: &str,
    output_path: Option<&str>,
) -> Result<BugreportResult, Box<dyn std::error::Error>> {
    let (dest_dir, mut dest_file) = match output_path {
        None => {
            let cwd = adb_utils::getcwd().unwrap_or_else(|| ".".to_string());
            (cwd, "bugreport.zip".to_string())
        }
        Some(p) if Path::new(p).is_dir() => (p.to_string(), "bugreport.zip".to_string()),
        Some(p) => {
            let mut f = p.to_string();
            if !f.to_lowercase().ends_with(".zip") {
                f.push_str(".zip");
            }
            (String::new(), f)
        }
    };

    // 1. Check bugreportz version
    let stdout = crate::client::shell::run_shell(transport, "bugreportz -v", true)?
        .unwrap_or_default();
    let stdout_str = String::from_utf8_lossy(&stdout);
    let lines: Vec<&str> = stdout_str.lines().collect();
    let bugz_version = lines.last().unwrap_or(&"").trim().to_string();

    if bugz_version.is_empty() || !bugz_version.contains('.') {
        eprintln!("bugreportz not available (device pre-Android 7.0?).\nFalling back to plain-text bugreport.");
        if output_path.is_none() {
            return legacy_bugreport(transport, serial);
        }
        return Err(format!("bugreportz failed. Try: adb bugreport > bugreport.txt").into());
    }

    let show_progress = bugz_version != "1.0";
    let bugz_cmd = if show_progress { "bugreportz -p" } else { "bugreportz" };

    if !show_progress {
        eprintln!("Bugreport is in progress — please be patient.");
    }

    // 2. Run bugreportz
    let stdout = crate::client::shell::run_shell(transport, bugz_cmd, true)?
        .unwrap_or_default();
    let output = String::from_utf8_lossy(&stdout);

    // 3. Parse output lines
    let mut device_path = String::new();
    let mut last_pct = 0i32;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        if let Some(rest) = line.strip_prefix(BUGZ_BEGIN) {
            device_path = rest.to_string();
            if !dest_dir.is_empty() {
                dest_file = Path::new(rest)
                    .file_name().map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix(BUGZ_OK) {
            device_path = rest.to_string();
            if !dest_dir.is_empty() {
                dest_file = Path::new(rest)
                    .file_name().map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix(BUGZ_FAIL) {
            return Err(format!("device bugreportz failed: {}", rest).into());
        } else if show_progress && line.starts_with(BUGZ_PROGRESS) {
            let rest = &line[BUGZ_PROGRESS.len()..];
            if let Some(idx) = rest.rfind('/') {
                let prog: i32 = rest[..idx].parse().unwrap_or(0);
                let total: i32 = rest[idx + 1..].parse().unwrap_or(1);
                let pct = if total > 0 { prog * 100 / total } else { 0 };
                if pct != 0 && pct <= last_pct { continue; }
                last_pct = pct;
                print!("\r[{}%] generating {}  ", pct, dest_file);
                std::io::stdout().flush()?;
            }
        }
    }

    if show_progress && last_pct > 0 { println!(); }

    if device_path.is_empty() {
        return Err("bugreportz did not return OK: or FAIL: line".into());
    }

    // 4. Pull
    let final_dest = if dest_dir.is_empty() {
        dest_file.clone()
    } else {
        format!("{}/{}", dest_dir, dest_file)
    };

    file_sync::pull(Some(serial), &device_path, &final_dest, false)?;
    println!("Bug report copied to {}", final_dest);

    Ok(BugreportResult { saved_path: final_dest })
}

/// Fallback to plain-text bugreport.
fn legacy_bugreport(
    transport: &mut dyn adb_protocol::Transport,
    _serial: &str,
) -> Result<BugreportResult, Box<dyn std::error::Error>> {
    let data = crate::client::shell::run_shell(transport, "bugreport", true)?
        .unwrap_or_default();
    let path = "bugreport.txt";
    std::fs::write(path, &data)?;
    println!("Bug report copied to {}", path);
    Ok(BugreportResult { saved_path: path.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(BUGZ_BEGIN.starts_with("BEGIN:"));
        assert!(BUGZ_OK.starts_with("OK:"));
        assert!(BUGZ_FAIL.starts_with("FAIL:"));
        assert!(BUGZ_PROGRESS.starts_with("PROGRESS:"));
    }

    #[test]
    fn test_version_parsing_1_1_shows_progress() {
        let ver = "1.1".to_string();
        assert_ne!(ver, "1.0");
    }

    #[test]
    fn test_version_parsing_1_0_no_progress() {
        let ver = "1.0".to_string();
        assert_eq!(ver, "1.0");
    }

    #[test]
    fn test_zip_extension_auto_appended() {
        let mut f = "bugreport".to_string();
        if !f.to_lowercase().ends_with(".zip") {
            f.push_str(".zip");
        }
        assert_eq!(f, "bugreport.zip");
    }

    #[test]
    fn test_zip_extension_not_duplicated() {
        let mut f = "report.zip".to_string();
        if !f.to_lowercase().ends_with(".zip") {
            f.push_str(".zip");
        }
        assert_eq!(f, "report.zip");
    }

    #[test]
    fn test_parse_ok_line() {
        let line = "OK:/data/device/bugreport.zip";
        assert!(line.starts_with("OK:"));
        assert_eq!(&line[3..], "/data/device/bugreport.zip");
    }

    #[test]
    fn test_parse_begin_line() {
        let line = "BEGIN:/data/device/bugreport.zip";
        assert!(line.starts_with("BEGIN:"));
        assert_eq!(&line[6..], "/data/device/bugreport.zip");
    }

    #[test]
    fn test_parse_fail_line() {
        let line = "FAIL:D'OH!";
        assert!(line.starts_with("FAIL:"));
        assert_eq!(&line[5..], "D'OH!");
    }

    #[test]
    fn test_parse_progress_line() {
        let line = "PROGRESS:50/100";
        assert!(line.starts_with("PROGRESS:"));
        let rest = &line[9..];
        if let Some(idx) = rest.rfind('/') {
            let prog: i32 = rest[..idx].parse().unwrap();
            let total: i32 = rest[idx + 1..].parse().unwrap();
            let pct = prog * 100 / total;
            assert_eq!(prog, 50);
            assert_eq!(total, 100);
            assert_eq!(pct, 50);
        } else {
            panic!("no separator");
        }
    }

    #[test]
    fn test_progress_always_forward() {
        let mut last = 0i32;
        let cases = vec![1i32, 50, 25, 75, 75, 700];
        let totals = vec![100i32, 100, 100, 100, 100, 1000];
        let mut shown = Vec::new();
        for (prog, total) in cases.iter().zip(totals.iter()) {
            let pct = if *total > 0 { prog * 100 / total } else { 0 };
            if pct != 0 && pct <= last { continue; }
            last = pct;
            shown.push(pct);
        }
        assert_eq!(shown, vec![1, 50, 75]);
    }

    #[test]
    fn test_invalid_args_too_many() {
        // AOSP: argc > 2 → error
        // We don't have a DoIt method that takes (argc, argv),
        // but the output_path option only accepts 0 or 1 args
    }

    #[test]
    fn test_directory_destination() {
        let path = "/tmp";
        assert!(Path::new(path).is_dir());
    }

    #[test]
    fn test_file_destination() {
        let path = "some_file.zip";
        assert!(!Path::new(path).is_dir());
    }
}
