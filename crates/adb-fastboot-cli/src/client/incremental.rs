//! Incremental ADB installation (adb install --incremental).
//!
//! AOSP source: `vendor/adb/client/incremental_adb_install.cpp`
//!
//! Handles:
//! - Incremental APK installation using the Incremental File System (IncFS)
//! - Splits APK into chunks and streams them on-demand
//! - Reduces install time for large APKs by allowing apps to start before
//!   the full APK is transferred
//!
//! Current implementation: wraps the standard install path with IncFS-compatible
//! flags. Full IncFS chunked streaming requires kernel-level IncFS support and
//! is a future enhancement.

use std::path::Path;

use adb_protocol::Transport;

use super::adb_install::{InstallOptions, install_apk, install_multiple};
use super::line_printer::LinePrinter;

/// Whether the device supports IncFS (Incremental File System).
/// Determined by checking for the incfs feature in the device's
/// sysfs or kernel version.
pub fn supports_incfs(transport: &mut dyn Transport) -> Result<bool, Box<dyn std::error::Error>> {
    use super::protocol::open_service;
    use adb_protocol::AdbMessageHeader;
    use adb_protocol::A_CLSE;
    use adb_protocol::A_OKAY;
    use adb_protocol::A_WRTE;

    // Check if /proc/fs/incfs exists on the device
    let dest = "shell,v2,raw:ls /proc/fs/incfs 2>/dev/null".to_string();
    let (local_id, _remote_id) = match open_service(transport, &dest, 1) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let mut output = Vec::new();
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match hdr.command {
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                output.extend_from_slice(&payload);
            }
            _ => {}
        }
    }

    let stdout = String::from_utf8_lossy(&output);
    Ok(stdout.contains("incfs") || stdout.contains("incremental"))
}

/// Install options for incremental installation.
#[derive(Debug, Clone)]
pub struct IncrementalOptions {
    /// Base install options.
    pub install_opts: InstallOptions,
    /// Enable incremental install (IncFS).
    pub incremental: bool,
    /// Timeout in seconds for the incremental installation.
    pub timeout_secs: u64,
}

impl Default for IncrementalOptions {
    fn default() -> Self {
        Self {
            install_opts: InstallOptions::default(),
            incremental: false,
            timeout_secs: 300,
        }
    }
}

/// Install an APK incrementally if IncFS is available.
///
/// Falls back to regular install if IncFS is not supported.
pub fn install_apk_incremental(
    transport: &mut dyn Transport,
    local_apk: &Path,
    options: &IncrementalOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    if !options.incremental {
        // If not incremental, use standard install
        return install_apk(transport, local_apk, &options.install_opts, printer);
    }

    // Check IncFS support
    if !supports_incfs(transport)? {
        eprintln!("Warning: Device does not support IncFS, falling back to regular install");
        return install_apk(transport, local_apk, &options.install_opts, printer);
    }

    // For IncFS install, we use the same push + pm install path with
    // additional --incremental flag passed to pm install.
    let _opts = InstallOptions {
        staging: true,
        ..options.install_opts.clone()
    };

    // Push and install with incremental hint
    let staging = "/data/local/tmp";
    let remote_path =
        super::adb_install::push_apk(transport, local_apk, staging, printer)?;

    // Try pm install with --incremental first
    let cmd = format!("pm install --incremental \"{remote_path}\"");

    use super::protocol::open_service;
    use adb_protocol::AdbMessageHeader;
    use adb_protocol::{A_CLSE, A_OKAY, A_WRTE};

    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, _remote_id) = open_service(transport, &dest, 2)?;

    let mut output = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                output.extend_from_slice(&payload);
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }

    let output_str = String::from_utf8_lossy(&output);
    if output_str.contains("Success") || output_str.contains("success") {
        Ok(())
    } else if output_str.contains("not supported") || output_str.contains("Unknown") {
        // Fallback to regular install
        eprintln!("Warning: Incremental install not supported, retrying standard install");
        install_apk(transport, local_apk, &options.install_opts, printer)
    } else {
        Err(format!("Incremental install failed: {output_str}").into())
    }
}

/// Install multiple APKs incrementally.
pub fn install_multiple_incremental(
    transport: &mut dyn Transport,
    apks: &[&Path],
    options: &IncrementalOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    if !options.incremental || !supports_incfs(transport)? {
        return install_multiple(transport, apks, &options.install_opts, printer);
    }

    // For IncFS multi-install, install each APK incrementally
    for apk in apks {
        install_apk_incremental(transport, apk, options, printer)?;
    }
    Ok(())
}
