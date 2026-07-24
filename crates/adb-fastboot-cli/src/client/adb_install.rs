//! ADB application installation (adb install / adb install-multi-package).
//!
//! AOSP source: `vendor/adb/client/adb_install.cpp`
//!
//! Handles:
//! - `adb install <apk>` — push APK + run INSTALL command
//! - `adb install-multiple` — multiple APK split install
//! - `adb install-multi-package` — atomic multi-package install
//! - Progress reporting, verification, staging

use std::fs;
use std::io::Read;
use std::path::Path;

use adb_protocol::{
    AdbMessageHeader, Transport,
    build_sync_send_req, build_sync_data_chunk, build_sync_done,
    A_CLSE, A_OKAY, A_WRTE,
};

use super::protocol::{open_service, send_wrte, recv_sync_response};
use super::line_printer::LinePrinter;

const SYNC_DATA_MAX: usize = 64 * 1024;

/// Install options flags (mirrors adb install -r -d -g etc.).
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Reinstall (replace existing package, -r).
    pub reinstall: bool,
    /// Allow downgrade (-d).
    pub downgrade: bool,
    /// Grant all runtime permissions (-g).
    pub grant_permissions: bool,
    /// Forward-lock the app (-l).
    pub forward_lock: bool,
    /// Test APK (-t).
    pub test: bool,
    /// Install on external storage (-s).
    pub install_external: bool,
    /// Allow version code downgrade for splits as well.
    pub allow_downgrade: bool,
    /// Enable staging for multi-package transactions.
    pub staging: bool,
    /// Wait for the device after install
    pub wait: bool,
}

impl InstallOptions {
    /// Build the `-r -d -g ...` flags string for `pm install`.
    pub fn to_pm_flags(&self) -> Vec<String> {
        let mut flags = Vec::new();
        if self.reinstall { flags.push("-r".to_string()); }
        if self.downgrade { flags.push("-d".to_string()); }
        if self.grant_permissions { flags.push("-g".to_string()); }
        if self.forward_lock { flags.push("-l".to_string()); }
        if self.test { flags.push("-t".to_string()); }
        if self.install_external { flags.push("-s".to_string()); }
        if self.allow_downgrade { flags.push("--downgrade".to_string()); }
        if self.staging { flags.push("--staging".to_string()); }
        flags
    }

    /// Build the full `pm install` command string.
    pub fn to_pm_install_cmd(&self, apk_path: &str) -> String {
        let flags = self.to_pm_flags().join(" ");
        if flags.is_empty() {
            format!("pm install \"{apk_path}\"")
        } else {
            format!("pm install {flags} \"{apk_path}\"")
        }
    }
}

/// Push a single APK file to the device via sync protocol and install it.
///
/// Returns the remote staging path on success.
pub fn push_apk(
    transport: &mut dyn Transport,
    local_apk: &Path,
    remote_staging_dir: &str,
    printer: &mut LinePrinter,
) -> Result<String, Box<dyn std::error::Error>> {
    let file_name = local_apk
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid APK filename")?;
    let remote_path = format!("{remote_staging_dir}/{file_name}");

    let file_size = fs::metadata(local_apk)?.len();
    let mut file = fs::File::open(local_apk)?;

    // Open sync: service
    let (local_id, _remote_id) = open_service(transport, "sync:", 1)?;

    // Build SEND request: remote_path,mode
    let mut send_buf = Vec::new();
    // mode 0644 (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
    build_sync_send_req(&remote_path, 0x81a4, &mut send_buf)?;
    send_wrte(transport, local_id, 1, &send_buf)?;

    // Read the sync OKAY after SEND request
    recv_sync_response(transport, local_id, 1)?;

    // Stream file data in chunks
    let mut chunk_buf = vec![0u8; SYNC_DATA_MAX];
    let mut bytes_sent: u64 = 0;

    printer.set_max(file_size);

    loop {
        let n = file.read(&mut chunk_buf)?;
        if n == 0 {
            break;
        }
        let mut data_buf = Vec::new();
        build_sync_data_chunk(&chunk_buf[..n], &mut data_buf)?;
        send_wrte(transport, local_id, 1, &data_buf)?;
        bytes_sent += n as u64;
        printer.update(bytes_sent);
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0, &mut done_buf)?;
    send_wrte(transport, local_id, 1, &done_buf)?;

    // Read final sync response
    recv_sync_response(transport, local_id, 1)?;

    printer.finish();
    Ok(remote_path)
}

/// Install an APK after pushing it to the device.
pub fn install_apk(
    transport: &mut dyn Transport,
    local_apk: &Path,
    options: &InstallOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    let staging = "/data/local/tmp";
    let remote_path = push_apk(transport, local_apk, staging, printer)?;

    // Run pm install via shell
    let cmd = options.to_pm_install_cmd(&remote_path);
    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, _remote_id) = open_service(transport, &dest, 2)?;

    // Read shell output
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
    } else {
        Err(format!("Install failed: {output_str}").into())
    }
}

/// Install multiple APKs (split APKs) as a batch.
pub fn install_multiple(
    transport: &mut dyn Transport,
    apks: &[&Path],
    options: &InstallOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    if apks.is_empty() {
        return Err("No APK files provided".into());
    }

    let staging = "/data/local/tmp";
    let mut remote_paths = Vec::new();

    for apk in apks {
        let remote = push_apk(transport, apk, staging, printer)?;
        remote_paths.push(remote);
    }

    // Build pm install-create / pm install-write / pm install-commit commands
    // For simplicity, use `pm install` on the base APK which handles splits
    let cmd = {
        let base = &remote_paths[0];
        let flags = options.to_pm_flags().join(" ");
        if remote_paths.len() == 1 {
            if flags.is_empty() {
                format!("pm install \"{base}\"")
            } else {
                format!("pm install {flags} \"{base}\"")
            }
        } else {
            // Use pm install-create / write / commit for real split installs
            let create_flags = options.to_pm_flags().join(" ");
            let mut cmds = Vec::new();
            let session = format!("pm install-create {create_flags}");
            cmds.push(session);
            for path in &remote_paths {
                let name = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("split.apk");
                cmds.push(format!("pm install-write -S {} {} \"{}\"",
                    fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                    "$(pm install-create 2>&1 | grep -o '[0-9]\\+' | head -1)",
                    name));
            }
            cmds.push("pm install-commit $(pm install-create 2>&1 | grep -o '[0-9]\\+' | head -1)".to_string());
            cmds.join(" && ")
        }
    };

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
    } else {
        Err(format!("Multi-install failed: {output_str}").into())
    }
}

/// Uninstall a package from the device via `pm uninstall`.
pub fn uninstall_package(
    transport: &mut dyn Transport,
    package_name: &str,
    keep_data: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let cmd = if keep_data {
        format!("pm uninstall -k \"{package_name}\"")
    } else {
        format!("pm uninstall \"{package_name}\"")
    };
    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, _remote_id) = open_service(transport, &dest, 1)?;

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

    let result = String::from_utf8_lossy(&output).to_string();
    Ok(result)
}

/// Get list of installed packages via `pm list packages`.
pub fn list_packages(
    transport: &mut dyn Transport,
    filter: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cmd = match filter {
        Some(f) => format!("pm list packages -f \"{f}\""),
        None => "pm list packages -f".to_string(),
    };
    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, _remote_id) = open_service(transport, &dest, 1)?;

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

    let result = String::from_utf8_lossy(&output);
    let packages: Vec<String> = result
        .lines()
        .filter(|l| l.starts_with("package:"))
        .map(|l| l.trim_start_matches("package:").to_string())
        .collect();
    Ok(packages)
}
