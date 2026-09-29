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
            format!("pm install {}", shell_quote(apk_path))
        } else {
            format!("pm install {flags} {}", shell_quote(apk_path))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallModeRequest {
    Auto,
    Streaming,
    NoStreaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Push,
    Streamed,
}

/// Select a safe mode from the device's A_CNXN feature banner.
///
/// Streamed mode uses `exec:cmd package` and requires the peer's `cmd` feature
/// to intersect with this client's implemented feature set, matching AOSP's
/// `CanUseFeature` gate.
pub fn select_install_mode(
    device_banner: &str,
    request: InstallModeRequest,
) -> Result<InstallMode, String> {
    let device_features = adb_protocol::features::parse_banner_features(device_banner);
    let supports_cmd = adb_protocol::features::can_use_feature(&device_features, "cmd");
    match request {
        InstallModeRequest::NoStreaming => Ok(InstallMode::Push),
        InstallModeRequest::Streaming if supports_cmd => Ok(InstallMode::Streamed),
        InstallModeRequest::Streaming => {
            Err("streaming install requested but device does not support cmd".to_string())
        }
        InstallModeRequest::Auto if supports_cmd => Ok(InstallMode::Streamed),
        InstallModeRequest::Auto => Ok(InstallMode::Push),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedApk {
    remote_path: String,
    file_name: String,
    size: u64,
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn parse_install_session_id(output: &str) -> Option<String> {
    if !output.contains("Success") {
        return None;
    }
    let open = output.rfind('[')?;
    let close = output[open + 1..].find(']')? + open + 1;
    let id = &output[open + 1..close];
    if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(id.to_string())
}

fn run_shell_command(
    transport: &mut dyn Transport,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let destination = format!("shell,v2,raw:{command}");
    let (local_id, _remote_id) = open_service(transport, &destination, 1)?;
    let mut output = Vec::new();
    loop {
        let (header, payload) = transport.recv_message()?;
        match header.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, header.arg0, &[]);
                transport.send_message(&ack, &[])?;
                output.extend_from_slice(&payload);
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, header.arg0, &[]);
                transport.send_message(&ack, &[])?;
                break;
            }
            other => return Err(format!("Unexpected command while running shell: {other:#x}").into()),
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn write_exec_payload(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    payload: &[u8],
    pending_output: &mut Vec<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let header = AdbMessageHeader::new(A_WRTE, local_id, remote_id, payload);
    transport.send_message(&header, payload)?;
    loop {
        let (response, data) = transport.recv_message()?;
        match response.command {
            A_OKAY => {
                if response.arg0 != remote_id || response.arg1 != local_id {
                    return Err(format!("Unexpected A_OKAY ids ({}, {})", response.arg0, response.arg1).into());
                }
                return Ok(());
            }
            A_WRTE => {
                if response.arg0 != remote_id || response.arg1 != local_id {
                    return Err(format!("Unexpected A_WRTE ids ({}, {})", response.arg0, response.arg1).into());
                }
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                transport.send_message(&ack, &[])?;
                pending_output.push(data);
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let _ = transport.send_message(&ack, &[]);
                return Err("exec service closed before all input was sent".into());
            }
            other => return Err(format!("Unexpected exec input response: {other:#x}").into()),
        }
    }
}

fn read_exec_output(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    pending_output: Vec<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    for payload in pending_output {
        output.extend_from_slice(&payload);
    }
    loop {
        let (header, payload) = transport.recv_message()?;
        match header.command {
            A_OKAY => {}
            A_WRTE => {
                if header.arg0 != remote_id || header.arg1 != local_id {
                    return Err(format!("Unexpected A_WRTE ids ({}, {})", header.arg0, header.arg1).into());
                }
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                transport.send_message(&ack, &[])?;
                output.extend_from_slice(&payload);
            }
            A_CLSE => {
                if header.arg0 != remote_id || header.arg1 != local_id {
                    return Err(format!("Unexpected A_CLSE ids ({}, {})", header.arg0, header.arg1).into());
                }
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                transport.send_message(&ack, &[])?;
                break;
            }
            other => return Err(format!("Unexpected exec output command: {other:#x}").into()),
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn run_exec_command(
    transport: &mut dyn Transport,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let destination = format!("exec:{command}");
    let (local_id, remote_id) = open_service(transport, &destination, 1)?;
    read_exec_output(transport, local_id, remote_id, Vec::new())
}

/// Stream a single APK to `cmd package install` using the size-delimited exec service.
/// The APK bytes are raw A_WRTE payloads; `-S` tells package manager when input is complete.
pub fn install_apk_streamed(
    transport: &mut dyn Transport,
    local_apk: &Path,
    options: &InstallOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let extension = local_apk.extension().and_then(|value| value.to_str()).unwrap_or_default();
    if !extension.eq_ignore_ascii_case("apk") {
        return Err("streamed install currently supports .apk files only".into());
    }
    let file_size = fs::metadata(local_apk)?.len();
    let mut file = fs::File::open(local_apk)?;
    let flags = options.to_pm_flags().join(" ");
    let command = if flags.is_empty() {
        format!("cmd package install -S {file_size}")
    } else {
        format!("cmd package install {flags} -S {file_size}")
    };
    let destination = format!("exec:{command}");
    let (local_id, remote_id) = open_service(transport, &destination, 1)?;

    let mut pending_output = Vec::new();
    let mut chunk = vec![0u8; SYNC_DATA_MAX];
    let mut bytes_sent = 0u64;
    loop {
        let length = file.read(&mut chunk)?;
        if length == 0 {
            break;
        }
        write_exec_payload(transport, local_id, remote_id, &chunk[..length], &mut pending_output)?;
        bytes_sent += length as u64;
    }
    if bytes_sent != file_size {
        return Err(format!("APK changed while streaming: expected {file_size} bytes, sent {bytes_sent}").into());
    }

    let output = read_exec_output(transport, local_id, remote_id, pending_output)?;
    if output.lines().any(|line| line.starts_with("Success")) {
        Ok(output)
    } else {
        Err(format!("Streamed install failed: {}", output.trim()).into())
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

    let (local_id, remote_id) = open_service(transport, "sync:", 1)?;

    // Build SEND request: remote_path,mode
    let mut send_buf = Vec::new();
    // mode 0644 (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
    build_sync_send_req(&remote_path, 0x81a4, &mut send_buf)?;
    send_wrte(transport, local_id, remote_id, &send_buf)?;

    // Read the sync OKAY after SEND request
    recv_sync_response(transport, local_id, remote_id)?;

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
        send_wrte(transport, local_id, remote_id, &data_buf)?;
        bytes_sent += n as u64;
        printer.update(bytes_sent);
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0, &mut done_buf)?;
    send_wrte(transport, local_id, remote_id, &done_buf)?;

    // Read final sync response
    recv_sync_response(transport, local_id, remote_id)?;

    // Close the sync stream before opening the next one.
    let close = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&close, &[])?;
    loop {
        let (header, payload) = transport.recv_message()?;
        match header.command {
            // We initiated this close, so the peer CLSE completes the handshake; do not echo it.
            A_CLSE => break,
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, header.arg0, &[]);
                transport.send_message(&ack, &[])?;
                if !payload.is_empty() {
                    return Err("Unexpected sync payload while closing stream".into());
                }
            }
            A_OKAY => {}
            other => return Err(format!("Unexpected sync close command: {other:#x}").into()),
        }
    }

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
    let command = options.to_pm_install_cmd(&remote_path);
    let install_result = run_exec_command(transport, &command);
    let cleanup_command = format!("rm {} </dev/null", shell_quote(&remote_path));
    let _ = run_exec_command(transport, &cleanup_command);
    let output = install_result?;
    if output.lines().any(|line| line.starts_with("Success")) {
        Ok(())
    } else {
        Err(format!("Install failed: {}", output.trim()).into())
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
    let mut staged = Vec::with_capacity(apks.len());
    let mut names = std::collections::HashSet::with_capacity(apks.len());
    let mut total_size = 0u64;

    // Validate every local input before making any remote changes.
    for apk in apks {
        let file_name = apk
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Invalid APK filename")?
            .to_string();
        if Path::new(&file_name)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("apex"))
        {
            return Err("APEX packages are not compatible with install-multiple".into());
        }
        if !names.insert(file_name.clone()) {
            return Err(format!("Duplicate APK filename: {file_name}").into());
        }
        let size = fs::metadata(apk)?.len();
        total_size = total_size
            .checked_add(size)
            .ok_or("Combined APK size overflows u64")?;
        staged.push(StagedApk {
            remote_path: format!("{staging}/{file_name}"),
            file_name,
            size,
        });
    }

    // If any push fails, remove all planned paths, including a partially written file.
    for (apk, staged_apk) in apks.iter().zip(&staged) {
        if let Err(error) = push_apk(transport, apk, staging, printer) {
            cleanup_staged_apks(transport, &staged);
            return Err(error);
        }
        debug_assert_eq!(
            staged_apk.remote_path,
            format!("{staging}/{}", staged_apk.file_name)
        );
    }

    let install_result = install_staged_multiple(transport, &staged, total_size, options);
    cleanup_staged_apks(transport, &staged);
    install_result
}

fn cleanup_staged_apks(transport: &mut dyn Transport, apks: &[StagedApk]) {
    for apk in apks {
        let cleanup = format!("rm {} </dev/null", shell_quote(&apk.remote_path));
        let _ = run_shell_command(transport, &cleanup);
    }
}

fn install_staged_multiple(
    transport: &mut dyn Transport,
    apks: &[StagedApk],
    total_size: u64,
    options: &InstallOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let flags = options.to_pm_flags().join(" ");
    let create_command = if flags.is_empty() {
        format!("pm install-create -S {total_size}")
    } else {
        format!("pm install-create -S {total_size} {flags}")
    };
    let create_output = run_shell_command(transport, &create_command)?;
    let session_id = parse_install_session_id(&create_output)
        .ok_or_else(|| format!("Failed to create install session: {}", create_output.trim()))?;

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for apk in apks {
            let write_command = format!(
                "pm install-write -S {} {} {} - < {}",
                apk.size,
                session_id,
                shell_quote(&apk.file_name),
                shell_quote(&apk.remote_path),
            );
            let output = run_shell_command(transport, &write_command)?;
            if !output.contains("Success") {
                return Err(format!("install-write failed for {}: {}", apk.file_name, output.trim()).into());
            }
        }

        let commit_command = format!("pm install-commit {session_id}");
        let output = run_shell_command(transport, &commit_command)?;
        if !output.contains("Success") {
            return Err(format!("install-commit failed for session {session_id}: {}", output.trim()).into());
        }
        Ok(())
    })();

    if result.is_err() {
        let abandon_command = format!("pm install-abandon {session_id}");
        let _ = run_shell_command(transport, &abandon_command);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use adb_protocol::{SyncMessageHeader, TransportError, SYNC_OKAY};

    struct FakeTransport {
        incoming: VecDeque<(AdbMessageHeader, Vec<u8>)>,
        opened_services: Vec<String>,
        fail_install_write: bool,
        close_pending: bool,
        host_close_response_pending: bool,
    }

    impl FakeTransport {
        fn new(fail_install_write: bool) -> Self {
            Self {
                incoming: VecDeque::new(),
                opened_services: Vec::new(),
                fail_install_write,
                close_pending: false,
                host_close_response_pending: false,
            }
        }

        fn enqueue(&mut self, command: u32, arg0: u32, arg1: u32, payload: &[u8]) {
            self.incoming.push_back((
                AdbMessageHeader::new(command, arg0, arg1, payload),
                payload.to_vec(),
            ));
        }

        fn enqueue_sync_okay(&mut self, remote_id: u32, local_id: u32) {
            let mut payload = [0u8; SyncMessageHeader::SIZE];
            SyncMessageHeader::new(SYNC_OKAY, 0).encode(&mut payload);
            self.enqueue(A_WRTE, remote_id, local_id, &payload);
        }

        fn shell_output(&self, command: &str) -> &'static [u8] {
            if command.contains("pm install-create") {
                b"Success: created install session [42]\n"
            } else if command.contains("pm install-write") && self.fail_install_write {
                b"Failure: injected write error\n"
            } else {
                b"Success\n"
            }
        }
    }

    impl Read for FakeTransport {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for FakeTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Transport for FakeTransport {
        fn send_message(
            &mut self,
            header: &AdbMessageHeader,
            payload: &[u8],
        ) -> Result<(), TransportError> {
            const REMOTE_ID: u32 = 41;
            match header.command {
                adb_protocol::A_OPEN => {
                    let destination = String::from_utf8_lossy(payload).into_owned();
                    self.opened_services.push(destination.clone());
                    self.enqueue(A_OKAY, REMOTE_ID, header.arg0, &[]);
                    let command = destination
                        .strip_prefix("shell,v2,raw:")
                        .or_else(|| destination.strip_prefix("exec:"));
                    if let Some(command) = command {
                        let output = self.shell_output(command);
                        self.enqueue(A_WRTE, REMOTE_ID, header.arg0, output);
                        self.close_pending = true;
                        self.enqueue(A_CLSE, REMOTE_ID, header.arg0, &[]);
                    }
                }
                A_WRTE => {
                    if header.arg1 != REMOTE_ID {
                        return Err(TransportError::Protocol(format!(
                            "host wrote to stream {}, expected {REMOTE_ID}",
                            header.arg1
                        )));
                    }
                    self.enqueue(A_OKAY, REMOTE_ID, header.arg0, &[]);
                    if payload.starts_with(b"SEND") || payload.starts_with(b"DONE") {
                        self.enqueue_sync_okay(REMOTE_ID, header.arg0);
                    }
                }
                A_CLSE => {
                    if header.arg1 != REMOTE_ID {
                        return Err(TransportError::Protocol(format!(
                            "host closed stream {}, expected {REMOTE_ID}",
                            header.arg1
                        )));
                    }
                    if self.close_pending {
                        self.close_pending = false;
                    } else {
                        self.enqueue(A_CLSE, header.arg1, header.arg0, &[]);
                        self.host_close_response_pending = true;
                    }
                }
                _ => {}
            }
            Ok(())
        }

        fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
            let message = self.incoming.pop_front().ok_or_else(|| {
                TransportError::Protocol("fake peer has no queued response".to_string())
            })?;
            if message.0.command == A_CLSE && self.host_close_response_pending {
                self.host_close_response_pending = false;
            }
            Ok(message)
        }
    }

    fn fixture_apks() -> (PathBuf, Vec<PathBuf>) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "adb-install-multiple-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        let first = root.join("base.apk");
        let second = root.join("split'cfg.apk");
        fs::write(&first, b"base").unwrap();
        fs::write(&second, b"split!").unwrap();
        (root, vec![first, second])
    }

    fn shell_commands(peer: &FakeTransport) -> Vec<String> {
        peer.opened_services
            .iter()
            .filter_map(|service| service.strip_prefix("shell,v2,raw:"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn install_multiple_uses_one_session_and_commits_after_all_writes() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(false);
        let mut printer = LinePrinter::new();
        let options = InstallOptions {
            reinstall: true,
            ..Default::default()
        };

        install_multiple(&mut peer, &references, &options, &mut printer).unwrap();

        let commands = shell_commands(&peer);
        let transaction: Vec<&str> = commands
            .iter()
            .map(String::as_str)
            .filter(|command| command.starts_with("pm install-"))
            .collect();
        assert_eq!(
            transaction,
            [
                "pm install-create -S 10 -r",
                "pm install-write -S 4 42 'base.apk' - < '/data/local/tmp/base.apk'",
                "pm install-write -S 6 42 'split'\\''cfg.apk' - < '/data/local/tmp/split'\\''cfg.apk'",
                "pm install-commit 42",
            ]
        );
        assert!(commands.iter().any(|command| command == "rm '/data/local/tmp/base.apk' </dev/null"));
        assert!(commands.iter().any(|command| command.contains("pm install-write")));
        assert!(!commands.iter().any(|command| command.contains("pm install-abandon")));
        assert!(!peer.close_pending);
        assert!(!peer.host_close_response_pending);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_abandons_session_after_write_failure() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(true);
        let mut printer = LinePrinter::new();
        let result = install_multiple(
            &mut peer,
            &references,
            &InstallOptions::default(),
            &mut printer,
        );

        assert!(result.is_err());
        let commands = shell_commands(&peer);
        assert!(commands.iter().any(|command| command == "pm install-abandon 42"));
        assert!(!commands.iter().any(|command| command == "pm install-commit 42"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_rejects_apex_before_opening_remote_services() {
        let (root, _) = fixture_apks();
        let apex = root.join("bundle.apex");
        fs::write(&apex, b"apex").unwrap();
        let mut peer = FakeTransport::new(false);
        let mut printer = LinePrinter::new();

        let result = install_multiple(
            &mut peer,
            &[apex.as_path()],
            &InstallOptions::default(),
            &mut printer,
        );

        assert!(result.unwrap_err().to_string().contains("APEX"));
        assert!(peer.opened_services.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    struct FakeExecTransport {
        incoming: VecDeque<(AdbMessageHeader, Vec<u8>)>,
        opened_services: Vec<String>,
        streamed_bytes: Vec<u8>,
        expected_size: Option<usize>,
        install_succeeds: bool,
        close_pending: bool,
    }

    impl FakeExecTransport {
        fn new(install_succeeds: bool) -> Self {
            Self {
                incoming: VecDeque::new(),
                opened_services: Vec::new(),
                streamed_bytes: Vec::new(),
                expected_size: None,
                install_succeeds,
                close_pending: false,
            }
        }

        fn enqueue(&mut self, command: u32, arg0: u32, arg1: u32, payload: &[u8]) {
            self.incoming.push_back((
                AdbMessageHeader::new(command, arg0, arg1, payload),
                payload.to_vec(),
            ));
        }
    }

    impl Read for FakeExecTransport {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for FakeExecTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Transport for FakeExecTransport {
        fn send_message(
            &mut self,
            header: &AdbMessageHeader,
            payload: &[u8],
        ) -> Result<(), TransportError> {
            const REMOTE_ID: u32 = 73;
            match header.command {
                adb_protocol::A_OPEN => {
                    let destination = String::from_utf8_lossy(payload).into_owned();
                    let (_, size) = destination
                        .rsplit_once(" -S ")
                        .ok_or_else(|| TransportError::Protocol("stream command lacks -S".into()))?;
                    self.expected_size = Some(
                        size.parse::<usize>()
                            .map_err(|error| TransportError::Protocol(error.to_string()))?,
                    );
                    self.opened_services.push(destination);
                    self.enqueue(A_OKAY, REMOTE_ID, header.arg0, &[]);
                }
                A_WRTE => {
                    if header.arg1 != REMOTE_ID {
                        return Err(TransportError::Protocol(format!(
                            "host wrote to stream {}, expected {REMOTE_ID}",
                            header.arg1
                        )));
                    }
                    self.streamed_bytes.extend_from_slice(payload);
                    self.enqueue(A_OKAY, REMOTE_ID, header.arg0, &[]);
                    if self.expected_size == Some(self.streamed_bytes.len()) {
                        let output: &[u8] = if self.install_succeeds {
                            b"Success: streamed install\n"
                        } else {
                            b"Failure: package rejected\n"
                        };
                        self.enqueue(A_WRTE, REMOTE_ID, header.arg0, output);
                        self.close_pending = true;
                        self.enqueue(A_CLSE, REMOTE_ID, header.arg0, &[]);
                    }
                }
                A_CLSE => {
                    if header.arg1 != REMOTE_ID || !self.close_pending {
                        return Err(TransportError::Protocol("unexpected A_CLSE".into()));
                    }
                    self.close_pending = false;
                }
                _ => {}
            }
            Ok(())
        }

        fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
            self.incoming.pop_front().ok_or_else(|| {
                TransportError::Protocol("fake exec peer has no queued response".to_string())
            })
        }
    }

    #[test]
    fn install_mode_selection_uses_device_cmd_feature_and_explicit_override() {
        let capable = "device::ro.product.name=test;features=shell_v2,cmd";
        let legacy = "device::ro.product.name=test;features=shell_v2";
        assert_eq!(
            select_install_mode(capable, InstallModeRequest::Auto),
            Ok(InstallMode::Streamed)
        );
        assert_eq!(
            select_install_mode(capable, InstallModeRequest::NoStreaming),
            Ok(InstallMode::Push)
        );
        assert_eq!(
            select_install_mode(legacy, InstallModeRequest::Auto),
            Ok(InstallMode::Push)
        );
        assert!(select_install_mode(legacy, InstallModeRequest::Streaming)
            .unwrap_err()
            .contains("does not support cmd"));
    }

    #[test]
    fn pm_install_command_shell_quotes_apk_path() {
        assert_eq!(
            InstallOptions::default().to_pm_install_cmd("folder/a'b.apk"),
            r#"pm install 'folder/a'\''b.apk'"#
        );
    }

    #[test]
    fn streamed_install_sends_raw_apk_bytes_and_reads_exec_result() {
        let (root, paths) = fixture_apks();
        let mut peer = FakeExecTransport::new(true);
        let output = install_apk_streamed(
            &mut peer,
            &paths[0],
            &InstallOptions { reinstall: true, ..Default::default() },
        )
        .unwrap();

        assert!(output.starts_with("Success"));
        assert_eq!(peer.opened_services, ["exec:cmd package install -r -S 4"]);
        assert_eq!(peer.streamed_bytes, b"base");
        assert!(!peer.close_pending);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streamed_install_returns_device_failure_output() {
        let (root, paths) = fixture_apks();
        let mut peer = FakeExecTransport::new(false);
        let error = install_apk_streamed(&mut peer, &paths[0], &InstallOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("package rejected"));
        assert_eq!(peer.streamed_bytes, b"base");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_apk_push_mode_uses_sync_then_exec_pm_and_cleans_up() {
        let (root, paths) = fixture_apks();
        let mut peer = FakeTransport::new(false);
        let mut printer = LinePrinter::new();
        install_apk(
            &mut peer,
            &paths[0],
            &InstallOptions { reinstall: true, ..Default::default() },
            &mut printer,
        )
        .unwrap();

        assert!(peer.opened_services.iter().any(|service| service == "sync:"));
        assert!(peer.opened_services.iter().any(|service| {
            service == "exec:pm install -r '/data/local/tmp/base.apk'"
        }));
        assert!(peer.opened_services.iter().any(|service| {
            service == "exec:rm '/data/local/tmp/base.apk' </dev/null"
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_session_id_parser_rejects_failure_and_malformed_ids() {
        assert_eq!(
            parse_install_session_id("Success: created install session [42]"),
            Some("42".to_string())
        );
        assert_eq!(parse_install_session_id("Failure [42]"), None);
        assert_eq!(parse_install_session_id("Success [not-a-number]"), None);
        assert_eq!(parse_install_session_id("Success [42"), None);
    }
}
