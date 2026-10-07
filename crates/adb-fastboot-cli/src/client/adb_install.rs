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
use std::path::{Path, PathBuf};

use adb_protocol::{
    AdbMessageHeader, Transport,
    build_sync_send_req, build_sync_data_chunk, build_sync_done,
    escape_arg,
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
    /// Explicit streaming preference (Some(true) = --streaming, Some(false) = --no-streaming, None = default auto-detect).
    pub streaming: Option<bool>,
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
    /// AOSP `INSTALL_INCREMENTAL` (adb_install.cpp:52-58).
    Incremental,
}

/// AOSP `send_command` (adb_install.cpp:152-158) transport selection:
/// when the device advertises `abb_exec` (adb_install.cpp:73-76) install
/// commands go to the in-process binder bridge service `abb_exec:` with
/// NUL-joined args (client/commandline.h:212-222,
/// `ABB_ARG_DELIMITER = '\0'`, adb.h:205); otherwise they go to
/// `exec:cmd package ...` (or `exec:pm ...` for the legacy pm path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTransport {
    /// `abb_exec:arg\0arg...` — raw args, no shell escaping (adb_install.cpp:215-217).
    AbbExec,
    /// `exec:cmd package ...` with `escape_arg`-escaped args (adb_install.cpp:210-223).
    ExecCmd,
    /// `exec:pm ...` with escaped args — legacy push-mode path (adb_install.cpp:610-613).
    ExecPm,
}

/// Whether the device advertises the `abb_exec` feature (AOSP
/// `is_abb_exec_supported()`, adb_install.cpp:73-76). Incremental installs
/// require it (calculate_install_mode, adb_install.cpp:371-377).
pub fn abb_exec_supported(device_banner: &str) -> bool {
    let device_features = adb_protocol::features::parse_banner_features(device_banner);
    adb_protocol::features::can_use_feature(&device_features, "abb_exec")
}

impl CommandTransport {
    /// Pick the transport from the device banner (AOSP `is_abb_exec_supported()`).
    pub fn from_banner(device_banner: &str) -> Self {
        if abb_exec_supported(device_banner) {
            CommandTransport::AbbExec
        } else {
            CommandTransport::ExecCmd
        }
    }

    /// Whether `.apex` inputs are accepted (AOSP `is_apex_supported()`,
    /// adb_install.cpp:68-70).
    pub fn apex_supported(device_banner: &str) -> bool {
        let device_features = adb_protocol::features::parse_banner_features(device_banner);
        adb_protocol::features::can_use_feature(&device_features, "apex")
    }

    /// Build the service destination string. `args` are final wire tokens:
    /// AOSP escapes only user-provided passthrough options with
    /// `escape_arg` (adb_install.cpp:213-223); programmatic tokens (`-S`,
    /// size, session id, `-`, basenames) are pushed raw upstream, so they
    /// arrive here raw too.
    ///
    /// - AbbExec: `abb_exec:package\0<arg>\0...` — raw, NUL-joined.
    /// - ExecCmd: `exec:cmd package <args...>`.
    /// - ExecPm:  `exec:pm <args...>`.
    pub fn service_string(&self, args: &[String]) -> String {
        match self {
            CommandTransport::AbbExec => {
                // ABB_ARG_DELIMITER = '\0' (adb.h:205): NUL-joined raw args.
                let mut service = String::from("abb_exec:package");
                for arg in args {
                    service.push('\0');
                    service.push_str(arg);
                }
                service
            }
            CommandTransport::ExecCmd => {
                let mut service = String::from("exec:cmd package");
                for arg in args {
                    service.push(' ');
                    service.push_str(arg);
                }
                service
            }
            CommandTransport::ExecPm => {
                let mut service = String::from("exec:pm");
                for arg in args {
                    service.push(' ');
                    service.push_str(arg);
                }
                service
            }
        }
    }
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

/// AOSP `CmdlineOption` (adb_install.cpp:44-49): the `--incremental` /
/// `--no-incremental` command-line request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdlineIncremental {
    None,
    Enable,
    Disable,
}

/// AOSP `android::base::ParseBool` (libbase/strings.cpp): exact-match
/// lowercase tokens only; anything else is unparseable (`None`).
pub fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "yes" | "on" | "true" => Some(true),
        "0" | "n" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}

/// AOSP `calculate_install_mode` (adb_install.cpp:353-415): resolve the
/// primary install mode and optional fallback.
///
/// The `(Incremental, Some(regular))` result is the incremental-by-default
/// posture: attempt incremental silently, fall back to the regular mode on
/// failure. `probe_device_default` performs the device-side gate
/// (`settings get global enable_adb_incremental_install_default`) and is only
/// invoked when the abb_exec / env / mode-from-args gates allow it; the
/// closure's `None` means "unparseable or unavailable" (incremental stays on).
pub fn calculate_install_mode(
    mode_from_args: Option<InstallMode>,
    incremental_request: CmdlineIncremental,
    abb_exec_supported: bool,
    env_value: Option<String>,
    best_mode: InstallMode,
    mut probe_device_default: impl FnMut() -> Option<bool>,
) -> Result<(InstallMode, Option<InstallMode>), String> {
    // (`--incremental` vs `--fastdeploy` cannot conflict here: this port has
    // no --fastdeploy flag.)
    if let Some(mode) = mode_from_args {
        if incremental_request == CmdlineIncremental::Enable {
            return Err("--incremental is not compatible with other installation modes".to_string());
        }
        return Ok((mode, None));
    }

    let mut request = incremental_request;
    if request != CmdlineIncremental::Disable && !abb_exec_supported {
        if request == CmdlineIncremental::None {
            request = CmdlineIncremental::Disable;
        } else {
            return Err("Device doesn't support incremental installations".to_string());
        }
    }
    if request == CmdlineIncremental::None {
        // Check whether the host is OK with incremental by default.
        if let Some(value) = env_value.as_deref() {
            if parse_bool(value) == Some(false) {
                request = CmdlineIncremental::Disable;
            }
        }
    }
    if request == CmdlineIncremental::None {
        // Still OK: ask the device whether it allows incremental by default.
        if probe_device_default() == Some(false) {
            request = CmdlineIncremental::Disable;
        }
    }

    if request == CmdlineIncremental::Enable {
        // Explicitly requested — no fallback.
        return Ok((InstallMode::Incremental, None));
    }
    if request == CmdlineIncremental::None {
        // No opinion — use incremental, fall back to regular on failure.
        return Ok((InstallMode::Incremental, Some(best_mode)));
    }
    // Incremental turned off — the regular best mode without a fallback.
    Ok((best_mode, None))
}

/// AOSP calculate_install_mode's device gate (adb_install.cpp:391-408): ask
/// the device for `settings get global enable_adb_incremental_install_default`.
///
/// Returns the parsed value (`None` = unparseable/missing), or an error when
/// the probe command itself failed. Deviation note: upstream feeds
/// `read_status_line`'s buffer (trailing newline included) straight into
/// `ParseBool`, which makes the gate effectively inert; this port trims the
/// line before parsing so an explicit `false` actually disables.
pub fn probe_incremental_default_disabled(
    transport: &mut dyn Transport,
) -> Result<Option<bool>, String> {
    const SERVICE: &str = "abb_exec:settings\0get\0global\0enable_adb_incremental_install_default";
    let (local_id, remote_id) =
        super::protocol::open_service(transport, SERVICE, 1).map_err(|e| e.to_string())?;
    let output =
        read_exec_output(transport, local_id, remote_id, Vec::new()).map_err(|e| e.to_string())?;
    let first_line = output.lines().next().unwrap_or("");
    Ok(parse_bool(first_line.trim()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedApk {
    remote_path: String,
    file_name: String,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MultiPackageApk {
    local_path: PathBuf,
    split_name: String,
    size: u64,
    is_apex: bool,
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

pub(crate) fn write_exec_payload(
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

pub(crate) fn read_exec_output(
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

/// Execute a package-manager command over the AOSP `send_command` transport
/// (adb_install.cpp:152-158): `abb_exec:` when the device supports it,
/// `exec:` otherwise. `args` exclude the program prefix.
fn run_install_command(
    transport: &mut dyn Transport,
    cmd_transport: CommandTransport,
    args: &[String],
) -> Result<String, Box<dyn std::error::Error>> {
    let destination = cmd_transport.service_string(args);
    let (local_id, remote_id) = open_service(transport, &destination, 1)?;
    read_exec_output(transport, local_id, remote_id, Vec::new())
}

/// Stream a local file into a package-manager write command over the AOSP
/// `send_command` transport (adb_install.cpp:666-690): the command is
/// `abb_exec:...` or `exec:cmd package install-write -S <size> <session>
/// <name> -`, and the file bytes flow as raw A_WRTE payloads.
fn stream_file_to_install_command(
    transport: &mut dyn Transport,
    cmd_transport: CommandTransport,
    args: &[String],
    local_file: &Path,
    expected_file_size: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let file_size = fs::metadata(local_file)?.len();
    if file_size != expected_file_size {
        return Err(format!(
            "Input file changed before streaming: expected {expected_file_size} bytes, found {file_size}"
        )
        .into());
    }
    let mut file = fs::File::open(local_file)?;
    let destination = cmd_transport.service_string(args);
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
        return Err(format!("Input file changed while streaming: expected {file_size} bytes, sent {bytes_sent}").into());
    }
    read_exec_output(transport, local_id, remote_id, pending_output)
}

/// Stream a single package to `cmd package install` using the size-delimited
/// command transport (AOSP install_app_streamed, adb_install.cpp:160-253):
/// `.apk` always accepted; `.apex` requires the device `apex` feature and
/// appends `--apex`. The payload bytes are raw A_WRTE frames; `-S` tells
/// package manager when input is complete.
pub fn install_apk_streamed(
    transport: &mut dyn Transport,
    local_apk: &Path,
    options: &InstallOptions,
    cmd_transport: CommandTransport,
    device_banner: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let extension = local_apk.extension().and_then(|value| value.to_str()).unwrap_or_default();
    let is_apex = extension.eq_ignore_ascii_case("apex");
    if !extension.eq_ignore_ascii_case("apk") && !is_apex {
        return Err(format!("filename doesn't end .apk or .apex: {}", local_apk.display()).into());
    }
    if is_apex && !CommandTransport::apex_supported(device_banner) {
        return Err(".apex is not supported on the target device".into());
    }
    let file_size = fs::metadata(local_apk)?.len();
    let mut args: Vec<String> = vec!["install".to_string()];
    args.extend(options.to_pm_flags());
    args.push("-S".to_string());
    args.push(file_size.to_string());
    if is_apex {
        args.push("--apex".to_string());
    }
    let output = stream_file_to_install_command(
        transport,
        cmd_transport,
        &args,
        local_apk,
        file_size,
    )?;
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
        .and_then(|name| name.to_str())
        .ok_or("Invalid APK filename")?;
    let remote_path = format!("{remote_staging_dir}/{file_name}");
    push_apk_to_path(transport, local_apk, &remote_path, printer)?;
    Ok(remote_path)
}

fn push_apk_to_path(
    transport: &mut dyn Transport,
    local_apk: &Path,
    remote_path: &str,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = fs::metadata(local_apk)?.len();
    let mut file = fs::File::open(local_apk)?;
    let (local_id, remote_id) = open_service(transport, "sync:", 1)?;

    let mut send_buf = Vec::new();
    build_sync_send_req(remote_path, 0x81a4, &mut send_buf)?;
    // A_OKAY only acknowledges WRTE(SEND); SYNC_OKAY is the final result.
    send_wrte(transport, local_id, remote_id, &send_buf)?;

    let mut chunk_buf = vec![0u8; SYNC_DATA_MAX];
    let mut bytes_sent = 0u64;
    printer.set_max(file_size);
    loop {
        let length = file.read(&mut chunk_buf)?;
        if length == 0 {
            break;
        }
        let mut data_buf = Vec::new();
        build_sync_data_chunk(&chunk_buf[..length], &mut data_buf)?;
        send_wrte(transport, local_id, remote_id, &data_buf)?;
        bytes_sent += length as u64;
        printer.update(bytes_sent);
    }
    if bytes_sent != file_size {
        return Err(format!("APK changed while pushing: expected {file_size} bytes, sent {bytes_sent}").into());
    }

    let mut done_buf = Vec::new();
    build_sync_done(0, &mut done_buf)?;
    send_wrte(transport, local_id, remote_id, &done_buf)?;
    recv_sync_response(transport, local_id, remote_id)?;

    let close = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&close, &[])?;
    loop {
        let (header, payload) = transport.recv_message()?;
        match header.command {
            // We initiated this close; the peer CLSE completes the handshake.
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
    Ok(())
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
    device_banner: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if apks.is_empty() {
        return Err("No APK files provided".into());
    }

    let staging = "/data/local/tmp";
    let mut staged = Vec::with_capacity(apks.len());
    let mut names = std::collections::HashSet::with_capacity(apks.len());
    let mut total_size = 0u64;

    // Validate every local input before making any remote changes.
    // Accepted extensions mirror AOSP install_multiple_app_streamed
    // (adb_install.cpp:541-546): .apk, .dm, .sdm, .fsv_sig, .idsig;
    // .apex is rejected (adb_install.cpp:539-540).
    for apk in apks {
        let file_name = apk
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Invalid APK filename")?
            .to_string();
        let extension = Path::new(&file_name)
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .unwrap_or_default();
        match extension.as_str() {
            "apex" => {
                return Err("APEX packages are not compatible with install-multiple".into());
            }
            "apk" | "dm" | "sdm" | "fsv_sig" | "idsig" => {}
            _ => {
                return Err(format!(
                    "install-multiple accepts .apk/.dm/.sdm/.fsv_sig/.idsig files only, got: {file_name}"
                )
                .into());
            }
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

    if options.streaming == Some(true) {
        return install_multiple_streamed(
            transport,
            apks,
            total_size,
            options,
            CommandTransport::from_banner(device_banner),
        );
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

fn install_multiple_streamed(
    transport: &mut dyn Transport,
    apks: &[&Path],
    total_size: u64,
    options: &InstallOptions,
    cmd_transport: CommandTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut create_args: Vec<String> = vec!["install-create".to_string(), "-S".to_string(), total_size.to_string()];
    create_args.extend(options.to_pm_flags());
    let create_output = run_install_command(transport, cmd_transport, &create_args)?;
    let session_id = parse_install_session_id(&create_output)
        .ok_or_else(|| format!("Failed to create streamed install session: {}", create_output.trim()))?;

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for apk in apks {
            let file_name = apk
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("Invalid APK filename")?;
            let size = fs::metadata(apk)?.len();
            let write_args = vec![
                "install-write".to_string(),
                "-S".to_string(),
                size.to_string(),
                session_id.clone(),
                file_name.to_string(),
                "-".to_string(),
            ];
            let output = stream_file_to_install_command(transport, cmd_transport, &write_args, apk, size)?;
            if !output.lines().any(|line| line.starts_with("Success")) {
                return Err(format!(
                    "install-write failed for {file_name}: {}",
                    output.trim()
                )
                .into());
            }
        }

        let commit_args = vec!["install-commit".to_string(), session_id.clone()];
        let commit_output = run_install_command(transport, cmd_transport, &commit_args)?;
        if !commit_output.lines().any(|line| line.starts_with("Success")) {
            return Err(format!(
                "install-commit failed for session {session_id}: {}",
                commit_output.trim()
            )
            .into());
        }
        Ok(())
    })();

    if result.is_err() {
        let abandon_args = vec!["install-abandon".to_string(), session_id.clone()];
        let _ = run_install_command(transport, cmd_transport, &abandon_args);
    }
    result
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

fn split_package_argument(argument: &str) -> Vec<&str> {
    #[cfg(windows)]
    {
        argument.split(';').collect()
    }
    #[cfg(not(windows))]
    {
        argument.split(':').collect()
    }
}

/// Atomically install one APK (or a colon-separated split set) per package argument.
pub fn install_multi_package(
    transport: &mut dyn Transport,
    package_arguments: &[String],
    device_banner: &str,
    options: &InstallOptions,
    staged_ready_timeout: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if package_arguments.is_empty() {
        return Err("No packages provided".into());
    }
    select_install_mode(device_banner, InstallModeRequest::Streaming)?;

    let mut packages: Vec<Vec<MultiPackageApk>> = Vec::with_capacity(package_arguments.len());
    for (package_index, argument) in package_arguments.iter().enumerate() {
        let splits = split_package_argument(argument);
        if splits.is_empty() || splits.iter().any(|split| split.is_empty()) {
            return Err(format!("Invalid empty split path in package argument: {argument}").into());
        }
        let mut basenames = std::collections::HashSet::with_capacity(splits.len());
        let mut package = Vec::with_capacity(splits.len());
        for split in splits {
            let local_path = Path::new(split);
            if !local_path.is_file() {
                return Err(format!("APK not found or not a regular file: {split}").into());
            }
            let file_name = local_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("Invalid APK filename")?;
            let extension = local_path.extension().and_then(|value| value.to_str()).unwrap_or_default();
            let is_apex = extension.eq_ignore_ascii_case("apex");
            if !extension.eq_ignore_ascii_case("apk") && !is_apex {
                return Err(format!("Expected an .apk or .apex input, got {split}").into());
            }
            if !basenames.insert(file_name.to_string()) {
                return Err(format!("Duplicate split basename in package {argument}: {file_name}").into());
            }
            let size = fs::metadata(local_path)?.len();
            package.push(MultiPackageApk {
                local_path: local_path.to_path_buf(),
                split_name: format!("{}_{}", package_index + 1, file_name),
                size,
                is_apex,
            });
        }
        packages.push(package);
    }

    install_multi_package_sessions(
        transport,
        &packages,
        options,
        CommandTransport::from_banner(device_banner),
        CommandTransport::apex_supported(device_banner),
        staged_ready_timeout,
    )
}

fn install_multi_package_sessions(
    transport: &mut dyn Transport,
    packages: &[Vec<MultiPackageApk>],
    options: &InstallOptions,
    cmd_transport: CommandTransport,
    apex_supported: bool,
    staged_ready_timeout: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // AOSP install_multi_package (adb_install.cpp:756-758, 803-815): any
    // .apex input flips the whole transaction into staged mode — parent
    // install-create gets --staged, child install-create gets --staged and
    // the APEX child additionally --apex.
    let apex_found = packages
        .iter()
        .flatten()
        .any(|apk| apk.is_apex);
    if apex_found && !apex_supported {
        return Err(".apex is not supported on the target device".into());
    }
    let mut parent_args: Vec<String> = vec!["install-create".to_string(), "--multi-package".to_string()];
    parent_args.extend(options.to_pm_flags());
    if apex_found {
        parent_args.push("--staged".to_string());
    }
    let parent_output = run_install_command(transport, cmd_transport, &parent_args)?;
    let parent_id = parse_install_session_id(&parent_output).ok_or_else(|| {
        format!("Failed to create multi-package parent session: {}", parent_output.trim())
    })?;
    let mut child_ids = Vec::with_capacity(packages.len());

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for package in packages {
            let mut child_args: Vec<String> = vec!["install-create".to_string()];
            child_args.extend(options.to_pm_flags());
            // AOSP: every child session gets --staged when apex_found;
            // a child whose first split is an .apex additionally gets --apex
            // (adb_install.cpp:803-815 — the APEX command template applies to
            // any package argument containing an .apex file).
            let package_has_apex = package.iter().any(|apk| apk.is_apex);
            if apex_found {
                child_args.push("--staged".to_string());
                if package_has_apex {
                    child_args.push("--apex".to_string());
                }
            }
            let child_output = run_install_command(transport, cmd_transport, &child_args)?;
            let child_id = parse_install_session_id(&child_output)
                .ok_or_else(|| format!("Failed to create child session: {}", child_output.trim()))?;
            child_ids.push(child_id.clone());

            for apk in package {
                let write_args = vec![
                    "install-write".to_string(),
                    "-S".to_string(),
                    apk.size.to_string(),
                    child_id.clone(),
                    apk.split_name.clone(),
                    "-".to_string(),
                ];
                let output = stream_file_to_install_command(
                    transport,
                    cmd_transport,
                    &write_args,
                    &apk.local_path,
                    apk.size,
                )?;
                if !output.lines().any(|line| line.starts_with("Success")) {
                    return Err(format!(
                        "install-write failed for child session {child_id}, split {}: {}",
                        apk.split_name,
                        output.trim()
                    )
                    .into());
                }
            }
        }

        let mut add_args = vec!["install-add-session".to_string(), parent_id.clone()];
        add_args.extend(child_ids.iter().cloned());
        let add_output = run_install_command(transport, cmd_transport, &add_args)?;
        if !add_output.lines().any(|line| line.starts_with("Success")) {
            return Err(format!("install-add-session failed: {}", add_output.trim()).into());
        }

        let mut commit_args = vec!["install-commit".to_string()];
        // AOSP forwards `--staged-ready-timeout <value>` to install-commit
        // verbatim (adb_install.cpp:930-941).
        if let Some(timeout) = staged_ready_timeout {
            commit_args.push("--staged-ready-timeout".to_string());
            commit_args.push(timeout.to_string());
        }
        commit_args.push(parent_id.clone());
        let commit_output = run_install_command(transport, cmd_transport, &commit_args)?;
        if !commit_output.lines().any(|line| line.starts_with("Success")) {
            return Err(format!("parent install-commit failed: {}", commit_output.trim()).into());
        }
        Ok(())
    })();

    if result.is_err() {
        let abandon_args = vec!["install-abandon".to_string(), parent_id.clone()];
        let _ = run_install_command(transport, cmd_transport, &abandon_args);
        for child_id in &child_ids {
            let abandon_args = vec!["install-abandon".to_string(), child_id.clone()];
            let _ = run_install_command(transport, cmd_transport, &abandon_args);
        }
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

    use adb_protocol::{SyncMessageHeader, TransportError, SYNC_DATA, SYNC_DONE, SYNC_FAIL, SYNC_OKAY, SYNC_SEND};

    #[test]
    fn parse_bool_matches_libbase_exactly() {
        for true_token in ["1", "y", "yes", "on", "true"] {
            assert_eq!(parse_bool(true_token), Some(true), "{true_token}");
        }
        for false_token in ["0", "n", "no", "off", "false"] {
            assert_eq!(parse_bool(false_token), Some(false), "{false_token}");
        }
        // Exact-match, lowercase only — anything else is unparseable.
        for garbage in ["", "False", "TRUE", "false ", "null", "2"] {
            assert_eq!(parse_bool(garbage), None, "{garbage:?}");
        }
    }

    #[test]
    fn calculate_install_mode_matches_aosp_gates() {
        use CmdlineIncremental::{Disable, Enable, None as NoRequest};
        let never = || -> Option<bool> { panic!("device probe must not run") };

        // Explicit --incremental: no fallback, conflicts with a mode flag.
        assert_eq!(
            calculate_install_mode(None, Enable, true, None, InstallMode::Streamed, never),
            Ok((InstallMode::Incremental, None))
        );
        assert_eq!(
            calculate_install_mode(
                Some(InstallMode::Streamed),
                Enable,
                true,
                None,
                InstallMode::Streamed,
                never
            ),
            Err("--incremental is not compatible with other installation modes".to_string())
        );
        // Explicit --incremental without abb_exec: hard error.
        assert_eq!(
            calculate_install_mode(None, Enable, false, None, InstallMode::Streamed, never),
            Err("Device doesn't support incremental installations".to_string())
        );

        // Mode from args wins; --no-incremental is compatible with it.
        assert_eq!(
            calculate_install_mode(
                Some(InstallMode::Push),
                Disable,
                true,
                None,
                InstallMode::Streamed,
                never
            ),
            Ok((InstallMode::Push, None))
        );

        // No abb_exec → gate off, no env/probe consultation.
        assert_eq!(
            calculate_install_mode(None, NoRequest, false, None, InstallMode::Push, never),
            Ok((InstallMode::Push, None))
        );

        // Env gate: "false" (libbase token) disables; garbage keeps the default.
        assert_eq!(
            calculate_install_mode(
                None,
                NoRequest,
                true,
                Some("false".to_string()),
                InstallMode::Streamed,
                never
            ),
            Ok((InstallMode::Streamed, None))
        );
        assert_eq!(
            calculate_install_mode(
                None,
                NoRequest,
                true,
                Some("0".to_string()),
                InstallMode::Streamed,
                never
            ),
            Ok((InstallMode::Streamed, None))
        );

        // Device gate: probed only when earlier gates allow.
        assert_eq!(
            calculate_install_mode(
                None,
                NoRequest,
                true,
                None,
                InstallMode::Streamed,
                || Some(false)
            ),
            Ok((InstallMode::Streamed, None))
        );
        assert_eq!(
            calculate_install_mode(
                None,
                NoRequest,
                true,
                None,
                InstallMode::Streamed,
                || Some(true)
            ),
            Ok((InstallMode::Incremental, Some(InstallMode::Streamed)))
        );
        // Unparseable/unavailable probe → incremental stays on (with fallback).
        assert_eq!(
            calculate_install_mode(None, NoRequest, true, None, InstallMode::Push, || None),
            Ok((InstallMode::Incremental, Some(InstallMode::Push)))
        );
        // Garbage env keeps incremental on too, and the probe then runs.
        assert_eq!(
            calculate_install_mode(
                None,
                NoRequest,
                true,
                Some("garbage".to_string()),
                InstallMode::Streamed,
                || None
            ),
            Ok((InstallMode::Incremental, Some(InstallMode::Streamed)))
        );
    }

    #[derive(Clone, Copy)]
    enum SyncOutcome { Okay, Fail, Disconnect }

    struct FakeTransport {
        incoming: VecDeque<(AdbMessageHeader, Vec<u8>)>,
        opened_services: Vec<String>,
        fail_install_write: bool,
        fail_install_add: bool,
        next_session_id: u32,
        active_stream: Option<(String, usize, Vec<u8>)>,
        streamed_splits: Vec<(String, Vec<u8>)>,
        expected_pushes: VecDeque<(String, Vec<u8>)>,
        active_sync: Option<(String, Vec<u8>, Vec<u8>)>,
        staged_apks: Vec<(String, Vec<u8>)>,
        sync_outcome: SyncOutcome,
        close_pending: bool,
        host_close_response_pending: bool,
    }

    impl FakeTransport {
        fn new(fail_install_write: bool) -> Self {
            Self {
                incoming: VecDeque::new(),
                opened_services: Vec::new(),
                fail_install_write,
                fail_install_add: false,
                next_session_id: 42,
                active_stream: None,
                streamed_splits: Vec::new(),
                expected_pushes: VecDeque::new(),
                active_sync: None,
                staged_apks: Vec::new(),
                sync_outcome: SyncOutcome::Okay,
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

        fn expect_pushes(&mut self, paths: &[PathBuf]) {
            self.expected_pushes = paths.iter().map(|path| (
                format!("/data/local/tmp/{}", path.file_name().unwrap().to_str().unwrap()),
                fs::read(path).unwrap(),
            )).collect();
        }

        fn accept_sync(&mut self, payload: &[u8], remote_id: u32, local_id: u32) {
            let header = SyncMessageHeader::decode(payload).unwrap();
            let data = &payload[8..];
            match header.id {
                SYNC_SEND => {
                    assert!(self.active_sync.is_none());
                    assert_eq!(header.length as usize, data.len());
                    let (path, bytes) = self.expected_pushes.pop_front().expect("unexpected staged SEND");
                    assert_eq!(data, format!("{path},{}", 0x81a4).as_bytes());
                    self.active_sync = Some((path, bytes, Vec::new()));
                    // A_OKAY was queued by send_message; there is no SYNC_OKAY here.
                }
                SYNC_DATA => {
                    assert_eq!(header.length as usize, data.len());
                    assert!(data.len() <= SYNC_DATA_MAX);
                    let (_, expected, received) = self.active_sync.as_mut().expect("DATA before SEND");
                    received.extend_from_slice(data);
                    assert!(received.len() <= expected.len());
                    assert_eq!(received.as_slice(), &expected[..received.len()]);
                }
                SYNC_DONE => {
                    assert_eq!(header.length, 0, "staged DONE mtime changed");
                    assert!(data.is_empty());
                    let (path, expected, received) = self.active_sync.take().expect("DONE before SEND");
                    assert_eq!(received, expected, "incomplete staged APK");
                    self.staged_apks.push((path, received));
                    let (id, message): (u32, &[u8]) = match self.sync_outcome {
                        SyncOutcome::Okay => (SYNC_OKAY, b""),
                        SyncOutcome::Fail => (SYNC_FAIL, b"staging rejected"),
                        SyncOutcome::Disconnect => {
                            self.enqueue(A_CLSE, remote_id, local_id, &[]);
                            self.close_pending = true;
                            return;
                        }
                    };
                    let mut header = [0u8; 8];
                    SyncMessageHeader::new(id, message.len() as u32).encode(&mut header);
                    self.enqueue(A_WRTE, remote_id, local_id, &[header.as_slice(), message].concat());
                }
                other => panic!("unexpected staged SYNC request {other:#x}"),
            }
        }

        fn shell_output(&mut self, command: &str) -> Vec<u8> {
            if command.contains("install-create") {
                let id = self.next_session_id;
                self.next_session_id += 1;
                format!("Success: created install session [{id}]\n").into_bytes()
            } else if command.contains("install-write") && self.fail_install_write {
                b"Failure: injected write error\n".to_vec()
            } else if command.contains("install-add-session") && self.fail_install_add {
                b"Failure: injected link error\n".to_vec()
            } else {
                b"Success\n".to_vec()
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
                        if command.starts_with("cmd package install-write ") {
                            let words: Vec<&str> = command.split_whitespace().collect();
                            let size_index = words.iter().position(|word| *word == "-S").unwrap() + 1;
                            let expected_size = words[size_index].parse::<usize>().unwrap();
                            self.active_stream = Some((command.to_string(), expected_size, Vec::new()));
                        } else {
                            let output = self.shell_output(command);
                            self.enqueue(A_WRTE, REMOTE_ID, header.arg0, &output);
                            self.close_pending = true;
                            self.enqueue(A_CLSE, REMOTE_ID, header.arg0, &[]);
                        }
                    }
                }
                A_WRTE => {
                    if header.arg1 != REMOTE_ID {
                        return Err(TransportError::Protocol(format!(
                            "host wrote to stream {}, expected {REMOTE_ID}",
                            header.arg1
                        )));
                    }
                    let stream_complete = if let Some((_, expected_size, streamed)) = self.active_stream.as_mut() {
                        streamed.extend_from_slice(payload);
                        Some(streamed.len() == *expected_size)
                    } else {
                        None
                    };
                    self.enqueue(A_OKAY, REMOTE_ID, header.arg0, &[]);
                    match stream_complete {
                        Some(true) => {
                            let (command, _, bytes) = self.active_stream.take().unwrap();
                            self.streamed_splits.push((command.clone(), bytes));
                            let output = self.shell_output(&command);
                            self.enqueue(A_WRTE, REMOTE_ID, header.arg0, &output);
                            self.close_pending = true;
                            self.enqueue(A_CLSE, REMOTE_ID, header.arg0, &[]);
                        }
                        Some(false) => {}
                        None => self.accept_sync(payload, REMOTE_ID, header.arg0),
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

    fn exec_commands(peer: &FakeTransport) -> Vec<String> {
        peer.opened_services
            .iter()
            .filter_map(|service| service.strip_prefix("exec:"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn install_multiple_uses_one_session_and_commits_after_all_writes() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(false);
        peer.expect_pushes(&paths);
        let mut printer = LinePrinter::new();
        let options = InstallOptions {
            reinstall: true,
            ..Default::default()
        };

        install_multiple(&mut peer, &references, &options, &mut printer, "device::features=cmd,shell_v2").unwrap();

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
        assert_eq!(peer.staged_apks.iter().map(|(_, bytes)| bytes.as_slice()).collect::<Vec<_>>(), [b"base".as_slice(), b"split!".as_slice()]);
        assert!(peer.expected_pushes.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_abandons_session_after_write_failure() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(true);
        peer.expect_pushes(&paths);
        let mut printer = LinePrinter::new();
        let result = install_multiple(
            &mut peer,
            &references,
            &InstallOptions::default(),
            &mut printer,
            "device::features=cmd,shell_v2",
        );

        assert!(result.is_err());
        let commands = shell_commands(&peer);
        assert!(commands.iter().any(|command| command == "pm install-abandon 42"));
        assert!(!commands.iter().any(|command| command == "pm install-commit 42"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_streamed_uses_direct_stream_writes_and_commits() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(false);
        let mut printer = LinePrinter::new();
        let options = InstallOptions {
            streaming: Some(true),
            reinstall: true,
            ..Default::default()
        };

        install_multiple(&mut peer, &references, &options, &mut printer, "device::features=cmd,shell_v2").unwrap();

        let commands = exec_commands(&peer);
        assert_eq!(
            commands,
            vec![
                "cmd package install-create -S 10 -r".to_string(),
                "cmd package install-write -S 4 42 base.apk -".to_string(),
                "cmd package install-write -S 6 42 split'cfg.apk -".to_string(),
                "cmd package install-commit 42".to_string(),
            ]
        );
        // Direct stream: no staging pushes, no rm cleanups!
        assert!(!peer.opened_services.iter().any(|s| s.contains("sync:")));
        assert!(!peer.opened_services.iter().any(|s| s.contains("rm ")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_streamed_abandons_session_on_write_failure() {
        let (root, paths) = fixture_apks();
        let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(true);
        let mut printer = LinePrinter::new();
        let options = InstallOptions {
            streaming: Some(true),
            ..Default::default()
        };

        let result = install_multiple(&mut peer, &references, &options, &mut printer, "device::features=cmd,shell_v2");
        assert!(result.is_err());
        let commands = exec_commands(&peer);
        assert!(commands.iter().any(|cmd| cmd == "cmd package install-abandon 42"));
        assert!(!commands.iter().any(|cmd| cmd == "cmd package install-commit 42"));
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
            "device::features=cmd,shell_v2",
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
                    // Flatten abb_exec's NUL-joined args to spaces so the
                    // trailing "-S <size>" parse works for both transports;
                    // a "--apex" suffix after the size is cut by the
                    // take-while(digit) below.
                    let flattened = if let Some(rest) = destination.strip_prefix("abb_exec:") {
                        rest.split('\0').collect::<Vec<_>>().join(" ")
                    } else {
                        destination.clone()
                    };
                    let (_, size) = flattened
                        .rsplit_once(" -S ")
                        .ok_or_else(|| TransportError::Protocol("stream command lacks -S".into()))?;
                    let size_token: String = size
                        .chars()
                        .take_while(|character| character.is_ascii_digit())
                        .collect();
                    self.expected_size = Some(
                        size_token
                            .parse::<usize>()
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
            CommandTransport::ExecCmd,
            "device::features=cmd,shell_v2",
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
        let error = install_apk_streamed(
            &mut peer,
            &paths[0],
            &InstallOptions::default(),
            CommandTransport::ExecCmd,
            "device::features=cmd,shell_v2",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("package rejected"));
        assert_eq!(peer.streamed_bytes, b"base");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streamed_install_uses_abb_exec_service_with_nul_joined_args() {
        let (root, paths) = fixture_apks();
        let mut peer = FakeExecTransport::new(true);
        let output = install_apk_streamed(
            &mut peer,
            &paths[0],
            &InstallOptions { reinstall: true, ..Default::default() },
            CommandTransport::AbbExec,
            "device::features=cmd,shell_v2,abb_exec",
        )
        .unwrap();

        assert!(output.starts_with("Success"));
        assert_eq!(
            peer.opened_services,
            ["abb_exec:package\0install\0-r\0-S\04"]
        );
        assert_eq!(peer.streamed_bytes, b"base");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streamed_apex_requires_device_apex_feature_and_appends_apex_flag() {
        let (root, _) = fixture_apks();
        let apex = root.join("bundle.apex");
        fs::write(&apex, b"apex").unwrap();

        // No `apex` feature → reject before any service opens.
        let mut peer = FakeExecTransport::new(true);
        let error = install_apk_streamed(
            &mut peer,
            &apex,
            &InstallOptions::default(),
            CommandTransport::ExecCmd,
            "device::features=cmd,shell_v2",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not supported on the target device"), "{error}");
        assert!(peer.opened_services.is_empty());

        // With `apex` feature → `--apex` appended after -S (AOSP order).
        let mut peer = FakeExecTransport::new(true);
        install_apk_streamed(
            &mut peer,
            &apex,
            &InstallOptions::default(),
            CommandTransport::ExecCmd,
            "device::features=cmd,shell_v2,apex",
        )
        .unwrap();
        assert_eq!(
            peer.opened_services,
            ["exec:cmd package install -S 4 --apex"]
        );
        assert_eq!(peer.streamed_bytes, b"apex");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_transport_from_banner_selects_abb_exec_and_apex_gates() {
        assert_eq!(
            CommandTransport::from_banner("device::features=cmd,shell_v2,abb_exec"),
            CommandTransport::AbbExec
        );
        assert_eq!(
            CommandTransport::from_banner("device::features=cmd,shell_v2"),
            CommandTransport::ExecCmd
        );
        assert!(CommandTransport::apex_supported("device::features=cmd,apex"));
        assert!(!CommandTransport::apex_supported("device::features=cmd"));
        // Host must not let a bare device claim unlock abb_exec without host support.
        assert_eq!(
            CommandTransport::from_banner("device::features=abb_exec_only_nonsense"),
            CommandTransport::ExecCmd
        );
    }

    #[test]
    fn install_multiple_accepts_dm_sdm_fsv_sig_idsig_inputs() {
        let (root, _) = fixture_apks();
        let mut inputs = Vec::new();
        for name in ["base.apk", "meta.dm", "cloud.sdm", "sig.fsv_sig", "v4.idsig"] {
            let path = root.join(name);
            fs::write(&path, b"x").unwrap();
            inputs.push(path);
        }
        let references: Vec<&Path> = inputs.iter().map(PathBuf::as_path).collect();
        let mut peer = FakeTransport::new(false);
        peer.expect_pushes(&inputs);
        let mut printer = LinePrinter::new();

        install_multiple(
            &mut peer,
            &references,
            &InstallOptions::default(),
            &mut printer,
            "device::features=cmd,shell_v2",
        )
        .unwrap();

        let commands = shell_commands(&peer);
        assert!(commands.iter().any(|command| command.contains("pm install-write -S 1 42 'meta.dm'")));
        assert!(commands.iter().any(|command| command.contains("pm install-write -S 1 42 'v4.idsig'")));
        assert!(commands.iter().any(|command| command == "pm install-commit 42"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_multiple_rejects_unknown_extension_before_opening_services() {
        let (root, _) = fixture_apks();
        let zip = root.join("bundle.zip");
        fs::write(&zip, b"zip").unwrap();
        let mut peer = FakeTransport::new(false);
        let mut printer = LinePrinter::new();

        let result = install_multiple(
            &mut peer,
            &[zip.as_path()],
            &InstallOptions::default(),
            &mut printer,
            "device::features=cmd,shell_v2",
        );

        assert!(result.unwrap_err().to_string().contains(".apk/.dm/.sdm/.fsv_sig/.idsig"));
        assert!(peer.opened_services.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_apk_push_mode_uses_sync_then_exec_pm_and_cleans_up() {
        let (root, paths) = fixture_apks();
        let mut peer = FakeTransport::new(false);
        peer.expect_pushes(&paths);
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
    fn staged_send_propagates_fail_and_disconnect_before_install_or_commit() {
        for outcome in [SyncOutcome::Fail, SyncOutcome::Disconnect] {
            let (root, paths) = fixture_apks();
            let mut peer = FakeTransport::new(false);
            peer.expect_pushes(&paths);
            peer.sync_outcome = outcome;
            let mut printer = LinePrinter::new();
            let error = install_apk(&mut peer, &paths[0], &InstallOptions::default(), &mut printer)
                .unwrap_err().to_string();
            assert!(error.contains("staging rejected") || error.contains("closed"), "{error}");
            assert_eq!(peer.opened_services, ["sync:"]);
            assert_eq!(peer.staged_apks[0].1, b"base");

            let mut peer = FakeTransport::new(false);
            peer.expect_pushes(&paths);
            peer.sync_outcome = outcome;
            let references: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
            assert!(install_multiple(&mut peer, &references, &InstallOptions::default(), &mut printer, "device::features=cmd,shell_v2").is_err());
            let commands = shell_commands(&peer);
            // Staging happens before session creation: preserve cleanup of all
            // planned paths, but never create/write/commit/abandon a session.
            assert_eq!(commands, [
                "rm '/data/local/tmp/base.apk' </dev/null",
                "rm '/data/local/tmp/split'\\''cfg.apk' </dev/null",
            ]);
            assert_eq!(peer.staged_apks.len(), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn multi_package_apex_inputs_flip_transaction_to_staged_with_apex_child() {
        let (root, _) = fixture_apks();
        let apex = root.join("main.apex");
        fs::write(&apex, b"apex").unwrap();
        let apk = root.join("app.apk");
        fs::write(&apk, b"apk").unwrap();
        let package_args = vec![apex.display().to_string(), apk.display().to_string()];
        let mut peer = FakeTransport::new(false);
        let banner = "device::features=cmd,shell_v2,apex";

        install_multi_package(&mut peer, &package_args, banner, &InstallOptions::default(), None)
            .unwrap();

        let commands = exec_commands(&peer);
        // Parent gets --staged; APEX child gets --staged --apex; the plain
        // APK child gets --staged only.
        assert!(
            commands.iter().any(|command| command == "cmd package install-create --multi-package --staged"),
            "parent missing --staged: {commands:?}"
        );
        let creates: Vec<&String> = commands
            .iter()
            .filter(|command| *command == "cmd package install-create --staged --apex" || *command == "cmd package install-create --staged")
            .collect();
        assert_eq!(creates.len(), 2, "child creates: {commands:?}");
        assert!(commands.iter().any(|command| command == "cmd package install-create --staged --apex"));
        assert!(commands.iter().any(|command| command == "cmd package install-create --staged"));
        assert!(commands.iter().any(|command| command == "cmd package install-add-session 42 43 44"));
        assert!(commands.iter().any(|command| command == "cmd package install-commit 42"));
        assert!(!commands.iter().any(|command| command.contains("install-abandon")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_apex_requires_device_apex_feature_before_services() {
        let (root, _) = fixture_apks();
        let apex = root.join("main.apex");
        fs::write(&apex, b"apex").unwrap();
        let mut peer = FakeTransport::new(false);
        let banner = "device::features=cmd,shell_v2";

        let error = install_multi_package(
            &mut peer,
            &[apex.display().to_string()],
            banner,
            &InstallOptions::default(),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not supported on the target device"), "{error}");
        assert!(peer.opened_services.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_parent_child_writes_link_then_commit_parent() {
        let (root, paths) = fixture_apks();
        let extra = root.join("feature.apk");
        fs::write(&extra, b"feature").unwrap();
        let package_args = vec![
            format!("{}:{}", paths[0].display(), extra.display()),
            paths[1].display().to_string(),
        ];
        let mut peer = FakeTransport::new(false);
        let banner = "device::ro.product.name=test;features=shell_v2,cmd";

        install_multi_package(
            &mut peer,
            &package_args,
            banner,
            &InstallOptions::default(),
            None,
        )
        .unwrap();

        let commands = exec_commands(&peer);
        let transaction: Vec<&str> = commands
            .iter()
            .map(String::as_str)
            .filter(|command| command.starts_with("cmd package install-"))
            .collect();
        assert_eq!(
            transaction,
            [
                "cmd package install-create --multi-package",
                "cmd package install-create",
                "cmd package install-write -S 4 43 1_base.apk -",
                "cmd package install-write -S 7 43 1_feature.apk -",
                "cmd package install-create",
                "cmd package install-write -S 6 44 2_split'cfg.apk -",
                "cmd package install-add-session 42 43 44",
                "cmd package install-commit 42",
            ]
        );
        assert_eq!(
            peer.streamed_splits.iter().map(|(_, bytes)| bytes.as_slice()).collect::<Vec<_>>(),
            [b"base".as_slice(), b"feature".as_slice(), b"split!".as_slice()]
        );
        assert!(!peer.opened_services.iter().any(|service| service == "sync:"));
        assert!(!commands.iter().any(|command| command == "cmd package install-abandon 42"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_write_failure_abandons_parent_and_created_child_without_fallback() {
        let (root, paths) = fixture_apks();
        let package_args: Vec<String> = paths.iter().map(|path| path.display().to_string()).collect();
        let mut peer = FakeTransport::new(true);
        let banner = "device::features=cmd,shell_v2";

        let result = install_multi_package(
            &mut peer,
            &package_args,
            banner,
            &InstallOptions::default(),
            None,
        );

        assert!(result.is_err());
        let commands = exec_commands(&peer);
        assert!(commands.iter().any(|command| command == "cmd package install-abandon 42"));
        assert!(commands.iter().any(|command| command == "cmd package install-abandon 43"));
        assert!(!commands.iter().any(|command| command.contains("install-add-session")));
        assert!(!commands.iter().any(|command| command.contains("install-commit")));
        assert!(!commands.iter().any(|command| command.starts_with("pm install -r")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_add_session_failure_abandons_parent_and_every_child() {
        let (root, paths) = fixture_apks();
        let package_args: Vec<String> = paths.iter().map(|path| path.display().to_string()).collect();
        let mut peer = FakeTransport::new(false);
        peer.fail_install_add = true;
        let banner = "device::features=cmd,shell_v2";

        let result = install_multi_package(
            &mut peer,
            &package_args,
            banner,
            &InstallOptions::default(),
            None,
        );

        assert!(result.is_err());
        let commands = exec_commands(&peer);
        assert!(commands.iter().any(|command| command == "cmd package install-add-session 42 43 44"));
        assert!(commands.iter().any(|command| command == "cmd package install-abandon 42"));
        assert!(commands.iter().any(|command| command == "cmd package install-abandon 43"));
        assert!(commands.iter().any(|command| command == "cmd package install-abandon 44"));
        assert!(!commands.iter().any(|command| command.contains("install-commit")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_staged_ready_timeout_is_forwarded_to_commit() {
        let (root, paths) = fixture_apks();
        let extra = root.join("feature.apk");
        fs::write(&extra, b"feature").unwrap();
        let package_args = vec![
            format!("{}:{}", paths[0].display(), extra.display()),
            paths[1].display().to_string(),
        ];
        let mut peer = FakeTransport::new(false);
        let banner = "device::features=cmd,shell_v2,apex";

        install_multi_package(
            &mut peer,
            &package_args,
            banner,
            &InstallOptions::default(),
            Some("30"),
        )
        .unwrap();

        let commands = exec_commands(&peer);
        assert!(
            commands
                .iter()
                .any(|command| command == "cmd package install-commit --staged-ready-timeout 30 42"),
            "commit missing forwarded timeout: {commands:?}"
        );
        assert!(!commands.iter().any(|command| command.contains("install-abandon")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_package_requires_cmd_before_opening_any_service() {
        let (root, paths) = fixture_apks();
        let package_args = vec![paths[0].display().to_string()];
        let mut peer = FakeTransport::new(false);

        let error = install_multi_package(
            &mut peer,
            &package_args,
            "device::features=shell_v2",
            &InstallOptions::default(),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("does not support cmd"));
        assert!(peer.opened_services.is_empty());
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
