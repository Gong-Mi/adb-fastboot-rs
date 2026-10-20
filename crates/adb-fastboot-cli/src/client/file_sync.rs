//! File sync operations — push, pull, list, and stat via ADB sync protocol.
//!
//! Maps to AOSP `vendor/adb/client/file_sync_client.cpp`.
//!
//! Provides public functions:
//! - `push()` / `pull()` — single file transfer (existing, unchanged)
//! - `push_dir()` — recursive directory push
//! - `pull_dir()` — recursive directory pull
//! - `list()` — remote directory listing
//! - `stat()` — remote file status query
//!
//! All functions try the ADB server (port 5037) first for transport reuse,
//! falling back to direct USB/TCP with full CNXN/AUTH handshake.
//!
//! Internal helpers handle two modes:
//! - **Direct**: sync protocol messages wrapped in ADB WRTE frames
//!   (transport connected directly to adbd via USB or TCP).
//! - **Server**: raw sync protocol bytes tunneled through the ADB server
//!   bridge (which strips ADB framing).

use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, AdbServerTransport, Transport,
    A_CLSE, A_OKAY, A_WRTE,
    build_sync_recv_req, build_sync_send_req, build_sync_data_chunk, build_sync_done,
    build_sync_list_req, build_sync_stat_req,
    SyncDentResponse, SyncMessageHeader, SyncStatResponse,
    SYNC_DATA, SYNC_DENT, SYNC_DONE, SYNC_FAIL, SYNC_OKAY, SYNC_STAT,
};

use super::protocol;
use super::auth::default_auth;
use super::transport::{open_adb_transport, connect_and_handshake_with_tls_upgrade};

/// Max payload chunk size for sync DATA messages (64 KB).
const MAX_CHUNK: usize = 64 * 1024;

const ADB_SERVER_PORT: u16 = 5037;

/// AOSP honors `ANDROID_ADB_SERVER_PORT`; without it every server probe would
/// hit 5037 even when the caller selected a different server.
fn adb_server_port() -> u16 {
    std::env::var("ANDROID_ADB_SERVER_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(ADB_SERVER_PORT)
}

/// File and directory entry from a remote `list` operation.
#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
    pub name: String,
}

/// Result of a `stat` operation.
#[derive(Debug, Clone, Copy)]
pub struct FileStat {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

/// Local file mtime in whole seconds, saturating at `u32::MAX` (SYNC wire field).
fn local_mtime_secs(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let modified = fs::metadata(path)?.modified()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(u32::try_from(secs).unwrap_or(u32::MAX))
}

/// A SYNC STAT response of all zeros means "not found" (V1 cannot report errno).
fn remote_exists(st: &FileStat) -> bool {
    st.mode != 0 || st.size != 0 || st.mtime != 0
}

/// AOSP `sync_send(sync=true)`: skip only when the remote mtime equals the local one.
fn sync_equal(st: &FileStat, local_mtime: u32) -> bool {
    remote_exists(st) && st.mtime == local_mtime
}

/// `S_ISDIR` over a raw V1 STAT mode word.
fn mode_is_dir(mode: u32) -> bool {
    mode & 0o170000 == 0o040000
}

/// Basename of the local file, used when the destination is a directory.
///
/// AOSP uses `android::base::Basename(src_path)`. A path whose basename cannot
/// be named (trailing `/..`, filesystem root) or is not UTF-8 is an error — the
/// remote path is never built by silently lossy-converting the name.
fn local_push_basename(local: &str) -> Result<String, String> {
    let name = Path::new(local)
        .file_name()
        .ok_or_else(|| format!("cannot determine basename of local path '{local}'"))?;
    name.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("local file name '{name:?}' is not valid UTF-8"))
}

/// Resolve the remote SEND path for a single local file.
///
/// Mirrors AOSP `do_sync_push` (`client/file_sync_client.cpp:1454-1486`, then
/// `1523-1533` for the file destination, consumed by `sync_send` at `:1537`):
/// - destination exists and is a directory → `remote + "/" + basename(local)`;
/// - destination exists and is not a directory, `remote` ends with `/` →
///   `failed to access '<remote>': Not a directory` (AOSP only rejects a
///   trailing slash when the path *exists*, `:1479-1484`);
/// - otherwise → `remote` verbatim, trailing slash included.
fn resolve_remote_file_target(
    remote: &str,
    remote_is_dir: bool,
    remote_exists: bool,
    local_basename: &str,
) -> Result<String, String> {
    if remote_is_dir {
        let mut target = String::with_capacity(remote.len() + 1 + local_basename.len());
        target.push_str(remote);
        if !target.ends_with('/') {
            target.push('/');
        }
        target.push_str(local_basename);
        return Ok(target);
    }

    // A path that ends with a slash doesn't have to be a directory if it
    // doesn't exist yet (AOSP `:1479-1481`).
    if remote.ends_with('/') && remote_exists {
        return Err(format!("failed to access '{remote}': Not a directory"));
    }
    Ok(remote.to_string())
}

// ---------------------------------------------------------------------------
// Public API — existing single-file push/pull (unchanged)
// ---------------------------------------------------------------------------

/// Push a local file or directory to a remote path on the device.
///
/// `sync` mirrors AOSP `adb push --sync`: before sending, the remote path is
/// stat'ed and the file is skipped when the remote mtime equals the local one.
/// This port uses SYNC V1 `STAT` (12-byte reply) rather than AOSP's LSTAT_V2;
/// symlinks are not pushed, so following the link is equivalent for this surface.
///
/// # Priority
/// 1. ADB server (port 5037) — borrows the system ADB's authenticated
///    transport via the server bridge, avoiding repeated AUTH handshakes.
/// 2. Direct USB/TCP — connects directly to adbd on the device.
pub fn push(
    serial: Option<&str>,
    local: &str,
    remote: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(local).is_dir() {
        return push_dir(serial, local, remote, sync);
    }
    // Priority 1: ADB server (port 5037)
    let server_addr = format!("127.0.0.1:{}", adb_server_port());
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            // Open sync: service via server bridge
            server.send_host_request("sync:")?;
            server.read_status()?;
            // Now in forwarding mode — raw sync protocol
            return push_file_server(&mut server, local, remote, sync);
        }
    }

    // Priority 2: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    push_file_direct(&mut transport, local_id, remote_id, local, remote, sync)
}

/// Pull a remote file from the device to a local path.
///
/// # Priority
/// Same as `push()` — ADB server first, then direct USB/TCP.
pub fn pull(
    serial: Option<&str>,
    remote: &str,
    local: &str,
    preserve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Priority 1: ADB server
    let server_addr = format!("127.0.0.1:{}", adb_server_port());
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return pull_file_server(&mut server, remote, local, preserve);
        }
    }

    // Priority 2: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    pull_file_direct(&mut transport, local_id, remote_id, remote, local, preserve)
}

// ---------------------------------------------------------------------------
// Public API — new directory sync operations
// ---------------------------------------------------------------------------

/// List the contents of a remote directory.
///
/// Returns a vector of [`RemoteEntry`] with mode, size, mtime, and name
/// for each entry (excluding `.` and `..`).
pub fn list(
    serial: Option<&str>,
    remote_path: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    let server_addr = format!("127.0.0.1:{}", adb_server_port());
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return list_server(&mut server, remote_path);
        }
    }

    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    list_direct(&mut transport, local_id, remote_id, remote_path)
}

/// Stat a remote file or directory on the device.
///
/// Returns [`FileStat`] with mode, size, and mtime.
/// If the path does not exist, returns an error.
pub fn stat(
    serial: Option<&str>,
    remote_path: &str,
) -> Result<FileStat, Box<dyn std::error::Error>> {
    let server_addr = format!("127.0.0.1:{}", adb_server_port());
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return stat_server(&mut server, remote_path);
        }
    }

    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    stat_direct(&mut transport, local_id, remote_id, remote_path)
}

/// Recursively push a local directory to a remote path on the device.
///
/// Walks `local_dir` recursively and pushes every regular file to the
/// corresponding path under `remote_dir`. Parent directories are created
/// on the device via the sync service by sending each file with its full
/// remote path (adbd creates parent dirs as needed for V1 SEND).
pub fn push_dir(
    serial: Option<&str>,
    local_dir: &str,
    remote_dir: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Collect all files to push
    let files = build_local_file_list(local_dir, remote_dir)?;
    if files.is_empty() {
        println!("[adb-rs] No files to push in '{}'", local_dir);
        return Ok(());
    }

    println!(
        "[adb-rs] Pushing {} files from '{}' -> '{}'",
        files.len(),
        local_dir,
        remote_dir
    );

    let server_addr = format!("127.0.0.1:{}", adb_server_port());

    // Try ADB server first
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return push_files_server(&mut server, &files, sync);
        }
    }

    // Fallback: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    push_files_direct(&mut transport, local_id, remote_id, &files, sync)
}

/// Recursively pull a remote directory to a local path.
///
/// Lists `remote_dir` recursively and pulls every regular file to the
/// corresponding path under `local_dir`. Local parent directories are
/// created as needed.
pub fn pull_dir(
    serial: Option<&str>,
    remote_dir: &str,
    local_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build list of remote entries recursively
    let server_addr = format!("127.0.0.1:{}", adb_server_port());

    // First, enumerate remote directory recursively
    let entries = if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            build_remote_file_list_server(&mut server, remote_dir, local_dir)?
        } else {
            let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
            let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
            build_remote_file_list_direct(&mut transport, local_id, remote_id, remote_dir, local_dir)?
        }
    } else {
        let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
        let (_info, mut transport) =
            connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
        let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
        build_remote_file_list_direct(&mut transport, local_id, remote_id, remote_dir, local_dir)?
    };

    if entries.is_empty() {
        println!("[adb-rs] No files to pull from '{}'", remote_dir);
        return Ok(());
    }

    println!(
        "[adb-rs] Pulling {} files from '{}' -> '{}'",
        entries.len(),
        remote_dir,
        local_dir
    );

    // Create local parent directories
    for pair in &entries {
        if let Some(parent) = Path::new(&pair.local).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create directory '{}': {e}", parent.display()))?;
        }
    }

    // Pull each file — open a new sync connection per pull
    // (Each `pull()` call handles server-first/direct fallback)
    for pair in &entries {
        pull(serial, &pair.remote, &pair.local, false)?;
    }

    println!("[adb-rs] Pull complete: '{}' -> '{}'", remote_dir, local_dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal — file list building
// ---------------------------------------------------------------------------

/// A (local_path, remote_path) pair for a file to transfer.
struct FilePair {
    local: String,
    remote: String,
}

/// Recursively walk a local directory and build the list of files to push.
///
/// Replaces the `local_dir` prefix with `remote_dir` to construct the
/// remote path for each file.
fn build_local_file_list(local_dir: &str, remote_dir: &str) -> Result<Vec<FilePair>, Box<dyn std::error::Error>> {
    let local_dir = if local_dir.ends_with('/') {
        local_dir.to_string()
    } else {
        format!("{}/", local_dir)
    };
    let remote_dir = if remote_dir.ends_with('/') {
        remote_dir.to_string()
    } else {
        format!("{}/", remote_dir)
    };

    let mut files = Vec::new();
    build_local_file_list_recursive(&local_dir, &remote_dir, &local_dir, &mut files)?;
    Ok(files)
}

fn build_local_file_list_recursive(
    local_dir: &str,
    remote_dir: &str,
    current_local_dir: &str,
    files: &mut Vec<FilePair>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(current_local_dir)
        .map_err(|e| format!("Cannot read directory '{current_local_dir}': {e}"))?
    {
        let entry = entry.map_err(|e| format!("Read dir entry error: {e}"))?;
        let path = entry.path();

        // Skip hidden files and . / ..
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[adb-rs] Warning: cannot stat '{}': {e}", path.display());
                continue;
            }
        };

        // Build the relative path from local_dir to this entry
        let local_path_str = path.to_string_lossy().to_string();
        let relative = local_path_str
            .strip_prefix(local_dir)
            .unwrap_or(&local_path_str);
        let remote_path = format!("{}{}", remote_dir, relative);

        if metadata.is_dir() {
            build_local_file_list_recursive(
                local_dir,
                remote_dir,
                &format!("{}/", local_path_str),
                files,
            )?;
        } else if metadata.is_file() {
            files.push(FilePair {
                local: local_path_str,
                remote: remote_path,
            });
        }
    }
    Ok(())
}

/// A (local_path, remote_path) pair for a pull operation.
struct PullPair {
    local: String,
    remote: String,
}

/// Recursively enumerate a remote directory by walking the LIST response tree.
fn build_remote_file_list_server(
    transport: &mut dyn Transport,
    remote_dir: &str,
    local_dir: &str,
) -> Result<Vec<PullPair>, Box<dyn std::error::Error>> {
    let mut pulls = Vec::new();
    build_remote_file_list_recursive_server(transport, remote_dir, local_dir, &mut pulls)?;
    Ok(pulls)
}

fn build_remote_file_list_recursive_server(
    transport: &mut dyn Transport,
    current_remote: &str,
    current_local: &str,
    pulls: &mut Vec<PullPair>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = list_server_inner(transport, current_remote)?;
    for entry in &entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let remote_child = if current_remote.ends_with('/') {
            format!("{}{}", current_remote, entry.name)
        } else {
            format!("{}/{}", current_remote, entry.name)
        };
        let local_child = if current_local.ends_with('/') {
            format!("{}{}", current_local, entry.name)
        } else {
            format!("{}/{}", current_local, entry.name)
        };

        // Check if this is a directory (S_IFDIR = 0o40000)
        if entry.mode & 0o170000 == 0o040000 {
            // Ensure local dir exists
            fs::create_dir_all(&local_child)
                .map_err(|e| format!("Cannot create directory '{local_child}': {e}"))?;
            build_remote_file_list_recursive_server(transport, &remote_child, &local_child, pulls)?;
        } else {
            pulls.push(PullPair {
                local: local_child,
                remote: remote_child,
            });
        }
    }
    Ok(())
}

fn build_remote_file_list_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote_dir: &str,
    local_dir: &str,
) -> Result<Vec<PullPair>, Box<dyn std::error::Error>> {
    let mut pulls = Vec::new();
    build_remote_file_list_recursive_direct(transport, local_id, remote_id, remote_dir, local_dir, &mut pulls)?;
    Ok(pulls)
}

fn build_remote_file_list_recursive_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    current_remote: &str,
    current_local: &str,
    pulls: &mut Vec<PullPair>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = list_direct_inner(transport, local_id, remote_id, current_remote)?;
    for entry in &entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let remote_child = if current_remote.ends_with('/') {
            format!("{}{}", current_remote, entry.name)
        } else {
            format!("{}/{}", current_remote, entry.name)
        };
        let local_child = if current_local.ends_with('/') {
            format!("{}{}", current_local, entry.name)
        } else {
            format!("{}/{}", current_local, entry.name)
        };

        if entry.mode & 0o170000 == 0o040000 {
            fs::create_dir_all(&local_child)
                .map_err(|e| format!("Cannot create directory '{local_child}': {e}"))?;
            build_remote_file_list_recursive_direct(transport, local_id, remote_id, &remote_child, &local_child, pulls)?;
        } else {
            pulls.push(PullPair {
                local: local_child,
                remote: remote_child,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Direct-mode helpers (ADB WRTE framing)
// ---------------------------------------------------------------------------

/// Push a file via direct transport (ADB WRTE framing).
fn push_file_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    local: &str,
    remote: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // AOSP do_sync_push stats the destination first and sends to the resolved
    // dst_path; sync_send then compares that resolved path (`:1537`).
    let (remote_present, remote_is_dir) =
        match stat_direct_inner(transport, local_id, remote_id, remote) {
            Ok(st) => (remote_exists(&st), mode_is_dir(st.mode)),
            // V1 STAT cannot report errno: a failed stat takes AOSP's
            // ENOENT/ENOPROTOOPT branch (destination treated as absent).
            Err(_) => (false, false),
        };
    let target = if remote_is_dir {
        resolve_remote_file_target(
            remote,
            true,
            remote_present,
            &local_push_basename(local)?,
        )?
    } else {
        resolve_remote_file_target(remote, false, remote_present, "")?
    };

    let local_path = Path::new(local);
    let mtime = local_mtime_secs(local_path)?;
    if sync {
        if let Ok(st) = stat_direct_inner(transport, local_id, remote_id, &target) {
            if sync_equal(&st, mtime) {
                println!("[adb-rs] Skipped '{}' (remote mtime matches)", target);
                return Ok(());
            }
        }
    }
    let file_data = std::fs::read(local_path)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    println!("[adb-rs] Pushing '{}' -> '{}' ({} bytes)", local, target, file_data.len());

    // Build SEND request (sync header + path,mode)
    let mut send_buf = Vec::new();
    build_sync_send_req(&target, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;

    // send_wrte consumed A_OKAY (transport ACK), not a SEND approval.
    // The successful SYNC_OKAY belongs after DATA/DONE; read status there.

    // Send DATA chunks (max 64 KB each)
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        protocol::send_wrte(transport, local_id, remote_id, &data_buf)?;
    }

    // Send DONE: the SYNC V1 DONE field carries the file mtime.
    let mut done_buf = Vec::new();
    build_sync_done(mtime, &mut done_buf)
        .map_err(|e| format!("Build DONE failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &done_buf)?;

    // Expect final SYNC_OKAY or SYNC_FAIL
    protocol::recv_sync_response(transport, local_id, remote_id)?;

    Ok(())
}

/// Pull a file via direct transport (ADB WRTE framing).
fn pull_file_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote: &str,
    local: &str,
    preserve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[adb-rs] Pulling '{}' -> '{}'", remote, local);
    let attrs = if preserve {
        Some(stat_direct_inner(transport, local_id, remote_id, remote)?)
    } else {
        None
    };

    let mut recv_buf = Vec::new();
    build_sync_recv_req(remote, &mut recv_buf)
        .map_err(|e| format!("Build RECV req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &recv_buf)?;

    let mut file_data = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                transport.send_message(&ack, &[])?;
                if payload.len() < SyncMessageHeader::SIZE {
                    return Err("Sync response too short during pull".into());
                }
                let sync_hdr = SyncMessageHeader::decode(&payload)
                    .map_err(|e| format!("Bad sync header during pull: {e}"))?;
                match sync_hdr.id {
                    SYNC_DATA => file_data.extend_from_slice(&payload[SyncMessageHeader::SIZE..]),
                    // AOSP RECV ends with DONE; retain OKAY for existing peers.
                    SYNC_DONE | SYNC_OKAY => break,
                    SYNC_FAIL => return Err(format!(
                        "Sync FAIL during pull: {}",
                        String::from_utf8_lossy(&payload[SyncMessageHeader::SIZE..])
                    ).into()),
                    other => return Err(format!("Unexpected sync id {other:#x} during pull").into()),
                }
            }
            A_CLSE => return Err("Sync connection closed prematurely".into()),
            _ => {}
        }
    }

    let local_path = Path::new(local);
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create directory '{}': {e}", parent.display()))?;
    }
    fs::write(local_path, &file_data)
        .map_err(|e| format!("Cannot write local file '{local}': {e}"))?;
    if let Some(attrs) = attrs {
        set_time_and_mode(local_path, attrs.mtime, attrs.mode)?;
    }

    println!("[adb-rs] Pull complete: '{}' -> '{}' ({} bytes)", remote, local, file_data.len());
    Ok(())
}

/// Preserve the subset of remote attributes that AOSP `adb pull -a` applies:
/// mtime and permission bits. The process umask is sampled under a lock because
/// POSIX exposes no non-mutating umask getter.
fn set_time_and_mode(path: &Path, mtime: u32, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let times = libc::utimbuf { actime: mtime as libc::time_t, modtime: mtime as libc::time_t };
    if unsafe { libc::utime(c_path.as_ptr(), &times) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = UMASK_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let umask = unsafe { libc::umask(0) };
    unsafe { libc::umask(umask) };
    fs::set_permissions(path, fs::Permissions::from_mode((mode & 0o7777) & !umask))?;
    Ok(())
}

/// STAT without closing the already-open direct SYNC channel.
fn stat_direct_inner(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote_path: &str,
) -> Result<FileStat, Box<dyn std::error::Error>> {
    let mut req_buf = Vec::new();
    build_sync_stat_req(remote_path, &mut req_buf)
        .map_err(|e| format!("Build STAT req failed: {e}"))?;
    // send_wrte would consume and discard the first A_WRTE reply while waiting
    // for A_OKAY — that reply is the STAT result. Send raw and let the loop read it.
    let req_hdr = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &req_buf);
    transport.send_message(&req_hdr, &req_buf)?;

    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                transport.send_message(&ack, &[])?;
                if payload.len() < SyncMessageHeader::SIZE {
                    return Err("Sync response too short during stat".into());
                }
                let sync_hdr = SyncMessageHeader::decode(&payload)
                    .map_err(|e| format!("Bad sync header during stat: {e}"))?;
                match sync_hdr.id {
                    SYNC_STAT => {
                        let s = SyncStatResponse::decode(&payload[SyncMessageHeader::SIZE..])
                            .map_err(|e| format!("Bad STAT response: {e}"))?;
                        return Ok(FileStat { mode: s.mode, size: s.size, mtime: s.mtime });
                    }
                    SYNC_FAIL => return Err(format!(
                        "Sync FAIL during stat: {}",
                        String::from_utf8_lossy(&payload[SyncMessageHeader::SIZE..])
                    ).into()),
                    other => return Err(format!("Unexpected sync id {other:#x} during stat").into()),
                }
            }
            A_CLSE => return Err("Sync connection closed during stat".into()),
            _ => {}
        }
    }
}

/// Push multiple files via a single direct-mode sync connection.
fn push_files_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    files: &[FilePair],
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        push_file_direct_with_ids(transport, local_id, remote_id, &file.local, &file.remote, sync)?;
    }

    // Close sync connection
    let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&clse_hdr, &[])?;
    let _ = transport.recv_message(); // wait for CLSE ack

    Ok(())
}

/// Push a single file on an existing direct-mode sync connection.
fn push_file_direct_with_ids(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    local: &str,
    remote: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if sync {
        let mtime = local_mtime_secs(Path::new(local))?;
        if let Ok(st) = stat_direct_inner(transport, local_id, remote_id, remote) {
            if sync_equal(&st, mtime) {
                println!("[adb-rs] Skipped '{}' (remote mtime matches)", remote);
                return Ok(());
            }
        }
    }
    let file_data = std::fs::read(local)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;
    let mtime = local_mtime_secs(Path::new(local))?;

    // Build SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    // SEND is acknowledged only at the ADB transport layer.
    protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        protocol::send_wrte(transport, local_id, remote_id, &data_buf)?;
    }

    // Send DONE: the SYNC V1 DONE field carries the file mtime.
    let mut done_buf = Vec::new();
    build_sync_done(mtime, &mut done_buf)
        .map_err(|e| format!("Build DONE failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &done_buf)?;

    // Expect final SYNC_OKAY or SYNC_FAIL
    protocol::recv_sync_response(transport, local_id, remote_id)?;

    println!(
        "[adb-rs] Pushed '{}' -> '{}' ({} bytes)",
        local,
        remote,
        file_data.len()
    );

    Ok(())
}

/// List a remote directory via direct transport.
fn list_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote_path: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    let result = list_direct_inner(transport, local_id, remote_id, remote_path)?;

    // Close sync connection
    let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&clse_hdr, &[])?;
    let _ = transport.recv_message();

    Ok(result)
}

/// Inner list — reads DENT entries from a direct transport without closing the connection.
fn list_direct_inner(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote_path: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    let mut recv_buf = Vec::new();
    build_sync_list_req(remote_path, &mut recv_buf)
        .map_err(|e| format!("Build LIST req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &recv_buf)?;

    let mut entries = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;

        match hdr.command {
            A_OKAY => { /* WRTE ack — skip */ }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                if payload.len() < 8 {
                    return Err("Sync response too short during list".into());
                }

                let sync_hdr = SyncMessageHeader::decode(&payload)
                    .map_err(|e| format!("Bad sync header during list: {e}"))?;

                match sync_hdr.id {
                    SYNC_DENT => {
                        let dent = SyncDentResponse::decode(&payload[8..])
                            .map_err(|e| format!("Bad DENT: {e}"))?;
                        entries.push(RemoteEntry {
                            mode: dent.mode,
                            size: dent.size,
                            mtime: dent.mtime,
                            name: dent.name,
                        });
                    }
                    SYNC_DONE => {
                        // End of directory listing
                        break;
                    }
                    SYNC_FAIL => {
                        let msg = String::from_utf8_lossy(&payload[8..]).to_string();
                        return Err(format!("Sync FAIL during list: {msg}").into());
                    }
                    other => {
                        return Err(format!("Unexpected sync id {other:#x} during list").into());
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }

    Ok(entries)
}

/// Stat a remote path via direct transport.
fn stat_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    remote_path: &str,
) -> Result<FileStat, Box<dyn std::error::Error>> {
    let mut req_buf = Vec::new();
    build_sync_stat_req(remote_path, &mut req_buf)
        .map_err(|e| format!("Build STAT req failed: {e}"))?;
    // Same STAT rule as stat_direct_inner: read the A_WRTE result, don't let
    // send_wrte swallow it while waiting for the request A_OKAY.
    let req_hdr = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &req_buf);
    transport.send_message(&req_hdr, &req_buf)?;

    let mut stat_result: Option<FileStat> = None;
    loop {
        let (hdr, payload) = transport.recv_message()?;

        match hdr.command {
            A_OKAY => { /* WRTE ack — skip */ }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                if payload.len() < 8 {
                    return Err("Sync response too short during stat".into());
                }

                let sync_hdr = SyncMessageHeader::decode(&payload)
                    .map_err(|e| format!("Bad sync header during stat: {e}"))?;

                match sync_hdr.id {
                    SYNC_STAT => {
                        let s = SyncStatResponse::decode(&payload[8..])
                            .map_err(|e| format!("Bad STAT response: {e}"))?;
                        stat_result = Some(FileStat {
                            mode: s.mode,
                            size: s.size,
                            mtime: s.mtime,
                        });
                    }
                    SYNC_OKAY => {
                        // After STAT data — done
                        break;
                    }
                    SYNC_FAIL => {
                        let msg = String::from_utf8_lossy(&payload[8..]).to_string();
                        return Err(format!("Sync FAIL during stat: {msg}").into());
                    }
                    other => {
                        return Err(format!("Unexpected sync id {other:#x} during stat").into());
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }

    // Close sync connection
    let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&clse_hdr, &[])?;
    let _ = transport.recv_message();

    stat_result.ok_or_else(|| "STAT request returned no result".into())
}

// ---------------------------------------------------------------------------
// Server-mode helpers (raw sync protocol through bridge)
// ---------------------------------------------------------------------------

/// Write raw sync data to the transport (used in server bridge forwarding mode).
fn write_raw_sync(transport: &mut dyn Transport, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    transport.write_all(data)?;
    transport.flush()?;
    Ok(())
}

/// Read raw sync response header + payload.
/// Returns (sync_header, payload_bytes) after the 8-byte sync header.
fn read_raw_sync(
    transport: &mut dyn Transport,
) -> Result<(SyncMessageHeader, Vec<u8>), Box<dyn std::error::Error>> {
    let mut hdr_buf = [0u8; 8];
    transport.read_exact(&mut hdr_buf)?;
    let sync_hdr = SyncMessageHeader::decode(&hdr_buf)
        .map_err(|e| format!("Bad sync header: {e}"))?;

    let payload_len = sync_hdr.length as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        transport.read_exact(&mut payload)?;
    }

    Ok((sync_hdr, payload))
}

/// Push a file via server bridge forwarding mode (raw sync protocol).
fn push_file_server(
    transport: &mut dyn Transport,
    local: &str,
    remote: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same AOSP do_sync_push destination resolution as the direct path.
    let (remote_present, remote_is_dir) = match stat_server(transport, remote) {
        Ok(st) => (remote_exists(&st), mode_is_dir(st.mode)),
        Err(_) => (false, false),
    };
    let target = if remote_is_dir {
        resolve_remote_file_target(remote, true, remote_present, &local_push_basename(local)?)?
    } else {
        resolve_remote_file_target(remote, false, remote_present, "")?
    };
    let remote = target.as_str();

    let local_path = Path::new(local);
    let mtime = local_mtime_secs(local_path)?;
    if sync {
        // AOSP sync_lstat: any failure to stat the remote path means "send".
        if let Ok(st) = stat_server(transport, remote) {
            if sync_equal(&st, mtime) {
                println!("[adb-rs] Skipped '{}' (remote mtime matches)", remote);
                return Ok(());
            }
        }
    }
    let file_data = std::fs::read(local_path)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    println!("[adb-rs] Pushing '{}' -> '{}' ({} bytes)", local, remote, file_data.len());

    // Build and send SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    write_raw_sync(transport, &send_buf)?;

    // A server bridge carries raw SYNC bytes: no response follows SEND.
    // Read the application OKAY/FAIL only after sending DATA and DONE.

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        write_raw_sync(transport, &data_buf)?;
    }

    // Send DONE: the SYNC V1 DONE field carries the file mtime.
    let mut done_buf = Vec::new();
    build_sync_done(mtime, &mut done_buf)
        .map_err(|e| format!("Build DONE failed: {e}"))?;
    write_raw_sync(transport, &done_buf)?;

    // Expect final SYNC_OKAY or SYNC_FAIL
    let (final_hdr, final_payload) = read_raw_sync(transport)?;
    if final_hdr.id == SYNC_FAIL {
        let msg = String::from_utf8_lossy(&final_payload).to_string();
        return Err(format!("Sync FAIL: {msg}").into());
    }
    if final_hdr.id != SYNC_OKAY {
        return Err(format!("Expected SYNC_OKAY, got {:#x}", final_hdr.id).into());
    }

    println!("[adb-rs] Push complete: '{}' -> '{}'", local, remote);
    Ok(())
}

/// Pull a file via server bridge forwarding mode (raw sync protocol).
fn pull_file_server(
    transport: &mut dyn Transport,
    remote: &str,
    local: &str,
    preserve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[adb-rs] Pulling '{}' -> '{}'", remote, local);
    let attrs = if preserve { Some(stat_server(transport, remote)?) } else { None };

    // Build and send RECV request
    let mut recv_buf = Vec::new();
    build_sync_recv_req(remote, &mut recv_buf)
        .map_err(|e| format!("Build RECV req failed: {e}"))?;
    write_raw_sync(transport, &recv_buf)?;

    // Read DATA chunks until DONE or FAIL
    let mut file_data = Vec::new();
    loop {
        let (sync_hdr, payload) = read_raw_sync(transport)?;

        match sync_hdr.id {
            SYNC_DATA => {
                file_data.extend_from_slice(&payload);
            }
            SYNC_DENT => {
                // DENT response — file metadata, not expected for single-file pull
                file_data.extend_from_slice(&payload);
            }
            SYNC_DONE | SYNC_OKAY => {
                // AOSP RECV terminates with DONE; retain OKAY for existing peers.
                break;
            }
            SYNC_FAIL => {
                let msg = String::from_utf8_lossy(&payload).to_string();
                return Err(format!("Sync FAIL during pull: {msg}").into());
            }
            other => {
                return Err(format!("Unexpected sync id {other:#x} during pull").into());
            }
        }
    }

    // Write received data to local file
    let local_path = Path::new(local);
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create directory '{}': {e}", parent.display()))?;
    }
    std::fs::write(local_path, &file_data)
        .map_err(|e| format!("Cannot write local file '{local}': {e}"))?;
    if let Some(attrs) = attrs {
        set_time_and_mode(local_path, attrs.mtime, attrs.mode)?;
    }

    println!("[adb-rs] Pull complete: '{}' -> '{}' ({} bytes)", remote, local, file_data.len());
    Ok(())
}

/// Push multiple files via a single server-mode sync connection.
fn push_files_server(
    transport: &mut dyn Transport,
    files: &[FilePair],
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        push_file_server_inner(transport, &file.local, &file.remote, sync)?;
    }
    Ok(())
}

/// Push a single file on an existing server-mode sync connection.
fn push_file_server_inner(
    transport: &mut dyn Transport,
    local: &str,
    remote: &str,
    sync: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mtime = local_mtime_secs(Path::new(local))?;
    if sync {
        if let Ok(st) = stat_server(transport, remote) {
            if sync_equal(&st, mtime) {
                println!("[adb-rs] Skipped '{}' (remote mtime matches)", remote);
                return Ok(());
            }
        }
    }
    let file_data = std::fs::read(local)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    // Build and send SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    write_raw_sync(transport, &send_buf)?;

    // SEND has no SYNC response; the terminal result belongs after DONE.

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        write_raw_sync(transport, &data_buf)?;
    }

    // Send DONE: the SYNC V1 DONE field carries the file mtime.
    let mut done_buf = Vec::new();
    build_sync_done(mtime, &mut done_buf)
        .map_err(|e| format!("Build DONE failed: {e}"))?;
    write_raw_sync(transport, &done_buf)?;

    // Expect final SYNC_OKAY or SYNC_FAIL
    let (final_hdr, final_payload) = read_raw_sync(transport)?;
    if final_hdr.id == SYNC_FAIL {
        let msg = String::from_utf8_lossy(&final_payload).to_string();
        return Err(format!("Push '{}' Sync FAIL: {msg}", local).into());
    }
    if final_hdr.id != SYNC_OKAY {
        return Err(format!("Expected SYNC_OKAY, got {:#x}", final_hdr.id).into());
    }

    println!(
        "[adb-rs] Pushed '{}' -> '{}' ({} bytes)",
        local,
        remote,
        file_data.len()
    );

    Ok(())
}

/// List a remote directory via server mode.
fn list_server(
    transport: &mut dyn Transport,
    remote_path: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    list_server_inner(transport, remote_path)
}

/// Inner list — reads DENT entries from a server-mode transport.
fn list_server_inner(
    transport: &mut dyn Transport,
    remote_path: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    let mut req_buf = Vec::new();
    build_sync_list_req(remote_path, &mut req_buf)
        .map_err(|e| format!("Build LIST req failed: {e}"))?;
    write_raw_sync(transport, &req_buf)?;

    let mut entries = Vec::new();
    loop {
        let (sync_hdr, payload) = read_raw_sync(transport)?;

        match sync_hdr.id {
            SYNC_DENT => {
                let dent = SyncDentResponse::decode(&payload)
                    .map_err(|e| format!("Bad DENT: {e}"))?;
                entries.push(RemoteEntry {
                    mode: dent.mode,
                    size: dent.size,
                    mtime: dent.mtime,
                    name: dent.name,
                });
            }
            SYNC_DONE => {
                // End of directory listing
                break;
            }
            SYNC_FAIL => {
                let msg = String::from_utf8_lossy(&payload).to_string();
                return Err(format!("Sync FAIL during list: {msg}").into());
            }
            other => {
                return Err(format!("Unexpected sync id {other:#x} during list").into());
            }
        }
    }

    Ok(entries)
}

/// Stat a remote path via server mode.
fn stat_server(
    transport: &mut dyn Transport,
    remote_path: &str,
) -> Result<FileStat, Box<dyn std::error::Error>> {
    let mut req_buf = Vec::new();
    build_sync_stat_req(remote_path, &mut req_buf)
        .map_err(|e| format!("Build STAT req failed: {e}"))?;
    write_raw_sync(transport, &req_buf)?;

    let (sync_hdr, payload) = read_raw_sync(transport)?;
    match sync_hdr.id {
        SYNC_STAT => {
            let s = SyncStatResponse::decode(&payload)
                .map_err(|e| format!("Bad STAT response: {e}"))?;
            Ok(FileStat {
                mode: s.mode,
                size: s.size,
                mtime: s.mtime,
            })
        }
        SYNC_OKAY => Err("STAT request returned no data".into()),
        SYNC_FAIL => {
            let msg = String::from_utf8_lossy(&payload).to_string();
            Err(format!("Sync FAIL during stat: {msg}").into())
        }
        other => Err(format!("Unexpected sync id {other:#x} during stat").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct ScriptedTransport {
        reads: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl Read for ScriptedTransport {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.read(buf)
        }
    }

    impl Write for ScriptedTransport {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Transport for ScriptedTransport {}

    #[derive(Clone, Copy, Debug)]
    enum SendOutcome { Okay, Fail, Disconnect }

    /// A strict adbd SYNC peer: SEND has no application reply. Only a complete
    /// DATA sequence followed by DONE produces the terminal status.
    struct SendPeer {
        expected: std::collections::VecDeque<(String, Vec<u8>, u32)>,
        active: Option<(Vec<u8>, Vec<u8>)>,
        pending_mtime: Option<u32>,
        incoming: std::collections::VecDeque<(AdbMessageHeader, Vec<u8>)>,
        raw_reply: Cursor<Vec<u8>>,
        direct: bool,
        outcome: SendOutcome,
        completed: usize,
        status_acks: usize,
        stats: usize,
    }

    impl SendPeer {
        fn accept_sync(&mut self, payload: &[u8]) {
            let header = SyncMessageHeader::decode(payload).unwrap();
            let data = &payload[8..];
            match header.id {
                SYNC_STAT => {
                    // do_sync_push stats the destination before choosing dst_path.
                    assert_eq!(header.length as usize, data.len());
                    self.stats += 1;
                    let requested = std::str::from_utf8(data).unwrap();
                    let (pending_path, _, _) = self.expected.front().expect("STAT without pending SEND");
                    assert_eq!(requested, pending_path.as_str(), "STAT must target the requested path");
                    // A plain file keeps the SEND path unchanged (no basename append).
                    let stat = SyncStatResponse { mode: 0o100644, size: 0, mtime: 0 };
                    let mut encoded_stat = [0u8; SyncStatResponse::SIZE];
                    stat.encode(&mut encoded_stat);
                    let mut stat_header = [0u8; SyncMessageHeader::SIZE];
                    SyncMessageHeader::new(SYNC_STAT, SyncStatResponse::SIZE as u32)
                        .encode(&mut stat_header);
                    let reply = [stat_header.as_slice(), encoded_stat.as_slice()].concat();
                    if self.direct {
                        self.incoming.push_back((AdbMessageHeader::new(A_WRTE, 41, 7, &reply), reply));
                    } else {
                        self.raw_reply = Cursor::new(reply);
                    }
                }
                adb_protocol::SYNC_SEND => {
                    assert!(self.active.is_none(), "SEND before previous DONE");
                    assert_eq!(header.length as usize, data.len());
                    let (path, bytes, mtime) = self.expected.pop_front().expect("unexpected SEND");
                    assert_eq!(data, format!("{path},{}", 0o644).as_bytes());
                    self.active = Some((bytes, Vec::new()));
                    self.pending_mtime = Some(mtime);
                }
                SYNC_DATA => {
                    assert_eq!(header.length as usize, data.len());
                    assert!(data.len() <= MAX_CHUNK);
                    let (expected, received) = self.active.as_mut().expect("DATA before SEND");
                    received.extend_from_slice(data);
                    assert!(received.len() <= expected.len(), "extra DATA bytes");
                    assert_eq!(received.as_slice(), &expected[..received.len()]);
                }
                SYNC_DONE => {
                    assert!(data.is_empty(), "DONE has no payload");
                    let expected_mtime = self.pending_mtime.take().expect("DONE before SEND");
                    assert_eq!(header.length, expected_mtime, "DONE must carry the local mtime");
                    let (expected, received) = self.active.take().expect("DONE before SEND");
                    assert_eq!(received, expected, "DONE before complete DATA");
                    self.completed += 1;
                    let (id, message): (u32, &[u8]) = match self.outcome {
                        SendOutcome::Okay => (SYNC_OKAY, b""),
                        SendOutcome::Fail => (SYNC_FAIL, b"strict peer rejected file"),
                        SendOutcome::Disconnect => {
                            if self.direct {
                                self.incoming.push_back((AdbMessageHeader::new(A_CLSE, 41, 7, &[]), Vec::new()));
                            }
                            return;
                        }
                    };
                    let mut reply = [0u8; 8];
                    SyncMessageHeader::new(id, message.len() as u32).encode(&mut reply);
                    let reply = [reply.as_slice(), message].concat();
                    if self.direct {
                        self.incoming.push_back((AdbMessageHeader::new(A_WRTE, 41, 7, &reply), reply));
                    } else {
                        self.raw_reply = Cursor::new(reply);
                    }
                }
                other => panic!("unexpected SYNC request {other:#x}"),
            }
        }
    }

    impl Read for SendPeer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(!self.direct);
            if self.active.is_some() {
                return Err(std::io::Error::other("host waited for SYNC_OKAY before DATA/DONE"));
            }
            self.raw_reply.read(buf)
        }
    }

    impl Write for SendPeer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            assert!(!self.direct);
            self.accept_sync(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    impl Transport for SendPeer {
        fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> Result<(), adb_protocol::TransportError> {
            assert!(self.direct);
            assert_eq!((header.arg0, header.arg1), (7, 41));
            match header.command {
                A_WRTE => {
                    // A_OKAY only acknowledges delivery of this WRTE, including SEND.
                    self.incoming.push_back((AdbMessageHeader::new(A_OKAY, 41, 7, &[]), Vec::new()));
                    self.accept_sync(payload);
                }
                A_OKAY => { assert!(payload.is_empty()); self.status_acks += 1; }
                A_CLSE => {
                    assert!(self.active.is_none());
                    self.incoming.push_back((AdbMessageHeader::new(A_CLSE, 41, 7, &[]), Vec::new()));
                }
                other => panic!("unexpected ADB command {other:#x}"),
            }
            Ok(())
        }
        fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), adb_protocol::TransportError> {
            self.incoming.pop_front().ok_or_else(|| adb_protocol::TransportError::Protocol(
                "host waited for SYNC_OKAY before DATA/DONE".into()
            ))
        }
    }

    fn check_send_paths(outcome: SendOutcome) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("adb-sync-send-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&root).unwrap();
        let bytes: Vec<u8> = (0..MAX_CHUNK * 2 + 9).map(|index| (index % 251) as u8).collect();
        let file = root.join("payload");
        let empty = root.join("empty");
        fs::write(&file, &bytes).unwrap();
        fs::write(&empty, b"").unwrap();
        for (direct, batch) in [(true, false), (true, true), (false, false), (false, true)] {
            let files = vec![
                FilePair { local: file.to_str().unwrap().into(), remote: "/remote/payload".into() },
                FilePair { local: empty.to_str().unwrap().into(), remote: "/remote/empty".into() },
            ];
            let mtime = |path: &std::path::Path| -> u32 {
                use std::os::unix::fs::MetadataExt;
                fs::metadata(path).unwrap().mtime() as u32
            };
            let mut peer = SendPeer {
                expected: [
                    (files[0].remote.clone(), bytes.clone(), mtime(std::path::Path::new(&files[0].local))),
                    (files[1].remote.clone(), Vec::new(), mtime(std::path::Path::new(&files[1].local))),
                ].into(),
                active: None,
                pending_mtime: None,
                incoming: Default::default(), raw_reply: Cursor::new(Vec::new()),
                direct, outcome, completed: 0, status_acks: 0, stats: 0,
            };
            let result = match (direct, batch) {
                (true, false) => push_file_direct(&mut peer, 7, 41, &files[0].local, &files[0].remote, false),
                (true, true) => push_files_direct(&mut peer, 7, 41, &files, false),
                (false, false) => push_file_server(&mut peer, &files[0].local, &files[0].remote, false),
                (false, true) => push_files_server(&mut peer, &files, false),
            };
            match outcome {
                SendOutcome::Okay => result.unwrap_or_else(|e| panic!("direct={direct}, batch={batch}: {e}")),
                SendOutcome::Fail => assert!(result.unwrap_err().to_string().contains("strict peer rejected file")),
                SendOutcome::Disconnect => {
                    let error = result.unwrap_err().to_string();
                    assert!(error.contains("closed") || error.contains("fill whole buffer"), "{error}");
                }
            }
            assert_eq!(peer.completed, if batch && matches!(outcome, SendOutcome::Okay) { 2 } else { 1 });
            // Single-file push stats the destination once (do_sync_push); the
            // batch path (push_dir) has already resolved its own targets.
            assert_eq!(peer.stats, if batch { 0 } else { 1 }, "direct={direct}");
            assert!(peer.active.is_none());
            if direct && !matches!(outcome, SendOutcome::Disconnect) {
                assert_eq!(peer.status_acks, peer.completed + peer.stats);
                assert!(peer.incoming.is_empty());
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn send_paths_wait_for_result_only_after_data_and_done() { check_send_paths(SendOutcome::Okay); }

    #[test]
    fn send_paths_propagate_final_fail_without_sending_next_file() { check_send_paths(SendOutcome::Fail); }

    #[test]
    fn send_paths_reject_disconnect_instead_of_treating_adb_ack_as_success() { check_send_paths(SendOutcome::Disconnect); }

    fn adb_frame(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Vec<u8> {
        let header = AdbMessageHeader::new(command, arg0, arg1, payload);
        let mut encoded = [0u8; 24];
        header.encode(&mut encoded);
        [encoded.as_slice(), payload].concat()
    }

    #[test]
    fn pull_with_preserve_stats_then_receives_and_applies_remote_mtime_and_mode() {
        let mut stat_payload = Vec::new();
        let stat = SyncStatResponse { mode: 0o100600, size: 6, mtime: 1_720_000_000 };
        let mut encoded_stat = [0u8; SyncStatResponse::SIZE];
        stat.encode(&mut encoded_stat);
        let mut stat_header = [0u8; SyncMessageHeader::SIZE];
        SyncMessageHeader::new(SYNC_STAT, SyncStatResponse::SIZE as u32).encode(&mut stat_header);
        stat_payload.extend_from_slice(&stat_header);
        stat_payload.extend_from_slice(&encoded_stat);

        let mut data_payload = Vec::new();
        build_sync_data_chunk(b"pulled", &mut data_payload).unwrap();
        let mut done_payload = [0u8; SyncMessageHeader::SIZE];
        SyncMessageHeader::new(SYNC_DONE, 0).encode(&mut done_payload);

        let script = [
            adb_frame(A_OKAY, 2, 1, &[]),
            adb_frame(A_WRTE, 2, 1, &stat_payload),
            adb_frame(A_OKAY, 2, 1, &[]),
            adb_frame(A_WRTE, 2, 1, &data_payload),
            adb_frame(A_WRTE, 2, 1, &done_payload),
        ]
        .concat();
        let mut transport = ScriptedTransport { reads: Cursor::new(script), writes: Vec::new() };
        let destination = std::env::temp_dir().join(format!("adb-rs-preserve-{}", std::process::id()));
        let _ = fs::remove_file(&destination);

        pull_file_direct(&mut transport, 1, 2, "/remote/file", destination.to_str().unwrap(), true).unwrap();

        let metadata = fs::metadata(&destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"pulled");
        assert_eq!(metadata.mtime(), 1_720_000_000);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let stat_request = AdbMessageHeader::decode(&transport.writes[..24]).unwrap();
        assert_eq!(stat_request.command, A_WRTE);
        assert_eq!(SyncMessageHeader::decode(&transport.writes[24..]).unwrap().id, SYNC_STAT);
        let recv_offset = 24 + stat_request.data_length as usize + 24;
        let recv_request = AdbMessageHeader::decode(&transport.writes[recv_offset..]).unwrap();
        assert_eq!(recv_request.command, A_WRTE);
        assert_eq!(
            SyncMessageHeader::decode(&transport.writes[recv_offset + 24..]).unwrap().id,
            adb_protocol::SYNC_RECV
        );
        let _ = fs::remove_file(destination);
    }

    // ---- do_sync_push destination resolution (pure) ----

    #[test]
    fn resolve_appends_basename_only_for_an_existing_directory() {
        assert_eq!(
            resolve_remote_file_target("/remote/dir", true, true, "payload.bin").unwrap(),
            "/remote/dir/payload.bin"
        );
        // A directory destination that already ends with '/' keeps one slash.
        assert_eq!(
            resolve_remote_file_target("/remote/dir/", true, true, "payload.bin").unwrap(),
            "/remote/dir/payload.bin"
        );
        // Root directory destination.
        assert_eq!(
            resolve_remote_file_target("/", true, true, "payload.bin").unwrap(),
            "/payload.bin"
        );
    }

    #[test]
    fn resolve_keeps_an_existing_file_path_verbatim() {
        assert_eq!(
            resolve_remote_file_target("/remote/payload.bin", false, true, "payload.bin").unwrap(),
            "/remote/payload.bin"
        );
        // A different local name must not be appended onto a file destination.
        assert_eq!(
            resolve_remote_file_target("/remote/other.bin", false, true, "payload.bin").unwrap(),
            "/remote/other.bin"
        );
    }

    #[test]
    fn resolve_rejects_trailing_slash_on_an_existing_non_directory() {
        let error = resolve_remote_file_target("/remote/payload.bin/", false, true, "payload.bin")
            .unwrap_err();
        assert_eq!(error, "failed to access '/remote/payload.bin/': Not a directory");
    }

    #[test]
    fn resolve_keeps_trailing_slash_when_the_target_does_not_exist() {
        // AOSP :1479-1481 — only an *existing* non-directory is an error.
        assert_eq!(
            resolve_remote_file_target("/remote/missing/", false, false, "payload.bin").unwrap(),
            "/remote/missing/"
        );
        assert_eq!(
            resolve_remote_file_target("/remote/missing", false, false, "payload.bin").unwrap(),
            "/remote/missing"
        );
    }

    #[test]
    fn local_basename_is_explicit_and_never_lossy() {
        assert_eq!(local_push_basename("/data/local/tmp/payload.bin").unwrap(), "payload.bin");
        assert_eq!(local_push_basename("payload.bin").unwrap(), "payload.bin");
        // ".." has no basename (AOSP would build "./.." from it).
        assert!(local_push_basename("/data/local/tmp/..").is_err());
        assert!(local_push_basename("/").is_err());
    }

    #[test]
    fn mode_word_dir_detection_matches_s_isdir() {
        assert!(mode_is_dir(0o040755));
        assert!(!mode_is_dir(0o100644));
        assert!(!mode_is_dir(0));
    }
}
