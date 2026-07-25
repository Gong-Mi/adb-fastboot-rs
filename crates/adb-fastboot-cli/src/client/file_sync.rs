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

// ---------------------------------------------------------------------------
// Public API — existing single-file push/pull (unchanged)
// ---------------------------------------------------------------------------

/// Push a local file or directory to a remote path on the device.
///
/// # Priority
/// 1. ADB server (port 5037) — borrows the system ADB's authenticated
///    transport via the server bridge, avoiding repeated AUTH handshakes.
/// 2. Direct USB/TCP — connects directly to adbd on the device.
pub fn push(
    serial: Option<&str>,
    local: &str,
    remote: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Priority 1: ADB server (port 5037)
    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            // Open sync: service via server bridge
            server.send_host_request("sync:")?;
            server.read_status()?;
            // Now in forwarding mode — raw sync protocol
            return push_file_server(&mut server, local, remote);
        }
    }

    // Priority 2: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    push_file_direct(&mut transport, local_id, remote_id, local, remote)
}

/// Pull a remote file from the device to a local path.
///
/// # Priority
/// Same as `push()` — ADB server first, then direct USB/TCP.
pub fn pull(
    serial: Option<&str>,
    remote: &str,
    local: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Priority 1: ADB server
    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return pull_file_server(&mut server, remote, local);
        }
    }

    // Priority 2: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    pull_file_direct(&mut transport, local_id, remote_id, remote, local)
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
    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
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
    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
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

    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");

    // Try ADB server first
    if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
        if server.switch_transport(serial).is_ok() {
            server.send_host_request("sync:")?;
            server.read_status()?;
            return push_files_server(&mut server, &files);
        }
    }

    // Fallback: direct USB/TCP
    let transport = open_adb_transport(serial, false, Duration::from_secs(3))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;
    let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;
    push_files_direct(&mut transport, local_id, remote_id, &files)
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
    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");

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
        pull(serial, &pair.remote, &pair.local)?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let local_path = Path::new(local);
    let file_data = std::fs::read(local_path)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    println!("[adb-rs] Pushing '{}' -> '{}' ({} bytes)", local, remote, file_data.len());

    // Build SEND request (sync header + path,mode)
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;

    // Expect SYNC_OKAY
    protocol::recv_sync_response(transport, local_id, remote_id)?;

    // Send DATA chunks (max 64 KB each)
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        protocol::send_wrte(transport, local_id, remote_id, &data_buf)?;
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0xFFFF_FFFF, &mut done_buf)
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
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[adb-rs] Pulling '{}' -> '{}'", remote, local);

    // Build RECV request
    let mut recv_buf = Vec::new();
    build_sync_recv_req(remote, &mut recv_buf)
        .map_err(|e| format!("Build RECV req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &recv_buf)?;

    // Read DATA chunks until DONE or FAIL
    let mut file_data = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;

        match hdr.command {
            A_OKAY => {
                // WRTE ack — skip, continue reading
            }
            A_WRTE => {
                // Ack the WRTE
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                if payload.len() < 8 {
                    return Err("Sync response too short during pull".into());
                }

                let sync_hdr = SyncMessageHeader::decode(&payload)
                    .map_err(|e| format!("Bad sync header during pull: {e}"))?;

                match sync_hdr.id {
                    SYNC_DATA => {
                        // Accumulate file data
                        let data = &payload[8..];
                        file_data.extend_from_slice(data);
                    }
                    SYNC_DENT => {
                        // DENT response — file info, not expected here
                        file_data.extend_from_slice(&payload[8..]);
                    }
                    SYNC_OKAY => {
                        // Transfer complete
                        break;
                    }
                    SYNC_FAIL => {
                        let msg = String::from_utf8_lossy(&payload[8..]).to_string();
                        return Err(format!("Sync FAIL during pull: {msg}").into());
                    }
                    other => {
                        return Err(format!("Unexpected sync id {other:#x} during pull").into());
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                // If we have data, it's a normal close after transfer
                if !file_data.is_empty() {
                    break;
                }
                return Err("Sync connection closed prematurely".into());
            }
            _ => {}
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

    println!("[adb-rs] Pull complete: '{}' -> '{}' ({} bytes)", remote, local, file_data.len());
    Ok(())
}

/// Push multiple files via a single direct-mode sync connection.
fn push_files_direct(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    files: &[FilePair],
) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        push_file_direct_with_ids(transport, local_id, remote_id, &file.local, &file.remote)?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let file_data = std::fs::read(local)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    // Build SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;
    protocol::recv_sync_response(transport, local_id, remote_id)?;

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        protocol::send_wrte(transport, local_id, remote_id, &data_buf)?;
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0xFFFF_FFFF, &mut done_buf)
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
    protocol::send_wrte(transport, local_id, remote_id, &req_buf)?;

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
) -> Result<(), Box<dyn std::error::Error>> {
    let local_path = Path::new(local);
    let file_data = std::fs::read(local_path)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    println!("[adb-rs] Pushing '{}' -> '{}' ({} bytes)", local, remote, file_data.len());

    // Build and send SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    write_raw_sync(transport, &send_buf)?;

    // Expect SYNC_OKAY
    let (resp_hdr, _payload) = read_raw_sync(transport)?;
    if resp_hdr.id == SYNC_FAIL {
        let msg = String::from_utf8_lossy(&_payload).to_string();
        return Err(format!("Sync FAIL: {msg}").into());
    }
    if resp_hdr.id != SYNC_OKAY {
        return Err(format!("Expected SYNC_OKAY, got {:#x}", resp_hdr.id).into());
    }

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        write_raw_sync(transport, &data_buf)?;
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0xFFFF_FFFF, &mut done_buf)
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
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[adb-rs] Pulling '{}' -> '{}'", remote, local);

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
            SYNC_OKAY => {
                // Transfer complete
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

    println!("[adb-rs] Pull complete: '{}' -> '{}' ({} bytes)", remote, local, file_data.len());
    Ok(())
}

/// Push multiple files via a single server-mode sync connection.
fn push_files_server(
    transport: &mut dyn Transport,
    files: &[FilePair],
) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        push_file_server_inner(transport, &file.local, &file.remote)?;
    }
    Ok(())
}

/// Push a single file on an existing server-mode sync connection.
fn push_file_server_inner(
    transport: &mut dyn Transport,
    local: &str,
    remote: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_data = std::fs::read(local)
        .map_err(|e| format!("Cannot read local file '{local}': {e}"))?;

    // Build and send SEND request
    let mut send_buf = Vec::new();
    build_sync_send_req(remote, 0o644, &mut send_buf)
        .map_err(|e| format!("Build SEND req failed: {e}"))?;
    write_raw_sync(transport, &send_buf)?;

    // Expect SYNC_OKAY
    let (resp_hdr, _payload) = read_raw_sync(transport)?;
    if resp_hdr.id == SYNC_FAIL {
        let msg = String::from_utf8_lossy(&_payload).to_string();
        return Err(format!("Push '{}' Sync FAIL: {msg}", local).into());
    }
    if resp_hdr.id != SYNC_OKAY {
        return Err(format!("Expected SYNC_OKAY, got {:#x}", resp_hdr.id).into());
    }

    // Send DATA chunks
    for chunk in file_data.chunks(MAX_CHUNK) {
        let mut data_buf = Vec::new();
        build_sync_data_chunk(chunk, &mut data_buf)
            .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
        write_raw_sync(transport, &data_buf)?;
    }

    // Send DONE
    let mut done_buf = Vec::new();
    build_sync_done(0xFFFF_FFFF, &mut done_buf)
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

    loop {
        let (sync_hdr, payload) = read_raw_sync(transport)?;

        match sync_hdr.id {
            SYNC_STAT => {
                let s = SyncStatResponse::decode(&payload)
                    .map_err(|e| format!("Bad STAT response: {e}"))?;
                return Ok(FileStat {
                    mode: s.mode,
                    size: s.size,
                    mtime: s.mtime,
                });
            }
            SYNC_OKAY => {
                // Stat response already consumed, this is an extra OKAY
                return Err("STAT request returned no data".into());
            }
            SYNC_FAIL => {
                let msg = String::from_utf8_lossy(&payload).to_string();
                return Err(format!("Sync FAIL during stat: {msg}").into());
            }
            other => {
                return Err(format!("Unexpected sync id {other:#x} during stat").into());
            }
        }
    }
}
