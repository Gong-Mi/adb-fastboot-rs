//! File sync operations — push and pull files via ADB sync protocol.
//!
//! Maps to AOSP `vendor/adb/client/file_sync_client.cpp`.
//!
//! Provides public `push()` and `pull()` functions that try the ADB server
//! (port 5037) first for transport reuse, falling back to direct USB/TCP
//! connection with full CNXN/AUTH handshake.
//!
//! Internal helpers handle two modes:
//! - **Direct**: sync protocol messages wrapped in ADB WRTE frames
//!   (transport connected directly to adbd via USB or TCP).
//! - **Server**: raw sync protocol bytes tunneled through the ADB server
//!   bridge (which strips ADB framing).

use std::path::Path;
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, AdbServerTransport, Transport,
    A_CLSE, A_OKAY, A_WRTE,
    build_sync_recv_req, build_sync_send_req, build_sync_data_chunk, build_sync_done,
    SyncMessageHeader,
    SYNC_DATA, SYNC_DENT, SYNC_FAIL, SYNC_OKAY,
};

use super::protocol;
use super::auth::default_auth;
use super::transport::{open_adb_transport, connect_and_handshake_with_tls_upgrade};

/// Max payload chunk size for sync DATA messages (64 KB).
const MAX_CHUNK: usize = 64 * 1024;

const ADB_SERVER_PORT: u16 = 5037;

// ---------------------------------------------------------------------------
// Public API
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

    // Close sync connection
    let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&clse_hdr, &[])?;
    let _ = transport.recv_message(); // wait for CLSE ack

    println!("[adb-rs] Push complete: '{}' -> '{}'", local, remote);
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

    // Close sync connection
    let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    transport.send_message(&clse_hdr, &[])?;
    let _ = transport.recv_message();

    println!("[adb-rs] Pull complete: '{}' -> '{}' ({} bytes)", remote, local, file_data.len());
    Ok(())
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
