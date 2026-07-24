//! ADB wire-protocol helpers: open service, send/receive WRTE frames, sync responses.
//!
//! Maps to the ADB message-level protocol over a raw `Transport`.
//! These operate on the A_OPEN / A_OKAY / A_WRTE / A_CLSE message cycle,
//! not the ADB server (5037) host-service protocol.

use adb_protocol::{
    AdbMessageHeader, SyncMessageHeader, Transport,
    A_CLSE, A_OKAY, A_OPEN, A_WRTE,
    SYNC_FAIL, SYNC_OKAY,
};

/// Open an adbd service (shell:, sync:, reboot:, etc.) via A_OPEN.
/// Returns (local_id, remote_id) after A_OKAY.
pub fn open_service(
    transport: &mut dyn Transport,
    dest: &str,
    local_id: u32,
) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, dest.as_bytes());
    transport.send_message(&open_hdr, dest.as_bytes())?;

    // Read until we get A_OKAY with our local_id
    loop {
        let (hdr, _) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {
                return Ok((local_id, hdr.arg0));
            }
            A_CLSE => {
                return Err(format!("Service '{}' closed immediately", dest).into());
            }
            _ => {
                // Keep reading
            }
        }
    }
}

/// Send a WRTE frame and wait for OKAY ack
pub fn send_wrte(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, local_id, remote_id, payload);
    transport.send_message(&wrte_hdr, payload)?;
    // Wait for OKAY ack
    loop {
        let (hdr, _) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => return Ok(()),
            A_WRTE => {
                // Device sent data; ack it
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                // Don't consume it, let caller handle — but for sync we don't expect this
            }
            A_CLSE => return Err("Connection closed by peer".into()),
            _ => {}
        }
    }
}

/// Read WRTE frames until CLSE or EOF. Returns collected payload bytes.
#[allow(dead_code)]
pub fn recv_wrte_all(
    transport: &mut dyn Transport,
    local_id: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut collected = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                collected.extend_from_slice(&payload);
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            A_OKAY => {}
            _ => break,
        }
    }
    Ok(collected)
}

/// Read a sync response (expects OKAY or FAIL in SyncMessageHeader format).
pub fn recv_sync_response(
    transport: &mut dyn Transport,
    local_id: u32,
    _remote_id: u32,
) -> Result<(), String> {
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(m) => m,
            Err(e) => return Err(format!("recv sync response error: {e}")),
        };
        match hdr.command {
            A_OKAY => {
                // This is ack for our WRTE, keep reading
            }
            A_WRTE => {
                // Ack the WRTE
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Parse sync header
                if payload.len() < 8 {
                    return Err("Sync response too short".to_string());
                }
                let sync_hdr = match SyncMessageHeader::decode(&payload) {
                    Ok(h) => h,
                    Err(e) => return Err(format!("Bad sync header: {e}")),
                };
                match sync_hdr.id {
                    SYNC_OKAY => return Ok(()),
                    SYNC_FAIL => {
                        let msg = String::from_utf8_lossy(&payload[8..]).to_string();
                        return Err(format!("Sync FAIL: {msg}"));
                    }
                    other => {
                        return Err(format!("Unexpected sync response id {other:#x}"));
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                return Err("Sync connection closed".to_string());
            }
            _ => {}
        }
    }
}
