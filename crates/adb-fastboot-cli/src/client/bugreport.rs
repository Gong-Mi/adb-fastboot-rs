//! ADB bugreport generation and collection.
//!
//! AOSP source: `vendor/adb/client/bugreport.cpp`
//!
//! Handles:
//! - `adb bugreport [path]` — generate and pull a bugreport zip
//! - Coordinates `dumpstate` service on the device
//! - Manages bugreport progress and cancellation

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use adb_protocol::{
    AdbMessageHeader, Transport,
    A_CLSE, A_OKAY, A_WRTE,
};

use super::protocol::open_service;

/// Result of a bugreport operation.
pub struct BugreportResult {
    /// The raw bugreport data (zipped).
    pub data: Vec<u8>,
    /// The suggested file name from the device.
    pub suggested_name: String,
}

/// Execute `bugreportz` on the device and collect the resulting zip data.
///
/// Uses the `shell,raw:bugreportz` approach which streams the zipped bugreport
/// to stdout. Returns the raw zip bytes and the suggested filename.
pub fn collect_bugreport(
    transport: &mut dyn Transport,
) -> Result<BugreportResult, Box<dyn std::error::Error>> {
    // Try bugreportz first (compressed, modern)
    let result = try_bugreportz(transport);
    if result.is_ok() {
        return result;
    }

    // Fallback: legacy bugreport (text, can be very large)
    try_legacy_bugreport(transport)
}

/// Try the `bugreportz` service for compressed bugreport.
fn try_bugreportz(
    transport: &mut dyn Transport,
) -> Result<BugreportResult, Box<dyn std::error::Error>> {
    // First, check if bugreportz is available
    let dest = "shell,v2,raw:bugreportz -p".to_string();
    let (local_id, _remote_id) = open_service(transport, &dest, 1)?;

    let mut output = Vec::new();
    let mut suggested_name = String::from("bugreport.zip");

    let deadline = Instant::now() + Duration::from_secs(120);

    loop {
        if Instant::now() > deadline {
            // Send CLSE to abort
            let _ = transport.send_message(
                &AdbMessageHeader::new(A_CLSE, local_id, 0, &[]),
                &[],
            );
            return Err("Bugreport timed out".into());
        }

        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(_) => {
                // Timeout or EOF — try to finish with what we have
                break;
            }
        };

        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Parse bugreportz progress lines: "OK: <path>"
                // or "BEGIN:<name>", "PROGRESS:<pct>", etc.
                let text = String::from_utf8_lossy(&payload);
                if text.starts_with("OK:") {
                    // Path reported — the bugreportz has written a file
                    let path = text[3..].trim().to_string();
                    suggested_name = Path::new(&path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("bugreport.zip")
                        .to_string();

                    // Now we need to pull the file via sync
                    let file_data = pull_file_via_sync(transport, &path)?;
                    return Ok(BugreportResult {
                        data: file_data,
                        suggested_name,
                    });
                } else if text.starts_with("BEGIN:") {
                    suggested_name = text[6..].trim().to_string();
                } else if text.starts_with("PROGRESS:") {
                    let pct = text[9..].trim();
                    eprintln!("  bugreport: {pct}%");
                }

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

    // If we got here, bugreportz output contains the file path in plain text
    let output_str = String::from_utf8_lossy(&output);
    for line in output_str.lines() {
        if let Some(path) = line.strip_prefix("OK:") {
            let path = path.trim();
            suggested_name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("bugreport.zip")
                .to_string();
            let file_data = pull_file_via_sync(transport, path)?;
            return Ok(BugreportResult {
                data: file_data,
                suggested_name,
            });
        }
    }

    Err("bugreportz did not produce output file".into())
}

/// Fallback: use legacy `dumpstate` via shell.
fn try_legacy_bugreport(
    transport: &mut dyn Transport,
) -> Result<BugreportResult, Box<dyn std::error::Error>> {
    let dest = "shell,v2,raw:dumpstate".to_string();
    let (local_id, _remote_id) = open_service(transport, &dest, 1)?;

    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(180);

    loop {
        if Instant::now() > deadline {
            let _ = transport.send_message(
                &AdbMessageHeader::new(A_CLSE, local_id, 0, &[]),
                &[],
            );
            return Err("Legacy bugreport timed out".into());
        }

        transport
            .recv_message()

            .ok();
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(_) => break,
        };

        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                output.extend_from_slice(&payload);
                eprint!(".");
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }

    eprintln!();

    Ok(BugreportResult {
        data: output,
        suggested_name: "bugreport.txt".to_string(),
    })
}

/// Pull a file from the device using the sync protocol.
fn pull_file_via_sync(
    transport: &mut dyn Transport,
    remote_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use adb_protocol::build_sync_recv_req;
    use adb_protocol::SyncMessageHeader;

    let (local_id, _remote_id) = open_service(transport, "sync:", 1)?;

    // Send RECV request
    let mut recv_buf = Vec::new();
    build_sync_recv_req(remote_path, &mut recv_buf)?;

    let recv_hdr = AdbMessageHeader::new(A_WRTE, local_id, 1, &recv_buf);
    transport.send_message(&recv_hdr, &recv_buf)?;

    // Wait for OKAY ack
    loop {
        let (hdr, _) = transport.recv_message()?;
        if hdr.command == A_OKAY {
            break;
        }
    }

    // Read DATA frames until DONE
    let mut file_data = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {}
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Parse sync header
                if payload.len() >= 8 {
                    if let Ok(sync_hdr) = SyncMessageHeader::decode(&payload) {
                        let data = &payload[8..];
                        match sync_hdr.id {
                            adb_protocol::constants::SYNC_DATA => {
                                file_data.extend_from_slice(data);
                            }
                            adb_protocol::constants::SYNC_DONE => {
                                // File transfer done
                            }
                            adb_protocol::constants::SYNC_FAIL => {
                                let msg = String::from_utf8_lossy(data);
                                return Err(format!("Sync RECV failed: {msg}").into());
                            }
                            _ => {}
                        }
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

    Ok(file_data)
}

/// Save the bugreport data to a local file.
pub fn save_bugreport(
    result: &BugreportResult,
    output_path: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = match output_path {
        Some(p) => {
            if p.is_dir() {
                p.join(&result.suggested_name)
            } else {
                p.to_path_buf()
            }
        }
        None => Path::new(&result.suggested_name).to_path_buf(),
    };

    let mut file = fs::File::create(&path)?;
    file.write_all(&result.data)?;

    Ok(path.to_string_lossy().to_string())
}

/// Generate and save a bugreport. High-level convenience function.
pub fn generate_bugreport(
    transport: &mut dyn Transport,
    output_path: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    let result = collect_bugreport(transport)?;
    let saved_path = save_bugreport(&result, output_path)?;
    Ok(saved_path)
}
