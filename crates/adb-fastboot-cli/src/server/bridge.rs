//! Transport Bridge — connect client to device after host:transport succeeds.
//!
//! Mirrors AOSP `sockets.cpp` → smart_socket_enqueue + connect_to_remote.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use crate::server::models::{DeviceOrigin, TransportRegistry};
use crate::server::transport::open_transport_by_origin;

/// Bridge a client TCP connection to an ADB device (TCP or USB).
///
/// Returns `Ok(true)` on successful bridge end (device disconnected),
/// `Ok(false)` for non-error finish (should not happen), or `Err(...)`.
pub(crate) fn bridge_to_device(
    client: std::net::TcpStream,
    serial: String,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<bool, String> {
    let origin = {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        reg.find_by_serial(&serial).map(|d| d.origin)
    };

    let is_tcp = matches!(origin, Some(DeviceOrigin::Tcp { .. }));
    let origin_ref = origin.as_ref().ok_or_else(|| format!("device '{serial}' not found"))?;
    let result = smart_socket_bridge(client, open_transport_by_origin(origin_ref, &serial)?, &serial);

    // After bridge ends, remove TCP device from registry
    if is_tcp && result.is_ok() {
        let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        if reg.remove_device(&serial) {
            eprintln!(
                "[adb-server] TCP device '{serial}' disconnected — removed from registry"
            );
        }
    }

    result
}

/// Smart socket bridge: reads hex-length prefixed commands from client,
/// routes host services to dispatch_host_service, and creates A_OPEN
/// on the device transport for device services.  Matches AOSP's
/// smart_socket_enqueue + connect_to_remote behavior.
fn smart_socket_bridge(
    mut client: std::net::TcpStream,
    mut transport: Box<dyn adb_protocol::Transport>,
    _serial: &str,
) -> Result<bool, String> {
    let client_clone = client.try_clone()
        .map_err(|e| format!("client clone: {e}"))?;

    loop {
        let mut len_buf = [0u8; 4];
        if client.read_exact(&mut len_buf).is_err() {
            return Ok(true);
        }
        let len_str = std::str::from_utf8(&len_buf)
            .map_err(|_| "Invalid UTF-8 in length prefix".to_string())?;
        let cmd_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| format!("Invalid hex length: {len_str}"))?;

        if cmd_len == 0 || cmd_len > 4096 {
            return Err(format!("Invalid command length: {cmd_len}"));
        }

        let mut cmd_buf = vec![0u8; cmd_len];
        client.read_exact(&mut cmd_buf)
            .map_err(|e| format!("Failed to read command: {e}"))?;
        let cmd = String::from_utf8(cmd_buf)
            .map_err(|_| "Command is not valid UTF-8".to_string())?;

        // Host service?  Route to dispatch_host_service (but we don't have
        // registry access here, so handle common ones directly).
        if cmd.starts_with("host:get-serialno") {
            let resp = _serial;
            let len_hdr = format!("{:04x}", resp.len());
            client.write_all(b"OKAY")
                .and_then(|_| client.write_all(len_hdr.as_bytes()))
                .and_then(|_| client.write_all(resp.as_bytes()))
                .and_then(|_| client.flush())
                .map_err(|e| format!("write failed: {e}"))?;
            continue;
        }
        if cmd.starts_with("host:") {
            // Unknown host service — fail
            let msg = format!("unknown host service: {}", cmd);
            let len_hdr = format!("{:04x}", msg.len());
            client.write_all(b"FAIL")
                .and_then(|_| client.write_all(len_hdr.as_bytes()))
                .and_then(|_| client.write_all(msg.as_bytes()))
                .and_then(|_| client.flush())
                .map_err(|e| format!("write failed: {e}"))?;
            continue;
        }

        // --- Device service: A_OPEN via services module ---
        let (local_id, remote_id) = crate::server::services::device_service_to_socket(
            &cmd, &mut transport)?;

        // Send OKAY to client
        client.write_all(b"OKAY")
            .and_then(|_| client.flush())
            .map_err(|e| format!("write OKAY failed: {e}"))?;

        // --- Bridge ADB frames bidirectionally ---
        // Direction: device → client
        let mut dev_clone = transport.try_clone_box()
            .ok_or_else(|| "transport cannot be cloned".to_string())?;
        let mut client_writer = client_clone;
        std::thread::spawn(move || -> Result<(), String> {
            loop {
                let (hdr, payload) = dev_clone.recv_message()
                    .map_err(|_| "device disconnected".to_string())?;
                match hdr.command {
                    adb_protocol::A_WRTE => {
                        let ack = adb_protocol::AdbMessageHeader::new(
                            adb_protocol::A_OKAY, hdr.arg1, hdr.arg0, &[]);
                        let _ = dev_clone.send_message(&ack, &[]);
                        client_writer.write_all(&payload)
                            .map_err(|_| "client write".to_string())?;
                    }
                    adb_protocol::A_CLSE => {
                        let ack = adb_protocol::AdbMessageHeader::new(
                            adb_protocol::A_CLSE, hdr.arg1, hdr.arg0, &[]);
                        let _ = dev_clone.send_message(&ack, &[]);
                        break;
                    }
                    _ => {}
                }
            }
            Ok(())
        });

        // Direction: client → device
        let mut buf = [0u8; 65536];
        loop {
            let n = client.read(&mut buf)
                .map_err(|_| "client read".to_string())?;
            if n == 0 { break; }
            let wrte_hdr = adb_protocol::AdbMessageHeader::new(
                adb_protocol::A_WRTE, local_id, remote_id, &buf[..n]);
            transport.send_message(&wrte_hdr, &buf[..n])
                .map_err(|e| format!("WRTE: {e}"))?;
            let (ack_hdr, _) = transport.recv_message()
                .map_err(|_| "ack".to_string())?;
            if ack_hdr.command != adb_protocol::A_OKAY {
                break;
            }
        }

        return Ok(true);
    }
}
