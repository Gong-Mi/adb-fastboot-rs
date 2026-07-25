//! Transport Bridge — connect client to device after host:transport succeeds.
//!
//! Mirrors AOSP `sockets.cpp` → smart_socket_enqueue + connect_to_remote.
//!
//! # AUTH/CNXN strategy
//!
//! - **USB devices**: pre-authenticated at discovery time (watcher).  The bridge
//!   reuses the cached authenticated transport from the registry, wrapped in a
//!   `SharedTransport` so both the reader thread and the writer loop share the
//!   same underlying `Arc<Mutex<Box<dyn Transport>>>`.
//! - **TCP devices**: cannot be pre-authenticated because the watcher has no TCP
//!   visibility.  The bridge opens a fresh TCP connection and does the CNXN
//!   handshake (including AUTH if the device requests it).

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use adb_protocol::{AdbMessageHeader, Transport, A_AUTH, A_AUTH_TOKEN, A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, SharedTransport};

use crate::server::models::{DeviceOrigin, TransportRegistry};

/// Bridge a client TCP connection to an ADB device (TCP or USB).
///
/// Returns `Ok(true)` on successful bridge end (device disconnected),
/// `Ok(false)` for non-error finish (should not happen), or `Err(...)`.
pub(crate) fn bridge_to_device(
    client: std::net::TcpStream,
    serial: String,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<bool, String> {
    let (origin, is_tcp) = {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        let origin = reg.find_by_serial(&serial).map(|d| d.origin);
        let is_tcp = matches!(origin, Some(DeviceOrigin::Tcp { .. }));
        (origin, is_tcp)
    };

    let origin_ref = origin.as_ref().ok_or_else(|| format!("device '{serial}' not found"))?;

    let result = if matches!(origin_ref, DeviceOrigin::Usb) {
        // --- USB: use authenticated transport from registry ---
        #[cfg(feature = "usb")]
        {
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            let transport_arc = reg.ensure_usb_auth(&serial)?;
            let shared = Box::new(SharedTransport::new(transport_arc))
                as Box<dyn Transport>;
            drop(reg);
            smart_socket_bridge(client, shared, &serial)
        }
        #[cfg(not(feature = "usb"))]
        {
            Err("USB transport not supported (compile with --features usb)".to_string())
        }
    } else {
        // --- TCP: open raw transport and authenticate inline ---
        let transport = crate::server::transport::open_transport_by_origin(origin_ref, &serial)?;
        let transport = tcp_auth_handshake(transport, &serial)?;
        smart_socket_bridge(client, transport, &serial)
    };

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

/// Perform CNXN + optional AUTH handshake on a TCP transport.
///
/// TCP devices may require AUTH (same as USB).  This function sends A_CNXN,
/// then loops on A_AUTH until A_CNXN is received or auth fails.
pub(crate) fn tcp_auth_handshake(
    mut transport: Box<dyn Transport>,
    _serial: &str,
) -> Result<Box<dyn Transport>, String> {
    let cnxn_payload = b"host::";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

    transport
        .send_message(&cnxn_hdr, cnxn_payload)
        .map_err(|e| format!("CNXN send failed: {e}"))?;

    let (mut resp_hdr, mut payload) = transport
        .recv_message()
        .map_err(|e| format!("CNXN recv failed: {e}"))?;

    // If device responds with A_CNXN directly (no auth required), we're done.
    if resp_hdr.command == A_CNXN {
        return Ok(transport);
    }

    // Otherwise, handle AUTH loop (same as USB auth).
    let auth = crate::client::auth::default_auth();
    let mut sent_signature = false;
    let mut sent_public_key = false;

    while resp_hdr.command == A_AUTH {
        eprintln!("[adb-auth] AUTH loop: resp_hdr.arg0={:#x}, sent_sig={}, sent_key={}",
            resp_hdr.arg0, sent_signature, sent_public_key);
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0));
        }
        if payload.len() != 20 {
            return Err(format!(
                "Invalid ADB AUTH token length: {}",
                payload.len()
            ));
        }

        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            eprintln!("[adb-auth] Sending SIGNATURE ({} bytes)", payload.len());
            auth.make_signature_message(&payload)
                .map_err(|e| format!("signature failed: {e}"))?
        } else if !sent_public_key {
            sent_public_key = true;
            eprintln!("[adb-auth] Sending RSAKEY");
            auth.make_rsakey_message()
                .map_err(|e| format!("rsakey failed: {e}"))?
        } else {
            return Err(
                "adbd rejected the ADB RSA key after signature and public-key exchange"
                    .to_string(),
            );
        };

        transport
            .send_message(&auth_hdr, &auth_payload)
            .map_err(|e| format!("AUTH send failed: {e}"))?;

        (resp_hdr, payload) = transport
            .recv_message()
            .map_err(|e| format!("AUTH recv failed: {e}"))?;
        eprintln!("[adb-auth] AUTH response: cmd={:#x} (A_CNXN={:#x}, A_AUTH={:#x})",
            resp_hdr.command, A_CNXN, A_AUTH);
    }

    if resp_hdr.command != A_CNXN {
        return Err(format!(
            "Expected A_CNXN after AUTH, got cmd={:#x}",
            resp_hdr.command
        ));
    }

    // Persist public key on Android
    #[cfg(target_os = "android")]
    if sent_public_key {
        let _ = crate::client::auth::persist_adb_pubkey(auth);
    }

    Ok(transport)
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
