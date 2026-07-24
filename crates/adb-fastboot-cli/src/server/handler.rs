//! ADB Client handler — host service dispatch loop.
//!
//! Mirrors AOSP `sockets.cpp` → handle_client, smart_socket.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_CNXN, MAX_PAYLOAD_V2};

use crate::server::bridge::bridge_to_device;
use crate::server::forward::{handle_forward, handle_reverse};
use crate::server::models::{
    is_usable_state, DeviceOrigin, TransportRegistry, SERVER_VERSION,
};

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

pub(crate) fn handle_client(
    mut client: TcpStream,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_nodelay(true);

    loop {
        let mut len_buf = [0u8; 4];
        if client.read_exact(&mut len_buf).is_err() {
            return Ok(());
        }
        let len_str =
            std::str::from_utf8(&len_buf).map_err(|_| "Invalid UTF-8 in length prefix".to_string())?;
        let cmd_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| format!("Invalid hex length: {len_str}"))?;

        if cmd_len == 0 || cmd_len > 4096 {
            return Err(format!("Invalid command length: {cmd_len}"));
        }

        let mut cmd_buf = vec![0u8; cmd_len];
        client
            .read_exact(&mut cmd_buf)
            .map_err(|e| format!("Failed to read command: {e}"))?;
        let cmd = String::from_utf8(cmd_buf)
            .map_err(|_| "Command is not valid UTF-8".to_string())?;

        let is_transport_cmd = cmd.starts_with("host:transport:")
            || cmd.starts_with("host:tport:")
            || cmd.starts_with("host:transport-id:");

        dispatch_host_service(&mut client, &cmd, registry, running)?;

        if is_transport_cmd {
            // dispatch_host_service already sent OKAY — now enter bridge mode.
            // Move client into the bridge (this function is the last use).
            let serial: String = if cmd.starts_with("host:transport:") {
                cmd["host:transport:".len()..].to_string()
            } else if cmd.starts_with("host:tport:serial:") {
                cmd["host:tport:serial:".len()..].to_string()
            } else if cmd.starts_with("host:transport-id:") {
                let id_str = &cmd["host:transport-id:".len()..];
                let tid: u64 = id_str.parse().map_err(|_| format!("invalid transport id: {id_str}"))?;
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_by_transport_id(tid)
                    .map(|d| d.serial.clone())
                    .ok_or_else(|| format!("transport id {tid} not found"))?
            } else {
                // host:tport: or host:tport:any — find any device
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_any_device()
                    .map(|d| d.serial.clone())
                    .ok_or_else(|| "no devices available".to_string())?
            };
            let _ = bridge_to_device(client, serial, registry)?;
            // bridge always returns at this point, but in case of false…
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------------------
// Host Service Dispatch
// ---------------------------------------------------------------------------

/// Parse the ADB host-service `connect` address.
///
/// AOSP's ParseNetAddress accepts the usual `host:port` spelling and requires
/// brackets around IPv6 literals when a port is present. Keep the host
/// unbracketed for DNS resolution, while preserving the socket's canonical
/// bracketed spelling for the registry serial below.
pub(crate) fn parse_adb_host_port(target: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 address: missing closing ']'".to_string())?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid address: IPv6 host must be followed by ':port'".to_string())?;
        (host, port)
    } else {
        if target.matches(':').count() != 1 {
            return Err("invalid address: IPv6 literals must be enclosed in '[' and ']'".to_string());
        }
        target
            .split_once(':')
            .ok_or_else(|| "invalid connect format: use host:port".to_string())?
    };

    if host.is_empty() {
        return Err("invalid address: host is empty".to_string());
    }
    let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;
    if port == 0 {
        return Err("invalid port: 0".to_string());
    }
    Ok((host.to_string(), port))
}

pub(crate) fn dispatch_host_service(
    client: &mut TcpStream,
    cmd: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    // ----- Helper closures -----

    let ok = |sock: &mut TcpStream, data: &[u8]| -> Result<(), String> {
        let len_hdr = format!("{:04x}", data.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(data))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let ok_empty = |sock: &mut TcpStream| -> Result<(), String> {
        sock.write_all(b"OKAY")
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let ok_str = |sock: &mut TcpStream, s: &str| -> Result<(), String> {
        ok(sock, s.as_bytes())
    };

    let fail = |sock: &mut TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    // ----- Dispatch -----

    match cmd {
        // -- host:version ---------------------------------------------------
        "host:version" => {
            let ver_str = format!("{:04x}", SERVER_VERSION);
            ok_str(client, &ver_str)
        }

        // -- host:kill ------------------------------------------------------
        "host:kill" => {
            ok_empty(client)?;
            eprintln!("[adb-server] Received host:kill — shutting down.");
            running.store(false, Ordering::Relaxed);
            Ok(())
        }

        // -- host:start-server ------------------------------------------------
        // AOSP adb_client.cpp sends this after connecting to the server to
        // confirm the daemon is running. Always succeed — if we're here,
        // the server is alive and responding.
        "host:start-server" => ok_empty(client),

        // -- host:devices / host:devices-l ----------------------------------
        "host:devices" | "host:devices-l" => {
            let verbose = cmd.ends_with("-l");
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_devices(verbose)
            };
            ok_str(client, &list)
        }

        // -- host:track-devices ----------------------------------------------
        // Keep this connection open and publish a new length-prefixed device
        // list whenever the registry changes. This is the service used by IDEs
        // and scrcpy to receive hotplug updates.
        "host:track-devices" => {
            let mut last: Option<String> = None;
            ok_empty(client)?;
            while running.load(Ordering::Relaxed) {
                let current = {
                    let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.list_devices(false)
                };
                if last.as_deref() != Some(current.as_str()) {
                    let len_hdr = format!("{:04x}", current.len());
                    client
                        .write_all(len_hdr.as_bytes())
                        .and_then(|_| client.write_all(current.as_bytes()))
                        .and_then(|_| client.flush())
                        .map_err(|e| format!("track-devices write failed: {e}"))?;
                    last = Some(current);
                }
                thread::sleep(Duration::from_millis(250));
            }
            Ok(())
        }

        // -- host:wait-for-device ---------------------------------------------
        // AOSP clients use this service to block until at least one transport
        // reaches a usable registry state. Do not acknowledge before a device
        // exists; otherwise callers race the transport watcher.
        "host:wait-for-device" | "host:wait-for-any-device" => {
            while running.load(Ordering::Relaxed) {
                let available = {
                    let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.find_any_device().is_some()
                };
                if available {
                    return ok_empty(client);
                }
                thread::sleep(Duration::from_millis(250));
            }
            fail(client, "server is shutting down")
        }

        // -- host:get-state / host:get-serialno / host:get-devpath ----------
        c if c == "host:get-state" || c == "host:get-serialno" || c == "host:get-devpath" => {
            let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            let device = reg.find_any_device();
            match (c, device) {
                ("host:get-state", Some(dev)) => ok_str(client, dev.state.as_str()),
                ("host:get-serialno", Some(dev)) => ok_str(client, &dev.serial),
                ("host:get-devpath", Some(dev)) => {
                    let path = match dev.origin {
                        DeviceOrigin::Usb => "usb".to_string(),
                        DeviceOrigin::Tcp { addr } => format!("{}:{}", addr.ip(), addr.port()),
                    };
                    ok_str(client, &path)
                }
                _ => fail(client, "device not found"),
            }
        }

        // -- host:transport:<serial> ----------------------------------------
        c if c.starts_with("host:transport:") => {
            let serial = &c["host:transport:".len()..];
            let exists = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_by_serial(serial)
                    .map(|d| is_usable_state(d.state))
                    .unwrap_or(false)
            };
            if exists {
                ok_empty(client)
            } else {
                fail(client, &format!("device '{serial}' not found"))
            }
        }

        // -- host:transport-any ---------------------------------------------
        "host:transport-any" => {
            let exists = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_any_device().is_some()
            };
            if exists {
                ok_empty(client)
            } else {
                fail(client, "no devices available")
            }
        }

        // -- host:tport:serial:<serial> (AOSP v2, returns transport_id) -------
        c if c.starts_with("host:tport:serial:") => {
            let serial = &c["host:tport:serial:".len()..];
            let device = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_by_serial(serial).cloned()
            };
            match device {
                Some(dev) if is_usable_state(dev.state) => {
                    let tid = dev.transport_id;
                    ok_empty(client)?;
                    let tid_bytes = tid.to_le_bytes();
                    client
                        .write_all(&tid_bytes)
                        .and_then(|_| client.flush())
                        .map_err(|e| format!("write transport_id failed: {e}"))
                }
                Some(_) => fail(client, &format!("device '{serial}' is offline")),
                None => fail(client, &format!("device '{serial}' not found")),
            }
        }

        // -- host:tport: / host:tport:any (AOSP v2 transport-any) --------------
        "host:tport:" | "host:tport:any" => {
            let device = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_any_device().cloned()
            };
            match device {
                Some(dev) => {
                    let tid = dev.transport_id;
                    ok_empty(client)?;
                    let tid_bytes = tid.to_le_bytes();
                    client
                        .write_all(&tid_bytes)
                        .and_then(|_| client.flush())
                        .map_err(|e| format!("write transport_id failed: {e}"))
                }
                None => fail(client, "no devices available"),
            }
        }

        // -- host:transport-id:<id> (select by transport_id) -------------------
        c if c.starts_with("host:transport-id:") => {
            let id_str = &c["host:transport-id:".len()..];
            let tid: u64 = match id_str.parse() {
                Ok(id) => id,
                Err(_) => return fail(client, "invalid transport id"),
            };
            let exists = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_by_transport_id(tid)
                    .map(|d| is_usable_state(d.state))
                    .unwrap_or(false)
            };
            if exists {
                ok_empty(client)
            } else {
                fail(client, &format!("transport id {tid} not found"))
            }
        }

        // -- host-serial:<serial>:<service> (serial-qualified commands) --------
        // Commands like host-serial:<serial>:features
        c if c.starts_with("host-serial:") && c.contains(":features") => {
            // Strip "host-serial:" prefix, split on first ':' to get serial + service
            let rest = &c["host-serial:".len()..];
            if let Some((serial, service)) = rest.split_once(':') {
                if service == "features" {
                    let features = {
                        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                        reg.find_by_serial(serial)
                            .and_then(|d| d.transport_features.as_deref())
                            .and_then(|banner| {
                                // Parse CNXN banner for features=...
                                banner.split(';')
                                    .find_map(|part| part.strip_prefix("features="))
                            })
                            .map(|s| s.to_string())
                    };
                    if let Some(feat) = features {
                        ok_str(client, &feat)
                    } else {
                        fail(client, &format!("device '{serial}' not found or no features"))
                    }
                } else {
                    fail(client, &format!("unsupported host-serial service: {service}"))
                }
            } else {
                fail(client, "invalid host-serial format")
            }
        }

        // -- host:connect <host>:<port> -------------------------------------
        c if c.starts_with("host:connect:") => {
            let target = &c["host:connect:".len()..];
            let (parsed_host, port) = parse_adb_host_port(target)?;
            let host = &parsed_host;

            let addr_str = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let sock_addrs: Vec<SocketAddr> = addr_str
                .to_socket_addrs()
                .map_err(|e| format!("resolve failed: {e}"))?
                .collect();
            let addr = sock_addrs
                .first()
                .ok_or_else(|| "no address resolved".to_string())?
                .to_owned();

            let mut test_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
                .map_err(|e| format!("cannot connect to {addr_str}: {e}"))?;
            let _ = test_stream.set_nodelay(true);

            // Probe with CNXN
            let probe = b"host::";
            let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
            let mut hdr_buf = [0u8; 24];
            cnxn.encode(&mut hdr_buf);

            let cnxn_sent = test_stream
                .write_all(&hdr_buf)
                .and_then(|_| test_stream.write_all(probe))
                .and_then(|_| test_stream.flush());

            let response = if cnxn_sent.is_ok() && test_stream.read_exact(&mut hdr_buf).is_ok() {
                AdbMessageHeader::decode(&hdr_buf).ok()
            } else {
                None
            };
            let is_adbd = response
                .as_ref()
                .map(|h| h.command == A_CNXN)
                .unwrap_or(false);

            if is_adbd {
                let serial = addr.to_string();
                {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.upsert_tcp_device(addr, serial.clone());

                    // Read CNXN payload for features
                    let payload_len = response.unwrap().data_length as usize;
                    if payload_len > 0 && payload_len < 4096 {
                        let mut actual_payload = vec![0u8; payload_len];
                        let _ = test_stream.read_exact(&mut actual_payload);
                        let cnxn_str = String::from_utf8_lossy(&actual_payload);
                        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
                            dev.transport_features = Some(cnxn_str.to_string());
                            for part in cnxn_str.trim().split(';') {
                                if let Some(val) = part.strip_prefix("product=") {
                                    dev.product = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("model=") {
                                    dev.model = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("device=") {
                                    dev.device_name = Some(val.to_string());
                                }
                            }
                        }
                    }
                }
                ok_str(client, &serial)
            } else {
                fail(client, "connection refused: not an ADB device")
            }
        }

        // -- host:disconnect / host:disconnect:<serial> --------------------
        c if c == "host:disconnect" || c.starts_with("host:disconnect:") => {
            if c == "host:disconnect" {
                let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                let count =
                    reg.devices.iter().filter(|d| matches!(d.origin, DeviceOrigin::Tcp { .. })).count();
                reg.remove_all_tcp_devices();
                ok_str(client, &format!("disconnected {count} devices"))
            } else {
                let serial = &c["host:disconnect:".len()..];
                let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                if reg.remove_device(serial) {
                    ok_str(client, &format!("disconnected {serial}"))
                } else {
                    fail(client, &format!("device '{serial}' not found"))
                }
            }
        }

        // -- host:forward:* --------------------------------------------------
        c if c.starts_with("host:forward:") => {
            let sub = &c["host:forward:".len()..];
            handle_forward(client, sub, registry)
        }

        // -- host:reverse:* --------------------------------------------------
        c if c.starts_with("host:reverse:") => {
            let sub = &c["host:reverse:".len()..];
            handle_reverse(client, sub, registry)
        }
        c if c.starts_with("reverse:") => {
            let sub = &c["reverse:".len()..];
            handle_reverse(client, sub, registry)
        }

        // -- host:host-features ---------------------------------------------
        "host:host-features" => {
            let features =
                "shell_v2,cmd,abb,abb_exec,remount_shell_v2,fixed_push_symlink_target,fixed_push_mkdir";
            ok_str(client, features)
        }

        // -- host:jdwp -------------------------------------------------------
        "host:jdwp" => {
            ok_str(client, "")
        }

        // -- Unknown ---------------------------------------------------------
        other => fail(client, &format!("unknown host service: {other}")),
    }
}
