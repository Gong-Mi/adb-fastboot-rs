//! ADB Client handler — host service dispatch loop.
//!
//! Mirrors AOSP `sockets.cpp` → handle_client, smart_socket.
//!
//! The main entry point [`handle_client`] delegates to [`run_smart_socket_loop`]
//! which implements the full asocket state machine (hex-length prefix parsing,
//! host service dispatch, transport selection, and device service bridging).
//! [`dispatch_host_service`] remains here for reuse by the smart socket module.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::server::forward::{handle_forward, handle_reverse};
use crate::server::models::{
    is_usable_state, DeviceOrigin, TransportRegistry, SERVER_VERSION,
};
use crate::server::smart_socket;

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

pub(crate) fn handle_client(
    client: TcpStream,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_nodelay(true);

    // Delegate to the smart socket state machine.
    smart_socket::run_smart_socket_loop(client, registry, running)
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

    eprintln!("[adb-debug] dispatch_host_service: cmd={:?}", cmd);
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
            let selection = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_unique_device().map(|_| ())
            };
            match selection {
                Ok(()) => ok_empty(client),
                Err(error) => fail(client, error),
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
            let selection = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_unique_device().map(|dev| dev.transport_id)
            };
            match selection {
                Ok(tid) => {
                    ok_empty(client)?;
                    let tid_bytes = tid.to_le_bytes();
                    client
                        .write_all(&tid_bytes)
                        .and_then(|_| client.flush())
                        .map_err(|e| format!("write transport_id failed: {e}"))
                }
                Err(error) => fail(client, error),
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

            let serial = target.to_string(); // keep original hostname for matching

            // Check if already connected (using original hostname serial)
            {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                eprintln!("[adb-debug] checking already: serial={:?}, devices={:?}", 
                    &serial,
                    reg.devices.iter().map(|d| &d.serial).collect::<Vec<_>>());
                if reg.devices.iter().any(|d| d.serial == serial) {
                    eprintln!("[adb-debug] already connected: {}", &serial);
                    return ok_str(client, &format!("already connected to {serial}"));
                }
            }

            let ip_serial = addr.to_string(); // resolved IP for transport registration
            match crate::server::transport::connect_to_remote(addr, registry) {
                Ok(t) => {
                    let _ = t; // keep transport alive
                    eprintln!("[adb-debug] connect_to_remote OK for {}", &ip_serial);
                    // Register AND return the original hostname serial
                    // This makes disconnect by hostname work
                    {
                        let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == ip_serial) {
                            dev.serial = serial.clone();
                            eprintln!("[adb-debug] updated serial: {} -> {}", &ip_serial, &serial);
                        }
                    }
                    ok_str(client, &serial)?;
                }
                Err(e) => {
                    eprintln!("[adb-debug] connect_to_remote FAIL: {}", &e);
                    fail(client, &format!("connection failed: {e}"))?;
                }
            }
            Ok(())
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
            // AOSP (adb.cpp:1443-1452) reports supported_features(); report
            // exactly the features this binary implements (features.rs) so
            // clients gate shell-v2/sync-v2 on what we actually speak.
            let features = adb_protocol::features::features_to_string(
                adb_protocol::features::host_supported_features(),
            );
            ok_str(client, &features)
        }

        // -- host:jdwp -------------------------------------------------------
        "host:jdwp" => {
            ok_str(client, "")
        }

        // -- Unknown ---------------------------------------------------------
        other => fail(client, &format!("unknown host service: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_CNXN, MAX_PAYLOAD_V2};

    use super::*;
    use crate::server::models::*;

    #[test]
    fn test_parse_adb_host_port_supports_ipv4_hostname_and_bracketed_ipv6() {
        assert_eq!(parse_adb_host_port("127.0.0.1:5555").unwrap(), ("127.0.0.1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("device.local:5555").unwrap(), ("device.local".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[::1]:5555").unwrap(), ("::1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[fe80::1%wlan0]:5555").unwrap(), ("fe80::1%wlan0".to_string(), 5555));
    }

    #[test]
    fn test_parse_adb_host_port_rejects_ambiguous_or_invalid_addresses() {
        assert!(parse_adb_host_port("::1:5555").is_err());
        assert!(parse_adb_host_port("[::1]").is_err());
        assert!(parse_adb_host_port("host:not-a-port").is_err());
        assert!(parse_adb_host_port("host:0").is_err());
        assert!(parse_adb_host_port(":5555").is_err());
    }

    #[test]
    fn test_host_connect_ipv6_wire_and_canonical_serial() {
        let device_listener = TcpListener::bind("[::1]:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut request_header = [0u8; 24];
            stream.read_exact(&mut request_header).unwrap();
            let request = AdbMessageHeader::decode(&request_header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response_payload = b"device::features=shell_v2;";
            let response = AdbMessageHeader::new(
                A_CNXN,
                ADB_VERSION,
                MAX_PAYLOAD_V2,
                response_payload,
            );
            let mut response_header = [0u8; 24];
            response.encode(&mut response_header);
            stream.write_all(&response_header).unwrap();
            stream.write_all(response_payload).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let command = format!("host:connect:[::1]:{}", device_addr.port());
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let mut client = TcpStream::connect(server_addr).unwrap();
        let mut status = [0u8; 4];
        client.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"OKAY");
        let mut length = [0u8; 4];
        client.read_exact(&mut length).unwrap();
        let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
        let mut payload = vec![0u8; length];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(std::str::from_utf8(&payload).unwrap(), format!("[::1]:{}", device_addr.port()));

        server.join().unwrap();
        device.join().unwrap();
        let reg = registry.lock().unwrap();
        assert!(reg.find_by_serial(&format!("[::1]:{}", device_addr.port())).is_some());
    }

    #[test]
    fn test_connect_consumes_response_cnxn_banner_length() {
        use std::net::TcpListener;
        use std::thread;

        let device_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let banner = b"device::features=shell_v2;".to_vec();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut header = [0u8; 24];
            stream.read_exact(&mut header).unwrap();
            let request = AdbMessageHeader::decode(&header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, &banner);
            response.encode(&mut header);
            stream.write_all(&header).unwrap();
            stream.write_all(&banner).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            let command = format!("host:connect:{device_addr}");
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let _client = TcpStream::connect(server_addr).unwrap();
        server.join().unwrap();
        device.join().unwrap();

        let serial = device_addr.to_string();
        let reg = registry.lock().unwrap();
        assert_eq!(reg.find_by_serial(&serial).unwrap().transport_features.as_deref(),
                   Some("device::features=shell_v2;"));
    }

    #[test]
    fn test_track_devices_emits_initial_snapshot() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:track-devices",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut okay = [0u8; 4];
        client.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        let snapshot_len = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut snapshot = vec![0u8; snapshot_len];
        client.read_exact(&mut snapshot).unwrap();
        assert!(std::str::from_utf8(&snapshot).is_ok());

        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn test_wait_for_device_acknowledges_available_transport() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        registry.lock().unwrap().devices.push(DeviceEntry {
            serial: "test-device".to_string(),
            transport_id: 1,
            state: DeviceState::Device,
            origin: DeviceOrigin::Tcp {
                addr: "127.0.0.1:5555".parse().unwrap(),
            },
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:wait-for-device",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"OKAY");
        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
    }
}
