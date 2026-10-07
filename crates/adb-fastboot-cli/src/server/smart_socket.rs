//! ASocket abstraction — the core socket state machine for ADB host server.
//!
//! Mirrors AOSP `vendor/adb/sockets.cpp`:
//!
//! - **LocalSocket** — wraps a local TcpStream fd; writes data to the client.
//! - **RemoteSocket** — talks to a device service over a `Transport` using ADB
//!   protocol frames (A_WRTE / A_OKAY / A_CLSE).
//! - **SmartSocket** — parses hex-length-prefixed commands from a client stream,
//!   routes `host:*` services via `dispatch_host_service`, and bridges device
//!   services to a `RemoteSocket`.
//!
//! The AOSP `asocket` is a C struct with mutable function-pointer vtables that
//! get rewired at runtime (`local_socket_ready_notify`, etc.).  Here we use an
//! enum + explicit functions instead, keeping the runtime semantics while
//! maintaining Rust's type safety.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use adb_protocol::Transport;

#[path = "duplex.rs"]
mod duplex;
use duplex::RemoteSocket;

use crate::server::models::TransportRegistry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hex-length-prefixed command size (AOSP `MAX_PAYLOAD` — 4 KiB).
const MAX_CMD_LEN: usize = 4096;


// ---------------------------------------------------------------------------
// ASocket enum
// ---------------------------------------------------------------------------

/// ADB socket types, mirroring AOSP `asocket` struct variants.
///
/// Unlike AOSP's struct-with-function-pointers design, Rust's enum allows
/// compile-time dispatch.  The AOSP pattern of rewiring a socket's callbacks
/// at runtime (e.g. `local_socket_ready_notify`) is expressed here as
/// transitions between enum variants.
#[allow(dead_code)]
pub(crate) enum ASocket {
    /// Local socket bound to a TCP client stream.
    Local(LocalSocket),
    /// Remote socket connected to a device service via a `Transport`.
    Remote(RemoteSocket),
    /// Smart socket: parses hex-length-prefixed commands, routes to host
    /// services or bridges to device services.
    Smart(SmartSocket),
}

// ---------------------------------------------------------------------------
// LocalSocket
// ---------------------------------------------------------------------------

/// A local TCP socket — wraps the client's `TcpStream`.
///
/// Mirrors AOSP's `local_socket_enqueue` / `local_socket_ready` / `local_socket_close`.
/// In AOSP the local socket writes to its fd when data arrives from the peer;
/// here we just hold the stream; the single bridge owner performs the I/O.
#[derive(Debug)]
pub(crate) struct LocalSocket {
    /// Local socket ID (allocated monotonically, like AOSP `local_socket_next_id`).
    pub id: u32,
    /// The client TCP stream.
    pub stream: TcpStream,
}

// ---------------------------------------------------------------------------
// SmartSocket
// ---------------------------------------------------------------------------

/// A smart socket — parses hex-length-prefixed commands from a client stream.
///
/// Mirrors AOSP's `smart_socket_enqueue` / `smart_socket_ready` / `smart_socket_close`.
/// The smart socket sits between a local TCP client and either a host service
/// handler or a remote device service.
///
/// The protocol is:
///   1. Client sends 4 hex chars (ASCII) representing the command length.
///   2. Client sends that many bytes of command text.
///   3. Commands starting with `host:` are host services (devices, connect,
///      forward, etc.) handled by `dispatch_host_service`.
///   4. Commands starting with `host:transport:*`, `host:tport:*`, etc.
///      select a device transport.  Subsequent commands (without `host:`)
///      are device services (shell, exec, etc.) sent via A_OPEN to adbd.
///   5. Non-`host:` commands are device services — the smart socket sends
///      A_OPEN to the device and bridges data bidirectionally.
pub(crate) struct SmartSocket {
    /// The client TCP stream.
    pub stream: TcpStream,
    /// Pending data buffer (used for partial reads, matching AOSP's
    /// `smart_socket_data`).
    pub buffer: Vec<u8>,
}

impl SmartSocket {
    /// Create a new `SmartSocket` wrapping a client TcpStream.
    pub(crate) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Read one hex-length-prefixed command from the client.
    ///
    /// Returns `Ok(Some(cmd))` on success, `Ok(None)` when the client
    /// disconnects (EOF), or `Err(...)` on protocol error.
    pub(crate) fn read_command(&mut self) -> Result<Option<String>, String> {
        let mut len_buf = [0u8; 4];
        if self.stream.read_exact(&mut len_buf).is_err() {
            return Ok(None);
        }
        let len_str = std::str::from_utf8(&len_buf)
            .map_err(|_| "Invalid UTF-8 in length prefix".to_string())?;
        let cmd_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| format!("Invalid hex length: {len_str}"))?;

        if cmd_len == 0 || cmd_len > MAX_CMD_LEN {
            return Err(format!("Invalid command length: {cmd_len}"));
        }

        let mut cmd_buf = vec![0u8; cmd_len];
        self.stream
            .read_exact(&mut cmd_buf)
            .map_err(|e| format!("Failed to read command: {e}"))?;
        let cmd = String::from_utf8(cmd_buf)
            .map_err(|_| "Command is not valid UTF-8".to_string())?;

        Ok(Some(cmd))
    }

    /// Write OKAY to the client (simple 4-byte acknowledgement).
    pub(crate) fn send_okay(&mut self) -> Result<(), String> {
        self.stream
            .write_all(b"OKAY")
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("write OKAY failed: {e}"))
    }

    /// Write OKAY + hex-length-prefixed data to the client.
    pub(crate) fn send_okay_with_data(&mut self, data: &[u8]) -> Result<(), String> {
        let len_hdr = format!("{:04x}", data.len());
        self.stream
            .write_all(b"OKAY")
            .and_then(|_| self.stream.write_all(len_hdr.as_bytes()))
            .and_then(|_| self.stream.write_all(data))
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("write failed: {e}"))
    }

    /// Write FAIL + hex-length-prefixed error message to the client.
    pub(crate) fn send_fail(&mut self, msg: &str) -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        self.stream
            .write_all(b"FAIL")
            .and_then(|_| self.stream.write_all(len_hdr.as_bytes()))
            .and_then(|_| self.stream.write_all(err_bytes))
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("write failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// connect_to_remote — open a device service via A_OPEN
// ---------------------------------------------------------------------------

/// Move the exclusively owned transport to its only frame reader/writer.
pub(crate) fn connect_to_remote(
    transport: Box<dyn Transport>,
    service: &str,
) -> Result<RemoteSocket, String> {
    RemoteSocket::open(transport, service)
}

pub(crate) fn bridge_smart_remote(
    client: TcpStream,
    remote: RemoteSocket,
    running: &AtomicBool,
) -> Result<(), String> {
    remote.bridge(client, running)
}

// ---------------------------------------------------------------------------
// Smart socket run loop — top-level entry point
// ---------------------------------------------------------------------------

/// The result of processing a single command in the smart socket loop.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommandResult {
    /// Command was handled (host service) — continue reading.
    Continue,
    /// A transport was selected — caller should enter bridge mode with this serial.
    TransportSelected(String),
    /// The connection should be closed.
    Close,
}

/// Run the smart socket command loop: read hex-length-prefixed commands from
/// the client, dispatch host services, and bridge device services.
///
/// Mirrors AOSP's `smart_socket_enqueue()` + `handle_client()` combined flow.
///
/// # Arguments
///
/// * `client` — the client TCP stream.
/// * `registry` — the transport registry.
/// * `running` — the server shutdown signal.
///
/// # Returns
///
/// `Ok(())` on clean disconnect, `Err(...)` on fatal protocol error.
pub(crate) fn run_smart_socket_loop(
    client: TcpStream,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut smart = SmartSocket::new(client.try_clone().map_err(|e| format!("clone: {e}"))?);

    loop {
        let cmd = match smart.read_command()? {
            Some(cmd) => cmd,
            None => return Ok(()), // clean disconnect
        };

        let is_host_cmd = cmd.starts_with("host:") || cmd.starts_with("host-");
        let is_transport_cmd = is_host_cmd && (cmd.starts_with("host:transport:")
            || cmd == "host:transport-any"
            || cmd.starts_with("host:tport:")
            || cmd.starts_with("host:transport-id:"));

        // Only dispatch host:* commands to the host service handler.
        // Non-host commands (e.g. shell,v2,raw:...) will be handled
        // after a transport is selected in bridge mode.
        if is_host_cmd {
            eprintln!("[adb-debug-ss] dispatching host cmd: {:?}, is_transport={}", &cmd, is_transport_cmd);
            crate::server::handler::dispatch_host_service(
                &mut smart.stream,
                &cmd,
                registry,
                running,
            )?;

            if is_transport_cmd {
                // Transport selected — enter bridge mode.
                let serial = extract_serial_from_transport_cmd(&cmd, registry)?;
                return bridge_to_device_with_smart(client, &serial, registry, running);
            }
        } else {
            // Non-host command (e.g. shell,v2,raw:...) with no transport selected
            smart.send_fail(&format!("device service requires transport selection first: {cmd}"))?;
            return Ok(());
        }
    } // end loop
}

/// Extract the device serial from a transport-selection command.
fn extract_serial_from_transport_cmd(
    cmd: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<String, String> {
    if cmd.starts_with("host:transport:") {
        Ok(cmd["host:transport:".len()..].to_string())
    } else if cmd == "host:transport-any" {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        reg.find_unique_device()
            .map(|d| d.serial.clone())
            .map_err(str::to_string)
    } else if cmd.starts_with("host:tport:serial:") {
        Ok(cmd["host:tport:serial:".len()..].to_string())
    } else if cmd.starts_with("host:tport:") {
        // host:tport:any or host:tport:
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        reg.find_unique_device()
            .map(|d| d.serial.clone())
            .map_err(str::to_string)
    } else if cmd.starts_with("host:transport-id:") {
        let id_str = &cmd["host:transport-id:".len()..];
        let tid: u64 = id_str.parse().map_err(|_| format!("invalid transport id: {id_str}"))?;
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        reg.find_by_transport_id(tid)
            .map(|d| d.serial.clone())
            .ok_or_else(|| format!("transport id {tid} not found"))
    } else {
        Err(format!("unrecognised transport command: {cmd}"))
    }
}

/// Bridge the client stream to a device after transport selection.
///
/// This reads hex-length-prefixed device-service commands from the client
/// and bridges them to the device via `connect_to_remote` + `bridge_smart_remote`.
pub(crate) fn bridge_to_device_with_smart(
    client: TcpStream,
    serial: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &AtomicBool,
) -> Result<(), String> {
    let (origin, _is_tcp) = {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        let origin = reg.find_by_serial(serial).map(|d| d.origin);
        let is_tcp = matches!(origin, Some(crate::server::models::DeviceOrigin::Tcp { .. }));
        (origin, is_tcp)
    };

    let origin = origin.ok_or_else(|| format!("device '{serial}' not found"))?;

    let mut smart = SmartSocket::new(client.try_clone().map_err(|e| format!("clone: {e}"))?);
    // Now read device-service commands and bridge one raw session.

    loop {
        let cmd = match smart.read_command()? {
            Some(cmd) => cmd,
            None => return Ok(()),
        };

        // Handle host: services that may appear after transport select
        if cmd.starts_with("host:") {
            // Re-dispatch (but we don't have running flag here, so handle common ones)
            if cmd.starts_with("host:get-serialno") {
                smart.send_okay_with_data(serial.as_bytes())?;
                continue;
            }
            // Unknown host service — fail
            smart.send_fail(&format!("unknown host service: {cmd}"))?;
            continue;
        }

        // Consume the service request before reporting FAIL. Closing a socket
        // with unread client bytes can turn that response's EOF into TCP RST.
        // Get or establish transport. Report handshake/unsupported errors through
        // the smart-socket FAIL contract, never fallback to a different backend.
        let opened = if matches!(origin, crate::server::models::DeviceOrigin::Tcp { .. }) {
            crate::server::transport::open_transport_by_origin(&origin, serial)
                .and_then(|t| crate::server::bridge::tcp_auth_handshake(t, serial))
        } else {
            // Do not clone a cached USB handle or claim the device a second time.
            Err("USB server duplex dispatcher not implemented".to_string())
        };
        let transport = match opened {
            Ok(transport) => transport,
            Err(error) => { smart.send_fail(&error)?; return Err(error); }
        };

        // --- Device service: connect and bridge ---
        let remote = match connect_to_remote(transport, &cmd) {
            Ok(remote) => remote,
            Err(error) => { smart.send_fail(&error)?; return Err(error); }
        };

        // Send OKAY to client
        smart.send_okay()?;

        // Bridge bidirectionally
        bridge_smart_remote(client, remote, running)?;

        // After bridge returns, we're done with this connection
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use crate::server::models::{DeviceEntry, DeviceOrigin, DeviceState, TransportRegistry};

    use super::*;

    #[test]
    fn test_smart_socket_read_command() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut smart = SmartSocket::new(stream);
            let cmd = smart.read_command().unwrap().unwrap();
            assert_eq!(cmd, "host:version");
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.write_all(b"000chost:version").unwrap();
        client.flush().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn test_smart_socket_okay_fail_roundtrip() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut smart = SmartSocket::new(stream.try_clone().unwrap());
            smart.send_okay().unwrap();
            smart.send_fail("test error").unwrap();
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"OKAY");

        let mut fail = [0u8; 4];
        client.read_exact(&mut fail).unwrap();
        assert_eq!(&fail, b"FAIL");

        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        let msg_len = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut msg = vec![0u8; msg_len];
        client.read_exact(&mut msg).unwrap();
        assert_eq!(std::str::from_utf8(&msg).unwrap(), "test error");

        server.join().unwrap();
    }

    #[test]
    fn cached_usb_origin_fails_before_claim_or_open() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        registry.lock().unwrap().devices.push(DeviceEntry {
            serial: "fake-usb-no-hardware".into(), transport_id: 42,
            state: DeviceState::Device, origin: DeviceOrigin::Usb,
            product: None, model: None, device_name: None, transport_features: None,
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let (server, _) = listener.accept().unwrap();
        let handle = thread::spawn(move || {
            bridge_to_device_with_smart(server, "fake-usb-no-hardware", &registry, &AtomicBool::new(true))
        });
        peer.write_all(b"0008exec:cat").unwrap();
        let mut status = [0; 4]; peer.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"FAIL");
        let mut length = [0; 4]; peer.read_exact(&mut length).unwrap();
        let len = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
        let mut error = vec![0; len]; peer.read_exact(&mut error).unwrap();
        assert_eq!(error, b"USB server duplex dispatcher not implemented");
        let mut byte = [0]; assert_eq!(peer.read(&mut byte).unwrap(), 0);
        assert!(handle.join().unwrap().unwrap_err().contains("USB"));
    }

    #[test]
    fn test_extract_serial_transport_cmd() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        {
            let mut reg = registry.lock().unwrap();
            reg.devices.push(DeviceEntry {
                serial: "test-device".to_string(),
                transport_id: 42,
                state: DeviceState::Device,
                origin: DeviceOrigin::Tcp {
                    addr: "127.0.0.1:5555".parse().unwrap(),
                },
                product: None,
                model: None,
                device_name: None,
                transport_features: None,
            });
        }

        let serial = extract_serial_from_transport_cmd("host:transport:test-device", &registry).unwrap();
        assert_eq!(serial, "test-device");

        let serial = extract_serial_from_transport_cmd("host:transport-id:42", &registry).unwrap();
        assert_eq!(serial, "test-device");

        let serial = extract_serial_from_transport_cmd("host:tport:serial:test-device", &registry).unwrap();
        assert_eq!(serial, "test-device");

        let serial = extract_serial_from_transport_cmd("host:tport:", &registry).unwrap();
        assert_eq!(serial, "test-device");
    }
}
