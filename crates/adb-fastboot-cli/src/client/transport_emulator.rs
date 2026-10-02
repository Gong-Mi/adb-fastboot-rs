//! ADB transport for Android emulator connections.
//!
//! AOSP source: `vendor/adb/client/transport_emulator.cpp`
//!
//! Handles:
//! - Connecting to Android Virtual Device (AVD) emulators via local TCP ports
//! - Emulator auto-discovery via emulator console (qemu) protocol
//! - Port management for emulator instances (5554, 5555, ...)

use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use adb_protocol::{
    AdbMessageHeader, TcpTransport,
    MAX_PAYLOAD_V2,
};

/// Default emulator serial port range.
const EMULATOR_SERIAL_PORT_START: u16 = 5554;
const EMULATOR_SERIAL_PORT_END: u16 = 5584;
/// Emulator console port offset (serial_port - 1).
const EMULATOR_CONSOLE_PORT_OFFSET: i32 = -1;

/// Information about a discovered emulator.
#[derive(Debug, Clone)]
pub struct EmulatorInfo {
    /// Serial name (e.g. "emulator-5554").
    pub serial: String,
    /// ADB port (serial_port, e.g. 5555).
    pub adb_port: u16,
    /// Console port (e.g. 5554).
    pub console_port: u16,
    /// Whether the emulator is running.
    pub is_running: bool,
}

/// Discover running Android emulators by probing TCP ports in the
/// standard emulator range (5554-5584).
///
/// Returns a list of emulator `EmulatorInfo` for each active port.
pub fn discover_emulators() -> Vec<EmulatorInfo> {
    let mut emulators = Vec::new();

    for serial_port in (EMULATOR_SERIAL_PORT_START..=EMULATOR_SERIAL_PORT_END).step_by(2) {
        let adb_port = serial_port + 1; // serial_port is console, adb_port = serial_port + 1
        let addr = format!("127.0.0.1:{adb_port}");

        match TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_millis(200),
        ) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let serial = format!("emulator-{serial_port}");

                // Check if this is really an emulator by sending a CNXN-like probe
                let is_emulator = probe_emulator(stream).is_ok();

                emulators.push(EmulatorInfo {
                    serial,
                    adb_port,
                    console_port: serial_port,
                    is_running: is_emulator,
                });
            }
            Err(_) => {
                // Port not active
            }
        }
    }

    emulators
}

/// Probe a TCP connection to confirm it's an ADB emulator.
fn probe_emulator(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    // Send a minimal CNXN to check for ADB handshake
    let cnxn = AdbMessageHeader::new(
        adb_protocol::constants::A_CNXN,
        adb_protocol::constants::ADB_VERSION,
        MAX_PAYLOAD_V2,
        b"host::",
    );
    let mut hdr_buf = [0u8; 24];
    cnxn.encode(&mut hdr_buf);
    let mut stream_clone = stream.try_clone()?;
    let _ = stream_clone.set_read_timeout(Some(Duration::from_secs(2)));
    stream_clone.write_all(&hdr_buf)?;
    stream_clone.write_all(b"host::")?;
    stream_clone.flush()?;

    // Try to read response — if it's ADB, we'll get CNXN back
    let mut resp_buf = [0u8; 24];
    match stream_clone.read_exact(&mut resp_buf) {
        Ok(()) => {
            let hdr = AdbMessageHeader::decode(&resp_buf)?;
            if hdr.command == adb_protocol::constants::A_CNXN {
                return Ok(());
            }
            Err(format!("Unexpected command: {:#x}", hdr.command).into())
        }
        Err(e) => Err(format!("Not an ADB endpoint: {e}").into()),
    }
}

/// Connect to an emulator by serial name (e.g. "emulator-5554").
///
/// Returns a `TcpTransport` connected to the emulator's ADB port.
pub fn connect_to_emulator(
    serial: &str,
    timeout: Duration,
) -> Result<TcpTransport, Box<dyn std::error::Error>> {
    let port = serial_to_port(serial)?;
    let addr = format!("127.0.0.1:{port}");
    let transport = TcpTransport::connect_timeout(&addr, timeout)
        .map_err(|e| format!("Cannot connect to emulator {serial}: {e}"))?;
    Ok(transport)
}

/// Convert an emulator serial (e.g. "emulator-5554") to its ADB port.
fn serial_to_port(serial: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let stripped = serial
        .strip_prefix("emulator-")
        .ok_or_else(|| format!("Invalid emulator serial: {serial}"))?;
    let console_port: u16 = stripped
        .parse()
        .map_err(|_| format!("Invalid emulator port in serial: {serial}"))?;
    Ok(console_port + 1)
}

/// Check if a serial string refers to an emulator.
pub fn is_emulator_serial(serial: &str) -> bool {
    serial.starts_with("emulator-")
}

/// Send a command to the emulator console (QEMU console protocol).
///
/// The emulator console is accessible on serial_port - 1 (e.g. emulator-5554
/// has console on port 5554).
pub fn send_console_command(
    serial: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let port = serial_to_port(serial)?;
    let console_port = port - 1;
    let addr = format!("127.0.0.1:{console_port}");

    let mut stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2))
        .map_err(|e| format!("Cannot connect to emulator console at {addr}: {e}"))?;
    let _ = stream.set_nodelay(true);
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Emulator console greeting
    let mut greeting_buf = vec![0u8; 4096];
    let n = stream.read(&mut greeting_buf).unwrap_or(0);
    let _greeting = String::from_utf8_lossy(&greeting_buf[..n]).to_string();

    // Send command
    use std::io::Write;
    writeln!(stream, "{command}")?;

    // Read response
    let mut response = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 1024];

    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.push_str(&String::from_utf8_lossy(&buf[..n]));
                if response.contains("OK") || response.contains("KO:") {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }

    Ok(response.trim().to_string())
}

/// Get the emulator's ADB port from its serial number.
pub fn get_emulator_adb_port(serial: &str) -> Result<u16, Box<dyn std::error::Error>> {
    serial_to_port(serial)
}

/// List all running emulators found on localhost.
pub fn list_emulators() -> Vec<EmulatorInfo> {
    discover_emulators()
        .into_iter()
        .filter(|e| e.is_running)
        .collect()
}

/// Try to connect to any running emulator (returns first found).
pub fn connect_to_any_emulator(
    timeout: Duration,
) -> Result<(String, TcpTransport), Box<dyn std::error::Error>> {
    let emulators = list_emulators();
    for emu in &emulators {
        match connect_to_emulator(&emu.serial, timeout) {
            Ok(transport) => return Ok((emu.serial.clone(), transport)),
            Err(_) => continue,
        }
    }
    Err("No running emulator found".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn test_emulator_serial_parsing_and_detection() {
        assert!(is_emulator_serial("emulator-5554"));
        assert!(is_emulator_serial("emulator-5584"));
        assert!(!is_emulator_serial("127.0.0.1:5555"));
        assert!(!is_emulator_serial("device-1234"));

        assert_eq!(serial_to_port("emulator-5554").unwrap(), 5555);
        assert_eq!(serial_to_port("emulator-5584").unwrap(), 5585);
        assert_eq!(get_emulator_adb_port("emulator-5554").unwrap(), 5555);

        assert!(serial_to_port("not-an-emulator").is_err());
        assert!(serial_to_port("emulator-invalid").is_err());
    }

    #[test]
    fn test_probe_emulator_valid_and_invalid_handshake() {
        // Case 1: valid CNXN response
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();

            let handle = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut req_hdr = [0u8; 24];
                let _ = sock.read_exact(&mut req_hdr);
                let mut req_body = [0u8; 6];
                let _ = sock.read_exact(&mut req_body);

                // Send back valid A_CNXN header
                let resp = AdbMessageHeader::new(
                    adb_protocol::constants::A_CNXN,
                    adb_protocol::constants::ADB_VERSION,
                    MAX_PAYLOAD_V2,
                    b"device::\0",
                );
                let mut resp_buf = [0u8; 24];
                resp.encode(&mut resp_buf);
                sock.write_all(&resp_buf).unwrap();
            });

            let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            assert!(probe_emulator(client).is_ok());
            handle.join().unwrap();
        }

        // Case 2: unexpected command response
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();

            let handle = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut req_hdr = [0u8; 24];
                let _ = sock.read_exact(&mut req_hdr);

                // Send back A_AUTH instead of A_CNXN
                let resp = AdbMessageHeader::new(
                    adb_protocol::constants::A_AUTH,
                    1,
                    0,
                    &[],
                );
                let mut resp_buf = [0u8; 24];
                resp.encode(&mut resp_buf);
                sock.write_all(&resp_buf).unwrap();
            });

            let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let err = probe_emulator(client).unwrap_err().to_string();
            assert!(err.contains("Unexpected command"));
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_send_console_command_fake_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // Send greeting
            sock.write_all(b"Android Console: Authentication required\r\nOK\r\n").unwrap();
            sock.flush().unwrap();

            // Read command
            let mut buf = [0u8; 128];
            let n = sock.read(&mut buf).unwrap();
            let cmd = String::from_utf8_lossy(&buf[..n]);
            assert!(cmd.contains("avd name"));

            // Respond
            sock.write_all(b"test_avd_34\r\nOK\r\n").unwrap();
            sock.flush().unwrap();
        });

        let serial = format!("emulator-{port}");
        let response = send_console_command(&serial, "avd name").unwrap();
        assert!(response.contains("test_avd_34"));
        assert!(response.contains("OK"));
        handle.join().unwrap();
    }
}
