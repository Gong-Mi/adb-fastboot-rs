//! ADB detach command: disconnect from a device without killing the server.
//!
//! AOSP source: `vendor/adb/client/detach.cpp`
//!
//! Handles:
//! - `adb detach <serial>` — detach a specific device from the ADB server
//! - Disconnects the transport without affecting other devices

use std::time::Duration;

use adb_protocol::AdbServerTransport;

/// Detach a device from the ADB server by serial number.
///
/// Sends `host:disconnect:<serial>` to the ADB server to disconnect
/// the specified device without affecting other connections or the
/// server itself.
pub fn detach_device(
    serial: &str,
    server_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_serial(serial)?;

    let addr = server_addr.unwrap_or("127.0.0.1:5037");
    let mut server = AdbServerTransport::connect_timeout(addr, Duration::from_secs(3))
        .map_err(|e| format!("Cannot connect to ADB server at {addr}: {e}"))?;

    let request = format!("host:disconnect:{}", serial);
    server.send_host_request(&request)?;
    server.read_status()?;

    // Read response payload (success message or error)
    let payload = server.read_payload()?;
    let response = String::from_utf8_lossy(&payload).to_string();

    if response.contains("disconnected") || response.contains("error") {
        return Err(format!("Detach: {response}").into());
    }

    Ok(())
}

/// Validate that the serial looks reasonable.
fn validate_serial(serial: &str) -> Result<(), Box<dyn std::error::Error>> {
    if serial.is_empty() {
        return Err("Serial number cannot be empty".into());
    }
    if serial.contains(' ') {
        return Err("Serial number cannot contain spaces".into());
    }
    if serial.len() > 64 {
        return Err("Serial number too long (max 64 characters)".into());
    }
    Ok(())
}

/// Detach all devices from the ADB server.
///
/// Sends `host:disconnect` (with no serial) to disconnect all
/// connected devices.
pub fn detach_all(
    server_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = server_addr.unwrap_or("127.0.0.1:5037");
    let mut server = AdbServerTransport::connect_timeout(addr, Duration::from_secs(3))
        .map_err(|e| format!("Cannot connect to ADB server at {addr}: {e}"))?;

    server.send_host_request("host:disconnect")?;
    server.read_status()?;

    let payload = server.read_payload()?;
    let response = String::from_utf8_lossy(&payload).to_string();
    eprintln!("{response}");

    Ok(())
}

/// Disconnect from a network ADB device by host:port.
///
/// Sends `host:disconnect:<host>:<port>` to disconnect a specific
/// TCP device.
pub fn detach_network_device(
    host: &str,
    port: u16,
    server_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = format!("{host}:{port}");
    detach_device(&target, server_addr)
}
