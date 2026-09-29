//! ADB host command execution via server.
//! Maps to AOSP `vendor/adb/client/adb_client.cpp`.

use std::time::Duration;
use adb_protocol::AdbServerTransport;

use crate::client::server_cmds::ensure_server_running;
use crate::client::transport::resolve_target_addr;

/// Connect to ADB server, switch transport if needed, execute host command.
pub fn host_command(
    serial: Option<&str>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = resolve_target_addr(serial, crate::ADB_SERVER_PORT);
    let mut server = match AdbServerTransport::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(s) => s,
        Err(_) => {
            ensure_server_running()?;
            AdbServerTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to ADB server at {addr}: {e}"))?
        }
    };

    if !request.starts_with("host:connect")
        && !request.starts_with("host:disconnect")
        && !request.starts_with("host:forward")
        && !request.starts_with("host:reverse")
        && !request.starts_with("host:devices")
        // Server-level informational services — no transport binding
        // (AOSP handle_host_request answers these before transport
        // selection; adb.cpp:1264-1281 handle_mdns_request).
        && !request.starts_with("host:mdns:")
        && !request.starts_with("host:host-features")
        && !request.starts_with("host:version")
    {
        server.switch_transport(serial)?;
    }

    let result = server.execute_host_command(request)
        .map_err(|e| format!("ADB host command failed: {e}"))?;
    eprintln!("[adb-debug] host_command OK: resp={:?}", &result);
    Ok(result)
}
