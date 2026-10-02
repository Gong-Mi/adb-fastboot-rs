//! ADB host command execution via server.
//! Maps to AOSP `vendor/adb/client/adb_client.cpp`.

use std::time::Duration;
use adb_protocol::AdbServerTransport;

use crate::client::server_cmds::ensure_server_running_at;
use crate::client::transport::resolve_target_addr;

/// Connect to ADB server, switch transport if needed, execute host command.
pub fn host_command(
    serial: Option<&str>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    host_command_at(crate::ADB_SERVER_PORT, serial, request)
}

/// Connect to ADB server at explicit port, switch transport if needed, execute host command.
pub fn host_command_at(
    server_port: u16,
    serial: Option<&str>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let candidate_addrs = [
        format!("127.0.0.1:{server_port}"),
        format!("[::1]:{server_port}"),
    ];
    let mut server = None;
    for addr in &candidate_addrs {
        if let Ok(s) = AdbServerTransport::connect_timeout(addr, Duration::from_millis(300)) {
            server = Some(s);
            break;
        }
    }
    let mut server = match server {
        Some(s) => s,
        None => {
            ensure_server_running_at(server_port)?;
            let mut s2 = None;
            for addr in &candidate_addrs {
                if let Ok(s) = AdbServerTransport::connect_timeout(addr, Duration::from_secs(2)) {
                    s2 = Some(s);
                    break;
                }
            }
            s2.ok_or_else(|| format!("Cannot connect to ADB server at port {server_port}"))?
        }
    };

    let actual_request = if request == "host:get-state"
        || request == "host:get-serialno"
        || request == "host:get-devpath"
    {
        if let Some(s) = serial {
            format!("host-serial:{s}:{}", &request["host:".len()..])
        } else {
            request.to_string()
        }
    } else {
        request.to_string()
    };

    if !actual_request.starts_with("host:connect")
        && !actual_request.starts_with("host:disconnect")
        && !actual_request.starts_with("host:forward")
        && !actual_request.starts_with("host:reverse")
        && !actual_request.starts_with("host:devices")
        // Server-level informational services — no transport binding
        // (AOSP handle_host_request answers these before transport
        // selection; adb.cpp:1264-1281 handle_mdns_request).
        && !actual_request.starts_with("host:mdns:")
        && !actual_request.starts_with("host:host-features")
        && !actual_request.starts_with("host:version")
        && !actual_request.starts_with("host-serial:")
        && !actual_request.starts_with("host:get-")
    {
        server.switch_transport(serial)?;
    }

    let result = server.execute_host_command(&actual_request)?;
    Ok(result)
}
