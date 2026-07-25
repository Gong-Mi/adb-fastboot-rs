//! ADB Service Routing — maps AOSP `vendor/adb/services.cpp`.
//!
//! Handles:
//! - Device services: routes shell:/exec:/root:/tcpip:/usb: to A_OPEN
//! - Host services: routes track-devices, wait-for, connect, pair
//! - Service thread creation (socketpair + thread)

use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use adb_protocol::{
    AdbMessageHeader, Transport, A_OKAY, A_OPEN,
};

/// Global monotonically increasing local-ID counter for A_OPEN frames.
///
/// Mirrors AOSP's `local_id` counter in `frameworks/native/adb/adb.cpp`.
/// Each new device service connection gets a fresh ID so multiple open
/// streams on the same transport are distinguishable.
static NEXT_LOCAL_ID: AtomicU32 = AtomicU32::new(1);

/// Open a device service on `transport` by sending an A_OPEN frame with
/// the given service string as the payload, then wait for A_OKAY.
///
/// Returns `(local_id, remote_id)` on success, where `local_id` is the
/// local handle and `remote_id` is the peer's handle for the opened stream.
///
/// # Errors
///
/// Returns an error string if:
/// - The transport fails to send A_OPEN or receive the response.
/// - The device responds with anything other than A_OKAY (e.g. A_CLSE).
///
/// # AOSP equivalent
///
/// `service_to_socket()` in `vendor/adb/services.cpp` — creates a socket
/// pair, forks the service impl on one end, and returns the other.
/// Since we are a host server talking to a remote adbd, we send A_OPEN
/// over the existing transport instead.
pub(crate) fn device_service_to_socket(
    service: &str,
    transport: &mut Box<dyn Transport>,
) -> Result<(u32, u32), String> {
    let local_id = NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed);

    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, service.as_bytes());
    transport
        .send_message(&open_hdr, service.as_bytes())
        .map_err(|e| format!("A_OPEN for '{}' failed: {e}", service))?;

    let (resp_hdr, _payload) = transport
        .recv_message()
        .map_err(|e| format!("recv after A_OPEN for '{}' failed: {e}", service))?;

    if resp_hdr.command != A_OKAY {
        return Err(format!(
            "device rejected service '{}' (expected A_OKAY, got cmd={:#010x})",
            service, resp_hdr.command
        ));
    }

    let remote_id = resp_hdr.arg0;
    Ok((local_id, remote_id))
}

// ---------------------------------------------------------------------------
// Service name validation — mirrors AOSP vendor/adb/services.cpp checks
// ---------------------------------------------------------------------------

/// Validate a shell service name.
///
/// AOSP shell service format:
/// - `shell,command` — arbitrary shell command
/// - `shell,v2,raw:<id>` — shell_v2 protocol, raw terminal mode
/// - `shell,v2,pty:<id>` — shell_v2 protocol, pty mode
/// - `shell:v2` — shell_v2 (legacy, colon separator)
/// - `shell:` — plain shell
///
/// We accept any service starting with `shell`; deeper validation is left
/// to adbd since shell service arguments are implementation-specific.
pub(crate) fn validate_shell(service: &str) -> Result<(), String> {
    if service.starts_with("shell") {
        Ok(())
    } else {
        Err(format!("not a shell service: {service}"))
    }
}

/// Validate an exec service name.
///
/// AOSP format: `exec:<command>` or `exec:v2:<command>`.
/// The command must be non-empty.
pub(crate) fn validate_exec(service: &str) -> Result<(), String> {
    if let Some(rest) = service.strip_prefix("exec:") {
        if rest.is_empty() || rest == "v2:" || rest == "v2" {
            return Err(format!(
                "exec service '{}' requires a non-empty command",
                service
            ));
        }
        Ok(())
    } else {
        Err(format!("not an exec service: {service}"))
    }
}

/// Validate a root service name.
///
/// Valid AOSP: `root:`, `unroot:`.
/// These are always available — adbd will reject if not supported.
pub(crate) fn validate_root(service: &str) -> Result<(), String> {
    if service == "root:" || service == "unroot:" {
        Ok(())
    } else {
        Err(format!("not a root/unroot service: {service}"))
    }
}

/// Validate a tcpip service name.
///
/// AOSP format: `tcpip:<port>`.
/// Port must be a valid u16 (1–65535).
pub(crate) fn validate_tcpip(service: &str) -> Result<(), String> {
    if let Some(port_str) = service.strip_prefix("tcpip:") {
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in tcpip service '{}': not a valid u16 port number", service))?;
        if port == 0 {
            return Err(format!("invalid port in tcpip service '{}': port cannot be 0", service));
        }
        Ok(())
    } else {
        Err(format!("not a tcpip service: {service}"))
    }
}

/// Validate a usb service name.
///
/// AOSP format: `usb:`.
/// Always available at the validation level; adbd may reject if no USB
/// gadget is active.
pub(crate) fn validate_usb(service: &str) -> Result<(), String> {
    if service == "usb:" {
        Ok(())
    } else {
        Err(format!("not a usb service: {service}"))
    }
}

/// High-level service name validator.
///
/// Inspects the service prefix and dispatches to the appropriate
/// validation function.  Returns `Ok(())` if the service name looks
/// structurally valid.
pub(crate) fn validate_service_name(service: &str) -> Result<(), String> {
    if service.starts_with("shell") {
        validate_shell(service)
    } else if service.starts_with("exec:") {
        validate_exec(service)
    } else if service.starts_with("root:") || service.starts_with("unroot:") {
        validate_root(service)
    } else if service.starts_with("tcpip:") {
        validate_tcpip(service)
    } else if service.starts_with("usb:") {
        validate_usb(service)
    } else {
        // Unknown service — pass through; adbd will decide.
        // This mirrors AOSP behaviour: unrecognised services are forwarded
        // and the device may accept or reject them.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Host service routing — mirrors AOSP `host_service_to_socket()`
// ---------------------------------------------------------------------------

/// Route a host service name to its local handler.
///
/// Returns `Ok(())` if handled, `Err` if unknown.
/// AOSP equivalent: `host_service_to_socket()` routes to:
/// - `create_device_tracker()` for track-devices
/// - `wait_service()` for wait-for-*
/// - `connect_service()` for connect:
/// - `pair_service()` for pair:
/// - `create_mdns_tracker()` for track-mdns
///
/// The actual I/O for these services is handled by dispatch_host_service
/// in handler.rs; this function validates and describes the routing.
pub(crate) fn host_service_to_socket(service: &str) -> Result<(), String> {
    if service == "track-devices"
        || service == "track-devices-l"
        || service == "track-devices-proto-binary"
        || service == "track-devices-proto-text"
    {
        return Ok(()); // handled by dispatch_host_service
    }
    if let Some(spec) = service.strip_prefix("wait-for-") {
        return validate_wait_spec(spec);
    }
    if let Some(host) = service.strip_prefix("connect:") {
        return validate_connect_target(host);
    }
    if let Some(pair_data) = service.strip_prefix("pair:") {
        return validate_pair_spec(pair_data);
    }
    if service == "track-mdns" || service == "track-mdns-services" {
        return Ok(());
    }
    Err(format!("unknown host service: {}", service))
}

fn validate_wait_spec(spec: &str) -> Result<(), String> {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() < 2 {
        return Err(format!("short wait-for spec: {}", spec));
    }
    let transport_ok = matches!(parts[0], "local" | "usb" | "any");
    if !transport_ok {
        return Err(format!("bad wait-for transport: {}", parts[0]));
    }
    for &state in &parts[1..] {
        match state {
            "device" | "recovery" | "rescue" | "sideload" | "bootloader" | "any" | "disconnect" => {}
            _ => return Err(format!("bad wait-for state: {}", state)),
        }
    }
    Ok(())
}

fn validate_connect_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("empty connect target".to_string());
    }
    if let Some(port_spec) = target.strip_prefix("emu:") {
        let ports: Vec<&str> = port_spec.split(',').collect();
        if ports.len() != 2 {
            return Err(format!("emu target requires console_port,adb_port: {}", target));
        }
        for p in &ports {
            let val: u16 = p.parse().map_err(|_| format!("invalid port: {}", p))?;
            if val == 0 { return Err("port must be > 0".to_string()); }
        }
    }
    Ok(())
}

fn validate_pair_spec(data: &str) -> Result<(), String> {
    // Format: password:host:port
    let divider = data.find(':').ok_or_else(|| "pair: requires password:host".to_string())?;
    let _password = &data[..divider];
    let host = &data[divider + 1..];
    if _password.is_empty() { return Err("empty pairing password".to_string()); }
    if host.is_empty() { return Err("empty pairing host".to_string()); }
    Ok(())
}

/// Create a service thread — mirrors AOSP `create_service_thread()`.
///
/// Creates a socketpair, spawns a thread that runs `func` with one end,
/// and returns the other end as a raw fd.
pub(crate) fn create_service_thread<F>(name: &str, func: F) -> Result<(i32, i32), String>
where
    F: FnOnce(i32) + Send + 'static,
{
    let mut sv = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, &mut sv as *mut i32) };
    if ret != 0 {
        return Err(format!("socketpair failed for {}", name));
    }
    let fd_client = sv[0];
    let fd_server = sv[1];

    thread::spawn(move || {
        func(fd_server);
        unsafe { libc::close(fd_server); }
    });

    Ok((fd_client, fd_server))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_shell ------------------------------------------------

    #[test]
    fn test_shell_plain() {
        validate_shell("shell:").unwrap();
    }

    #[test]
    fn test_shell_v2_raw() {
        validate_shell("shell,v2,raw:1234").unwrap();
    }

    #[test]
    fn test_shell_v2_pty() {
        validate_shell("shell,v2,pty:5678").unwrap();
    }

    #[test]
    fn test_shell_command() {
        validate_shell("shell:echo hello").unwrap();
    }

    // -- validate_exec ------------------------------------------------

    #[test]
    fn test_exec_with_command() {
        validate_exec("exec:ls -la").unwrap();
    }

    #[test]
    fn test_exec_empty_command_rejected() {
        assert!(validate_exec("exec:").is_err());
    }

    #[test]
    fn test_exec_v2_requires_command() {
        assert!(validate_exec("exec:v2:").is_err());
        assert!(validate_exec("exec:v2").is_err());
    }

    #[test]
    fn test_exec_v2_with_command() {
        validate_exec("exec:v2:/system/bin/sh -c id").unwrap();
    }

    // -- validate_root ------------------------------------------------

    #[test]
    fn test_root_service() {
        validate_root("root:").unwrap();
    }

    #[test]
    fn test_unroot_service() {
        validate_root("unroot:").unwrap();
    }

    #[test]
    fn test_root_bad_format() {
        assert!(validate_root("root:true").is_err());
        assert!(validate_root("unroot:0").is_err());
    }

    // -- validate_tcpip -----------------------------------------------

    #[test]
    fn test_tcpip_valid_port() {
        validate_tcpip("tcpip:5555").unwrap();
    }

    #[test]
    fn test_tcpip_port_zero_rejected() {
        assert!(validate_tcpip("tcpip:0").is_err());
    }

    #[test]
    fn test_tcpip_invalid_port() {
        assert!(validate_tcpip("tcpip:abc").is_err());
        assert!(validate_tcpip("tcpip:99999").is_err());
    }

    // -- validate_usb -------------------------------------------------

    #[test]
    fn test_usb_service() {
        validate_usb("usb:").unwrap();
    }

    #[test]
    fn test_usb_bad_format() {
        assert!(validate_usb("usb:1").is_err());
    }

    // -- validate_service_name ----------------------------------------

    #[test]
    fn test_service_name_dispatch_shell() {
        validate_service_name("shell:").unwrap();
        validate_service_name("shell,v2,raw:1").unwrap();
    }

    #[test]
    fn test_service_name_dispatch_exec() {
        validate_service_name("exec:ls").unwrap();
        assert!(validate_service_name("exec:").is_err());
    }

    #[test]
    fn test_service_name_dispatch_root() {
        validate_service_name("root:").unwrap();
        validate_service_name("unroot:").unwrap();
    }

    #[test]
    fn test_service_name_dispatch_tcpip() {
        validate_service_name("tcpip:5555").unwrap();
        assert!(validate_service_name("tcpip:0").is_err());
    }

    #[test]
    fn test_service_name_dispatch_usb() {
        validate_service_name("usb:").unwrap();
        assert!(validate_service_name("usb:1").is_err());
    }

    #[test]
    fn test_unknown_service_passes_through() {
        // Unknown services are forwarded to adbd for decision
        validate_service_name("reboot:").unwrap();
        validate_service_name("framebuffer:").unwrap();
        validate_service_name("backup:").unwrap();
    }

    // -- NEXT_LOCAL_ID monotonic --------------------------------------

    #[test]
    fn test_next_local_id_monotonic() {
        let prev = NEXT_LOCAL_ID.load(Ordering::Relaxed);
        let v1 = NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed);
        let v2 = NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed);
        // Reset to previous value to avoid affecting other tests
        NEXT_LOCAL_ID.store(prev, Ordering::Relaxed);
        assert_eq!(v2, v1 + 1);
    }
}
