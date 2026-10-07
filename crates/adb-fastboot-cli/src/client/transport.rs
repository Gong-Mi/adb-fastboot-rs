//! Client-side ADB transport (connection + handshake).
//! Maps to AOSP `vendor/adb/client/adb_client.cpp`.

use std::time::Duration;
use adb_protocol::{
    AdbMessageHeader, TcpTransport, Transport,
    ADB_VERSION, A_AUTH, A_AUTH_TOKEN, A_CNXN, A_STLS,
    MAX_PAYLOAD_V2,
};

// Preserve the existing production CLI's Android key-persistence path when
// consolidating its handshake here (do not switch to the legacy auth copy).
#[cfg(target_os = "android")]
use crate::persist_adb_pubkey;

const ADBD_PORT: u16 = 5555;
const ADB_SERVER_PORT: u16 = 5037;

pub fn resolve_target_addr(serial: Option<&str>, default_port: u16) -> String {
    serial.map_or_else(
        || format!("127.0.0.1:{default_port}"),
        |s| {
            if s.contains(':') { s.to_string() }
            else { format!("127.0.0.1:{default_port}") }
        },
    )
}

/// Information about the device received in the CNXN response banner.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub banner: String,
}

/// Open ADB transport to a device.
/// Tries ADB server first (reuses authenticated transport), then direct USB/TCP.
pub fn open_adb_transport(
    serial: Option<&str>,
    use_usb: bool,
    timeout: Duration,
) -> Result<Box<dyn Transport>, Box<dyn std::error::Error>> {
    let is_tcp_spec = serial.map_or(false, |s| s.contains(':'));
    if is_tcp_spec {
        let addr = resolve_target_addr(serial, ADBD_PORT);
        let t = TcpTransport::connect_timeout(&addr, timeout)?;
        return Ok(Box::new(t));
    }

    if use_usb {
        #[cfg(feature = "usb")]
        {
            let mut dev = if let Some(s) = serial {
                adb_protocol::UsbfsAdbDevice::open_by_serial(s)
            } else {
                adb_protocol::UsbfsAdbDevice::open_first()
            }
            .map_err(|e| format!("Failed to open ADB USB device: {e}"))?;
            dev.set_timeout(Duration::from_secs(30 * 60));
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }
        #[cfg(not(feature = "usb"))]
        {
            return Err("USB support is not enabled; rebuild with `--features usb`".into());
        }
    }

    #[cfg(feature = "usb")]
    {
        let usb_res = if let Some(s) = serial {
            adb_protocol::UsbfsAdbDevice::open_by_serial(s)
        } else {
            adb_protocol::UsbfsAdbDevice::open_first()
        };
        if let Ok(mut dev) = usb_res {
            dev.set_timeout(Duration::from_secs(30 * 60));
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }
    }

    let addr = resolve_target_addr(serial, ADBD_PORT);
    let t = TcpTransport::connect_timeout(&addr, timeout)
        .map_err(|_| format!("Connection failed to {addr} (Connection refused). \
            Specify target device with `-s <IP:PORT>` or start ADB server."))?;
    Ok(Box::new(t))
}

/// Shared production CNXN/AUTH/STLS handshake for CLI and client callers.
/// TLS failure consumes the transport: there is no plaintext fallback.
pub fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &adb_protocol::AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let mut transport: Box<dyn Transport> = Box::new(transport);
    let mut responder = adb_protocol::AuthResponder::single(auth.clone());
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    loop {
        let (resp_hdr, payload) = transport.recv_message()?;
        match resp_hdr.command {
            A_CNXN => {
                #[cfg(target_os = "android")]
                if responder.pubkey_sent() {
                    persist_adb_pubkey(auth)?;
                }
                return Ok((
                    DeviceInfo {
                        banner: String::from_utf8_lossy(&payload).into(),
                    },
                    transport,
                ));
            }
            A_AUTH if resp_hdr.arg0 == A_AUTH_TOKEN => {
                if payload.len() != 20 {
                    return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
                }
                if let Some((header, response)) = responder.respond_to_token(&payload)? {
                    transport.send_message(&header, &response)?;
                }
            }
            A_STLS => {
                #[cfg(feature = "tls")]
                {
                    // adb.cpp:447-453 sends the host STLS reply before TLS.
                    adb_protocol::tls::send_tls_request(&mut *transport)?;
                    let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())
                        .map_err(|error| format!("Failed to export RSA key: {error}"))?;
                    let (banner, transport) =
                        adb_protocol::tls::adb_auth_tls_handshake(transport, &pem)?;
                    return Ok((
                        DeviceInfo {
                            banner: String::from_utf8_lossy(&banner).into(),
                        },
                        transport,
                    ));
                }
                #[cfg(not(feature = "tls"))]
                return Err(
                    "Device requires TLS (A_STLS) but the `tls` feature is not enabled. \
                            Rebuild with --features tls"
                        .into(),
                );
            }
            _ => {
                return Err(
                    format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into(),
                )
            }
        }
    }
}
