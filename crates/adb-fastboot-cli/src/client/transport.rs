//! Client-side ADB transport (connection + handshake).
//! Maps to AOSP `vendor/adb/client/adb_client.cpp`.

use std::time::Duration;
use adb_protocol::{
    AdbMessageHeader, TcpTransport, Transport,
    ADB_VERSION, A_AUTH, A_AUTH_TOKEN, A_CNXN, A_STLS,
    MAX_PAYLOAD_V2,
};

#[cfg(target_os = "android")]
use crate::client::auth::persist_adb_pubkey;

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

/// Connect to adbd with CNXN handshake and optional AUTH support.
#[cfg(feature = "tls")]
pub fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &adb_protocol::AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    use adb_protocol::tls;
    use adb_protocol::AdbTlsTransport;

    let mut transport: Box<dyn Transport> = Box::new(transport);
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    let (mut resp_hdr, mut payload) = transport.recv_message()?;
    let mut sent_signature = false;
    let mut sent_public_key = false;
    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0).into());
        }
        if payload.len() != 20 {
            return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
        }
        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&payload)?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()?
        } else {
            return Err("adbd rejected the ADB RSA key after signature and public-key exchange".into());
        };
        transport.send_message(&auth_hdr, &auth_payload)?;
        (resp_hdr, payload) = transport.recv_message()?;
    }

    if resp_hdr.command == A_CNXN {
        let banner = String::from_utf8_lossy(&payload).to_string();
        #[cfg(target_os = "android")]
        if sent_public_key {
            persist_adb_pubkey(auth)?;
        }
        return Ok((DeviceInfo { banner }, transport));
    }

    if resp_hdr.command == A_STLS {
        let rsa_pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())
            .map_err(|e| format!("Failed to export RSA key: {e}"))?;
        let (cert_der, key_der) = tls::generate_self_signed_cert(&rsa_pem)
            .map_err(|e| format!("Failed to generate self-signed cert: {e}"))?;
        let config = tls::create_tls_config(cert_der, key_der)
            .map_err(|e| format!("Failed to create TLS config: {e}"))?;

        let tls_transport = AdbTlsTransport::new(transport, config, "adb")
            .map_err(|e| format!("TLS upgrade failed: {e}"))?;
        let mut tls_box: Box<dyn Transport> = Box::new(tls_transport);
        tls_box.send_message(&cnxn_hdr, cnxn_payload)?;
        let (resp_hdr2, payload2) = tls_box.recv_message()?;
        if resp_hdr2.command != A_CNXN {
            return Err(format!("Unexpected handshake response after TLS upgrade: cmd={:#x}", resp_hdr2.command).into());
        }
        let banner = String::from_utf8_lossy(&payload2).to_string();
        return Ok((DeviceInfo { banner }, tls_box));
    }

    Err(format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into())
}

/// Non-TLS fallback with AUTH support.
#[cfg(not(feature = "tls"))]
pub fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &adb_protocol::AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let mut transport: Box<dyn Transport> = Box::new(transport);
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    let (mut resp_hdr, mut payload) = transport.recv_message()?;
    let mut sent_signature = false;
    let mut sent_public_key = false;
    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0).into());
        }
        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&payload)?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()?
        } else {
            return Err("adbd rejected the ADB RSA key after signature and public-key exchange".into());
        };
        transport.send_message(&auth_hdr, &auth_payload)?;
        (resp_hdr, payload) = transport.recv_message()?;
    }
    if resp_hdr.command == A_STLS {
        return Err("Device requires TLS (A_STLS) but the `tls` feature is not enabled. \
                    Rebuild with --features tls".into());
    }
    if resp_hdr.command != A_CNXN {
        return Err(format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into());
    }
    let banner = String::from_utf8_lossy(&payload).to_string();
    #[cfg(target_os = "android")]
    if sent_public_key {
        persist_adb_pubkey(auth)?;
    }
    Ok((DeviceInfo { banner }, transport))
}
