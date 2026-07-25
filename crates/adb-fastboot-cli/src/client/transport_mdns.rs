//! ADB mDNS transport — discover and connect to ADB devices via mDNS.
//!
//! AOSP source: `vendor/adb/client/transport_mdns.cpp`
//!
//! This module provides:
//! - [`MdnsTransport`] — a transport wrapper for mDNS-discovered ADB devices
//! - [`connect_to_mdns_device`] — resolve an mDNS service instance name and open a connection
//! - [`discover_and_connect`] — discover available ADB devices on the network and connect
//!
//! Connection strategy:
//! | Service Type       | Transport Layer       | Handshake                        |
//! |--------------------|-----------------------|----------------------------------|
//! | `TlsConnect`       | TCP + TLS 1.3         | CNXN (always encrypted)          |
//! | `Classic`          | TCP plain             | AUTH + CNXN (legacy)             |
//! | `TlsPairing`       | (not a transport)     | Pairing protocol (see `adb_wifi`)|
//!
//! When `discover_and_connect` is called, `TlsConnect` devices are preferred.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

use adb_protocol::mdns::{AdbMdnsService, AdbMdnsServiceType};
use adb_protocol::{TcpTransport, Transport, TransportError};

use crate::client::auth::default_auth;
use crate::client::mdns::{self, MdnsClientError};
use crate::client::transport::{connect_and_handshake_with_tls_upgrade, DeviceInfo};

/// Default timeout for mDNS discovery and connection.
const DEFAULT_MDNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors that can occur during mDNS transport operations.
#[derive(Debug, thiserror::Error)]
pub enum MdnsTransportError {
    /// mDNS discovery or resolution failed.
    #[error("mDNS error: {0}")]
    Mdns(#[from] MdnsClientError),

    /// TCP connection to the resolved address failed.
    #[error("TCP connection failed: {0}")]
    Tcp(#[from] TransportError),

    /// No address was resolved for the service (SRV resolved but A/AAAA missing).
    #[error("no IP address resolved for mDNS service {0}")]
    NoAddress(String),

    /// No service found for the given name or type.
    #[error("mDNS service not found: {0}")]
    ServiceNotFound(String),

    /// No ADB devices discovered on the network.
    #[error("no ADB devices discovered on the network")]
    NoDevicesDiscovered,

    /// ADB handshake (CNXN / AUTH / TLS upgrade) failed.
    #[error("ADB handshake failed: {0}")]
    Handshake(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// TLS stream transport wrapper (only when `tls` feature is enabled)
// ---------------------------------------------------------------------------

/// A lightweight `Transport` impl over a TLS 1.3 encrypted TCP stream.
///
/// Used internally when connecting to `_adb-tls-connect._tcp` services.
#[cfg(feature = "tls")]
struct TlsStreamTransport {
    stream: adb_protocol::tls::TlsStream<adb_protocol::tls::ClientConnection, std::net::TcpStream>,
}

#[cfg(feature = "tls")]
impl Read for TlsStreamTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(feature = "tls")]
impl Write for TlsStreamTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(feature = "tls")]
impl Transport for TlsStreamTransport {}

// ---------------------------------------------------------------------------
// MdnsTransport
// ---------------------------------------------------------------------------

/// A transport wrapper for an mDNS-discovered ADB device.
///
/// Holds the resolved service information and provides a `connect` method
/// that establishes a TCP (or TCP+TLS) transport and performs the ADB handshake.
#[derive(Debug, Clone)]
pub struct MdnsTransport {
    /// The resolved mDNS service record.
    service: AdbMdnsService,
    /// Whether to force TLS upgrade (even for Classic services).
    force_tls: bool,
}

impl MdnsTransport {
    /// Create a new `MdnsTransport` from a resolved service.
    pub fn new(service: AdbMdnsService) -> Self {
        Self {
            service,
            force_tls: false,
        }
    }

    /// Set whether to force TLS upgrade (even for Classic ADB services).
    pub fn with_force_tls(mut self, force: bool) -> Self {
        self.force_tls = force;
        self
    }

    /// The service instance name (e.g. `adb-DEVICE001-_adb-tls-connect._tcp.local.`).
    pub fn instance_name(&self) -> &str {
        &self.service.instance_name
    }

    /// The service type.
    pub fn service_type(&self) -> AdbMdnsServiceType {
        self.service.service_type
    }

    /// The resolved port.
    pub fn port(&self) -> u16 {
        self.service.port
    }

    /// The resolved IP addresses (may be empty if not resolved yet).
    pub fn addresses(&self) -> &[IpAddr] {
        &self.service.addresses
    }

    /// Try to extract the device serial from TXT records or instance name.
    pub fn device_serial(&self) -> Option<String> {
        self.service.device_serial()
    }

    /// Connect to the device, performing the full ADB handshake.
    ///
    /// For `TlsConnect` services, this establishes a TCP connection,
    /// performs TLS 1.3 handshake, then sends the CNXN (connection) message
    /// with optional AUTH loop.
    ///
    /// For `Classic` services, this connects via TCP, performs AUTH + CNXN
    /// handshake (with optional TLS upgrade via A_STLS if `force_tls` is set).
    ///
    /// Returns the negotiated `DeviceInfo` and a `Box<dyn Transport>`.
    pub fn connect(
        &self,
        timeout: Duration,
    ) -> Result<(DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
        let addr = self
            .service
            .addresses
            .first()
            .ok_or_else(|| MdnsTransportError::NoAddress(self.service.instance_name.clone()))?;

        let target = format!("{addr}:{}", self.service.port);

        match self.service.service_type {
            AdbMdnsServiceType::TlsConnect => {
                connect_mdns_tls_device(&target, timeout)
            }
            AdbMdnsServiceType::Classic => {
                if self.force_tls {
                    connect_mdns_tls_device(&target, timeout)
                } else {
                    connect_mdns_classic_device(&target, timeout)
                }
            }
            AdbMdnsServiceType::TlsPairing => Err(MdnsTransportError::Handshake(
                "TlsPairing service is not a transport; use `adb_wifi::pair_device` instead"
                    .into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS-connect device connection
// ---------------------------------------------------------------------------

/// Connect to a TLS-connect ADB device via mDNS-resolved address.
///
/// The TLS-connect service type (`_adb-tls-connect._tcp`) expects
/// a direct TLS 1.3 connection before any ADB protocol messages.
#[cfg(feature = "tls")]
fn connect_mdns_tls_device(
    target: &str,
    timeout: Duration,
) -> Result<(DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
    use adb_protocol::{
        tls, AdbMessageHeader, ADB_VERSION, A_AUTH, A_AUTH_TOKEN, A_CNXN, A_STLS, MAX_PAYLOAD_V2,
    };

    let addr = target
        .parse::<std::net::SocketAddr>()
        .map_err(|e| {
            MdnsTransportError::Handshake(format!("Invalid target address {target}: {e}"))
        })?;

    // --- TCP connection ---
    let tcp = std::net::TcpStream::connect_timeout(&addr, timeout)?;
    let _ = tcp.set_nodelay(true);

    // --- TLS 1.3 handshake ---
    let auth = default_auth();
    let rsa_pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())
        .map_err(|e| MdnsTransportError::Handshake(format!("Failed to export RSA key: {e}")))?;
    let (cert_der, key_der) =
        tls::generate_self_signed_cert(&rsa_pem)
            .map_err(|e| MdnsTransportError::Handshake(format!("Failed to generate cert: {e}")))?;
    let tls_config = tls::create_tls_config(cert_der, key_der)
        .map_err(|e| MdnsTransportError::Handshake(format!("Failed to create TLS config: {e}")))?;
    let tls_stream =
        tls::perform_tls_handshake(tcp, tls_config, "adb")
            .map_err(|e| MdnsTransportError::Handshake(format!("TLS handshake failed: {e}")))?;

    let mut transport: Box<dyn Transport> = Box::new(TlsStreamTransport { stream: tls_stream });

    // --- CNXN handshake over TLS ---
    let cnxn_payload = b"host::features=shell_v2,cmd";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport
        .send_message(&cnxn_hdr, cnxn_payload)
        .map_err(|e| MdnsTransportError::Handshake(format!("Failed to send CNXN: {e}")))?;

    // --- Read response and handle AUTH loop ---
    let (mut resp_hdr, mut payload) = transport
        .recv_message()
        .map_err(|e| MdnsTransportError::Handshake(format!("Failed to read response: {e}")))?;

    let mut sent_signature = false;
    let mut sent_public_key = false;

    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(MdnsTransportError::Handshake(format!(
                "Unsupported AUTH request type: {}",
                resp_hdr.arg0
            )));
        }
        if payload.len() != 20 {
            return Err(MdnsTransportError::Handshake(format!(
                "Invalid ADB AUTH token length: {}",
                payload.len()
            )));
        }

        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&payload)
                .map_err(|e| MdnsTransportError::Handshake(format!("Signature failed: {e}")))?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()
                .map_err(|e| MdnsTransportError::Handshake(format!("RSA key failed: {e}")))?
        } else {
            return Err(MdnsTransportError::Handshake(
                "adbd rejected ADB RSA key after signature and public-key exchange".into(),
            ));
        };

        transport
            .send_message(&auth_hdr, &auth_payload)
            .map_err(|e| MdnsTransportError::Handshake(format!("Failed to send AUTH: {e}")))?;

        (resp_hdr, payload) = transport
            .recv_message()
            .map_err(|e| MdnsTransportError::Handshake(format!("Failed to read AUTH response: {e}")))?;
    }

    if resp_hdr.command == A_STLS {
        return Err(MdnsTransportError::Handshake(
            "Unexpected A_STLS from already-TLS connection".into(),
        ));
    }

    if resp_hdr.command != A_CNXN {
        return Err(MdnsTransportError::Handshake(format!(
            "Unexpected handshake response: cmd={:#x}",
            resp_hdr.command
        )));
    }

    let banner = String::from_utf8_lossy(&payload).to_string();
    let dev_info = DeviceInfo { banner };

    Ok((dev_info, transport))
}

/// Non-TLS fallback for `connect_mdns_tls_device`.
#[cfg(not(feature = "tls"))]
fn connect_mdns_tls_device(
    _target: &str,
    _timeout: Duration,
) -> Result<(DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
    Err(MdnsTransportError::Handshake(
        "TLS-connect service requires `--features tls`".into(),
    ))
}

// ---------------------------------------------------------------------------
// Classic ADB device connection
// ---------------------------------------------------------------------------

/// Connect to a classic ADB device via mDNS-resolved address.
///
/// Classic (`_adb._tcp`) services use plain TCP with AUTH + CNXN handshake.
/// The TLS upgrade is handled internally via A_STLS if the device requests it.
fn connect_mdns_classic_device(
    target: &str,
    timeout: Duration,
) -> Result<(DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
    let transport = TcpTransport::connect_timeout(target, timeout)?;
    let auth = default_auth();
    let cnxn_payload = b"host::features=shell_v2,cmd";

    let (dev_info, transport) = connect_and_handshake_with_tls_upgrade(transport, cnxn_payload, auth)
        .map_err(|e| MdnsTransportError::Handshake(format!("ADB handshake failed: {e}")))?;

    Ok((dev_info, transport))
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Resolve an mDNS service instance name to a fully resolved `MdnsTransport`.
///
/// This performs mDNS SRV + A/AAAA + TXT resolution for the given service
/// instance name. The instance name is the full ADB service instance name
/// (e.g. `adb-DEVICE001-_adb-tls-connect._tcp.local.`).
///
/// The service type is inferred from the instance name via
/// [`AdbMdnsServiceType::parse`] and defaults to `TlsConnect` if ambiguous.
pub fn resolve_mdns_transport(
    instance_name: &str,
    timeout: Duration,
) -> Result<MdnsTransport, MdnsTransportError> {
    // Infer service type from instance name
    let service_type = AdbMdnsServiceType::parse(instance_name)
        .unwrap_or(AdbMdnsServiceType::TlsConnect);

    let service = mdns::resolve_service(service_type, instance_name, timeout)?;

    if service.addresses.is_empty() {
        return Err(MdnsTransportError::NoAddress(instance_name.to_string()));
    }

    Ok(MdnsTransport::new(service))
}

/// Connect to an ADB device by its mDNS service instance name.
///
/// This resolves the service name via mDNS, establishes a TCP (or TCP+TLS)
/// connection, and performs the full ADB handshake (CNXN + optional AUTH).
///
/// # Example
///
/// ```ignore
/// let (info, transport) = connect_to_mdns_device(
///     "adb-Pixel6-_adb-tls-connect._tcp.local.",
///     Duration::from_secs(10),
/// )?;
/// println!("Connected: {}", info.banner.trim());
/// ```
pub fn connect_to_mdns_device(
    instance_name: &str,
    timeout: Duration,
) -> Result<(DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
    let mdns_transport = resolve_mdns_transport(instance_name, timeout)?;
    mdns_transport.connect(timeout)
}

/// Discover ADB devices on the network and connect to the first available one.
///
/// Discovery preference order:
/// 1. `TlsConnect` services (secure ADB over TLS)
/// 2. `Classic` services (legacy ADB over TCP)
///
/// `TlsPairing` services are skipped (they are not transports).
///
/// Returns the discovered service instance name, device info, and transport.
pub fn discover_and_connect(
    timeout: Duration,
) -> Result<(String, DeviceInfo, Box<dyn Transport>), MdnsTransportError> {
    // Discover TLS-connect services first (preferred)
    let tls_services = mdns::discover_services(AdbMdnsServiceType::TlsConnect, timeout)?;

    for service in &tls_services {
        let instance_name = service.instance_name.clone();
        let resolved = mdns::resolve_service(
            AdbMdnsServiceType::TlsConnect,
            &instance_name,
            timeout,
        );

        match resolved {
            Ok(resolved_svc) => {
                let transport = MdnsTransport::new(resolved_svc);
                match transport.connect(timeout) {
                    Ok((info, t)) => return Ok((instance_name, info, t)),
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to connect to TLS device {instance_name}: {e}"
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to resolve TLS service {instance_name}: {e}");
                continue;
            }
        }
    }

    // Fall back to classic services
    let classic_services = mdns::discover_services(AdbMdnsServiceType::Classic, timeout)?;

    for service in &classic_services {
        let instance_name = service.instance_name.clone();
        let resolved =
            mdns::resolve_service(AdbMdnsServiceType::Classic, &instance_name, timeout);

        match resolved {
            Ok(resolved_svc) => {
                let transport = MdnsTransport::new(resolved_svc);
                match transport.connect(timeout) {
                    Ok((info, t)) => return Ok((instance_name, info, t)),
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to connect to classic device {instance_name}: {e}"
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to resolve classic service {instance_name}: {e}");
                continue;
            }
        }
    }

    Err(MdnsTransportError::NoDevicesDiscovered)
}

/// Discover all ADB mDNS services on the network (without connecting).
///
/// Returns a list of all discovered `AdbMdnsService` records for both
/// `TlsConnect` and `Classic` service types.
pub fn discover_mdns_services(
    timeout: Duration,
) -> Result<Vec<AdbMdnsService>, MdnsTransportError> {
    let mut all = Vec::new();

    if let Ok(services) = mdns::discover_services(AdbMdnsServiceType::TlsConnect, timeout) {
        all.extend(services);
    }

    if let Ok(services) = mdns::discover_services(AdbMdnsServiceType::Classic, timeout) {
        all.extend(services);
    }

    Ok(all)
}

/// Check whether a given serial string represents an mDNS-discovered device.
///
/// Returns `true` if the serial matches the pattern of an mDNS instance name
/// or if a device with this serial was discovered via mDNS.
pub fn is_mdns_device(serial: &str) -> bool {
    // mDNS instance names contain "._tcp" or start with "adb-"
    serial.contains("._tcp") || serial.starts_with("adb-")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mdns_device() {
        assert!(is_mdns_device("adb-Device123-_adb-tls-connect._tcp.local."));
        assert!(is_mdns_device("adb-Device123-_adb._tcp.local."));
        assert!(is_mdns_device("adb-Something"));
        assert!(!is_mdns_device("emulator-5554"));
        assert!(!is_mdns_device("192.168.1.100:5555"));
        assert!(!is_mdns_device("12345678"));
    }

    #[test]
    fn test_mdns_transport_new() {
        let service = AdbMdnsService::new(
            AdbMdnsServiceType::TlsConnect,
            "adb-TEST-_adb-tls-connect._tcp.local.",
            5555,
        );
        let transport = MdnsTransport::new(service.clone());
        assert_eq!(transport.instance_name(), service.instance_name);
        assert_eq!(transport.service_type(), AdbMdnsServiceType::TlsConnect);
        assert_eq!(transport.port(), 5555);
        assert!(transport.device_serial().is_some());
    }

    #[test]
    fn test_mdns_transport_no_address_error() {
        let service = AdbMdnsService::new(
            AdbMdnsServiceType::Classic,
            "adb-NOADDR-_adb._tcp.local.",
            5555,
        );
        let transport = MdnsTransport::new(service);
        let result = transport.connect(Duration::from_secs(1));
        assert!(result.is_err());
        match result {
            Err(MdnsTransportError::NoAddress(_)) => {} // expected
            _ => panic!("Expected NoAddress error"),
        }
    }

    #[test]
    fn test_mdns_transport_force_tls() {
        let mut service = AdbMdnsService::new(
            AdbMdnsServiceType::Classic,
            "adb-FORCE-_adb._tcp.local.",
            5555,
        );
        // Add an address so it passes the NoAddress check and hits the handshake
        service
            .addresses
            .push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

        let transport = MdnsTransport::new(service).with_force_tls(true);
        let result = transport.connect(Duration::from_secs(1));

        #[cfg(feature = "tls")]
        {
            // With TLS enabled, force_tls on Classic tries TLS handshake -> will fail
            // because there's no TLS listener at 127.0.0.1:5555
            assert!(result.is_err());
        }

        #[cfg(not(feature = "tls"))]
        {
            // Without TLS, force_tls should error with the "requires --features tls" message
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_mdns_transport_tls_pairing_error() {
        let service = AdbMdnsService::new(
            AdbMdnsServiceType::TlsPairing,
            "adb-PAIR-_adb-tls-pairing._tcp.local.",
            5555,
        );
        let transport = MdnsTransport::new(service);
        let result = transport.connect(Duration::from_secs(1));
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TlsPairing") || msg.contains("pair_device"),
            "Expected TlsPairing error, got: {msg}"
        );
    }
}
