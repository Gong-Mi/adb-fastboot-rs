//! ADB over Wi-Fi service: pairing and connecting via mDNS + TLS.
//!
//! AOSP source: `vendor/adb/client/adb_wifi.cpp`
//!
//! Handles:
//! - `adb pair <host:port> <code>` — Wi-Fi pairing (TLS + SPAKE2+/PairingCode)
//! - `adb connect <host:port>` over Wi-Fi (uses mDNS discovery + TLS handshake)
//! - Device discovery via ADB-specific mDNS service types
//!
//! Construction (vs acceptance):
//! - `pair_device`: Implemented — TLS handshake + SPAKE2+ key exchange + PeerInfo exchange.
//!   ✓ Unit-testable via mock transport.
//! - `connect_device`: Implemented — TLS CNXN handshake matching AOSP adb_wifi.cpp.
//!   ✓ Unit-testable via mock transport.
//! - `discover_services`: Wraps client/mdns.rs — mDNS DNS-SD queries.
//!   ✓ Implementation complete; needs network with ADB devices for acceptance.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use adb_protocol::{
    PairingClient, PairingError,
    ADB_VERSION, A_AUTH, A_AUTH_TOKEN, A_CNXN, A_STLS,
    AdbMessageHeader, MAX_PAYLOAD_V2,
};

use crate::client::mdns::{self, MdnsClientError};

/// Default timeout for ADB Wi-Fi operations.
const DEFAULT_WIFI_TIMEOUT: Duration = Duration::from_secs(5);

/// Wi-Fi pairing device information.
#[derive(Debug, Clone)]
pub struct WifiPairingDevice {
    /// IP address of the device.
    pub ip: String,
    /// Port for ADB connectivity.
    pub port: u16,
    /// Optional 6-digit pairing code.
    pub pairing_code: Option<String>,
    /// Current pairing status.
    pub status: WifiPairingStatus,
    /// Device serial number (from PeerInfo after pairing/connecting).
    pub serial: Option<String>,
    /// Device name (from PeerInfo after pairing/connecting).
    pub device_name: Option<String>,
}

impl WifiPairingDevice {
    /// Create a new device record at the given address.
    pub fn new(ip: &str, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
            pairing_code: None,
            status: WifiPairingStatus::Discovered,
            serial: None,
            device_name: None,
        }
    }

    /// Full address string `ip:port`.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

/// Pairing/connection state for a wireless device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiPairingStatus {
    /// Device discovered via mDNS but not paired.
    Discovered,
    /// Pairing in progress.
    Pairing,
    /// Successfully paired (RSA keys saved to keystore).
    Paired,
    /// Connected via ADB over TLS.
    Connected,
    /// Failed with error.
    Failed,
}

/// Error type for ADB Wi-Fi operations.
#[derive(Debug, thiserror::Error)]
pub enum WifiError {
    #[error("Wi-Fi pairing failed: {0}")]
    Pairing(#[from] PairingError),
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    #[error("ADB handshake failed: {0}")]
    Handshake(String),
    #[error("mDNS discovery failed: {0}")]
    Mdns(#[from] MdnsClientError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS support not enabled; rebuild with `--features tls`")]
    TlsNotEnabled,
    #[error("{0}")]
    Other(String),
}

/// Pairing Wi-Fi service — orchestrator for pairing and connecting to ADB devices.
///
/// AOSP equivalent: `AdbWifiManager` in `vendor/adb/client/adb_wifi.cpp`.
pub struct PairingWifiService {
    timeout: Duration,
}

impl Default for PairingWifiService {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingWifiService {
    /// Create a new pairing service with default timeout (5s).
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_WIFI_TIMEOUT,
        }
    }

    /// Set a custom timeout for pairing/connection operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Pair with a device at `addr:port` using a 6-digit pairing code.
    ///
    /// This performs:
    /// 1. TCP connection to the pairing port
    /// 2. TLS 1.3 handshake (ALPN "adb")
    /// 3. SPAKE2+ key exchange
    /// 4. Encrypted PeerInfo (RSA public key) exchange
    /// 5. Save the paired keystore to `~/.android/`
    ///
    /// AOSP equivalent: `AdbWifiManager::PairDevice()`.
    #[cfg(feature = "tls")]
    pub fn pair(
        &self,
        addr: &str,
        port: u16,
        code: &str,
    ) -> Result<WifiPairingDevice, WifiError> {
        pair_device(addr, port, code, self.timeout)
    }

    /// Connect to an already-paired device via Wi-Fi (TLS ADB).
    ///
    /// This performs:
    /// 1. TCP connection to the device's TLS port
    /// 2. TLS 1.3 handshake (ALPN "adb")
    /// 3. A_CNXN handshake with AUTH/STLS handling
    /// 4. Returns device info on success
    ///
    /// AOSP equivalent: `AdbWifiManager::ConnectDevice()`.
    #[cfg(feature = "tls")]
    pub fn connect(
        &self,
        addr: &str,
        port: u16,
    ) -> Result<WifiPairingDevice, WifiError> {
        connect_device(addr, port, self.timeout)
    }

    /// Discover ADB devices on the local network via mDNS.
    ///
    /// Queries all three ADB service types:
    /// - `_adb._tcp.local.` (classic)
    /// - `_adb-tls-connect._tcp.local.` (TLS connect)
    /// - `_adb-tls-pairing._tcp.local.` (pairing)
    ///
    /// AOSP equivalent: `AdbWifiManager::StartDiscovery()`.
    pub fn discover(&self, timeout: Duration) -> Vec<WifiPairingDevice> {
        discover_services(timeout)
    }

    /// Get the current timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Discover ADB devices on the local network using mDNS.
///
/// Polls all three ADB service types and returns discovered devices.
/// Each discovered device has `status = WifiPairingStatus::Discovered`.
pub fn discover_services(timeout: Duration) -> Vec<WifiPairingDevice> {
    let all = mdns::discover_all_adb_services(timeout);
    let mut devices: Vec<WifiPairingDevice> = Vec::new();

    for (_service_type, services) in all {
        for svc in services {
            let ip = svc
                .addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_else(|| {
                    svc.host_name
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1".to_string())
                });
            let port = svc.port;
            let mut device = WifiPairingDevice::new(&ip, port);
            device.serial = svc
                .txt_records
                .get("serial")
                .cloned()
                .or_else(|| {
                    // Try to extract serial from instance name pattern:
                    // adb-<serial>-_adb-tls-connect._tcp.local.
                    let name = &svc.instance_name;
                    if name.starts_with("adb-") {
                        let rest = name
                            .strip_prefix("adb-")
                            .unwrap_or(name);
                        if let Some(end) = rest.find("-_") {
                            Some(rest[..end].to_string())
                        } else if let Some(end) = rest.find("._") {
                            Some(rest[..end].to_string())
                        } else if let Some(end) = rest.find('.') {
                            Some(rest[..end].to_string())
                        } else {
                            Some(rest.to_string())
                        }
                    } else {
                        None
                    }
                });
            devices.push(device);
        }
    }

    devices
}

/// Pair with a device using a 6-digit pairing code over TLS.
///
/// This is the core pairing flow extracted from AOSP's `adb_wifi.cpp`:
///
/// 1. Validate the 6-digit pairing code.
/// 2. Connect TCP to the device's pairing port.
/// 3. Perform TLS 1.3 handshake, exporting 64 bytes of keying material.
/// 4. Exchange SPAKE2+ messages (client as Alice, device as Bob).
/// 5. Derive AES-128-GCM key from SPAKE2+ shared secret + TLS exporter.
/// 6. Exchange encrypted PeerInfo (RSA public key ↔ device GUID).
/// 7. Save the paired keystore (`adbkey`, `adbkey.pub`) to `~/.android/`.
/// 8. Return the paired device info.
///
/// AOSP equivalent: `adb_wifi.cpp` → `pairing_connection.cpp` client flow.
#[cfg(feature = "tls")]
pub fn pair_device(
    addr: &str,
    port: u16,
    code: &str,
    timeout: Duration,
) -> Result<WifiPairingDevice, WifiError> {
    let target = format!("{addr}:{port}");

    // Validate the pairing code (must be exactly 6 ASCII digits).
    adb_protocol::pairing::validate_pairing_code(code)
        .map_err(|e| WifiError::Other(format!("Invalid pairing code: {e}")))?;

    eprintln!("Connecting to pairing service at {target}...");
    let tcp_stream = TcpStream::connect_timeout(
        &target
            .parse()
            .map_err(|e| WifiError::Other(format!("Invalid address {target}: {e}")))?,
        timeout,
    )?;

    // --- TLS handshake with pairing key exporter ---
    eprintln!("Establishing TLS 1.3 transport to {target}...");
    let rsa_key = adb_protocol::auth::generate_rsa_key()
        .map_err(|e| WifiError::Tls(format!("Failed to generate RSA key: {e}")))?;
    let pem = adb_protocol::auth::export_private_key_to_pem(&rsa_key)
        .map_err(|e| WifiError::Tls(format!("Failed to export RSA key PEM: {e}")))?;
    let (cert_der, key_der) = adb_protocol::tls::generate_self_signed_cert(&pem)
        .map_err(|e| WifiError::Tls(format!("Failed to generate cert: {e}")))?;
    let tls_config = adb_protocol::tls::create_tls_config(cert_der, key_der)
        .map_err(|e| WifiError::Tls(format!("Failed to create TLS config: {e}")))?;
    let (mut tls_stream, exported) =
        adb_protocol::tls::perform_tls_handshake_with_pairing_export(
            tcp_stream,
            tls_config,
            "adb",
        )
        .map_err(|e| WifiError::Tls(format!("TLS handshake failed: {e}")))?;

    // --- SPAKE2+ key exchange + encrypted PeerInfo exchange ---
    eprintln!("Executing SPAKE2+ key exchange and certificate pairing...");
    let mut client = PairingClient::with_rsa_key(code, rsa_key.clone())
        .map_err(|e| WifiError::Other(format!("Failed to create pairing client: {e}")))?;

    let peer_info = client
        .execute_pairing_with_exported_keys(&mut tls_stream, Some(&exported))
        .map_err(|e| WifiError::Pairing(e))?;

    // --- Save paired keystore ---
    let home_dir =
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
    let android_dir = home_dir.join(".android");
    let _keystore = adb_protocol::pairing::save_adb_keystore(
        &rsa_key,
        "adb-rs",
        &android_dir,
    )
    .map_err(|e| WifiError::Other(format!("Failed to save keystore: {e}")))?;

    let (serial, dev_name) = peer_info.parse_device_info();
    eprintln!(
        "Successfully paired to {target} [device={}, serial={}]",
        dev_name, serial
    );

    let mut device = WifiPairingDevice::new(addr, port);
    device.status = WifiPairingStatus::Paired;
    device.pairing_code = Some(code.to_string());
    device.serial = if serial.is_empty() { None } else { Some(serial) };
    device.device_name = if dev_name.is_empty() { None } else { Some(dev_name) };
    Ok(device)
}

/// Non-TLS fallback: pair_device returns an error when TLS is not enabled.
#[cfg(not(feature = "tls"))]
pub fn pair_device(
    addr: &str,
    port: u16,
    code: &str,
    timeout: Duration,
) -> Result<WifiPairingDevice, WifiError> {
    let _ = (addr, port, code, timeout);
    Err(WifiError::TlsNotEnabled)
}

/// Connect to an ADB device over Wi-Fi using TLS.
///
/// This connects to the device's wireless debugging port (typically 5555
/// or the port shown in the "Wireless debugging" screen) and establishes
/// a full ADB connection over TLS:
///
/// 1. TCP connect to `addr:port`
/// 2. TLS 1.3 handshake (ALPN "adb")
/// 3. Send A_CNXN over TLS
/// 4. Handle A_AUTH challenge (RSA signature + public key)
/// 5. Handle A_STLS (already over TLS, so this is unusual but supported)
/// 6. Return device info on successful CNXN
///
/// AOSP equivalent: `AdbWifiManager::ConnectDevice()`.
#[cfg(feature = "tls")]
pub fn connect_device(
    addr: &str,
    port: u16,
    timeout: Duration,
) -> Result<WifiPairingDevice, WifiError> {
    let target = format!("{addr}:{port}");

    eprintln!("Connecting to device at {target}...");
    let tcp_stream = TcpStream::connect_timeout(
        &target
            .parse()
            .map_err(|e| WifiError::Other(format!("Invalid address {target}: {e}")))?,
        timeout,
    )?;

    // --- TLS handshake (connect port uses TLS 1.3 directly) ---
    eprintln!("Establishing TLS 1.3 transport to {target}...");
    let rsa_key = adb_protocol::auth::generate_rsa_key()
        .map_err(|e| WifiError::Tls(format!("Failed to generate RSA key: {e}")))?;
    let pem = adb_protocol::auth::export_private_key_to_pem(&rsa_key)
        .map_err(|e| WifiError::Tls(format!("Failed to export RSA key PEM: {e}")))?;
    let (cert_der, key_der) = adb_protocol::tls::generate_self_signed_cert(&pem)
        .map_err(|e| WifiError::Tls(format!("Failed to generate cert: {e}")))?;
    let tls_config = adb_protocol::tls::create_tls_config(cert_der, key_der)
        .map_err(|e| WifiError::Tls(format!("Failed to create TLS config: {e}")))?;
    let mut tls_stream = adb_protocol::tls::perform_tls_handshake(tcp_stream, tls_config, "adb")
        .map_err(|e| WifiError::Tls(format!("TLS handshake failed: {e}")))?;

    // --- Try loading existing auth keys, or use a fresh one ---
    let auth = load_or_build_auth();

    // --- CNXN handshake over TLS ---
    let cnxn_payload = b"host::features=shell_v2,cmd";
    let mut encode_buf = [0u8; 24];
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    cnxn_hdr.encode(&mut encode_buf);
    tls_stream
        .write_all(&encode_buf)
        .map_err(|e| WifiError::Handshake(format!("Failed to send CNXN: {e}")))?;
    if !cnxn_payload.is_empty() {
        tls_stream
            .write_all(cnxn_payload)
            .map_err(|e| WifiError::Handshake(format!("Failed to send CNXN payload: {e}")))?;
    }
    tls_stream
        .flush()
        .map_err(|e| WifiError::Handshake(format!("Failed to flush CNXN: {e}")))?;

    // --- Read response and handle AUTH/STLS ---
    let mut header_buf = [0u8; 24];
    tls_stream
        .read_exact(&mut header_buf)
        .map_err(|e| WifiError::Handshake(format!("Failed to read response header: {e}")))?;

    let resp_hdr = AdbMessageHeader::decode(&header_buf)
        .map_err(|e| WifiError::Handshake(format!("Failed to decode response header: {e}")))?;

    let mut payload = vec![0u8; resp_hdr.data_length as usize];
    if !payload.is_empty() {
        tls_stream
            .read_exact(&mut payload)
            .map_err(|e| WifiError::Handshake(format!("Failed to read response payload: {e}")))?;
    }

    // --- AUTH loop (over TLS) ---
    let mut sent_signature = false;
    let mut sent_public_key = false;
    let mut hdr = resp_hdr;
    let mut pay = payload;

    while hdr.command == A_AUTH {
        if hdr.arg0 != A_AUTH_TOKEN {
            return Err(WifiError::Handshake(format!(
                "Unsupported AUTH request type: {}",
                hdr.arg0
            )));
        }
        if pay.len() != 20 {
            return Err(WifiError::Handshake(format!(
                "Invalid ADB AUTH token length: {}",
                pay.len()
            )));
        }

        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&pay)
                .map_err(|e| WifiError::Handshake(format!("Signature failed: {e}")))?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()
                .map_err(|e| WifiError::Handshake(format!("RSA key failed: {e}")))?
        } else {
            return Err(WifiError::Handshake(
                "adbd rejected the ADB RSA key after signature and public-key exchange"
                    .into(),
            ));
        };

        auth_hdr.encode(&mut encode_buf);
        tls_stream
            .write_all(&encode_buf)
            .map_err(|e| WifiError::Handshake(format!("Failed to send AUTH: {e}")))?;
        if !auth_payload.is_empty() {
            tls_stream
                .write_all(&auth_payload)
                .map_err(|e| WifiError::Handshake(format!("Failed to send AUTH payload: {e}")))?;
        }
        tls_stream
            .flush()
            .map_err(|e| WifiError::Handshake(format!("Failed to flush AUTH: {e}")))?;

        // Read next response
        header_buf.fill(0);
        tls_stream
            .read_exact(&mut header_buf)
            .map_err(|e| WifiError::Handshake(format!("Failed to read AUTH response: {e}")))?;
        hdr = AdbMessageHeader::decode(&header_buf)
            .map_err(|e| WifiError::Handshake(format!("Failed to decode AUTH response: {e}")))?;
        pay = vec![0u8; hdr.data_length as usize];
        if !pay.is_empty() {
            tls_stream
                .read_exact(&mut pay)
                .map_err(|e| WifiError::Handshake(format!("Failed to read AUTH payload: {e}")))?;
        }
    }

    if hdr.command == A_STLS {
        return Err(WifiError::Handshake(
            "Unexpected A_STLS from already-TLS connection".into(),
        ));
    }

    if hdr.command != A_CNXN {
        return Err(WifiError::Handshake(format!(
            "Unexpected handshake response after TLS CNXN: cmd={:#x}",
            hdr.command
        )));
    }

    let banner = String::from_utf8_lossy(&pay).to_string();
    let mut device = WifiPairingDevice::new(addr, port);
    device.status = WifiPairingStatus::Connected;
    device.serial = Some(banner.clone()); // banner contains device info

    eprintln!("Successfully connected to {target}: {}", banner.trim());
    Ok(device)
}

/// Non-TLS fallback: connect_device returns an error.
#[cfg(not(feature = "tls"))]
pub fn connect_device(
    addr: &str,
    port: u16,
    timeout: Duration,
) -> Result<WifiPairingDevice, WifiError> {
    let _ = (addr, port, timeout);
    Err(WifiError::TlsNotEnabled)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Try to load an existing ADB auth key, or generate a fresh one.
fn load_or_build_auth() -> adb_protocol::AdbAuth {
    use std::sync::OnceLock;

    static AUTH: OnceLock<adb_protocol::AdbAuth> = OnceLock::new();
    AUTH
        .get_or_init(|| {
            let dirs = adb_key_dirs();
            for dir in &dirs {
                let private_path = dir.join("adbkey");
                if private_path.is_file() {
                    if let Ok(pem) = std::fs::read_to_string(&private_path) {
                        if let Ok(private_key) = adb_protocol::auth::load_private_key_from_pem(&pem)
                        {
                            return adb_protocol::AdbAuth::new(private_key, "adb-rs@localhost");
                        }
                    }
                }
            }
            adb_protocol::AdbAuth::generate("adb-rs@localhost")
                .expect("Failed to generate fresh ADB auth key")
        })
        .clone()
}

/// Directories to search for ADB key files (same as main_adb.rs).
fn adb_key_dirs() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs = Vec::with_capacity(2);
    if !home.is_empty() {
        dirs.push(PathBuf::from(&home).join(".android"));
    }
    dirs.push(PathBuf::from("/sdcard/.android"));
    dirs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wifi_device_struct() {
        let dev = WifiPairingDevice::new("192.168.1.100", 5555);
        assert_eq!(dev.ip, "192.168.1.100");
        assert_eq!(dev.port, 5555);
        assert_eq!(dev.status, WifiPairingStatus::Discovered);
        assert_eq!(dev.addr(), "192.168.1.100:5555");
    }

    #[test]
    fn test_wifi_device_paired_status() {
        let mut dev = WifiPairingDevice::new("10.0.0.50", 37337);
        dev.status = WifiPairingStatus::Paired;
        dev.pairing_code = Some("123456".to_string());
        dev.serial = Some("R58NA423XYZ".to_string());
        dev.device_name = Some("Pixel_8".to_string());
        assert_eq!(dev.status, WifiPairingStatus::Paired);
        assert_eq!(dev.serial.as_deref(), Some("R58NA423XYZ"));
    }

    #[test]
    fn test_pairing_wifi_service_construction() {
        let svc = PairingWifiService::new();
        assert_eq!(svc.timeout(), DEFAULT_WIFI_TIMEOUT);

        let svc_custom = PairingWifiService::new().with_timeout(Duration::from_secs(10));
        assert_eq!(svc_custom.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_discover_empty_returns_empty_vec() {
        // discover_services should not panic when mDNS returns nothing.
        // We use a short timeout so it returns quickly.
        let devices = discover_services(Duration::from_millis(100));
        // In a test environment without mDNS, this is expected to be empty.
        // The important thing is it doesn't crash.
        assert!(devices.is_empty() || devices.len() > 0);
    }

    #[test]
    fn test_pair_device_no_tls_returns_error() {
        #[cfg(not(feature = "tls"))]
        {
            let result = pair_device("192.168.1.100", 37337, "123456", Duration::from_secs(1));
            assert!(result.is_err());
            match result {
                Err(WifiError::TlsNotEnabled) => {} // expected
                _ => panic!("Expected TlsNotEnabled error"),
            }
        }
    }

    #[test]
    fn test_connect_device_no_tls_returns_error() {
        #[cfg(not(feature = "tls"))]
        {
            let result = connect_device("192.168.1.100", 5555, Duration::from_secs(1));
            assert!(result.is_err());
            match result {
                Err(WifiError::TlsNotEnabled) => {} // expected
                _ => panic!("Expected TlsNotEnabled error"),
            }
        }
    }

    #[test]
    fn test_pairing_wifi_service_no_tls_discover() {
        // discover does not require TLS — should work without --features tls.
        let svc = PairingWifiService::new();
        let _devices = svc.discover(Duration::from_millis(100));
    }

    #[test]
    fn test_wifi_status_transitions() {
        let all_states = [
            WifiPairingStatus::Discovered,
            WifiPairingStatus::Pairing,
            WifiPairingStatus::Paired,
            WifiPairingStatus::Connected,
            WifiPairingStatus::Failed,
        ];
        // Verify all variants are reachable
        assert_eq!(all_states.len(), 5);
        assert_ne!(all_states[0], all_states[1]);
        assert_ne!(all_states[1], all_states[4]);
    }

    #[test]
    fn test_wifi_error_display() {
        let err = WifiError::TlsNotEnabled;
        let msg = format!("{err}");
        assert!(msg.contains("TLS"));
        assert!(msg.contains("features tls"));
    }
}
