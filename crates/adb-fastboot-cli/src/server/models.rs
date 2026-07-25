//! Device model types — TransportRegistry, DeviceEntry, Forward/Reverse rules.
//!
//! Mirrors AOSP `transport.cpp` (TransportRegistry, atransport) and
//! `adb_listeners.cpp` (ForwardRule / ReverseRule).

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_AUTH, A_AUTH_TOKEN, A_CNXN, MAX_PAYLOAD_V2};
#[cfg(feature = "usb")]
use adb_protocol::Transport;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub(crate) const ADB_SERVER_PORT: u16 = 5037;
pub(crate) const SERVER_VERSION: u32 = 0x01000001;
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Device model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum DeviceState {
    Offline,
    Device,
    Recovery,
    Sideload,
    Bootloader,
    Authorizing,
    Connecting,
    NoPerm,
    Unknown,
}

impl DeviceState {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Offline => "offline",
            DeviceState::Device => "device",
            DeviceState::Recovery => "recovery",
            DeviceState::Sideload => "sideload",
            DeviceState::Bootloader => "bootloader",
            DeviceState::Authorizing => "authorizing",
            DeviceState::Connecting => "connecting",
            DeviceState::NoPerm => "no permissions",
            DeviceState::Unknown => "unknown",
        }
    }
}

/// Matches AOSP's `acquire_one_transport(..., accept_any_state=false)` online
/// states. Connecting, authorizing, unauthorized, and offline transports must
/// not be selected for a device-level host service.
pub(crate) fn is_usable_state(state: DeviceState) -> bool {
    matches!(
        state,
        DeviceState::Device
            | DeviceState::Recovery
            | DeviceState::Sideload
            | DeviceState::Bootloader
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceOrigin {
    Usb,
    Tcp { addr: SocketAddr },
}

#[derive(Debug, Clone)]
pub(crate) struct DeviceEntry {
    pub serial: String,
    pub transport_id: u64,
    pub state: DeviceState,
    pub origin: DeviceOrigin,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device_name: Option<String>,
    pub transport_features: Option<String>,
}

// ---------------------------------------------------------------------------
// Transport Registry
// ---------------------------------------------------------------------------

pub(crate) struct TransportRegistry {
    pub devices: Vec<DeviceEntry>,
    pub forwards: Vec<ForwardRule>,
    pub reverses: Vec<ReverseRule>,
    pub next_id: u64,
    /// Authenticated USB transports keyed by serial number.
    /// Established on first client use, reused by subsequent clients.
    #[cfg(feature = "usb")]
    pub usb_auth: std::collections::HashMap<String, AuthenticatedUsbTransport>,
}

#[derive(Debug, Clone)]
pub(crate) struct ForwardRule {
    pub serial: String,
    pub local: String,
    pub remote: String,
    pub active_flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReverseRule {
    pub serial: String,
    pub remote: String,
    pub local: String,
}

// ---------------------------------------------------------------------------
// Authenticated USB Transport — persisted AUTH/CNXN state
// ---------------------------------------------------------------------------

/// Holds a USB transport that has completed the AUTH/CNXN handshake.
/// The write half (send transport) is shared behind `Arc<Mutex<>>` so
/// multiple clients can send through the same authenticated connection.
///
/// The receive direction opens a separate USB fd per client bridge (usbfs
/// allows multiple opens of the same device node), avoiding the lock
/// contention that would arise from sharing a single fd for both directions.
#[cfg(feature = "usb")]
pub(crate) struct AuthenticatedUsbTransport {
    pub _serial: String,
    /// Authenticated write-side transport. Shared via Arc<Mutex<>> so
    /// concurrent client threads serialise their send_message calls.
    pub send_transport: Arc<Mutex<Box<dyn Transport>>>,
}

// ---------------------------------------------------------------------------
// TransportRegistry impl — device management
// ---------------------------------------------------------------------------

impl TransportRegistry {
    pub(crate) fn new() -> Self {
        let mut reg = Self {
            devices: Vec::new(),
            forwards: Vec::new(),
            reverses: Vec::new(),
            next_id: 1,
            #[cfg(feature = "usb")]
            usb_auth: std::collections::HashMap::new(),
        };
        reg.refresh_usb_devices();
        reg
    }

    pub(crate) fn refresh_usb_devices(&mut self) {
        #[cfg(feature = "usb")]
        match adb_protocol::usb_android::UsbfsAdbDevice::enumerate() {
            Ok(candidates) => {
                for cand in &candidates {
                    let serial = cand
                        .serial
                        .clone()
                        .unwrap_or_else(|| format!("{:03}{:03}", cand.bus_number, cand.address));
                    if !self.devices.iter().any(|d| d.serial == serial) {
                        self.devices.push(DeviceEntry {
                            serial: serial.clone(),
                            transport_id: {
                                let id = self.next_id;
                                self.next_id += 1;
                                id
                            },
                            state: DeviceState::Device,
                            origin: DeviceOrigin::Usb,
                            product: None,
                            model: None,
                            device_name: None,
                            transport_features: None,
                        });
                    }
                }
                let known: std::collections::HashSet<String> = candidates
                    .into_iter()
                    .map(|c| c.serial.unwrap_or_else(|| format!("{:03}{:03}", c.bus_number, c.address)))
                    .collect();
                self.devices.retain(|d| {
                    if matches!(d.origin, DeviceOrigin::Usb) {
                        known.contains(&d.serial)
                    } else {
                        true
                    }
                });
            }
            Err(e) => eprintln!("[adb-server] USB enumeration: {e}"),
        }
    }

    pub(crate) fn list_devices(&self, verbose: bool) -> String {
        if self.devices.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for dev in &self.devices {
            let state = dev.state.as_str();
            if verbose {
                let product = dev.product.as_deref().unwrap_or("unknown");
                let model = dev.model.as_deref().unwrap_or("unknown");
                let dname = dev.device_name.as_deref().unwrap_or("unknown");
                out.push_str(&format!(
                    "{}\t{} product:{} model:{} device:{}\n",
                    dev.serial, state, product, model, dname,
                ));
            } else {
                out.push_str(&format!("{}\t{}\n", dev.serial, state));
            }
        }
        out
    }

    pub(crate) fn find_by_transport_id(&self, id: u64) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| d.transport_id == id)
    }

    pub(crate) fn find_by_serial(&self, serial: &str) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| d.serial == serial)
    }

    pub(crate) fn find_any_device(&self) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| is_usable_state(d.state))
    }

    /// Select the sole usable transport, matching AOSP's
    /// `acquire_one_transport(kTransportAny)`: implicit selection is invalid
    /// when more than one usable device or emulator is registered.
    pub(crate) fn find_unique_device(&self) -> Result<&DeviceEntry, &'static str> {
        let mut matches = self.devices.iter().filter(|d| is_usable_state(d.state));
        let Some(device) = matches.next() else {
            return Err("no devices/emulators found");
        };
        if matches.next().is_some() {
            return Err("more than one device/emulator");
        }
        Ok(device)
    }

    pub(crate) fn upsert_tcp_device(&mut self, addr: SocketAddr, serial: String) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.serial == serial) {
            existing.state = DeviceState::Device;
        } else {
            self.devices.push(DeviceEntry {
                transport_id: {
                    let id = self.next_id;
                    self.next_id += 1;
                    id
                },
                serial,
                state: DeviceState::Device,
                origin: DeviceOrigin::Tcp { addr },
                product: None,
                model: None,
                device_name: None,
                transport_features: None,
            });
        }
    }

    pub(crate) fn remove_device(&mut self, serial: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.serial != serial);
        before != self.devices.len()
    }

    pub(crate) fn remove_all_tcp_devices(&mut self) {
        self.devices.retain(|d| matches!(d.origin, DeviceOrigin::Usb));
    }

    // -- Authenticated USB transport ---------------------------------------

    /// Ensure an authenticated USB transport exists for `serial`.
    /// Returns a clone of the `Arc` so callers can lock and send.
    ///
    /// On first call for a given serial this opens the USB device, runs the
    /// full AUTH/CNXN handshake (RSA SIGNATURE + RSAKEY), then stores the
    /// authenticated transport in `usb_auth`.
    #[cfg(feature = "usb")]
    pub(crate) fn ensure_usb_auth(
        &mut self,
        serial: &str,
    ) -> Result<Arc<Mutex<Box<dyn Transport>>>, String> {
        // Already authenticated — return the existing Arc clone
        if let Some(existing) = self.usb_auth.get(serial) {
            return Ok(Arc::clone(&existing.send_transport));
        }

        eprintln!("[adb-server] Authenticating USB transport for '{serial}'...");

        use adb_protocol::usb::UsbTransportAdapter;
        use adb_protocol::usb_android::UsbfsAdbDevice;

        // 1. Open USB device
        let usb_dev = UsbfsAdbDevice::open_by_serial(serial)
            .map_err(|e| format!("Cannot open USB device '{serial}': {e}"))?;
        let transport = UsbTransportAdapter::new(usb_dev);

        // 2. Load ADB host auth key
        let auth = crate::client::auth::default_auth();

        // 3. Perform AUTH/CNXN handshake
        let cnxn_payload = b"host::";
        let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

        let mut t: Box<dyn Transport> = Box::new(transport);

        t.send_message(&cnxn_hdr, cnxn_payload)
            .map_err(|e| format!("CNXN send failed: {e}"))?;

        let (mut resp_hdr, mut payload) = t
            .recv_message()
            .map_err(|e| format!("CNXN recv failed: {e}"))?;

        let mut sent_signature = false;
        let mut sent_public_key = false;
        while resp_hdr.command == A_AUTH {
            if resp_hdr.arg0 != A_AUTH_TOKEN {
                return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0));
            }
            if payload.len() != 20 {
                return Err(format!(
                    "Invalid ADB AUTH token length: {}",
                    payload.len()
                ));
            }

            let (auth_hdr, auth_payload) = if !sent_signature {
                sent_signature = true;
                auth.make_signature_message(&payload)
                    .map_err(|e| format!("signature failed: {e}"))?
            } else if !sent_public_key {
                sent_public_key = true;
                auth.make_rsakey_message()
                    .map_err(|e| format!("rsakey failed: {e}"))?
            } else {
                return Err("adbd rejected the ADB RSA key after signature and public-key exchange"
                    .to_string());
            };
            t.send_message(&auth_hdr, &auth_payload)
                .map_err(|e| format!("AUTH send failed: {e}"))?;
            (resp_hdr, payload) = t
                .recv_message()
                .map_err(|e| format!("AUTH recv failed: {e}"))?;
        }

        if resp_hdr.command != A_CNXN {
            return Err(format!(
                "Expected A_CNXN after AUTH, got cmd={:#x}",
                resp_hdr.command
            ));
        }

        // Persist public key on Android so subsequent SIGNATURE-only auth works
        #[cfg(target_os = "android")]
        {
            if sent_public_key {
                let _ = crate::client::auth::persist_adb_pubkey(auth);
            }
        }

        let arc_t = Arc::new(Mutex::new(t));

        self.usb_auth.insert(
            serial.to_string(),
            AuthenticatedUsbTransport {
                _serial: serial.to_string(),
                send_transport: Arc::clone(&arc_t),
            },
        );

        eprintln!(
            "[adb-server] USB transport for '{serial}' authenticated and cached."
        );
        Ok(arc_t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_unique_device_rejects_implicit_ambiguous_selection() {
        let mut registry = TransportRegistry::new();
        registry.devices.clear();
        assert!(matches!(
            registry.find_unique_device(),
            Err("no devices/emulators found")
        ));

        registry.upsert_tcp_device("127.0.0.1:5555".parse().unwrap(), "one".to_string());
        assert_eq!(registry.find_unique_device().unwrap().serial, "one");

        registry.upsert_tcp_device("127.0.0.1:5556".parse().unwrap(), "two".to_string());
        assert!(matches!(
            registry.find_unique_device(),
            Err("more than one device/emulator")
        ));
    }

    #[test]
    fn test_transport_selection_accepts_only_aosp_online_states() {
        assert!(is_usable_state(DeviceState::Device));
        assert!(is_usable_state(DeviceState::Recovery));
        assert!(is_usable_state(DeviceState::Sideload));
        assert!(is_usable_state(DeviceState::Bootloader));
        assert!(!is_usable_state(DeviceState::Offline));
        assert!(!is_usable_state(DeviceState::Authorizing));
        assert!(!is_usable_state(DeviceState::Connecting));
        assert!(!is_usable_state(DeviceState::NoPerm));
    }
}
