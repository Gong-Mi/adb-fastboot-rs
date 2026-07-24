//! Transport lifecycle management — registration, state tracking, event notification,
//! and remote connection establishment.
//!
//! Mirrors AOSP `transport.cpp` (acquire_one_transport, connect_to_remote) plus
//! transport lifecycle hooks.  Connects to AOSP concepts:
//!
//! - `connect_to_remote(host, port)`   → TCP transport to adbd + CNXN handshake
//! - `acquire_one_transport(serial)`   → lookup / return connected transport
//! - `transport_registration` + events → callbacks on connect / disconnect / state change

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, ADB_VERSION, A_CNXN, MAX_PAYLOAD_V2,
    TcpTransport, Transport,
};
#[cfg(feature = "usb")]
use adb_protocol::usb::UsbTransportAdapter;
#[cfg(feature = "usb")]
use adb_protocol::usb_android::UsbfsAdbDevice;

use crate::server::models::{DeviceEntry, DeviceOrigin, DeviceState, TransportRegistry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout for transport connections.
const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Transport Event Callbacks
// ---------------------------------------------------------------------------

/// Collection of event hooks for transport lifecycle events.
///
/// All callbacks are fire-and-forget: errors inside a single callback do not
/// prevent later callbacks from running, nor do they propagate to the caller
/// that triggered the event.
///
/// # Thread safety
///
/// `TransportCallbacks` is intended to be shared behind `Arc<Mutex<>>` or
/// stored inside `TransportManager`.  Each callback must be `Send + Sync`.
#[derive(Default)]
pub(crate) struct TransportCallbacks {
    /// Fired when a transport connects (device discovered or TCP connected).
    pub on_connected: Vec<Box<dyn Fn(&str, &DeviceOrigin) + Send + Sync + 'static>>,
    /// Fired when a transport disconnects (device removed or TCP dropped).
    pub on_disconnected: Vec<Box<dyn Fn(&str) + Send + Sync + 'static>>,
    /// Fired when a transport's state changes (e.g. offline → device).
    pub on_state_changed: Vec<Box<dyn Fn(&str, DeviceState, DeviceState) + Send + Sync + 'static>>,
}

impl TransportCallbacks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire the `on_connected` event for all registered handlers.
    pub fn fire_connected(&self, serial: &str, origin: &DeviceOrigin) {
        for cb in &self.on_connected {
            cb(serial, origin);
        }
    }

    /// Fire the `on_disconnected` event for all registered handlers.
    pub fn fire_disconnected(&self, serial: &str) {
        for cb in &self.on_disconnected {
            cb(serial);
        }
    }

    /// Fire the `on_state_changed` event for all registered handlers.
    pub fn fire_state_changed(&self, serial: &str, old: DeviceState, new: DeviceState) {
        for cb in &self.on_state_changed {
            cb(serial, old, new);
        }
    }
}

// ---------------------------------------------------------------------------
// Transport Manager — extends TransportRegistry with lifecycle management
// ---------------------------------------------------------------------------

/// Wraps a `TransportRegistry` with event notifications and lifecycle helpers.
///
/// This is the primary interface for transport lifecycle management in the
/// ADB server.  It owns the registry (via `Arc<Mutex<>>`) and the callback
/// set, and provides methods that fire events as side effects.
pub(crate) struct TransportManager {
    pub registry: Arc<Mutex<TransportRegistry>>,
    pub callbacks: Arc<TransportCallbacks>,
}

impl TransportManager {
    /// Create a new `TransportManager` from an existing registry Arc.
    pub fn from_registry(registry: Arc<Mutex<TransportRegistry>>) -> Self {
        Self {
            registry,
            callbacks: Arc::new(TransportCallbacks::new()),
        }
    }

    /// Create a new `TransportManager` with a fresh registry.
    pub fn new() -> Self {
        Self::from_registry(Arc::new(Mutex::new(TransportRegistry::new())))
    }

    // -- Device registration / removal with event notification ---------------

    /// Register or update a TCP device in the registry and fire `on_connected`.
    pub fn register_tcp_device(&self, addr: SocketAddr, serial: String) {
        let mut reg = self.registry.lock().expect("registry lock");
        let is_new = reg.find_by_serial(&serial).is_none();
        reg.upsert_tcp_device(addr, serial.clone());
        if is_new {
            self.callbacks.fire_connected(&serial, &DeviceOrigin::Tcp { addr });
        }
    }

    /// Register a USB device and fire `on_connected`.
    #[cfg(feature = "usb")]
    pub fn register_usb_device(
        &self,
        serial: String,
        _bus_number: u8,
        _address: u8,
    ) {
        let mut reg = self.registry.lock().expect("registry lock");
        if reg.find_by_serial(&serial).is_some() {
            return;
        }
        let id = reg.next_id;
        reg.next_id += 1;
        reg.devices.push(crate::server::models::DeviceEntry {
            serial: serial.clone(),
            transport_id: id,
            state: DeviceState::Device,
            origin: DeviceOrigin::Usb,
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
        drop(reg);
        self.callbacks.fire_connected(&serial, &DeviceOrigin::Usb);
    }

    /// Remove a device from the registry and fire `on_disconnected`.
    /// Returns `true` if the device was actually removed.
    pub fn unregister_device(&self, serial: &str) -> bool {
        let mut reg = self.registry.lock().expect("registry lock");
        let removed = reg.remove_device(serial);
        if removed {
            self.callbacks.fire_disconnected(serial);
        }
        removed
    }

    /// Remove all TCP devices and fire `on_disconnected` for each.
    pub fn unregister_all_tcp_devices(&self) {
        let serials: Vec<String> = {
            let reg = self.registry.lock().expect("registry lock");
            reg.devices
                .iter()
                .filter(|d| matches!(d.origin, DeviceOrigin::Tcp { .. }))
                .map(|d| d.serial.clone())
                .collect()
        };
        {
            let mut reg = self.registry.lock().expect("registry lock");
            reg.remove_all_tcp_devices();
        }
        for s in &serials {
            self.callbacks.fire_disconnected(s);
        }
    }

    /// Update transport features and product/model/device from a CNXN banner.
    /// Fires `on_state_changed` if the state changes.
    ///
    /// AOSP CNXN banner format: `device::product=X;model=Y;device=Z;features=...`
    /// Properties are separated by `;` and may be prefixed with the device type
    /// (e.g. `device::product=X` instead of just `product=X`).  We split on
    /// `;` and then parse each segment by finding the first `=` separator
    /// and trimming any leading text (device type prefix) from the key.
    pub fn update_device_info(
        &self,
        serial: &str,
        banner: &str,
    ) {
        let mut reg = self.registry.lock().expect("registry lock");
        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
            let old_state = dev.state;
            dev.state = DeviceState::Device;
            dev.transport_features = Some(banner.to_string());
            for part in banner.trim().split(';') {
                // Each part may be: "product=X" or "device::product=X" etc.
                // Find the first '=' and extract the key (after any prefix)
                if let Some(eq_pos) = part.find('=') {
                    let key = &part[..eq_pos];
                    let val = &part[eq_pos + 1..];
                    // Trim any leading device type prefix (e.g. "device:" from "device:product")
                    let key_trimmed = key.rsplit(':').next().unwrap_or(key);
                    match key_trimmed {
                        "product" => dev.product = Some(val.to_string()),
                        "model" => dev.model = Some(val.to_string()),
                        "device" => dev.device_name = Some(val.to_string()),
                        _ => {} // features, etc. — ignored here
                    }
                }
            }
            if old_state != dev.state {
                self.callbacks.fire_state_changed(serial, old_state, dev.state);
            }
        }
    }

    /// Set transport state and fire event on change.
    pub fn set_device_state(&self, serial: &str, new_state: DeviceState) {
        let mut reg = self.registry.lock().expect("registry lock");
        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
            let old = dev.state;
            dev.state = new_state;
            if old != new_state {
                self.callbacks.fire_state_changed(serial, old, new_state);
            }
        }
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// connect_to_remote — connect to a remote ADB device (TCP)
// ---------------------------------------------------------------------------

/// Connect to a remote ADB daemon at `addr`, perform the CNXN handshake,
/// parse the device banner for features, and register the device in the
/// transport registry.
///
/// Mirrors AOSP `transport.cpp` → `connect_to_remote()`.
///
/// Returns the connected `Box<dyn Transport>` on success.
pub(crate) fn connect_to_remote(
    addr: SocketAddr,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<Box<dyn Transport>, String> {
    // 1. Open TCP connection
    let mut transport = Box::new(
        TcpTransport::connect_timeout(addr, TRANSPORT_CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot connect to device at {addr}: {e}"))?,
    );

    // 2. Send CNXN probe (AOSP: connect_to_remote sends A_CNXN)
    let probe = b"host::";
    let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
    transport
        .send_message(&cnxn, probe)
        .map_err(|e| format!("CNXN probe failed: {e}"))?;

    // 3. Await CNXN response
    let (resp_hdr, payload) = transport
        .recv_message()
        .map_err(|e| format!("CNXN response failed: {e}"))?;

    if resp_hdr.command != A_CNXN {
        return Err(format!(
            "expected A_CNXN from adbd at {addr}, got cmd={:#010x}",
            resp_hdr.command
        ));
    }

    // 4. Parse banner for features / product / model / device
    let serial = addr.to_string();
    if !payload.is_empty() {
        let banner = String::from_utf8_lossy(&payload);
        {
            let mut reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
            reg.upsert_tcp_device(addr, serial.clone());
            if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
                dev.transport_features = Some(banner.to_string());
                // Parse CNXN banner properties (e.g. "device::product=X;model=Y;device=Z")
                for part in banner.trim().split(';') {
                    if let Some(eq_pos) = part.find('=') {
                        let key = &part[..eq_pos];
                        let val = &part[eq_pos + 1..];
                        let key_trimmed = key.rsplit(':').next().unwrap_or(key);
                        match key_trimmed {
                            "product" => dev.product = Some(val.to_string()),
                            "model" => dev.model = Some(val.to_string()),
                            "device" => dev.device_name = Some(val.to_string()),
                            _ => {}
                        }
                    }
                }
            }
        }
    } else {
        let mut reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
        reg.upsert_tcp_device(addr, serial);
    }

    eprintln!("[adb-server] Connected to {addr}");
    Ok(transport)
}

// ---------------------------------------------------------------------------
// connect_usb_device — open and fully authenticate a USB ADB device
// ---------------------------------------------------------------------------

/// Open a USB ADB device, perform the full AUTH/CNXN handshake (RSA
/// SIGNATURE + RSAKEY), and register the device in the transport registry.
///
/// Mirrors AOSP USB transport connection logic in `transport_usb.cpp`.
///
/// Only available with `--features usb`.
#[cfg(feature = "usb")]
pub(crate) fn connect_usb_device(
    serial: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<Box<dyn Transport>, String> {
    use adb_protocol::{A_AUTH, A_AUTH_TOKEN};

    // 1. Open USB device
    let usb_dev = UsbfsAdbDevice::open_by_serial(serial)
        .map_err(|e| format!("cannot open USB device '{serial}': {e}"))?;
    let transport = UsbTransportAdapter::new(usb_dev);
    let mut t: Box<dyn Transport> = Box::new(transport);

    // 2. Load ADB host auth key (same pattern as models.rs ensure_usb_auth)
    let auth = crate::client::auth::default_auth();

    // 3. Perform AUTH/CNXN handshake
    let cnxn_payload = b"host::";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

    t.send_message(&cnxn_hdr, cnxn_payload)
        .map_err(|e| format!("CNXN send failed: {e}"))?;

    let (mut resp_hdr, mut payload) = t
        .recv_message()
        .map_err(|e| format!("CNXN recv failed: {e}"))?;

    let mut sent_signature = false;
    let mut sent_public_key = false;

    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("unsupported AUTH request type: {}", resp_hdr.arg0));
        }
        if payload.len() != 20 {
            return Err(format!(
                "invalid ADB AUTH token length: {} (expected 20)",
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
            return Err(
                "adbd rejected the ADB RSA key after signature and public-key exchange"
                    .to_string(),
            );
        };

        t.send_message(&auth_hdr, &auth_payload)
            .map_err(|e| format!("AUTH send failed: {e}"))?;

        (resp_hdr, payload) = t
            .recv_message()
            .map_err(|e| format!("AUTH recv failed: {e}"))?;
    }

    if resp_hdr.command != A_CNXN {
        return Err(format!(
            "expected A_CNXN after AUTH, got cmd={:#010x}",
            resp_hdr.command
        ));
    }

    // 4. Parse CNXN banner for features
    let banner = String::from_utf8_lossy(&payload);
    {
        let mut reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
            dev.state = DeviceState::Device;
            dev.transport_features = Some(banner.to_string());
            // Parse CNXN banner properties (e.g. "device::product=X;model=Y;device=Z")
            for part in banner.trim().split(';') {
                if let Some(eq_pos) = part.find('=') {
                    let key = &part[..eq_pos];
                    let val = &part[eq_pos + 1..];
                    let key_trimmed = key.rsplit(':').next().unwrap_or(key);
                    match key_trimmed {
                        "product" => dev.product = Some(val.to_string()),
                        "model" => dev.model = Some(val.to_string()),
                        "device" => dev.device_name = Some(val.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }

    // 5. Persist public key on Android so subsequent SIGNATURE-only auth works
    #[cfg(target_os = "android")]
    if sent_public_key {
        let _ = crate::client::auth::persist_adb_pubkey(auth);
    }

    eprintln!("[adb-server] USB device '{serial}' authenticated");
    Ok(t)
}

// ---------------------------------------------------------------------------
// acquire_transport — resolve a transport by serial or transport-id
// ---------------------------------------------------------------------------

/// Resolve a device by serial and return its transport origin for bridging.
///
/// This is a lightweight lookup — it does **not** open a new USB/TCP
/// connection; callers should first call `connect_to_remote` or
/// `connect_usb_device` as appropriate, then use this to find the entry.
///
/// Mirrors AOSP `acquire_one_transport()`.
pub(crate) fn acquire_transport(
    serial: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(DeviceEntry, DeviceOrigin), String> {
    let reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
    let dev = reg
        .find_by_serial(serial)
        .ok_or_else(|| format!("device '{serial}' not found"))?;

    if !crate::server::models::is_usable_state(dev.state) {
        return Err(format!(
            "device '{serial}' is in state {:?} (not usable)",
            dev.state
        ));
    }

    Ok((dev.clone(), dev.origin))
}

/// Resolve any usable device, preferring TCP over USB (matching AOSP
/// behavior where the most recently connected transport wins).
pub(crate) fn acquire_any_transport(
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(DeviceEntry, DeviceOrigin), String> {
    let reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
    let dev = reg
        .find_any_device()
        .ok_or_else(|| "no devices available".to_string())?;
    Ok((dev.clone(), dev.origin))
}

/// Resolve a device by transport ID.
pub(crate) fn acquire_transport_by_id(
    tid: u64,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(DeviceEntry, DeviceOrigin), String> {
    let reg = registry.lock().map_err(|e| format!("registry lock: {e}"))?;
    let dev = reg
        .find_by_transport_id(tid)
        .ok_or_else(|| format!("transport id {tid} not found"))?;

    if !crate::server::models::is_usable_state(dev.state) {
        return Err(format!(
            "transport id {tid} is in state {:?} (not usable)",
            dev.state
        ));
    }

    Ok((dev.clone(), dev.origin))
}

// ---------------------------------------------------------------------------
// Helper: establish a raw transport by origin (used by bridge)
// ---------------------------------------------------------------------------

/// Open a raw `Box<dyn Transport>` to the device matching `origin`.
///
/// - For `DeviceOrigin::Tcp { addr }` — connects TCP and returns
///   `TcpTransport`.
/// - For `DeviceOrigin::Usb` — opens USB device by serial (requires `usb`
///   feature) and returns a `UsbTransportAdapter`.
///
/// **Does NOT** perform AUTH/CNXN — assumes the caller either already did it
/// (TCP connect_to_remote) or will do it (USB within `bridge_to_device`).
pub(crate) fn open_transport_by_origin(
    origin: &DeviceOrigin,
    serial: &str,
) -> Result<Box<dyn Transport>, String> {
    match *origin {
        DeviceOrigin::Tcp { addr } => {
            let t = TcpTransport::connect_timeout(addr, TRANSPORT_CONNECT_TIMEOUT)
                .map_err(|e| format!("cannot connect to device at {addr}: {e}"))?;
            Ok(Box::new(t))
        }
        DeviceOrigin::Usb => {
            #[cfg(feature = "usb")]
            {
                let usb_dev = UsbfsAdbDevice::open_by_serial(serial)
                    .map_err(|e| format!("cannot open USB device '{serial}': {e}"))?;
                let transport = UsbTransportAdapter::new(usb_dev);
                Ok(Box::new(transport) as Box<dyn Transport>)
            }
            #[cfg(not(feature = "usb"))]
            {
                Err("USB transport not supported (compile with --features usb)".to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Refresh USB devices (delegates to TransportRegistry)
// ---------------------------------------------------------------------------

/// Refresh the list of USB devices in the registry by re-enumerating
/// USB bus.  Fires `on_connected` for newly discovered devices and
/// `on_disconnected` for removed ones (via `TransportCallbacks`).
#[cfg(feature = "usb")]
pub(crate) fn refresh_usb_devices(manager: &TransportManager) {
    let candidates = match UsbfsAdbDevice::enumerate() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[adb-server] USB enumeration error: {e}");
            return;
        }
    };

    // Collect serials of currently-known USB devices
    let before: std::collections::HashSet<String> = {
        let reg = manager.registry.lock().expect("registry lock");
        reg.devices
            .iter()
            .filter(|d| matches!(d.origin, DeviceOrigin::Usb))
            .map(|d| d.serial.clone())
            .collect()
    };

    // Collect serials of devices seen in this enumeration
    let mut now: std::collections::HashSet<String> = std::collections::HashSet::new();

    for cand in &candidates {
        let serial = cand
            .serial
            .clone()
            .unwrap_or_else(|| format!("{:03}{:03}", cand.bus_number, cand.address));
        now.insert(serial.clone());

        if !before.contains(&serial) {
            // New device: add to registry and fire connected
            {
                let mut reg = manager.registry.lock().expect("registry lock");
                let id = reg.next_id;
                reg.next_id += 1;
                reg.devices.push(crate::server::models::DeviceEntry {
                    serial: serial.clone(),
                    transport_id: id,
                    state: DeviceState::Device,
                    origin: DeviceOrigin::Usb,
                    product: None,
                    model: None,
                    device_name: None,
                    transport_features: None,
                });
            }
            manager.callbacks.fire_connected(&serial, &DeviceOrigin::Usb);
        }
    }

    // Find USB devices that disappeared
    let removed: Vec<String> = before.difference(&now).cloned().collect();

    // Fire disconnected events (without holding the lock)
    for s in &removed {
        manager.callbacks.fire_disconnected(s);
    }

    // Remove disappeared devices from registry
    {
        let mut reg = manager.registry.lock().expect("registry lock");
        // Need to remove in a way that doesn't borrow `reg` in the closure
        let mut i = 0;
        while i < reg.devices.len() {
            let is_usb = matches!(reg.devices[i].origin, DeviceOrigin::Usb);
            let should_remove = is_usb && !now.contains(&reg.devices[i].serial);
            if should_remove {
                reg.devices.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::models::DeviceOrigin;

    #[test]
    fn test_transport_callbacks_new() {
        let cbs = TransportCallbacks::new();
        assert!(cbs.on_connected.is_empty());
        assert!(cbs.on_disconnected.is_empty());
        assert!(cbs.on_state_changed.is_empty());
    }

    #[test]
    fn test_transport_manager_new() {
        let mgr = TransportManager::new();
        let reg = mgr.registry.lock().unwrap();
        assert!(reg.devices.is_empty());
        assert_eq!(reg.next_id, 1);
    }

    #[test]
    fn test_transport_callbacks_fire() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let connected_count = Arc::new(AtomicUsize::new(0));
        let disconnected_count = Arc::new(AtomicUsize::new(0));
        let state_changed_count = Arc::new(AtomicUsize::new(0));

        let cbs = TransportCallbacks {
            on_connected: vec![{
                let c = Arc::clone(&connected_count);
                Box::new(move |_serial: &str, _origin: &DeviceOrigin| {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            }],
            on_disconnected: vec![{
                let c = Arc::clone(&disconnected_count);
                Box::new(move |_serial: &str| {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            }],
            on_state_changed: vec![{
                let c = Arc::clone(&state_changed_count);
                Box::new(move |_serial: &str, _old: DeviceState, _new: DeviceState| {
                    c.fetch_add(1, Ordering::SeqCst);
                })
            }],
        };

        cbs.fire_connected("test-serial", &DeviceOrigin::Usb);
        cbs.fire_disconnected("test-serial");
        cbs.fire_state_changed("test-serial", DeviceState::Offline, DeviceState::Device);

        assert_eq!(connected_count.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_count.load(Ordering::SeqCst), 1);
        assert_eq!(state_changed_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_acquire_transport_not_found() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let result = acquire_transport("nonexistent", &registry);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_acquire_transport_offline() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        {
            let mut reg = registry.lock().unwrap();
            reg.devices.push(crate::server::models::DeviceEntry {
                serial: "test".to_string(),
                transport_id: 1,
                state: DeviceState::Offline,
                origin: DeviceOrigin::Usb,
                product: None,
                model: None,
                device_name: None,
                transport_features: None,
            });
        }
        let result = acquire_transport("test", &registry);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not usable"));
    }

    #[test]
    fn test_acquire_any_transport_none() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let result = acquire_any_transport(&registry);
        assert!(result.is_err());
    }

    #[test]
    fn test_acquire_transport_by_id() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        {
            let mut reg = registry.lock().unwrap();
            reg.devices.push(crate::server::models::DeviceEntry {
                serial: "test".to_string(),
                transport_id: 42,
                state: DeviceState::Device,
                origin: DeviceOrigin::Usb,
                product: None,
                model: None,
                device_name: None,
                transport_features: None,
            });
        }
        let (dev, _) = acquire_transport_by_id(42, &registry).unwrap();
        assert_eq!(dev.serial, "test");

        let result = acquire_transport_by_id(999, &registry);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_unregister_device() {
        let mgr = TransportManager::new();
        let addr = "192.168.1.100:5555".parse::<SocketAddr>().unwrap();

        mgr.register_tcp_device(addr, "192.168.1.100:5555".to_string());
        {
            let reg = mgr.registry.lock().unwrap();
            assert_eq!(reg.devices.len(), 1);
            assert_eq!(reg.devices[0].serial, "192.168.1.100:5555");
        }

        assert!(mgr.unregister_device("192.168.1.100:5555"));
        {
            let reg = mgr.registry.lock().unwrap();
            assert!(reg.devices.is_empty());
        }

        // Double unregister should return false
        assert!(!mgr.unregister_device("192.168.1.100:5555"));
    }

    #[test]
    fn test_update_device_info() {
        let mgr = TransportManager::new();
        let addr = "10.0.0.1:5555".parse::<SocketAddr>().unwrap();
        mgr.register_tcp_device(addr, "10.0.0.1:5555".to_string());

        mgr.update_device_info(
            "10.0.0.1:5555",
            "device::product=Pixel_6;model=Pixel_6_Pro;device=oriole;features=shell_v2",
        );

        let reg = mgr.registry.lock().unwrap();
        let dev = reg.find_by_serial("10.0.0.1:5555").unwrap();
        assert_eq!(dev.state, DeviceState::Device);
        assert_eq!(dev.product.as_deref(), Some("Pixel_6"));
        assert_eq!(dev.model.as_deref(), Some("Pixel_6_Pro"));
        assert_eq!(dev.device_name.as_deref(), Some("oriole"));
        assert!(dev
            .transport_features
            .as_deref()
            .unwrap()
            .contains("features=shell_v2"));
    }

    #[test]
    fn test_unregister_all_tcp_devices() {
        let mgr = TransportManager::new();
        let addr1 = "10.0.0.1:5555".parse::<SocketAddr>().unwrap();
        let addr2 = "10.0.0.2:5555".parse::<SocketAddr>().unwrap();
        mgr.register_tcp_device(addr1, "10.0.0.1:5555".to_string());
        mgr.register_tcp_device(addr2, "10.0.0.2:5555".to_string());

        {
            let reg = mgr.registry.lock().unwrap();
            assert_eq!(reg.devices.len(), 2);
        }

        mgr.unregister_all_tcp_devices();
        {
            let reg = mgr.registry.lock().unwrap();
            assert!(reg.devices.is_empty());
        }
    }

    #[test]
    fn test_open_transport_by_origin_usb_no_feature() {
        // When the `usb` feature is not enabled, this should return an error.
        let origin = DeviceOrigin::Usb;
        let result = open_transport_by_origin(&origin, "test-serial");
        #[cfg(not(feature = "usb"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_manager_default() {
        let mgr: TransportManager = Default::default();
        let reg = mgr.registry.lock().unwrap();
        // Default registry calls refresh_usb_devices in new(), which is a no-op
        // on non-Android or no-USB-bus systems, but the registry is valid.
        assert!(reg.next_id >= 1);
    }
}
