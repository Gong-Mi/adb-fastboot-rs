//! ADB server-side mDNS module — mDNS service management, discovery, and
//! advertisement integration with the transport registry.
//!
//! Maps to AOSP `vendor/adb/adb_mdns.cpp` (server-side mDNS module).
//!
//! This module provides:
//! - [`AdbMdns`] — manages mDNS service lifecycle (discovery + advertisement)
//! - [`start_discovery`] — background thread discovering ADB mDNS services
//! - [`stop_discovery`] — stops the discovery background thread
//! - [`register_adb_mdns_services`] — advertise local ADB services on mDNS
//! - Device state change callbacks for transport registry integration
//!
//! On the HOST side (the ADB server), `AdbMdns` discovers remote ADB devices
//! on the network via mDNS queries and automatically integrates them into
//! the [`TransportRegistry`].
//!
//! On Android (device-side), it registers/publishes mDNS services so that
//! ADB clients on the network can discover this device.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use adb_protocol::mdns::{AdbMdnsService, AdbMdnsServiceType, parse_txt_record};

use crate::server::models::TransportRegistry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default mDNS multicast address and port.
const MDNS_ADDR: &str = "224.0.0.251:5353";
/// Discovery query timeout (per round).
const MDNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Default polling interval for the background discovery thread.
const MDNS_DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);
/// Max mDNS packet size (RFC 6762).
const MDNS_MAX_PACKET: usize = 9000;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during server-side mDNS operations.
#[derive(Debug, thiserror::Error)]
pub enum AdbMdnsError {
    #[error("mDNS socket error: {0}")]
    Socket(String),
    #[error("mDNS send error: {0}")]
    Send(String),
    #[error("mDNS recv error: {0}")]
    Recv(String),
    #[error("mDNS parse error: {0}")]
    Parse(String),
    #[error("mDNS not running")]
    NotRunning,
    #[error("mDNS already running")]
    AlreadyRunning,
}

// ---------------------------------------------------------------------------
// mDNS Service Advertisement — responder registration
// ---------------------------------------------------------------------------

/// A registered mDNS service advertisement.
///
/// AOSP `vendor/adb/adb_mdns.cpp` registers services by calling into
/// the platform mDNS responder (e.g. `android.net.wifi` APIs on Android,
/// or Avahi/libdns_sd on desktop).  This Rust implementation provides
/// a lightweight self-contained responder for platforms without a system
/// mDNS daemon, or wraps the platform mechanism.
#[derive(Debug, Clone)]
pub(crate) struct AdbMdnsRegistration {
    /// The service type being registered.
    pub service_type: AdbMdnsServiceType,
    /// The service instance name (e.g. `adb-HOSTNAME-_adb._tcp`).
    pub instance_name: String,
    /// The port the ADB server is listening on for this service type.
    pub port: u16,
    /// Optional TXT record key-value pairs.
    pub txt_records: HashMap<String, String>,
    /// Whether this registration is currently active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// mDNS Device Discovery Cache
// ---------------------------------------------------------------------------

/// Internal cache of mDNS-discovered devices, keyed by a composite key
/// `{instance_name}:{service_type:?}`.
///
/// Used to detect when a device appears for the first time or disappears,
/// so we can fire appropriate callbacks and update the `TransportRegistry`.
#[derive(Debug, Clone)]
struct DiscoveredDeviceEntry {
    service: AdbMdnsService,
    /// When this device was first discovered (for TTL-like expiry checks).
    first_seen: Instant,
    /// When this device was last seen (for freshness checks).
    last_seen: Instant,
}

// ---------------------------------------------------------------------------
// AdbMdnsCallbacks — mDNS lifecycle event hooks
// ---------------------------------------------------------------------------

/// Collection of event hooks for mDNS-discovered device lifecycle.
///
/// All callbacks are fire-and-forget: errors inside a single callback do not
/// prevent later callbacks from running.
#[derive(Default)]
pub(crate) struct AdbMdnsCallbacks {
    /// Fired when a new ADB mDNS service is discovered on the network.
    pub on_device_discovered: Vec<Box<dyn Fn(&AdbMdnsService) + Send + Sync + 'static>>,
    /// Fired when an mDNS service is lost (no longer responding).
    pub on_device_lost: Vec<Box<dyn Fn(&str, &AdbMdnsServiceType) + Send + Sync + 'static>>,
    /// Fired when an mDNS service's information changes (e.g. address or TXT records).
    pub on_device_updated: Vec<Box<dyn Fn(&AdbMdnsService, &AdbMdnsService) + Send + Sync + 'static>>,
}

impl AdbMdnsCallbacks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire the `on_device_discovered` event for all registered handlers.
    pub fn fire_discovered(&self, service: &AdbMdnsService) {
        for cb in &self.on_device_discovered {
            cb(service);
        }
    }

    /// Fire the `on_device_lost` event for all registered handlers.
    pub fn fire_lost(&self, instance_name: &str, service_type: &AdbMdnsServiceType) {
        for cb in &self.on_device_lost {
            cb(instance_name, service_type);
        }
    }

    /// Fire the `on_device_updated` event for all registered handlers.
    pub fn fire_updated(&self, old: &AdbMdnsService, new: &AdbMdnsService) {
        for cb in &self.on_device_updated {
            cb(old, new);
        }
    }
}

// ---------------------------------------------------------------------------
// AdbMdns — main server-side mDNS manager
// ---------------------------------------------------------------------------

/// Manages mDNS service lifecycle in the ADB server.
///
/// This struct ties together:
/// 1. **Device discovery** — runs a background thread that periodically queries
///    for `_adb._tcp` and `_adb-tls-connect._tcp` services on the LAN, resolves
///    them, and adds/removes devices from the [`TransportRegistry`].
/// 2. **Service advertisement** — registers local ADB services with the mDNS
///    responder so clients on the network can discover this device.
/// 3. **Event callbacks** — fires [`AdbMdnsCallbacks`] on device connect /
///    disconnect / update for integration with [`TransportManager`].
///
/// # AOSP equivalent
///
/// `vendor/adb/adb_mdns.cpp` — `AdbMdns` class.
pub(crate) struct AdbMdns {
    /// Whether the background discovery thread is running.
    running: Arc<AtomicBool>,
    /// The background discovery thread handle (if started).
    discovery_thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// The transport registry for discovered devices.
    registry: Arc<Mutex<TransportRegistry>>,
    /// Registered mDNS advertisements.
    registrations: Mutex<Vec<AdbMdnsRegistration>>,
    /// The internal discovery cache (tracking known devices).
    discovered: Mutex<HashMap<String, DiscoveredDeviceEntry>>,
    /// Event callbacks.
    callbacks: Arc<AdbMdnsCallbacks>,
}

impl AdbMdns {
    /// Create a new `AdbMdns` instance tied to the given transport registry.
    pub fn new(registry: Arc<Mutex<TransportRegistry>>) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            discovery_thread: Mutex::new(None),
            registry,
            registrations: Mutex::new(Vec::new()),
            discovered: Mutex::new(HashMap::new()),
            callbacks: Arc::new(AdbMdnsCallbacks::new()),
        }
    }

    /// Access the callbacks for registering event hooks.
    pub fn callbacks(&self) -> &Arc<AdbMdnsCallbacks> {
        &self.callbacks
    }

    /// Register an ADB mDNS service for advertisement.
    ///
    /// This tells the mDNS responder to publish the given service so that
    /// clients on the network can discover it.
    pub fn register_service(&self, registration: AdbMdnsRegistration) -> Result<(), AdbMdnsError> {
        let mut regs = self.registrations.lock().map_err(|_| {
            AdbMdnsError::Socket("registrations lock poisoned".into())
        })?;
        regs.push(registration);
        Ok(())
    }

    /// Unregister an ADB mDNS service advertisement by instance name.
    pub fn unregister_service(&self, instance_name: &str) -> Result<bool, AdbMdnsError> {
        let mut regs = self.registrations.lock().map_err(|_| {
            AdbMdnsError::Socket("registrations lock poisoned".into())
        })?;
        let before = regs.len();
        regs.retain(|r| r.instance_name != instance_name);
        Ok(before != regs.len())
    }

    /// Start the background mDNS discovery loop.
    ///
    /// This spawns a thread that periodically:
    /// 1. Sends mDNS PTR queries for `_adb._tcp` and `_adb-tls-connect._tcp`.
    /// 2. Collects responses and resolves SRV + A/AAAA + TXT records.
    /// 3. Adds newly discovered devices to the [`TransportRegistry`].
    /// 4. Removes devices that have stopped responding.
    /// 5. Fires event callbacks for discovered/lost/updated devices.
    ///
    /// # AOSP equivalent
    ///
    /// `AdbMdns::StartDiscovery()` in `vendor/adb/adb_mdns.cpp`.
    pub fn start_discovery(&self) -> Result<(), AdbMdnsError> {
        if self.running.load(Ordering::Relaxed) {
            return Err(AdbMdnsError::AlreadyRunning);
        }

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let registry = Arc::clone(&self.registry);
        let callbacks = Arc::clone(&self.callbacks);
        let discovered_lock = Mutex::new(HashMap::<String, DiscoveredDeviceEntry>::new());

        let handle = thread::Builder::new()
            .name("adb-mdns-discovery".into())
            .spawn(move || {
                run_discovery_loop(
                    running,
                    registry,
                    callbacks,
                    &discovered_lock,
                );
            })
            .map_err(|e| AdbMdnsError::Socket(format!("spawn discovery thread: {e}")))?;

        *self.discovery_thread.lock().map_err(|_| {
            AdbMdnsError::Socket("discovery_thread lock poisoned".into())
        })? = Some(handle);

        eprintln!("[adb-mdns] mDNS discovery started");
        Ok(())
    }

    /// Stop the background mDNS discovery loop.
    ///
    /// Sets the running flag to `false`, which causes the discovery thread
    /// to exit on its next iteration.  Joins the thread.
    ///
    /// # AOSP equivalent
    ///
    /// `AdbMdns::StopDiscovery()` in `vendor/adb/adb_mdns.cpp`.
    pub fn stop_discovery(&self) -> Result<(), AdbMdnsError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(AdbMdnsError::NotRunning);
        }

        self.running.store(false, Ordering::Relaxed);

        // Join the discovery thread
        if let Some(handle) = self.discovery_thread.lock().map_err(|_| {
            AdbMdnsError::Socket("discovery_thread lock poisoned".into())
        })?.take() {
            let _ = handle.join();
        }

        eprintln!("[adb-mdns] mDNS discovery stopped");
        Ok(())
    }

    /// Check whether the discovery loop is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get the list of currently discovered ADB services.
    pub fn discovered_services(&self) -> Result<Vec<AdbMdnsService>, AdbMdnsError> {
        let disc = self.discovered.lock().map_err(|_| {
            AdbMdnsError::Socket("discovered lock poisoned".into())
        })?;
        Ok(disc.values().map(|e| e.service.clone()).collect())
    }

    /// Get a discovered service by its instance name.
    pub fn find_service_by_instance(
        &self,
        instance_name: &str,
    ) -> Result<Option<AdbMdnsService>, AdbMdnsError> {
        let disc = self.discovered.lock().map_err(|_| {
            AdbMdnsError::Socket("discovered lock poisoned".into())
        })?;
        Ok(disc.get(instance_name).map(|e| e.service.clone()))
    }

    /// Get a discovered service by its serial number.
    pub fn find_service_by_serial(
        &self,
        serial: &str,
    ) -> Result<Option<AdbMdnsService>, AdbMdnsError> {
        let disc = self.discovered.lock().map_err(|_| {
            AdbMdnsError::Socket("discovered lock poisoned".into())
        })?;
        Ok(disc.values().find_map(|e| {
            if e.service.device_serial().as_deref() == Some(serial) {
                Some(e.service.clone())
            } else {
                None
            }
        }))
    }
}

// ---------------------------------------------------------------------------
// Background Discovery Loop
// ---------------------------------------------------------------------------

/// The core mDNS discovery loop run in a background thread.
///
/// This function:
/// 1. Periodically sends mDNS PTR queries for ADB service types.
/// 2. Collects responses and resolves SRV + address + TXT records.
/// 3. Maintains a cache of known devices.
/// 4. Integrates changes into the [`TransportRegistry`].
/// 5. Fires [`AdbMdnsCallbacks`] for discovered/lost/updated devices.
fn run_discovery_loop(
    running: Arc<AtomicBool>,
    registry: Arc<Mutex<TransportRegistry>>,
    callbacks: Arc<AdbMdnsCallbacks>,
    discovered_lock: &Mutex<HashMap<String, DiscoveredDeviceEntry>>,
) {
    // Bind multicast socket once and reuse for the lifetime of the loop
    let socket = match bind_mdns_socket() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[adb-mdns] Failed to bind mDNS socket: {e}");
            return;
        }
    };

    // Service types to discover (classic + TLS-connect)
    let service_types = [
        AdbMdnsServiceType::Classic,
        AdbMdnsServiceType::TlsConnect,
    ];

    while running.load(Ordering::Relaxed) {
        let round_start = Instant::now();

        for &st in &service_types {
            let full_domain = st.full_domain();
            let query = build_ptr_query(full_domain);

            if let Err(e) = send_mdns_query(&socket, &query) {
                eprintln!("[adb-mdns] Failed to send query for {full_domain}: {e}");
                continue;
            }

            // Collect responses for this query round
            let mut discovered_this_round: Vec<AdbMdnsService> = Vec::new();
            let deadline = Instant::now() + MDNS_QUERY_TIMEOUT;
            let mut buf = vec![0u8; MDNS_MAX_PACKET];

            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let _ = socket.set_read_timeout(Some(remaining));

                match socket.recv_from(&mut buf) {
                    Ok((n, _src)) => {
                        if let Ok(parsed) = parse_mdns_response(&buf[..n], st) {
                            for svc in parsed {
                                let key = svc.instance_name.clone();
                                if !discovered_this_round.iter().any(|s| s.instance_name == key) {
                                    discovered_this_round.push(svc);
                                }
                            }
                        }
                        // Non-ADB responses are silently ignored.
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        eprintln!("[adb-mdns] recv error: {e}");
                        break;
                    }
                }
            }

            // Resolve each discovered service (SRV + address + TXT)
            let resolved_services: Vec<AdbMdnsService> = discovered_this_round
                .into_iter()
                .filter_map(|svc| {
                    // Skip TLS-pairing services — they are not transports
                    if svc.service_type == AdbMdnsServiceType::TlsPairing {
                        return None;
                    }

                    match resolve_service_on_socket(&socket, &svc, MDNS_QUERY_TIMEOUT) {
                        Ok(resolved) => {
                            if resolved.addresses.is_empty() {
                                // Use unresolved service as-is (address may be in PTR response)
                                Some(svc)
                            } else {
                                Some(resolved)
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[adb-mdns] Failed to resolve {}: {e}",
                                svc.instance_name
                            );
                            // Return the service with whatever info we have
                            Some(svc)
                        }
                    }
                })
                .collect();

            // Sync discovered services with the cache and registry
            sync_discovered_services(
                &registry,
                &callbacks,
                discovered_lock,
                &resolved_services,
            );
        }

        // Sleep until the next discovery interval
        let elapsed = round_start.elapsed();
        let sleep_dur = MDNS_DISCOVERY_INTERVAL.saturating_sub(elapsed);
        if !sleep_dur.is_zero() {
            // Use a shorter wake interval so we can respond promptly to stop signal
            let wake_step = Duration::from_millis(200);
            let mut remaining_sleep = sleep_dur;
            while remaining_sleep > Duration::ZERO && running.load(Ordering::Relaxed) {
                let step = remaining_sleep.min(wake_step);
                thread::sleep(step);
                remaining_sleep = remaining_sleep.saturating_sub(step);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Service Discovery Synchronization
// ---------------------------------------------------------------------------

/// Synchronize the discovered-services cache with the transport registry.
///
/// Compares the current discovery round results against the cache, then:
/// - New services → add to cache, fire `on_device_discovered`, register in registry.
/// - Removed services → remove from cache, fire `on_device_lost`, unregister from registry.
/// - Updated services → update cache, fire `on_device_updated`, update registry.
fn sync_discovered_services(
    registry: &Arc<Mutex<TransportRegistry>>,
    callbacks: &AdbMdnsCallbacks,
    discovered_lock: &Mutex<HashMap<String, DiscoveredDeviceEntry>>,
    new_services: &[AdbMdnsService],
) {
    let mut cache = match discovered_lock.lock() {
        Ok(c) => c,
        Err(_) => return,
    };

    let now = Instant::now();

    // Build a set of instance names from the current discovery round
    let current_names: std::collections::HashSet<String> = new_services
        .iter()
        .map(|s| s.instance_name.clone())
        .collect();

    // --- 1. Process new and updated services ---
    for svc in new_services {
        let key = svc.instance_name.clone();

        let existing_entry = cache.get(&key).cloned();
        if let Some(existing) = existing_entry {
            // Service was previously known — check for updates
            let has_changed = service_has_changed(&existing.service, svc);
            if has_changed {
                let old = existing.service.clone();
                cache.insert(key, DiscoveredDeviceEntry {
                    service: svc.clone(),
                    first_seen: existing.first_seen,
                    last_seen: now,
                });
                callbacks.fire_updated(&old, svc);
                update_registry_device(registry, svc);
            } else {
                // Just update last_seen
                if let Some(entry) = cache.get_mut(&key) {
                    entry.last_seen = now;
                }
            }
        } else {
            // New service discovered
            let serial = svc.device_serial().unwrap_or_else(|| svc.instance_name.clone());

            eprintln!(
                "[adb-mdns] Discovered ADB device '{}' (type={:?}, port={}, serial={})",
                svc.instance_name, svc.service_type, svc.port, serial,
            );

            cache.insert(key, DiscoveredDeviceEntry {
                service: svc.clone(),
                first_seen: now,
                last_seen: now,
            });

            // Fire discovery callback
            callbacks.fire_discovered(svc);

            // Register in the transport registry
            update_registry_device(registry, svc);
        }
    }

    // --- 2. Process removed services (in cache but not in current round) ---
    let stale_keys: Vec<String> = cache
        .keys()
        .filter(|k| !current_names.contains(*k))
        .cloned()
        .collect();

    for key in &stale_keys {
        if let Some(entry) = cache.remove(key) {
            let serial = entry.service.device_serial()
                .unwrap_or_else(|| entry.service.instance_name.clone());

            eprintln!(
                "[adb-mdns] Lost ADB device '{}' (serial={})",
                key, serial,
            );

            // Fire lost callback
            let svc_type = entry.service.service_type;
            callbacks.fire_lost(&entry.service.instance_name, &svc_type);

            // Remove from transport registry
            remove_registry_device(registry, &serial);
        }
    }
}

// ---------------------------------------------------------------------------
// Transport Registry Integration
// ---------------------------------------------------------------------------

/// Add or update a device in the transport registry based on mDNS discovery.
///
/// Uses the serial number from the mDNS service (or instance name as fallback)
/// and the first resolved IP address + port.
fn update_registry_device(
    registry: &Arc<Mutex<TransportRegistry>>,
    service: &AdbMdnsService,
) {
    let serial = service.device_serial().unwrap_or_else(|| {
        // Fallback: use the first address as serial if no serial in TXT records
        if let Some(addr) = service.addresses.first() {
            format!("{}:{}", addr, service.port)
        } else {
            service.instance_name.clone()
        }
    });

    // Use the first resolved address if available, otherwise construct
    // a placeholder that will be updated on the next discovery cycle
    let addr = match service.addresses.first() {
        Some(ip) => SocketAddr::new(*ip, service.port),
        None => {
            // Cannot determine address — skip registry update
            eprintln!(
                "[adb-mdns] No address resolved for '{}', deferring registration",
                service.instance_name,
            );
            return;
        }
    };

    let mut reg = match registry.lock() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[adb-mdns] Registry lock: {e}");
            return;
        }
    };

    // Check if device already exists in registry
    if let Some(existing) = reg.devices.iter_mut().find(|d| d.serial == serial) {
        // Update existing entry
        existing.state = crate::server::models::DeviceState::Device;
        if let Some(addr) = service.addresses.first() {
            existing.origin = crate::server::models::DeviceOrigin::Tcp {
                addr: SocketAddr::new(*addr, service.port),
            };
        }
    } else {
        // Add new device
        let new_id = reg.next_id;
        reg.next_id += 1;
        reg.devices.push(crate::server::models::DeviceEntry {
            transport_id: new_id,
            serial,
            state: crate::server::models::DeviceState::Device,
            origin: crate::server::models::DeviceOrigin::Tcp { addr },
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
    }
}

/// Remove a device from the transport registry by serial number.
fn remove_registry_device(
    registry: &Arc<Mutex<TransportRegistry>>,
    serial: &str,
) {
    let mut reg = match registry.lock() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[adb-mdns] Registry lock: {e}");
            return;
        }
    };
    reg.remove_device(serial);
}

// ---------------------------------------------------------------------------
// Service Change Detection
// ---------------------------------------------------------------------------

/// Check whether a service record has changed meaningfully.
///
/// Returns `true` if the address list, port, or TXT records differ.
fn service_has_changed(old: &AdbMdnsService, new: &AdbMdnsService) -> bool {
    if old.port != new.port {
        return true;
    }
    if old.addresses != new.addresses {
        return true;
    }
    if old.txt_records != new.txt_records {
        return true;
    }
    if old.host_name != new.host_name {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// mDNS Socket Helpers
// ---------------------------------------------------------------------------

/// Bind a UDP socket to the mDNS multicast address on a random port.
fn bind_mdns_socket() -> Result<UdpSocket, AdbMdnsError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| AdbMdnsError::Socket(format!("bind: {e}")))?;

    // Set read timeout for non-blocking recv
    socket.set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| AdbMdnsError::Socket(format!("set_read_timeout: {e}")))?;

    // Join the mDNS multicast group
    let mdns_addr: std::net::Ipv4Addr = "224.0.0.251".parse().unwrap();
    let local_addr: std::net::Ipv4Addr = "0.0.0.0".parse().unwrap();
    socket.join_multicast_v4(&mdns_addr, &local_addr)
        .map_err(|e| AdbMdnsError::Socket(format!("join_multicast: {e}")))?;

    Ok(socket)
}

/// Build a standard mDNS PTR query packet for the given service domain.
///
/// Format: [DNS header (id=0, flags=0x0000, QDCOUNT=1)]
///         [PTR query: <domain> type=12(PTR) class=1(IN)]
fn build_ptr_query(service_domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);

    // DNS header (12 bytes): id=0, flags=0x0000, QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // id
    pkt.extend_from_slice(&[0x00, 0x00]); // flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // QNAME: encode domain as length-prefixed labels
    encode_dns_name(&mut pkt, service_domain);

    // QTYPE (PTR = 12) + QCLASS (IN = 1, with QU bit = 0x8001 for unicast-response)
    pkt.extend_from_slice(&[0x00, 0x0C]); // PTR
    pkt.extend_from_slice(&[0x80, 0x01]); // IN + QU (unicast response requested)

    pkt
}

/// Build a standard mDNS SRV query packet.
fn build_srv_query(fqdn: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);

    pkt.extend_from_slice(&[0x00, 0x00]); // id
    pkt.extend_from_slice(&[0x00, 0x00]); // flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    encode_dns_name(&mut pkt, fqdn);

    // QTYPE (SRV = 33)
    pkt.extend_from_slice(&[0x00, 0x21]);
    // QCLASS (IN + QU)
    pkt.extend_from_slice(&[0x80, 0x01]);

    pkt
}

/// Build a standard mDNS A/AAAA query packet for a hostname.
fn build_address_query(hostname: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);

    pkt.extend_from_slice(&[0x00, 0x00]); // id
    pkt.extend_from_slice(&[0x00, 0x00]); // flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    encode_dns_name(&mut pkt, hostname);

    // QTYPE (A = 1, AAAA = 28)
    pkt.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS (IN + QU)
    pkt.extend_from_slice(&[0x80, 0x01]);

    pkt
}

/// Build a TXT query packet for a service instance.
fn build_txt_query(fqdn: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);

    pkt.extend_from_slice(&[0x00, 0x00]); // id
    pkt.extend_from_slice(&[0x00, 0x00]); // flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    encode_dns_name(&mut pkt, fqdn);

    // QTYPE (TXT = 16)
    pkt.extend_from_slice(&[0x00, 0x10]);
    // QCLASS (IN + QU)
    pkt.extend_from_slice(&[0x80, 0x01]);

    pkt
}

/// Encode a DNS name as length-prefixed labels, terminated by a zero-length label.
fn encode_dns_name(buf: &mut Vec<u8>, name: &str) {
    let trimmed = name.trim_end_matches('.');
    for label in trimmed.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63) as u8; // max label length is 63
        buf.push(len);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root terminator
}

/// Send a raw mDNS query packet to the multicast address.
fn send_mdns_query(socket: &UdpSocket, query: &[u8]) -> Result<(), AdbMdnsError> {
    let mdns_addr: SocketAddr = MDNS_ADDR
        .parse()
        .map_err(|e| AdbMdnsError::Socket(format!("invalid mDNS addr: {e}")))?;
    socket
        .send_to(query, mdns_addr)
        .map_err(|e| AdbMdnsError::Send(e.to_string()))?;
    Ok(())
}

/// Send a unicast mDNS query to a specific address (for SRV resolution).
fn send_mdns_unicast(socket: &UdpSocket, query: &[u8], target: SocketAddr) -> Result<(), AdbMdnsError> {
    socket
        .send_to(query, target)
        .map_err(|e| AdbMdnsError::Send(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// mDNS Response Parsing
// ---------------------------------------------------------------------------

/// Parse an mDNS response packet and extract ADB service records of the given type.
fn parse_mdns_response(
    data: &[u8],
    service_type: AdbMdnsServiceType,
) -> Result<Vec<AdbMdnsService>, AdbMdnsError> {
    if data.len() < 12 {
        return Err(AdbMdnsError::Parse("packet too short".into()));
    }

    // Skip DNS header (12 bytes)
    let mut offset = 12usize;

    // Parse header counts
    let _qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    // Skip question section (we sent the query, we know what we asked for)
    for _ in 0.._qdcount {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // skip QTYPE + QCLASS
    }

    // Collect instance names from PTR records, and other records by type
    let mut instance_names: Vec<String> = Vec::new();
    let mut srv_records: HashMap<String, (u16, String)> = HashMap::new();   // instance -> (port, hostname)
    let mut address_records: HashMap<String, Vec<IpAddr>> = HashMap::new(); // hostname -> addresses
    let mut txt_records: HashMap<String, HashMap<String, String>> = HashMap::new(); // instance -> TXT KV

    let mut record_offset = offset;
    for _ in 0..ancount {
        if record_offset >= data.len() {
            break;
        }

        let (name, _) = skip_and_decode_dns_name(data, record_offset)?;
        let consumed_name = record_offset; // saved for length calc

        if record_offset + 12 > data.len() {
            break;
        }

        // Find type and class
        let mut rr_offset = skip_dns_name(data, record_offset)?;
        if rr_offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[rr_offset], data[rr_offset + 1]]);
        rr_offset += 2;
        let _rclass = u16::from_be_bytes([data[rr_offset], data[rr_offset + 1]]);
        rr_offset += 2;
        let _ttl = u32::from_be_bytes([data[rr_offset], data[rr_offset + 1], data[rr_offset + 2], data[rr_offset + 3]]);
        rr_offset += 4;
        let rdlen = u16::from_be_bytes([data[rr_offset], data[rr_offset + 1]]) as usize;
        rr_offset += 2;

        if rr_offset + rdlen > data.len() {
            break;
        }

        match rtype {
            0x000C => {
                // PTR record — points to instance name
                let instance_fqdn = decode_dns_name(data, rr_offset)?;
                let instance = instance_fqdn
                    .trim_end_matches('.')
                    .trim_end_matches(service_type.full_domain().trim_end_matches('.'))
                    .trim_end_matches('.')
                    .to_string();
                if !instance.is_empty() {
                    instance_names.push(instance);
                }
            }
            0x0021 => {
                // SRV record
                if rdlen >= 6 {
                    let _priority = u16::from_be_bytes([data[rr_offset], data[rr_offset + 1]]);
                    let _weight = u16::from_be_bytes([data[rr_offset + 2], data[rr_offset + 3]]);
                    let port = u16::from_be_bytes([data[rr_offset + 4], data[rr_offset + 5]]);
                    let hostname = decode_dns_name(data, rr_offset + 6)?;

                    let instance_fqdn = decode_dns_name(data, consumed_name)?;
                    let instance = instance_fqdn
                        .trim_end_matches('.')
                        .to_string();

                    srv_records.insert(instance, (port, hostname.trim_end_matches('.').to_string()));
                }
            }
            0x0001 | 0x001C => {
                // A (IPv4) or AAAA (IPv6)
                let hostname = name.trim_end_matches('.').to_string();
                let addr = if rtype == 0x0001 && rdlen == 4 {
                    Some(IpAddr::V4(std::net::Ipv4Addr::new(
                        data[rr_offset], data[rr_offset + 1],
                        data[rr_offset + 2], data[rr_offset + 3],
                    )))
                } else if rtype == 0x001C && rdlen == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[rr_offset..rr_offset + 16]);
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                } else {
                    None
                };
                if let Some(a) = addr {
                    address_records.entry(hostname).or_default().push(a);
                }
            }
            0x0010 => {
                // TXT record
                if let Ok(txt) = parse_txt_record(&data[rr_offset..rr_offset + rdlen]) {
                    let instance = decode_dns_name(data, consumed_name)?;
                    let instance = instance.trim_end_matches('.').to_string();
                    txt_records.insert(instance, txt);
                }
            }
            _ => {
                // Unknown type — skip
            }
        }

        // Advance past this RR
        record_offset = skip_dns_name(data, record_offset)?;
        record_offset += 10 + rdlen; // type(2) + class(2) + ttl(4) + rdlen(2) + rdata(rdlen)
    }

    // --- Build AdbMdnsService records from collected data ---
    let mut services: Vec<AdbMdnsService> = Vec::new();

    // First pass: create services from instance names (from PTR)
    for instance in &instance_names {
        let mut svc = AdbMdnsService::new(service_type, instance.clone(), 0);

        // Apply SRV data if available
        let instance_fqdn = format!("{}.{}", instance, service_type.full_domain());
        if let Some((port, hostname)) = srv_records.get(&instance_fqdn) {
            svc.port = *port;
            svc.host_name = Some(hostname.clone());

            // Apply address records by hostname
            if let Some(addrs) = address_records.get(hostname) {
                svc.addresses = addrs.clone();
            }
        }

        // Apply TXT records if available
        // The TXT record's owner name is often the instance FQDN, but sometimes the service FQDN
        if let Some(txt) = txt_records.get(&instance_fqdn) {
            svc.txt_records = txt.clone();
        } else if let Some(txt) = txt_records.get(service_type.full_domain().trim_end_matches('.')) {
            svc.txt_records = txt.clone();
        }

        services.push(svc);
    }

    // Second pass: if we found SRV records without PTR records, create services from them
    if instance_names.is_empty() {
        for (instance_fqdn, (port, hostname)) in &srv_records {
            // Extract instance name from FQDN by removing the service domain suffix
            let domain_suffix = service_type.full_domain().trim_end_matches('.');
            let instance = instance_fqdn
                .trim_end_matches('.')
                .trim_end_matches(domain_suffix)
                .trim_end_matches('.')
                .to_string();

            if instance.is_empty() {
                continue;
            }

            let mut svc = AdbMdnsService::new(service_type, instance, *port);
            svc.host_name = Some(hostname.clone());

            if let Some(addrs) = address_records.get(hostname) {
                svc.addresses = addrs.clone();
            }

            if let Some(txt) = txt_records.get(instance_fqdn) {
                svc.txt_records = txt.clone();
            }

            services.push(svc);
        }
    }

    Ok(services)
}

/// Resolve a service by sending SRV + address + TXT queries.
///
/// This takes an `AdbMdnsService` that was discovered via PTR query and
/// resolves its SRV, A/AAAA, and TXT records to get the full service info.
fn resolve_service_on_socket(
    socket: &UdpSocket,
    service: &AdbMdnsService,
    timeout: Duration,
) -> Result<AdbMdnsService, AdbMdnsError> {
    let domain = service.service_type.full_domain();
    let fqdn = format!("{}.{}", service.instance_name.trim_end_matches('.'), domain);

    // --- Send SRV query ---
    let srv_query = build_srv_query(&fqdn);
    send_mdns_query(socket, &srv_query)?;

    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; MDNS_MAX_PACKET];

    let mut result_port = 0u16;
    let mut result_hostname: Option<String> = None;
    let mut result_addresses: Vec<IpAddr> = Vec::new();
    let mut result_txt: HashMap<String, String> = HashMap::new();

    // Collect responses
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = socket.set_read_timeout(Some(remaining));

        match socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if let Ok(parsed) = parse_mdns_response(&buf[..n], service.service_type) {
                    for svc in parsed {
                        if svc.instance_name != service.instance_name
                            && !svc.instance_name.ends_with(&format!(".{}", domain.trim_end_matches('.')))
                        {
                            continue;
                        }

                        if svc.port > 0 {
                            result_port = svc.port;
                        }
                        if let Some(hn) = svc.host_name {
                            result_hostname = Some(hn);
                        }
                        if !svc.addresses.is_empty() {
                            result_addresses.extend(svc.addresses);
                        }
                        if !svc.txt_records.is_empty() {
                            result_txt.extend(svc.txt_records);
                        }
                    }
                }
                // Non-ADB responses are silently ignored.
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                return Err(AdbMdnsError::Recv(e.to_string()));
            }
        }
    }

    // If SRV gave us a hostname, resolve its address
    if let Some(hostname) = &result_hostname {
        // Send A and AAAA queries
        let a_query = build_address_query(hostname, 0x0001);
        let aaaa_query = build_address_query(hostname, 0x001C);
        let _ = send_mdns_unicast(socket, &a_query, MDNS_ADDR.parse::<SocketAddr>().unwrap());
        let _ = send_mdns_unicast(socket, &aaaa_query, MDNS_ADDR.parse::<SocketAddr>().unwrap());

        // Also send TXT query for the service
        let txt_query = build_txt_query(&fqdn);
        let _ = send_mdns_query(socket, &txt_query);

        let resolve_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < resolve_deadline && result_addresses.is_empty() {
            let remaining = resolve_deadline.saturating_duration_since(Instant::now());
            let _ = socket.set_read_timeout(Some(remaining));

            match socket.recv_from(&mut buf) {
                Ok((n, _src)) => {
                    if let Ok(parsed_services) = parse_mdns_response(&buf[..n], service.service_type) {
                        for svc in parsed_services {
                            let new_addrs: Vec<IpAddr> = svc.addresses
                                .into_iter()
                                .filter(|addr| {
                                    // Filter duplicates: accept addresses not already in result_addresses
                                    !result_addresses.contains(addr)
                                })
                                .collect();
                            if !new_addrs.is_empty() {
                                result_addresses.extend(new_addrs);
                            }
                            if !svc.txt_records.is_empty() {
                                result_txt.extend(svc.txt_records);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    // Build the resolved service
    let mut resolved = AdbMdnsService::new(
        service.service_type,
        service.instance_name.clone(),
        if result_port > 0 { result_port } else { service.port },
    );
    resolved.host_name = result_hostname;
    resolved.addresses = result_addresses;
    resolved.txt_records = result_txt;

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// DNS Name Helpers
// ---------------------------------------------------------------------------

/// Skip a DNS-encoded name (either normal labels or a pointer) and return the offset after it.
fn skip_dns_name(data: &[u8], mut offset: usize) -> Result<usize, AdbMdnsError> {
    loop {
        if offset >= data.len() {
            return Err(AdbMdnsError::Parse("offset past end of DNS name".into()));
        }
        let len = data[offset] as usize;
        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            return Ok(offset + 2);
        }
        if len == 0 {
            // Root terminator
            return Ok(offset + 1);
        }
        if offset + 1 + len > data.len() {
            return Err(AdbMdnsError::Parse("label extends past end of DNS name".into()));
        }
        offset += 1 + len;
    }
}

/// Skip a DNS-encoded name AND return the decoded string.
/// Returns (name_string, offset_after_name).
fn skip_and_decode_dns_name(data: &[u8], offset: usize) -> Result<(String, usize), AdbMdnsError> {
    let name = decode_dns_name(data, offset)?;
    let after = skip_dns_name(data, offset)?;
    Ok((name, after))
}

/// Decode a DNS name (length-prefixed labels), handling compression pointers.
fn decode_dns_name(data: &[u8], mut offset: usize) -> Result<String, AdbMdnsError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut _jumped = false;

    loop {
        if offset >= data.len() {
            return Err(AdbMdnsError::Parse("offset past end of DNS name".into()));
        }
        let len = data[offset] as usize;

        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes): (0xC0 << 8) | offset
            _jumped = true;
            let ptr = ((len as u16 & 0x3F) << 8) | data[offset + 1] as u16;
            offset = ptr as usize;
            continue;
        }

        if len == 0 {
            // Root terminator
            break;
        }

        if offset + 1 + len > data.len() {
            return Err(AdbMdnsError::Parse("label extends past end of DNS name".into()));
        }

        labels.push(&data[offset + 1..offset + 1 + len]);
        offset += 1 + len;
    }

    let name = labels
        .iter()
        .map(|l| std::str::from_utf8(l).unwrap_or(""))
        .collect::<Vec<&str>>()
        .join(".");
    Ok(name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dns_name() {
        let mut buf = Vec::new();
        encode_dns_name(&mut buf, "_adb._tcp.local.");
        assert_eq!(buf, b"\x04_adb\x04_tcp\x05local\x00");
    }

    #[test]
    fn test_encode_dns_name_extra_dot_handling() {
        let mut buf = Vec::new();
        encode_dns_name(&mut buf, "_adb-tls-connect._tcp.local.");
        assert_eq!(buf, b"\x10_adb-tls-connect\x04_tcp\x05local\x00");
    }

    #[test]
    fn test_decode_dns_name_simple() {
        let encoded = b"\x04_adb\x04_tcp\x05local\x00";
        let decoded = decode_dns_name(encoded, 0).unwrap();
        assert_eq!(decoded, "_adb._tcp.local");
    }

    #[test]
    fn test_decode_dns_name_with_compression() {
        // A basic self-referential compression test:
        // First label "hello" then a pointer back to it
        let encoded = b"\x05hello\x00\xc0\x00";
        let decoded = decode_dns_name(encoded, 0).unwrap();
        assert_eq!(decoded, "hello");

        // The second name at offset 7 pointing to offset 0
        let decoded2 = decode_dns_name(encoded, 7).unwrap();
        assert_eq!(decoded2, "hello");
    }

    #[test]
    fn test_build_ptr_query() {
        let query = build_ptr_query("_adb._tcp.local.");
        assert!(query.len() > 12);
        // Header: id=0, flags=0, QDCOUNT=1
        assert_eq!(&query[0..2], &[0x00, 0x00]);
        assert_eq!(&query[2..4], &[0x00, 0x00]);
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        // QTYPE=PTER, QCLASS=IN+QU
        let qtype_offset = query.len() - 4;
        assert_eq!(&query[qtype_offset..qtype_offset + 2], &[0x00, 0x0C]);
        assert_eq!(&query[qtype_offset + 2..qtype_offset + 4], &[0x80, 0x01]);
    }

    #[test]
    fn test_build_srv_query() {
        let query = build_srv_query("adb-DEVICE001-_adb-tls-connect._tcp.local.");
        assert!(query.len() > 12);
        // QTYPE=SRV
        let qtype_offset = query.len() - 4;
        assert_eq!(&query[qtype_offset..qtype_offset + 2], &[0x00, 0x21]);
        assert_eq!(&query[qtype_offset + 2..qtype_offset + 4], &[0x80, 0x01]);
    }

    #[test]
    fn test_build_address_query() {
        let query = build_address_query("hostname.local.", 0x0001);
        assert!(query.len() > 12);
        let qtype_offset = query.len() - 4;
        assert_eq!(&query[qtype_offset..qtype_offset + 2], &[0x00, 0x01]); // A
        assert_eq!(&query[qtype_offset + 2..qtype_offset + 4], &[0x80, 0x01]);
    }

    #[test]
    fn test_build_txt_query() {
        let query = build_txt_query("adb-TEST-_adb._tcp.local.");
        assert!(query.len() > 12);
        let qtype_offset = query.len() - 4;
        assert_eq!(&query[qtype_offset..qtype_offset + 2], &[0x00, 0x10]); // TXT
        assert_eq!(&query[qtype_offset + 2..qtype_offset + 4], &[0x80, 0x01]);
    }

    #[test]
    fn test_service_has_changed_different_port() {
        let mut old = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5555);
        let new = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5556);
        assert!(service_has_changed(&old, &new));

        old.port = 5556;
        assert!(!service_has_changed(&old, &new));
    }

    #[test]
    fn test_service_has_changed_different_addresses() {
        let mut old = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5555);
        let mut new = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5555);

        use std::net::Ipv4Addr;
        new.addresses.push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        assert!(service_has_changed(&old, &new));
        old.addresses.push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(!service_has_changed(&old, &new));
    }

    #[test]
    fn test_service_has_changed_different_txt_records() {
        let mut old = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5555);
        let mut new = AdbMdnsService::new(AdbMdnsServiceType::Classic, "test", 5555);

        new.txt_records.insert("serial".into(), "12345".into());
        assert!(service_has_changed(&old, &new));

        old.txt_records.insert("serial".into(), "12345".into());
        assert!(!service_has_changed(&old, &new));
    }

    #[test]
    fn test_adb_mdns_registration_creation() {
        let reg = AdbMdnsRegistration {
            service_type: AdbMdnsServiceType::TlsConnect,
            instance_name: "adb-MYDEVICE-_adb-tls-connect._tcp".into(),
            port: 5555,
            txt_records: [("serial".into(), "MYDEVICE".into())].into(),
            active: true,
        };

        assert_eq!(reg.service_type, AdbMdnsServiceType::TlsConnect);
        assert!(reg.active);
    }

    #[test]
    fn test_adb_mdns_callbacks_default() {
        let callbacks = AdbMdnsCallbacks::new();
        assert!(callbacks.on_device_discovered.is_empty());
        assert!(callbacks.on_device_lost.is_empty());
        assert!(callbacks.on_device_updated.is_empty());
    }

    #[test]
    fn test_parse_mdns_response_too_short() {
        let result = parse_mdns_response(&[0u8; 4], AdbMdnsServiceType::Classic);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("packet too short"));
    }

    #[test]
    fn test_skip_and_decode_dns_name_roundtrip() {
        let data = b"\x05hello\x05world\x00extra";
        let (name, after) = skip_and_decode_dns_name(data, 0).unwrap();
        assert_eq!(name, "hello.world");
        assert_eq!(after, 13); // 1+5 + 1+5 + 1 = 13
    }

    #[test]
    fn test_skip_dns_name_compression_pointer() {
        // Single byte 0xC0 followed by offset byte
        let data = b"\xC0\x0A";
        let after = skip_dns_name(data, 0).unwrap();
        assert_eq!(after, 2);
    }

    #[test]
    fn test_adb_mdns_error_display() {
        let err = AdbMdnsError::Socket("bind failed".into());
        assert_eq!(err.to_string(), "mDNS socket error: bind failed");

        let err = AdbMdnsError::NotRunning;
        assert_eq!(err.to_string(), "mDNS not running");

        let err = AdbMdnsError::AlreadyRunning;
        assert_eq!(err.to_string(), "mDNS already running");
    }

    #[test]
    fn test_adb_mdns_initial_state() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let mdns = AdbMdns::new(registry);
        assert!(!mdns.is_running());
    }

    #[test]
    fn test_adb_mdns_stop_when_not_running() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let mdns = AdbMdns::new(registry);
        assert!(mdns.stop_discovery().is_err());
    }

    #[test]
    fn test_adb_mdns_register_service() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let mdns = AdbMdns::new(registry);

        let reg = AdbMdnsRegistration {
            service_type: AdbMdnsServiceType::Classic,
            instance_name: "adb-TEST-_adb._tcp".into(),
            port: 5555,
            txt_records: HashMap::new(),
            active: true,
        };

        assert!(mdns.register_service(reg).is_ok());
    }

    #[test]
    fn test_adb_mdns_unregister_service() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let mdns = AdbMdns::new(registry);

        let reg = AdbMdnsRegistration {
            service_type: AdbMdnsServiceType::Classic,
            instance_name: "adb-TEST-_adb._tcp".into(),
            port: 5555,
            txt_records: HashMap::new(),
            active: true,
        };

        mdns.register_service(reg).unwrap();
        assert!(mdns.unregister_service("adb-TEST-_adb._tcp").unwrap());
        assert!(!mdns.unregister_service("nonexistent").unwrap());
    }
}
