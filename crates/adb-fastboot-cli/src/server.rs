//! ADB Server — pure Rust implementation.
//!
//! Listens on `127.0.0.1:5037`, handles ADB host services, manages a transport
//! registry (USB + TCP devices), and bridges client connections to devices.
//!
//! ## Protocol (AOSP compatible)
//!
//! 1. Client connects to `127.0.0.1:5037`
//! 2. Sends `{:04x}<command>` (4-byte hex ASCII length + payload)
//! 3. Server responds:
//!    - **OKAY** + `{:04x}<payload>` — success with data
//!    - **FAIL** + `{:04x}<error>` — failure
//!    - **OKAY** (no payload) — command acknowledged (e.g. `host:kill`)
//! 4. After `host:transport:serial` succeeds, the connection switches to
//!    binary ADB protocol mode (24-byte header + payload frames).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(feature = "usb")]
use inotify::{Inotify, WatchMask};

use adb_protocol::{
    AdbMessageHeader, ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_WRTE, MAX_PAYLOAD_V2,
};
#[cfg(feature = "usb")]
use adb_protocol::{Transport, TransportError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ADB_SERVER_PORT: u16 = 5037;
/// AOSP adb.h:71 `#define ADB_SERVER_VERSION 41` — host:version replies
/// with "%04x" of this decimal number (0x0029), NOT the protocol version.
const SERVER_VERSION: u32 = 41;
const POLL_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Device model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum DeviceState {
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
    fn as_str(&self) -> &'static str {
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
fn is_usable_state(state: DeviceState) -> bool {
    matches!(
        state,
        DeviceState::Device
            | DeviceState::Recovery
            | DeviceState::Sideload
            | DeviceState::Bootloader
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceOrigin {
    Usb,
    Tcp { addr: SocketAddr },
}

#[derive(Debug, Clone)]
struct DeviceEntry {
    serial: String,
    state: DeviceState,
    origin: DeviceOrigin,
    product: Option<String>,
    model: Option<String>,
    device_name: Option<String>,
    transport_features: Option<String>,
}

// ---------------------------------------------------------------------------
// Transport Registry
// ---------------------------------------------------------------------------

struct TransportRegistry {
    devices: Vec<DeviceEntry>,
    forwards: Vec<ForwardRule>,
    reverses: Vec<ReverseRule>,
}

#[derive(Debug, Clone)]
struct ForwardRule {
    serial: String,
    local: String,
    remote: String,
    active_flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct ReverseRule {
    serial: String,
    remote: String,
    local: String,
}

impl TransportRegistry {
    fn new() -> Self {
        let mut reg = Self {
            devices: Vec::new(),
            forwards: Vec::new(),
            reverses: Vec::new(),
        };
        reg.refresh_usb_devices();
        reg
    }

    fn refresh_usb_devices(&mut self) {
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

    fn list_devices(&self, verbose: bool) -> String {
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

    fn find_by_serial(&self, serial: &str) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| d.serial == serial)
    }

    fn find_any_device(&self) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| is_usable_state(d.state))
    }

    fn upsert_tcp_device(&mut self, addr: SocketAddr, serial: String) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.serial == serial) {
            existing.state = DeviceState::Device;
        } else {
            self.devices.push(DeviceEntry {
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

    fn remove_device(&mut self, serial: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.serial != serial);
        before != self.devices.len()
    }

    fn remove_all_tcp_devices(&mut self) {
        self.devices.retain(|d| matches!(d.origin, DeviceOrigin::Usb));
    }

    // -- Forwards -----------------------------------------------------------

    fn list_forwards(&self) -> String {
        if self.forwards.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for fw in &self.forwards {
            out.push_str(&format!("{} {} {}\n", fw.serial, fw.local, fw.remote));
        }
        out
    }

    fn add_forward(
        &mut self,
        registry_arc: &Arc<Mutex<TransportRegistry>>,
        local_spec: &str,
        remote_spec: &str,
        no_rebind: bool,
    ) -> Result<String, String> {
        let (bound_port, canonical_local, listener) =
            if local_spec.starts_with("tcp:") || local_spec.chars().all(|c| c.is_ascii_digit()) {
                let port_str = if local_spec.starts_with("tcp:") {
                    &local_spec["tcp:".len()..]
                } else {
                    local_spec
                };
                let requested_port: u16 = port_str
                    .parse()
                    .map_err(|_| format!("invalid port in local spec: {local_spec}"))?;
                let l = TcpListener::bind(format!("127.0.0.1:{requested_port}"))
                    .map_err(|e| format!("cannot bind listener for {local_spec}: {e}"))?;
                let p = l
                    .local_addr()
                    .map_err(|e| format!("cannot get local addr: {e}"))?
                    .port();
                (p, format!("tcp:{p}"), Some(l))
            } else {
                (0, local_spec.to_string(), None)
            };

        if no_rebind && self.forwards.iter().any(|f| f.local == canonical_local) {
            return Err(format!("forward '{canonical_local}' already exists"));
        }

        self.remove_forward(&canonical_local);

        let active_flag = Arc::new(AtomicBool::new(true));

        if let Some(listener) = listener {
            let active = Arc::clone(&active_flag);
            let remote_str = remote_spec.to_string();
            let reg_arc = Arc::clone(registry_arc);
            thread::spawn(move || {
                run_forward_listener(listener, active, remote_str, reg_arc);
            });
        }

        let serial = self
            .find_any_device()
            .map(|d| d.serial.clone())
            .unwrap_or_else(|| "127.0.0.1:5555".to_string());

        self.forwards.push(ForwardRule {
            serial,
            local: canonical_local,
            remote: remote_spec.to_string(),
            active_flag,
        });

        if local_spec == "tcp:0" || local_spec == "0" {
            Ok(bound_port.to_string())
        } else {
            Ok(String::new())
        }
    }

    fn remove_forward(&mut self, local: &str) -> bool {
        let canonical = if !local.starts_with("tcp:") && local.chars().all(|c| c.is_ascii_digit()) {
            format!("tcp:{local}")
        } else {
            local.to_string()
        };
        let mut removed = false;
        self.forwards.retain(|f| {
            if f.local == canonical || f.local == local {
                f.active_flag.store(false, Ordering::Relaxed);
                removed = true;
                false
            } else {
                true
            }
        });
        removed
    }

    fn remove_all_forwards(&mut self) {
        for f in &self.forwards {
            f.active_flag.store(false, Ordering::Relaxed);
        }
        self.forwards.clear();
    }

    // -- Reverses -----------------------------------------------------------

    fn list_reverses(&self) -> String {
        if self.reverses.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for r in &self.reverses {
            out.push_str(&format!("{} {} {}\n", r.serial, r.remote, r.local));
        }
        out
    }

    fn add_reverse(&mut self, remote: &str, local: &str, no_rebind: bool) -> Result<(), String> {
        if no_rebind && self.reverses.iter().any(|r| r.remote == remote) {
            return Err(format!("reverse forward '{remote}' already exists"));
        }
        self.reverses.retain(|r| r.remote != remote);
        let serial = self
            .find_any_device()
            .map(|d| d.serial.clone())
            .unwrap_or_else(|| "127.0.0.1:5555".to_string());
        self.reverses.push(ReverseRule {
            serial,
            remote: remote.to_string(),
            local: local.to_string(),
        });
        Ok(())
    }

    fn remove_reverse(&mut self, remote: &str) -> bool {
        let before = self.reverses.len();
        self.reverses.retain(|r| r.remote != remote);
        before != self.reverses.len()
    }

    fn remove_all_reverses(&mut self) {
        self.reverses.clear();
    }
}

// ---------------------------------------------------------------------------
// USB Device Watcher — inotify event-driven, fallback to polling
// ---------------------------------------------------------------------------

/// USB device watcher: monitors `/dev/bus/usb` via inotify for create/delete/move
/// events. Falls back to regular polling (`POLL_INTERVAL`) when inotify is
/// unavailable (e.g. Android restrictions, kernel without inotify, etc.).
#[cfg(feature = "usb")]
fn usb_device_watcher(registry: Arc<Mutex<TransportRegistry>>, running: Arc<AtomicBool>) {
    // Strategy 1: inotify on /dev/bus/usb — event-driven, no CPU waste
    match Inotify::init() {
        Ok(mut inotify) => {
            let watch_result = inotify.watches().add(
                "/dev/bus/usb",
                WatchMask::CREATE
                    | WatchMask::DELETE
                    | WatchMask::MOVED_FROM
                    | WatchMask::MOVED_TO,
            );
            match watch_result {
                Ok(_) => {
                    eprintln!(
                        "[adb-server] USB watcher: using inotify on /dev/bus/usb"
                    );
                    let mut buffer = [0u8; 4096];
                    while running.load(Ordering::Relaxed) {
                        match inotify.read_events_blocking(&mut buffer) {
                            Ok(events) => {
                                // Any observable change → re-enumerate
                                if events.count() > 0 {
                                    if let Ok(mut reg) = registry.lock() {
                                        reg.refresh_usb_devices();
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "[adb-server] USB watcher: inotify read error ({e}), retrying"
                                );
                                // Brief pause to avoid busy-loop on persistent errors
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                    return; // inotify path done
                }
                Err(e) => {
                    eprintln!(
                        "[adb-server] USB watcher: cannot watch /dev/bus/usb ({e})"
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("[adb-server] USB watcher: inotify init failed ({e})");
        }
    }

    // Strategy 2: fallback — periodic polling
    eprintln!(
        "[adb-server] USB watcher: falling back to polling every {:?}",
        POLL_INTERVAL
    );
    while running.load(Ordering::Relaxed) {
        thread::sleep(POLL_INTERVAL);
        if let Ok(mut reg) = registry.lock() {
            reg.refresh_usb_devices();
        }
    }
}

/// No-op when USB feature is not compiled in.
#[cfg(not(feature = "usb"))]
fn usb_device_watcher(_registry: Arc<Mutex<TransportRegistry>>, _running: Arc<AtomicBool>) {}

// ---------------------------------------------------------------------------
// ADB Server — public entry point
// ---------------------------------------------------------------------------

pub fn run_server() -> ! {
    run_server_on_port(ADB_SERVER_PORT);
    std::process::exit(0);
}

pub fn run_server_on_port(port: u16) {
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[adb-server] Cannot bind to 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    run_server_with_listener(listener);
}

pub fn run_server_with_listener(listener: TcpListener) {
    let running = Arc::new(AtomicBool::new(true));
    let registry = Arc::new(Mutex::new(TransportRegistry::new()));

    let port = listener.local_addr().map(|a| a.port()).unwrap_or(ADB_SERVER_PORT);
    eprintln!(
        "[adb-server] Listening on 127.0.0.1:{port} (version {:08x})",
        SERVER_VERSION
    );

    // USB device watcher: try inotify (event-driven), fall back to polling
    let reg_for_poll = Arc::clone(&registry);
    let running_poll = Arc::clone(&running);
    thread::spawn(move || {
        usb_device_watcher(reg_for_poll, running_poll);
    });

    // Accept loop
    listener.set_nonblocking(true).ok();
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                let reg = Arc::clone(&registry);
                let running_flag = Arc::clone(&running);
                thread::spawn(move || {
                    if let Err(e) = handle_client(client, &reg, &running_flag) {
                        eprintln!("[adb-server] Client error: {e}");
                    }
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[adb-server] Accept error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    eprintln!("[adb-server] Shut down.");
}

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

fn handle_client(
    mut client: TcpStream,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_nodelay(true);

    // AOSP smart-socket state: the transport selection does NOT end command
    // mode. After `host:transport:<serial>`, further hex-length commands are
    // parsed; host services keep dispatching, and a device service (e.g.
    // `root:`, `shell:id`) is converted into an A_OPEN on the selected
    // transport and the connection becomes a raw stream bridge
    // (sockets.cpp smart_socket_enqueue / connect_to_remote).
    let mut selected: Option<String> = None;

    loop {
        let mut len_buf = [0u8; 4];
        if client.read_exact(&mut len_buf).is_err() {
            return Ok(());
        }
        let len_str =
            std::str::from_utf8(&len_buf).map_err(|_| "Invalid UTF-8 in length prefix".to_string())?;
        let cmd_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| format!("Invalid hex length: {len_str}"))?;

        // AOSP sockets.cpp:800 — `len == 0 || len > MAX_PAYLOAD` kills the
        // smart socket; MAX_PAYLOAD is 1 MiB, not 4 KiB.
        if cmd_len == 0 || cmd_len > MAX_PAYLOAD_V2 as usize {
            return Err(format!("Invalid command length: {cmd_len}"));
        }

        let mut cmd_buf = vec![0u8; cmd_len];
        client
            .read_exact(&mut cmd_buf)
            .map_err(|e| format!("Failed to read command: {e}"))?;
        let cmd = String::from_utf8(cmd_buf)
            .map_err(|_| "Command is not valid UTF-8".to_string())?;

        if cmd.starts_with("host:") || cmd.starts_with("host-") {
            dispatch_host_service(&mut client, &cmd, registry, running)?;
            if let Some(serial) = transport_selection(&cmd, registry)? {
                selected = Some(serial);
            }
            continue;
        }

        // Device service (shell:, root:, tcpip:, sync:, reboot:, ...).
        match selected {
            Some(ref serial) => {
                let serial = serial.clone();
                return bridge_device_service(client, &serial, &cmd, registry);
            }
            None => {
                // AOSP: "device offline (no transport)" then close.
                let msg = b"device offline (no transport)";
                let len_hdr = format!("{:04x}", msg.len());
                let _ = client
                    .write_all(b"FAIL")
                    .and_then(|_| client.write_all(len_hdr.as_bytes()))
                    .and_then(|_| client.write_all(msg))
                    .and_then(|_| client.flush());
                return Ok(());
            }
        }
    }
}

/// If `cmd` was a transport-selection host service that just succeeded,
/// return the serial to bind for subsequent device services. Returns None
/// for every other host command.
fn transport_selection(cmd: &str, registry: &Arc<Mutex<TransportRegistry>>) -> Result<Option<String>, String> {
    if let Some(serial) = cmd.strip_prefix("host:transport:") {
        let exists = {
            let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            reg.find_by_serial(serial)
                .map(|d| is_usable_state(d.state))
                .unwrap_or(false)
        };
        return Ok(if exists { Some(serial.to_string()) } else { None });
    }
    if cmd == "host:transport-any" {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        let found = reg
            .devices
            .iter()
            .find(|d| is_usable_state(d.state))
            .map(|d| d.serial.clone());
        return Ok(found);
    }
    // host:transport-usb/-local are not dispatched yet (unknown host
    // service → FAIL); never bind after a failed selection.
    Ok(None)
}

// ---------------------------------------------------------------------------
// Host Service Dispatch
// ---------------------------------------------------------------------------

/// Parse the ADB host-service `connect` address.
///
/// AOSP's ParseNetAddress accepts the usual `host:port` spelling and requires
/// brackets around IPv6 literals when a port is present. Keep the host
/// unbracketed for DNS resolution, while preserving the socket's canonical
/// bracketed spelling for the registry serial below.
fn parse_adb_host_port(target: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 address: missing closing ']'".to_string())?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid address: IPv6 host must be followed by ':port'".to_string())?;
        (host, port)
    } else {
        if target.matches(':').count() != 1 {
            return Err("invalid address: IPv6 literals must be enclosed in '[' and ']'".to_string());
        }
        target
            .split_once(':')
            .ok_or_else(|| "invalid connect format: use host:port".to_string())?
    };

    if host.is_empty() {
        return Err("invalid address: host is empty".to_string());
    }
    let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;
    if port == 0 {
        return Err("invalid port: 0".to_string());
    }
    Ok((host.to_string(), port))
}

fn dispatch_host_service(
    client: &mut TcpStream,
    cmd: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    // ----- Helper closures -----

    let ok = |sock: &mut TcpStream, data: &[u8]| -> Result<(), String> {
        let len_hdr = format!("{:04x}", data.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(data))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let ok_empty = |sock: &mut TcpStream| -> Result<(), String> {
        sock.write_all(b"OKAY")
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let ok_str = |sock: &mut TcpStream, s: &str| -> Result<(), String> {
        ok(sock, s.as_bytes())
    };

    let fail = |sock: &mut TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    // ----- Dispatch -----

    match cmd {
        // -- host:version ---------------------------------------------------
        "host:version" => {
            let ver_str = format!("{:04x}", SERVER_VERSION);
            ok_str(client, &ver_str)
        }

        // -- host:kill ------------------------------------------------------
        "host:kill" => {
            ok_empty(client)?;
            eprintln!("[adb-server] Received host:kill — shutting down.");
            running.store(false, Ordering::Relaxed);
            Ok(())
        }

        // -- host:devices / host:devices-l ----------------------------------
        "host:devices" | "host:devices-l" => {
            let verbose = cmd.ends_with("-l");
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_devices(verbose)
            };
            ok_str(client, &list)
        }

        // -- host:track-devices ----------------------------------------------
        // Keep this connection open and publish a new length-prefixed device
        // list whenever the registry changes. This is the service used by IDEs
        // and scrcpy to receive hotplug updates.
        "host:track-devices" => {
            let mut last: Option<String> = None;
            ok_empty(client)?;
            while running.load(Ordering::Relaxed) {
                let current = {
                    let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.list_devices(false)
                };
                if last.as_deref() != Some(current.as_str()) {
                    let len_hdr = format!("{:04x}", current.len());
                    client
                        .write_all(len_hdr.as_bytes())
                        .and_then(|_| client.write_all(current.as_bytes()))
                        .and_then(|_| client.flush())
                        .map_err(|e| format!("track-devices write failed: {e}"))?;
                    last = Some(current);
                }
                thread::sleep(Duration::from_millis(250));
            }
            Ok(())
        }

        // -- host:wait-for-device ---------------------------------------------
        // AOSP clients use this service to block until at least one transport
        // reaches a usable registry state. Do not acknowledge before a device
        // exists; otherwise callers race the transport watcher.
        "host:wait-for-device" | "host:wait-for-any-device" => {
            while running.load(Ordering::Relaxed) {
                let available = {
                    let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.find_any_device().is_some()
                };
                if available {
                    return ok_empty(client);
                }
                thread::sleep(Duration::from_millis(250));
            }
            fail(client, "server is shutting down")
        }

        // -- host:get-state / host:get-serialno / host:get-devpath ----------
        c if c == "host:get-state" || c == "host:get-serialno" || c == "host:get-devpath" => {
            let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            let device = reg.find_any_device();
            match (c, device) {
                ("host:get-state", Some(dev)) => ok_str(client, dev.state.as_str()),
                ("host:get-serialno", Some(dev)) => ok_str(client, &dev.serial),
                ("host:get-devpath", Some(dev)) => {
                    let path = match dev.origin {
                        DeviceOrigin::Usb => "usb".to_string(),
                        DeviceOrigin::Tcp { addr } => format!("{}:{}", addr.ip(), addr.port()),
                    };
                    ok_str(client, &path)
                }
                _ => fail(client, "device not found"),
            }
        }

        // -- host:transport:<serial> ----------------------------------------
        c if c.starts_with("host:transport:") => {
            let serial = &c["host:transport:".len()..];
            let exists = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_by_serial(serial)
                    .map(|d| is_usable_state(d.state))
                    .unwrap_or(false)
            };
            if exists {
                ok_empty(client)
            } else {
                fail(client, &format!("device '{serial}' not found"))
            }
        }

        // -- host:transport-any ---------------------------------------------
        "host:transport-any" => {
            let exists = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.find_any_device().is_some()
            };
            if exists {
                ok_empty(client)
            } else {
                fail(client, "no devices available")
            }
        }

        // -- host:connect <host>:<port> -------------------------------------
        c if c.starts_with("host:connect:") => {
            let target = &c["host:connect:".len()..];
            let (parsed_host, port) = parse_adb_host_port(target)?;
            let host = &parsed_host;

            let addr_str = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let sock_addrs: Vec<SocketAddr> = addr_str
                .to_socket_addrs()
                .map_err(|e| format!("resolve failed: {e}"))?
                .collect();
            let addr = sock_addrs
                .first()
                .ok_or_else(|| "no address resolved".to_string())?
                .to_owned();

            let mut test_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
                .map_err(|e| format!("cannot connect to {addr_str}: {e}"))?;
            let _ = test_stream.set_nodelay(true);

            // Probe with CNXN
            let probe = adb_protocol::features::host_cnxn_payload();
            let probe = probe.as_slice();
            let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
            let mut hdr_buf = [0u8; 24];
            cnxn.encode(&mut hdr_buf);

            let cnxn_sent = test_stream
                .write_all(&hdr_buf)
                .and_then(|_| test_stream.write_all(probe))
                .and_then(|_| test_stream.flush());

            let response = if cnxn_sent.is_ok() && test_stream.read_exact(&mut hdr_buf).is_ok() {
                AdbMessageHeader::decode(&hdr_buf).ok()
            } else {
                None
            };
            let is_adbd = response
                .as_ref()
                .map(|h| h.command == A_CNXN)
                .unwrap_or(false);

            if is_adbd {
                let serial = addr.to_string();
                {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    reg.upsert_tcp_device(addr, serial.clone());

                    // Read CNXN payload for features
                    // The response header, not our request header, describes the
                    // payload that follows. AOSP's CNXN banner carries the device
                    // state, properties, and negotiated features; consuming the
                    // request length desynchronizes the stream when those lengths
                    // differ.
                    let payload_len = response.unwrap().data_length as usize;
                    if payload_len > 0 && payload_len < 4096 {
                        let mut actual_payload = vec![0u8; payload_len];
                        let _ = test_stream.read_exact(&mut actual_payload);
                        let cnxn_str = String::from_utf8_lossy(&actual_payload);
                        if let Some(dev) = reg.devices.iter_mut().find(|d| d.serial == serial) {
                            dev.transport_features = Some(cnxn_str.to_string());
                            for part in cnxn_str.trim().split(';') {
                                if let Some(val) = part.strip_prefix("product=") {
                                    dev.product = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("model=") {
                                    dev.model = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("device=") {
                                    dev.device_name = Some(val.to_string());
                                }
                            }
                        }
                    }
                }
                ok_str(client, &serial)
            } else {
                fail(client, "connection refused: not an ADB device")
            }
        }

        // -- host:disconnect / host:disconnect:<serial> --------------------
        c if c == "host:disconnect" || c.starts_with("host:disconnect:") => {
            if c == "host:disconnect" {
                let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                let count =
                    reg.devices.iter().filter(|d| matches!(d.origin, DeviceOrigin::Tcp { .. })).count();
                reg.remove_all_tcp_devices();
                ok_str(client, &format!("disconnected {count} devices"))
            } else {
                let serial = &c["host:disconnect:".len()..];
                let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                if reg.remove_device(serial) {
                    ok_str(client, &format!("disconnected {serial}"))
                } else {
                    fail(client, &format!("device '{serial}' not found"))
                }
            }
        }

        // -- host:forward:* --------------------------------------------------
        c if c.starts_with("host:forward:") => {
            let sub = &c["host:forward:".len()..];
            handle_forward(client, sub, registry)
        }

        // -- host:reverse:* --------------------------------------------------
        c if c.starts_with("host:reverse:") => {
            let sub = &c["host:reverse:".len()..];
            handle_reverse(client, sub, registry)
        }
        c if c.starts_with("reverse:") => {
            let sub = &c["reverse:".len()..];
            handle_reverse(client, sub, registry)
        }

        // -- host:host-features ---------------------------------------------
        // AOSP (adb.cpp:1443-1452) reports supported_features(); report
        // exactly the features this binary implements (features.rs) so
        // clients never trust abb/abb_exec/push_sync we cannot execute.
        "host:host-features" => {
            let features = adb_protocol::features::features_to_string(
                adb_protocol::features::host_supported_features(),
            );
            ok_str(client, &features)
        }

        // -- host:jdwp -------------------------------------------------------
        "host:jdwp" => {
            ok_str(client, "")
        }

        // -- Unknown ---------------------------------------------------------
        other => fail(client, &format!("unknown host service: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Spec Pair Parsing Helper
// ---------------------------------------------------------------------------

fn parse_spec_pair(s: &str) -> Option<(&str, &str)> {
    if let Some((a, b)) = s.split_once(';') {
        return Some((a, b));
    }
    let prefixes = [
        "tcp:",
        "localabstract:",
        "localreserved:",
        "localfilesystem:",
        "dev:",
        "jdwp:",
    ];
    for prefix in &prefixes {
        if s.starts_with(prefix) {
            let rest = &s[prefix.len()..];
            if let Some((p1, _p2)) = rest.split_once(':') {
                let first_len = prefix.len() + p1.len();
                return Some((&s[..first_len], &s[first_len + 1..]));
            }
        }
    }
    if let Some((a, b)) = s.split_once(':') {
        return Some((a, b));
    }
    None
}

// ---------------------------------------------------------------------------
// Background TCP Forwarding Listener & Bridge
// ---------------------------------------------------------------------------\

fn run_forward_listener(
    listener: TcpListener,
    active: Arc<AtomicBool>,
    remote_spec: String,
    registry: Arc<Mutex<TransportRegistry>>,
) {
    listener.set_nonblocking(true).ok();
    while active.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client_conn, _)) => {
                let reg = Arc::clone(&registry);
                let remote = remote_spec.clone();
                thread::spawn(move || {
                    forward_connection_to_device(client_conn, &remote, &reg);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn forward_connection_to_device(
    mut client_conn: TcpStream,
    remote: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) {
    let origin = {
        let Ok(reg) = registry.lock() else { return; };
        reg.find_any_device().map(|d| d.origin)
    };

    let Some(DeviceOrigin::Tcp { addr }) = origin else {
        return;
    };

    let Ok(mut device_stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return;
    };
    let _ = device_stream.set_nodelay(true);
    let _ = client_conn.set_nodelay(true);

    let probe = adb_protocol::features::host_cnxn_payload();
    let probe = probe.as_slice();
    let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
    let mut hdr_buf = [0u8; 24];
    cnxn.encode(&mut hdr_buf);

    if device_stream.write_all(&hdr_buf).is_err()
        || device_stream.write_all(probe).is_err()
        || device_stream.flush().is_err()
    {
        return;
    }

    if device_stream.read_exact(&mut hdr_buf).is_err() {
        return;
    }
    let Ok(cnxn_resp) = AdbMessageHeader::decode(&hdr_buf) else {
        return;
    };
    if cnxn_resp.command != A_CNXN {
        return;
    }
    let payload_len = cnxn_resp.data_length as usize;
    if payload_len > 0 {
        let mut dummy = vec![0u8; payload_len];
        let _ = device_stream.read_exact(&mut dummy);
    }

    let local_id = 1u32;
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, remote.as_bytes());
    open_hdr.encode(&mut hdr_buf);
    if device_stream.write_all(&hdr_buf).is_err()
        || device_stream.write_all(remote.as_bytes()).is_err()
        || device_stream.flush().is_err()
    {
        return;
    }

    let remote_id = loop {
        if device_stream.read_exact(&mut hdr_buf).is_err() {
            return;
        }
        let Ok(resp) = AdbMessageHeader::decode(&hdr_buf) else {
            return;
        };
        if resp.command == A_OKAY {
            break resp.arg0;
        } else if resp.command == A_CLSE {
            return;
        }
    };

    let mut client_read = match client_conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut device_write = match device_stream.try_clone() {
        Ok(d) => d,
        Err(_) => return,
    };

    let h1 = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 16384];
        loop {
            let n = client_read.read(&mut buf)?;
            if n == 0 {
                let clse = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let mut buf24 = [0u8; 24];
                clse.encode(&mut buf24);
                let _ = device_write.write_all(&buf24);
                let _ = device_write.flush();
                break;
            }
            let wrte = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &buf[..n]);
            let mut buf24 = [0u8; 24];
            wrte.encode(&mut buf24);
            if device_write.write_all(&buf24).is_err()
                || device_write.write_all(&buf[..n]).is_err()
                || device_write.flush().is_err()
            {
                break;
            }
        }
        Ok(())
    });

    let h2 = thread::spawn(move || -> io::Result<()> {
        let mut buf24 = [0u8; 24];
        loop {
            if device_stream.read_exact(&mut buf24).is_err() {
                break;
            }
            let Ok(hdr) = AdbMessageHeader::decode(&buf24) else {
                break;
            };
            if hdr.command == A_WRTE {
                let mut payload = vec![0u8; hdr.data_length as usize];
                if hdr.data_length > 0 {
                    if device_stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    if client_conn.write_all(&payload).is_err() || client_conn.flush().is_err() {
                        break;
                    }
                }
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                let mut ack_buf = [0u8; 24];
                ack.encode(&mut ack_buf);
                let _ = device_stream.write_all(&ack_buf);
                let _ = device_stream.flush();
            } else if hdr.command == A_CLSE {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let mut ack_buf = [0u8; 24];
                ack.encode(&mut ack_buf);
                let _ = device_stream.write_all(&ack_buf);
                let _ = device_stream.flush();
                break;
            }
        }
        Ok(())
    });

    let _ = h1.join();
    let _ = h2.join();
}

// ---------------------------------------------------------------------------
// host:forward and host:reverse dispatch
// ---------------------------------------------------------------------------

fn handle_forward(
    client: &mut TcpStream,
    sub: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(), String> {
    let ok_str = |sock: &mut TcpStream, s: &str| -> Result<(), String> {
        let len_hdr = format!("{:04x}", s.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(s.as_bytes()))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let fail = |sock: &mut TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    match sub {
        "list" => {
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_forwards()
            };
            ok_str(client, &list)
        }
        "killforward-all" | "remove-all" => {
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            reg.remove_all_forwards();
            ok_str(client, "")
        }
        c if c.starts_with("killforward:") || c.starts_with("remove:") => {
            let local = if let Some(l) = c.strip_prefix("killforward:") {
                l
            } else {
                &c["remove:".len()..]
            };
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            if reg.remove_forward(local) {
                ok_str(client, "")
            } else {
                fail(client, &format!("forward '{local}' not found"))
            }
        }
        c if c.starts_with("norebind:") => {
            let rest = &c["norebind:".len()..];
            match parse_spec_pair(rest) {
                Some((local, remote)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_forward(registry, local, remote, true) {
                        Ok(res) => ok_str(client, &res),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid forward norebind format: use local;remote"),
            }
        }
        other => {
            match parse_spec_pair(other) {
                Some((local, remote)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_forward(registry, local, remote, false) {
                        Ok(res) => ok_str(client, &res),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, &format!("invalid forward: {other}")),
            }
        }
    }
}

fn handle_reverse(
    client: &mut TcpStream,
    sub: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(), String> {
    let ok_str = |sock: &mut TcpStream, s: &str| -> Result<(), String> {
        let len_hdr = format!("{:04x}", s.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(s.as_bytes()))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let fail = |sock: &mut TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    match sub {
        "list" => {
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_reverses()
            };
            ok_str(client, &list)
        }
        "killforward-all" | "killreverse-all" | "remove-all" => {
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            reg.remove_all_reverses();
            ok_str(client, "")
        }
        c if c.starts_with("killreverse:") || c.starts_with("killforward:") || c.starts_with("remove:") => {
            let remote = if let Some(r) = c.strip_prefix("killreverse:") {
                r
            } else if let Some(r) = c.strip_prefix("killforward:") {
                r
            } else {
                &c["remove:".len()..]
            };
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            if reg.remove_reverse(remote) {
                ok_str(client, "")
            } else {
                fail(client, &format!("reverse forward '{remote}' not found"))
            }
        }
        c if c.starts_with("norebind:") => {
            let rest = &c["norebind:".len()..];
            match parse_spec_pair(rest) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, true) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid reverse format: use remote;local or remote:local"),
            }
        }
        c if c.starts_with("forward:") => {
            let rest = &c["forward:".len()..];
            match parse_spec_pair(rest) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, false) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid reverse format: use remote;local or remote:local"),
            }
        }
        other => {
            match parse_spec_pair(other) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, false) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, &format!("invalid reverse: {other}")),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transport Bridge
// ---------------------------------------------------------------------------

/// AOSP smart-socket device-service bridge: the hex-length command `service`
/// (e.g. `root:`, `tcpip:5555`, `shell:id`) becomes an A_OPEN on the device
/// transport; after the device OKAYs it, the client connection is a raw byte
/// stream mapped onto WRTE/OKAY frames (sockets.cpp connect_to_remote).
///
/// TCP devices get the full conversion. The legacy TCP relay
/// (`bridge_to_device` → `bridge_tcp_to_tcp`) forwarded 24-byte ADB frames
/// verbatim and therefore only works for clients that speak raw ADB to the
/// server (our own adb-rs direct path) — an official AOSP client's
/// hex-length service strings got forwarded into the frame relay as
/// non-frame bytes and broke. USB devices keep the legacy frame relay; a
/// real hex-service USB bridge needs transport cloning that UsbfsAdbDevice
/// does not yet provide (tracked gap).
fn bridge_device_service(
    client: TcpStream,
    serial: &str,
    service: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(), String> {
    let origin = {
        let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
        reg.find_by_serial(serial).map(|d| d.origin)
    };
    match origin {
        Some(DeviceOrigin::Tcp { addr }) => {
            let result = service_bridge_tcp(client, addr, service);
            // A bridge that ends usually means the device went away mid-use.
            // AOSP removes the transport on disconnect; mirror that for TCP.
            if result.is_ok() {
                let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                if reg.remove_device(serial) {
                    eprintln!("[adb-server] TCP device '{serial}' disconnected — removed from registry");
                }
            }
            result
        }
        Some(DeviceOrigin::Usb) => {
            #[cfg(feature = "usb")]
            {
                // Legacy frame relay (see docs on bridge_device_service):
                // speaks raw ADB frames, not AOSP hex services.
                let _ = service;
                bridge_to_device_usb(client, serial).map(|_| ())
            }
            #[cfg(not(feature = "usb"))]
            {
                Err("USB transport not supported (compile with --features usb)".to_string())
            }
        }
        None => Err(format!("device '{serial}' not found")),
    }
}

/// TCP service bridge: dial adbd, CNXN handshake, A_OPEN(service), then
/// pump client bytes ⇄ device WRTE frames until either side closes.
fn service_bridge_tcp(mut client: TcpStream, addr: SocketAddr, service: &str) -> Result<(), String> {
    let device = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("cannot connect to device at {addr}: {e}"))?;
    let _ = device.set_nodelay(true);

    // CNXN on the device transport (server owns this handshake; the client
    // never sees it — AOSP local_socket/remote_socket split).
    let mut device = device;
    let probe = adb_protocol::features::host_cnxn_payload();
    let probe = probe.as_slice();
    let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
    let mut hdr_buf = [0u8; 24];
    cnxn.encode(&mut hdr_buf);
    device
        .write_all(&hdr_buf)
        .and_then(|_| device.write_all(probe))
        .and_then(|_| device.flush())
        .map_err(|e| format!("CNXN send: {e}"))?;
    device.read_exact(&mut hdr_buf).map_err(|e| format!("CNXN read: {e}"))?;
    let resp = AdbMessageHeader::decode(&hdr_buf).map_err(|e| format!("CNXN decode: {e}"))?;
    if resp.command != A_CNXN {
        return Err("device did not answer CNXN".to_string());
    }
    if resp.data_length > 0 {
        let mut banner = vec![0u8; resp.data_length as usize];
        device.read_exact(&mut banner).map_err(|e| format!("banner: {e}"))?;
    }

    // A_OPEN(service) → OKAY(remote_id) or FAIL/CLSE.
    let local_id = 1u32;
    let open = AdbMessageHeader::new(A_OPEN, local_id, 0, service.as_bytes());
    open.encode(&mut hdr_buf);
    device
        .write_all(&hdr_buf)
        .and_then(|_| device.write_all(service.as_bytes()))
        .and_then(|_| device.flush())
        .map_err(|e| format!("OPEN send: {e}"))?;

    let remote_id = loop {
        device.read_exact(&mut hdr_buf).map_err(|e| format!("OPEN resp: {e}"))?;
        let h = AdbMessageHeader::decode(&hdr_buf).map_err(|e| format!("OPEN decode: {e}"))?;
        match h.command {
            A_OKAY => break h.arg0,
            A_CLSE => return Err(format!("service '{service}' refused by device")),
            _ => continue,
        }
    };

    // Tell the client its service opened.
    client
        .write_all(b"OKAY")
        .and_then(|_| client.flush())
        .map_err(|e| format!("client OKAY: {e}"))?;

    // Bridges have no idle timeout (AOSP); the 30 s host-command read
    // timeout must not kill a long-lived shell.
    let _ = client.set_read_timeout(None);

    let mut client_w = client.try_clone().map_err(|e| e.to_string())?;
    let mut client_r = client;
    let mut dev_w = device.try_clone().map_err(|e| e.to_string())?;
    let mut dev_r = device;

    // client → device: bytes become WRTE frames (device acks are consumed).
    let h1 = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 16384];
        loop {
            let n = client_r.read(&mut buf)?;
            if n == 0 {
                let clse = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let mut b24 = [0u8; 24];
                clse.encode(&mut b24);
                let _ = dev_w.write_all(&b24);
                let _ = dev_w.flush();
                return Ok(());
            }
            let wrte = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &buf[..n]);
            // Header + payload in ONE write: the ack writer (device→client
            // thread) shares this socket, and two write_all calls could be
            // interleaved mid-frame.
            let mut frame = Vec::with_capacity(24 + n);
            let mut b24 = [0u8; 24];
            wrte.encode(&mut b24);
            frame.extend_from_slice(&b24);
            frame.extend_from_slice(&buf[..n]);
            if dev_w.write_all(&frame).is_err() || dev_w.flush().is_err() {
                return Ok(());
            }
        }
    });

    // device → client: WRTE payloads stream out (each acked), CLSE ends.
    let h2 = thread::spawn(move || -> io::Result<()> {
        let mut b24 = [0u8; 24];
        loop {
            if dev_r.read_exact(&mut b24).is_err() {
                break;
            }
            let Ok(hdr) = AdbMessageHeader::decode(&b24) else {
                break;
            };
            match hdr.command {
                A_WRTE => {
                    let mut payload = vec![0u8; hdr.data_length as usize];
                    if hdr.data_length > 0 && dev_r.read_exact(&mut payload).is_err() {
                        break;
                    }
                    let ack = AdbMessageHeader::new(A_OKAY, remote_id, local_id, &[]);
                    let mut ab = [0u8; 24];
                    ack.encode(&mut ab);
                    let _ = dev_r.write_all(&ab).map(|_| dev_r.flush());
                    if client_w.write_all(&payload).is_err() || client_w.flush().is_err() {
                        break;
                    }
                }
                A_CLSE => {
                    let ack = AdbMessageHeader::new(A_CLSE, remote_id, local_id, &[]);
                    let mut ab = [0u8; 24];
                    ack.encode(&mut ab);
                    let _ = dev_r.write_all(&ab).map(|_| dev_r.flush());
                    break;
                }
                A_OKAY => {}
                _ => {}
            }
        }
        // AOSP local_socket_close: when the device side ends, the client
        // must see EOF. Half-close toward the client so a blocked h1 reader
        // can finish and the bridge terminates.
        let _ = client_w.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    let _ = h1.join();
    let _ = h2.join();
    Ok(())
}

/// Legacy USB frame relay: relays 24-byte ADB frames between the client
/// socket and the USB transport (two independent usbfs handles, one per
/// direction). Kept for the adb-rs CLI direct-USB path; an official AOSP
/// client needs the hex-length → A_OPEN conversion (tracked gap).
#[cfg(feature = "usb")]
fn bridge_to_device_usb(
    client: TcpStream,
    serial: &str,
) -> Result<bool, String> {
    bridge_tcp_to_usb(client, serial)
}

/// Bridge TCP client <-> USB ADB device via usbfs.
/// Uses ADB message framing (24-byte header + payload).
#[cfg(feature = "usb")]
fn bridge_tcp_to_usb(mut client: TcpStream, serial: &str) -> Result<bool, String> {
    use adb_protocol::usb::UsbTransportAdapter;
    use adb_protocol::usb_android::UsbfsAdbDevice;

    let serial = serial.to_string();

    let usb_dev =
        UsbfsAdbDevice::open_by_serial(&serial).map_err(|e| format!("cannot open USB device: {e}"))?;
    let transport = UsbTransportAdapter::new(usb_dev);

    let mut client_clone = client
        .try_clone()
        .map_err(|e| format!("client clone failed: {e}"))?;

    // Direction: client TCP -> USB device
    let h1 = thread::spawn(move || -> Result<(), String> {
        let mut transport = transport;
        loop {
            let mut hdr_buf = [0u8; 24];
            if client_clone.read_exact(&mut hdr_buf).is_err() {
                return Ok(());
            }
            let header = AdbMessageHeader::decode(&hdr_buf)
                .map_err(|e| format!("bad hdr from client: {e}"))?;

            let mut payload = vec![0u8; header.data_length as usize];
            if header.data_length > 0 {
                if client_clone.read_exact(&mut payload).is_err() {
                    return Ok(());
                }
            }

            transport.send_message(&header, &payload).map_err(|e| format!("USB send: {e}"))?;
        }
    });

    // Direction: USB device -> client TCP
    let h2 = thread::spawn(move || -> Result<(), String> {
        let usb_dev2 = UsbfsAdbDevice::open_by_serial(&serial)
            .map_err(|e| format!("cannot open USB device for recv: {e}"))?;
        let mut transport2 = UsbTransportAdapter::new(usb_dev2);

        loop {
            let (header, payload) = match transport2.recv_message() {
                Ok(msg) => msg,
                Err(TransportError::Io(ref e))
                    if e.kind() == io::ErrorKind::UnexpectedEof =>
                {
                    return Ok(());
                }
                Err(e) => return Err(format!("USB recv: {e}")),
            };

            let mut hdr_buf = [0u8; 24];
            header.encode(&mut hdr_buf);
            if client.write_all(&hdr_buf).is_err() {
                return Ok(());
            }
            if !payload.is_empty() && client.write_all(&payload).is_err() {
                return Ok(());
            }
            let _ = client.flush();
        }
    });

    let _ = h1.join();
    let _ = h2.join();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_adb_host_port_supports_ipv4_hostname_and_bracketed_ipv6() {
        assert_eq!(parse_adb_host_port("127.0.0.1:5555").unwrap(), ("127.0.0.1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("device.local:5555").unwrap(), ("device.local".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[::1]:5555").unwrap(), ("::1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[fe80::1%wlan0]:5555").unwrap(), ("fe80::1%wlan0".to_string(), 5555));
    }

    #[test]
    fn test_parse_adb_host_port_rejects_ambiguous_or_invalid_addresses() {
        assert!(parse_adb_host_port("::1:5555").is_err());
        assert!(parse_adb_host_port("[::1]").is_err());
        assert!(parse_adb_host_port("host:not-a-port").is_err());
        assert!(parse_adb_host_port("host:0").is_err());
        assert!(parse_adb_host_port(":5555").is_err());
    }

    #[test]
    fn test_host_connect_ipv6_wire_and_canonical_serial() {
        let device_listener = TcpListener::bind("[::1]:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut request_header = [0u8; 24];
            stream.read_exact(&mut request_header).unwrap();
            let request = AdbMessageHeader::decode(&request_header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response_payload = b"device::features=shell_v2;";
            let response = AdbMessageHeader::new(
                A_CNXN,
                ADB_VERSION,
                MAX_PAYLOAD_V2,
                response_payload,
            );
            let mut response_header = [0u8; 24];
            response.encode(&mut response_header);
            stream.write_all(&response_header).unwrap();
            stream.write_all(response_payload).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let command = format!("host:connect:[::1]:{}", device_addr.port());
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let mut client = TcpStream::connect(server_addr).unwrap();
        let mut status = [0u8; 4];
        client.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"OKAY");
        let mut length = [0u8; 4];
        client.read_exact(&mut length).unwrap();
        let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
        let mut payload = vec![0u8; length];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(std::str::from_utf8(&payload).unwrap(), format!("[::1]:{}", device_addr.port()));

        server.join().unwrap();
        device.join().unwrap();
        let reg = registry.lock().unwrap();
        assert!(reg.find_by_serial(&format!("[::1]:{}", device_addr.port())).is_some());
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

    #[test]
    fn test_connect_consumes_response_cnxn_banner_length() {
        use std::net::TcpListener;
        use std::thread;

        let device_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let banner = b"device::features=shell_v2;".to_vec();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut header = [0u8; 24];
            stream.read_exact(&mut header).unwrap();
            let request = AdbMessageHeader::decode(&header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, &banner);
            response.encode(&mut header);
            stream.write_all(&header).unwrap();
            stream.write_all(&banner).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            let command = format!("host:connect:{device_addr}");
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let _client = TcpStream::connect(server_addr).unwrap();
        server.join().unwrap();
        device.join().unwrap();

        let serial = device_addr.to_string();
        let reg = registry.lock().unwrap();
        assert_eq!(reg.find_by_serial(&serial).unwrap().transport_features.as_deref(),
                   Some("device::features=shell_v2;"));
    }

    #[test]
    fn test_parse_spec_pair() {
        assert_eq!(
            parse_spec_pair("tcp:8080;tcp:9000"),
            Some(("tcp:8080", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("tcp:8080:tcp:9000"),
            Some(("tcp:8080", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("localabstract:foo;tcp:9000"),
            Some(("localabstract:foo", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("localabstract:foo:tcp:9000"),
            Some(("localabstract:foo", "tcp:9000"))
        );
        assert_eq!(parse_spec_pair("invalid"), None);
    }

    #[test]
    fn test_track_devices_emits_initial_snapshot() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:track-devices",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut okay = [0u8; 4];
        client.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        let snapshot_len = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut snapshot = vec![0u8; snapshot_len];
        client.read_exact(&mut snapshot).unwrap();
        assert!(std::str::from_utf8(&snapshot).is_ok());

        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn test_wait_for_device_acknowledges_available_transport() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        registry.lock().unwrap().devices.push(DeviceEntry {
            serial: "test-device".to_string(),
            state: DeviceState::Device,
            origin: DeviceOrigin::Tcp {
                addr: "127.0.0.1:5555".parse().unwrap(),
            },
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:wait-for-device",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"OKAY");
        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn test_registry_forward_management() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        {
            let mut reg = registry.lock().unwrap();
            let res = reg.add_forward(&registry, "tcp:0", "tcp:9000", false).unwrap();
            assert!(!res.is_empty());
            assert!(reg.list_forwards().contains("tcp:9000"));

            let res_dup = reg.add_forward(&registry, &format!("tcp:{res}"), "tcp:9000", true);
            assert!(res_dup.is_err());

            assert!(reg.remove_forward(&format!("tcp:{res}")));
            assert!(reg.list_forwards().is_empty());
        }
    }

    #[test]
    fn test_registry_reverse_management() {
        let mut reg = TransportRegistry::new();
        assert!(reg.add_reverse("tcp:8080", "tcp:9000", false).is_ok());
        assert!(reg.list_reverses().contains("tcp:8080 tcp:9000"));

        assert!(reg.add_reverse("tcp:8080", "tcp:9000", true).is_err());

        assert!(reg.remove_reverse("tcp:8080"));
        assert!(reg.list_reverses().is_empty());
    }

    /// AOSP-style server conversation: register a TCP device, then speak to
    /// the server like the official adb client does —
    /// host:version, host:transport:<serial>, and a hex-length *device*
    /// service (`root:`). The server must convert the service into an
    /// A_OPEN on the device transport (never forward the hex prefix raw),
    /// ack the client, and stream the device payload back.
    #[test]
    fn test_smart_socket_device_service_becomes_aopen() {
        use std::io::{Read, Write};

        // ---- fake adbd on a TCP port -------------------------------------
        let dev_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dev_addr = dev_listener.local_addr().unwrap();
        let dev_thread = thread::spawn(move || {
            let (mut sock, _) = dev_listener.accept().unwrap();
            let mut buf = [0u8; 24];
            // CNXN from the server
            sock.read_exact(&mut buf).unwrap();
            let cnxn = AdbMessageHeader::decode(&buf).unwrap();
            assert_eq!(cnxn.command, A_CNXN);
            let mut p = vec![0u8; cnxn.data_length as usize];
            sock.read_exact(&mut p).unwrap();
            let banner = b"device::features=shell_v2".to_vec();
            let resp = AdbMessageHeader::new(A_CNXN, 0x01000001, 1024 * 1024, &banner);
            let mut b = [0u8; 24];
            resp.encode(&mut b);
            sock.write_all(&b).unwrap();
            sock.write_all(&banner).unwrap();
            sock.flush().unwrap();

            // A_OPEN("root:") — NOT hex-length text.
            sock.read_exact(&mut b).unwrap();
            let open = AdbMessageHeader::decode(&b).unwrap();
            assert_eq!(open.command, A_OPEN);
            let mut svc = vec![0u8; open.data_length as usize];
            sock.read_exact(&mut svc).unwrap();
            assert_eq!(&svc, b"root:");

            // adbd acks the open with OKAY(remote_id=5) BEFORE streaming.
            let mut b = [0u8; 24];
            let okay = AdbMessageHeader::new(A_OKAY, 5, open.arg0, &[]);
            okay.encode(&mut b);
            sock.write_all(&b).unwrap();
            sock.flush().unwrap();

            // device output, then close the stream
            let out = b"restarting adbd as root";
            let wrte = AdbMessageHeader::new(A_WRTE, 5, open.arg0, out);
            wrte.encode(&mut b);
            sock.write_all(&b).unwrap();
            sock.write_all(out).unwrap();
            sock.flush().unwrap();
            // consume the client's OKAY ack
            let _ = sock.read_exact(&mut b);
            let clse = AdbMessageHeader::new(A_CLSE, 5, open.arg0, &[]);
            clse.encode(&mut b);
            let _ = sock.write_all(&b);
            let _ = sock.flush();
        });

        // ---- server under test -------------------------------------------
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let srv_addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry {
            devices: vec![DeviceEntry {
                serial: dev_addr.to_string(),
                state: DeviceState::Device,
                origin: DeviceOrigin::Tcp { addr: dev_addr },
                product: None,
                model: None,
                device_name: None,
                transport_features: None,
            }],
            forwards: Vec::new(),
            reverses: Vec::new(),
        }));
        let running = Arc::new(AtomicBool::new(true));
        let reg2 = Arc::clone(&registry);
        let run2 = Arc::clone(&running);
        let server_thread = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let _ = handle_client(client, &reg2, &run2);
        });

        let mut client = TcpStream::connect(srv_addr).unwrap();

        // helper: send one hex-length host command, read status + payload
        let mut txn = |client: &mut TcpStream, cmd: &str| -> Vec<u8> {
            let req = format!("{:04x}{cmd}", cmd.len());
            client.write_all(req.as_bytes()).unwrap();
            client.flush().unwrap();
            let mut status = [0u8; 4];
            client.read_exact(&mut status).unwrap();
            assert_eq!(&status, b"OKAY", "for {cmd}");
            if cmd == "host:version" {
                let mut len = [0u8; 4];
                client.read_exact(&mut len).unwrap();
                let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
                let mut data = vec![0u8; n];
                client.read_exact(&mut data).unwrap();
                return data;
            }
            Vec::new()
        };

        // 1. host:version must report ADB_SERVER_VERSION = 41 → "0029"
        let ver = txn(&mut client, "host:version");
        assert_eq!(String::from_utf8_lossy(&ver), "0029");

        // 2. transport selection (bare OKAY)
        let serial = dev_addr.to_string();
        let sel = format!("host:transport:{serial}");
        client
            .write_all(format!("{:04x}{sel}", sel.len()).as_bytes())
            .unwrap();
        client.flush().unwrap();
        let mut okay = [0u8; 4];
        client.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        // 3. device service as AOSP sends it: hex-length root:
        let svc = "root:";
        client
            .write_all(format!("{:04x}{svc}", svc.len()).as_bytes())
            .unwrap();
        client.flush().unwrap();
        client.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        // 4. the streamed device payload arrives raw
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"restarting adbd as root");

        // Server-side bridge readers only see EOF once the client socket is
        // dropped; join() would otherwise hang.
        drop(client);
        let _ = running;
        server_thread.join().unwrap();
        dev_thread.join().unwrap();
    }

    /// Device service before any transport selection must FAIL with the
    /// AOSP wording, not crash or bridge.
    #[test]
    fn test_device_service_without_transport_fails_offline() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry {
            devices: Vec::new(),
            forwards: Vec::new(),
            reverses: Vec::new(),
        }));
        let running = Arc::new(AtomicBool::new(true));
        let reg2 = Arc::clone(&registry);
        let run2 = Arc::clone(&running);
        let srv = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let _ = handle_client(client, &reg2, &run2);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let svc = "root:";
        client
            .write_all(format!("{:04x}{svc}", svc.len()).as_bytes())
            .unwrap();
        client.flush().unwrap();
        let mut status = [0u8; 4];
        client.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"FAIL");
        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut msg = vec![0u8; n];
        client.read_exact(&mut msg).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&msg),
            "device offline (no transport)"
        );
        let _ = srv.join();
    }
}
