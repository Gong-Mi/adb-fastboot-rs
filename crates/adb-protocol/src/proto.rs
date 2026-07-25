//! ADB protocol buffer type definitions.
//!
//! Mirrors AOSP `vendor/adb/proto/` (.proto files).
//! Covers: pairing, key_type, adb_host, adb_known_hosts, app_processes.

// ---------------------------------------------------------------------------
// pairing.proto — PairingPacket.Type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingPacketType {
    Spake2Msg = 0,
    PeerInfo = 1,
}

impl PairingPacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v { 0 => Some(Self::Spake2Msg), 1 => Some(Self::PeerInfo), _ => None }
    }
    pub fn to_u8(self) -> u8 { self as u8 }
}

// ---------------------------------------------------------------------------
// key_type.proto — KeyType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType { Rsa2048 = 0 }

impl KeyType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v { 0 => Some(Self::Rsa2048), _ => None }
    }
}

// ---------------------------------------------------------------------------
// adb_host.proto — ConnectionState, Device, Devices, AdbServerStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Any = 0, Connecting = 1, Authorizing = 2, Unauthorized = 3,
    NoPermission = 4, Detached = 5, Offline = 6, Bootloader = 7,
    Device = 8, Host = 9, Recovery = 10, Sideload = 11, Rescue = 12,
}

impl ConnectionState {
    pub fn from_u32(v: u32) -> Option<Self> {
        use ConnectionState::*;
        match v { 0 => Some(Any), 1 => Some(Connecting), 2 => Some(Authorizing),
                   3 => Some(Unauthorized), 4 => Some(NoPermission), 5 => Some(Detached),
                   6 => Some(Offline), 7 => Some(Bootloader), 8 => Some(Device),
                   9 => Some(Host), 10 => Some(Recovery), 11 => Some(Sideload),
                   12 => Some(Rescue), _ => None }
    }
    pub fn as_str(&self) -> &'static str {
        use ConnectionState::*;
        match self { Any => "any", Connecting => "connecting", Authorizing => "authorizing",
                     Unauthorized => "unauthorized", NoPermission => "nopermission",
                     Detached => "detached", Offline => "offline", Bootloader => "bootloader",
                     Device => "device", Host => "host", Recovery => "recovery",
                     Sideload => "sideload", Rescue => "rescue" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType { Unknown = 0, Usb = 1, Socket = 2 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub serial: String, pub state: ConnectionState, pub bus_address: String,
    pub product: String, pub model: String, pub device: String,
    pub connection_type: ConnectionType,
    pub negotiated_speed: i64, pub max_speed: i64, pub transport_id: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Devices { pub device: Vec<Device> }

#[derive(Debug, Clone)]
pub struct AdbServerStatus {
    pub usb_backend: UsbBackend, pub usb_backend_forced: bool, pub mdns_backend: MdnsBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbBackend { Unknown = 0, Native = 1, Libusb = 2 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsBackend { Unknown = 0, Bonjour = 1, Openscreen = 2 }

// ---------------------------------------------------------------------------
// adb_known_hosts.proto — HostInfo, AdbKnownHosts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo { pub guid: String }

#[derive(Debug, Clone, Default)]
pub struct AdbKnownHosts { pub host_infos: Vec<HostInfo> }

// ---------------------------------------------------------------------------
// app_processes.proto — ProcessEntry, AppProcesses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: i64, pub debuggable: bool, pub profileable: bool,
    pub architecture: String, pub user_id: Option<i64>,
    pub process_name: Option<String>, pub package_names: Vec<String>,
    pub waiting_for_debugger: Option<bool>, pub uid: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct AppProcesses { pub process: Vec<ProcessEntry> }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_packet_type() {
        assert_eq!(PairingPacketType::from_u8(0), Some(PairingPacketType::Spake2Msg));
        assert_eq!(PairingPacketType::from_u8(1), Some(PairingPacketType::PeerInfo));
        assert_eq!(PairingPacketType::Spake2Msg.to_u8(), 0);
    }

    #[test]
    fn test_key_type() {
        assert_eq!(KeyType::from_u32(0), Some(KeyType::Rsa2048));
        assert_eq!(KeyType::from_u32(1), None);
    }

    #[test]
    fn test_connection_state() {
        assert_eq!(ConnectionState::Device.as_str(), "device");
        assert_eq!(ConnectionState::Offline.as_str(), "offline");
        assert_eq!(ConnectionState::from_u32(8), Some(ConnectionState::Device));
        assert_eq!(ConnectionState::from_u32(99), None);
    }

    #[test]
    fn test_device_create() {
        let d = Device {
            serial: "123".into(), state: ConnectionState::Device,
            bus_address: "1-1".into(), product: "p".into(), model: "m".into(),
            device: "d".into(), connection_type: ConnectionType::Usb,
            negotiated_speed: 480, max_speed: 480, transport_id: 1,
        };
        assert_eq!(d.serial, "123");
    }

    #[test]
    fn test_process_entry() {
        let p = ProcessEntry {
            pid: 1234, debuggable: true, profileable: false,
            architecture: "arm64".into(), user_id: Some(0),
            process_name: Some("app".into()), package_names: vec!["app".into()],
            waiting_for_debugger: Some(false), uid: Some(10123),
        };
        assert_eq!(p.pid, 1234);
        assert!(p.debuggable);
    }

    #[test]
    fn test_devices_default_empty() {
        let d = Devices::default();
        assert!(d.device.is_empty());
    }

    #[test]
    fn test_known_hosts() {
        let kh = AdbKnownHosts { host_infos: vec![HostInfo { guid: "abc".into() }] };
        assert_eq!(kh.host_infos[0].guid, "abc");
    }
}
