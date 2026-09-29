pub mod adb_utils;
pub mod auth;
pub mod compress;
pub mod constants;
pub mod crypto;
pub mod features;
pub mod header;
pub mod mdns;
pub mod pairing;
pub mod pairing_auth;
pub mod pairing_connection;
pub mod proto;
pub mod shell_v2;
pub mod stls;
pub mod sync;
pub mod sysdeps;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transport;
#[cfg(any(feature = "usb", feature = "usb-rusb", feature = "usb-android"))]
pub mod usb;
#[cfg(feature = "usb-android")]
pub mod usb_android;
#[cfg(feature = "usb-android")]
pub use usb_android::{DeviceCandidate, UsbAndroidError, UsbfsAdbDevice};

pub use adb_utils::{escape_arg, exec_service_string};
#[cfg(unix)]
pub use sysdeps::errno::{errno_from_wire, errno_to_wire};
pub use auth::*;
pub use compress::*;
pub use constants::*;
pub use features::{
    can_use_feature, features_to_string, host_cnxn_payload, host_supported_features,
    parse_banner_features,
};
pub use header::{AdbMessageHeader, AuthType, HeaderError};
pub use mdns::{parse_txt_record, AdbMdnsService, AdbMdnsServiceType, MdnsError};
pub use pairing::{
    validate_pairing_code, PairingClient, PairingError, PairingPacket,
    PairingPacketType, MAX_PAIRING_PAYLOAD, PAIRING_HEADER_SIZE, PAIRING_VERSION,
};
#[cfg(not(feature = "pairing-vendored"))]
pub use pairing_auth::PairingCipher;
#[cfg(feature = "pairing-vendored")]
pub use pairing::PairingAuth as PairingCipherVendored;
#[cfg(feature = "pairing-vendored")]
pub use pairing::PairingAuth;
pub use shell_v2::{ShellV2Error, ShellV2Packet};
pub use stls::{StlsAction, StlsError, StlsPacket, StlsState, StlsStateMachine};
pub use sync::{
    build_recv_v2_req, build_send_v2_req, build_sync_data_block, build_sync_data_chunk,
    build_sync_done, build_sync_done_u64, build_sync_list_req, build_sync_recv_req,
    build_sync_send_req, build_sync_stat_req, saturating_mtime_u32, SyncDentResponse,
    SyncDentV2Response, SyncMessageHeader, SyncProtocolError, SyncStatResponse, SyncStatV2Response,
    SyncV2Decoder, SyncV2Encoder,
};
pub use transport::{AdbServerTransport, Connect, SharedTransport, TcpTransport, Transport, TransportError};
#[cfg(feature = "tls")]
pub use transport::AdbTlsTransport;
#[cfg(any(feature = "usb", feature = "usb-rusb"))]
pub use usb::{
    parse_adb_interface_descriptors, should_send_zlp, UsbEndpointInfo, UsbTransport,
    UsbTransportAdapter, UsbTransportError,
};
#[cfg(feature = "usb-rusb")]
pub use usb::{RusbUsbTransport, RusbUsbTransportError};
