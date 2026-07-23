pub mod boot_image;
pub mod command;
pub mod response;
pub mod sparse;
pub mod transport;
#[cfg(feature = "usb")]
pub mod usb;
#[cfg(feature = "usb-rusb")]
pub mod usb_rusb;
#[cfg(feature = "usb-android")]
pub mod usb_android;

pub use command::*;
pub use response::{FastbootResponse, FastbootResponseError};
pub use sparse::{
    SparseChunk, SparseChunkBuilder, SparseChunkHeader, SparseError, SparseFile, SparseHeader,
    CHUNK_TYPE_CRC32, CHUNK_TYPE_DONT_CARE, CHUNK_TYPE_FILL, CHUNK_TYPE_RAW,
    SPARSE_HEADER_MAGIC,
};
pub use transport::{Connect, FastbootTcpTransport, FastbootTransport, FastbootTransportError};
#[cfg(feature = "usb")]
pub use usb::{
    BulkIo, FastbootUsbTransport, UsbDescriptor, UsbEndpointDirection, UsbEndpointInfo,
    UsbTransportError,
};
#[cfg(feature = "usb-rusb")]
pub use usb_rusb::RusbBulkIo;
#[cfg(feature = "usb-android")]
pub use usb_android::{UsbfsFastbootDevice, FastbootDeviceCandidate, UsbAndroidError};
