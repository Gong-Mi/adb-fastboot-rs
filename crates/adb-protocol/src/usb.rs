//! First-phase USB transport boundary for ADB.
//!
//! This module deliberately contains no USB device discovery or I/O backend.  A
//! future usbfs/UsbManager/libusb adapter can implement [`UsbTransport`] after
//! it has an authorized bulk-transfer handle.  Descriptor parsing is kept pure
//! so it can be tested without a USB device (and without adding a native USB
//! dependency to the default build).

use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};

use thiserror::Error;

use crate::transport::Transport;

const INTERFACE_DESCRIPTOR: u8 = 0x04;
const ENDPOINT_DESCRIPTOR: u8 = 0x05;
const BULK_TRANSFER_TYPE: u8 = 0x02;
const USB_DIRECTION_IN: u8 = 0x80;

const ADB_CLASS: u8 = 0xff;
const ADB_SUBCLASS: u8 = 0x42;
const ADB_PROTOCOL: u8 = 0x01;
const ADB_DBC_CLASS: u8 = 0xdc;
const ADB_DBC_SUBCLASS: u8 = 0x02;

/// The descriptor-derived values needed by a USB ADB adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbEndpointInfo {
    pub interface_number: u8,
    pub bulk_in_endpoint_address: u8,
    pub bulk_out_endpoint_address: u8,
    pub out_max_packet_size: u16,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UsbTransportError {
    #[error("malformed USB descriptor at offset {offset}: {reason}")]
    MalformedDescriptor { offset: usize, reason: &'static str },
    #[error("ADB USB interface was not found")]
    NoAdbInterface,
    #[error("ADB interface {interface_number} is missing a bulk {missing} endpoint")]
    MissingBulkEndpoint { interface_number: u8, missing: &'static str },
    #[error("ADB interface {interface_number} has inconsistent bulk endpoint packet sizes")]
    InconsistentPacketSize { interface_number: u8 },
    #[error("ADB interface {interface_number} has a zero bulk endpoint packet size")]
    ZeroPacketSize { interface_number: u8 },
    #[error("USB transport I/O error: {0}")]
    Io(String),
    #[error("USB transport is disconnected")]
    Disconnected,
    #[error("USB transport operation timed out")]
    Timeout,
    #[error("USB transport permission denied")]
    PermissionDenied,
    #[error("no USB device was found")]
    NoDevice,
}

/// A backend-neutral boundary for an authorized ADB USB connection.
///
/// This is intentionally not implemented here: opening `/dev/bus/usb` and
/// Android `UsbManager` fd handoff are deployment-specific operations.  A
/// backend can expose bulk transfers through this trait and separately adapt
/// them to the protocol-level [`crate::Transport`] framing.
pub trait UsbTransport: Send {
    fn endpoint_info(&self) -> UsbEndpointInfo;
    fn bulk_read(&mut self, endpoint: u8, buffer: &mut [u8]) -> Result<usize, UsbTransportError>;
    fn bulk_write(&mut self, endpoint: u8, buffer: &[u8]) -> Result<usize, UsbTransportError>;
}

/// Adapts a bulk-only USB backend to the regular ADB message transport.
///
/// The backend must already represent an authorized connection. This adapter
/// performs no device discovery or fd opening; it only maps descriptor-derived
/// endpoints to `Read`/`Write`. ADB's 24-byte framing remains in `Transport`.
pub struct UsbTransportAdapter<T> {
    backend: T,
    endpoints: UsbEndpointInfo,
    pending_out_bytes: usize,
}

impl<T: UsbTransport> UsbTransportAdapter<T> {
    pub fn new(backend: T) -> Self {
        let endpoints = backend.endpoint_info();
        Self { backend, endpoints, pending_out_bytes: 0 }
    }

    pub fn endpoint_info(&self) -> UsbEndpointInfo { self.endpoints }

    pub fn into_inner(self) -> T { self.backend }
}

fn usb_io_error(error: UsbTransportError) -> IoError {
    let kind = match error {
        UsbTransportError::Disconnected => ErrorKind::NotConnected,
        UsbTransportError::Timeout => ErrorKind::TimedOut,
        UsbTransportError::PermissionDenied => ErrorKind::PermissionDenied,
        UsbTransportError::NoDevice => ErrorKind::NotFound,
        UsbTransportError::Io(_) => ErrorKind::Other,
        UsbTransportError::MalformedDescriptor { .. }
        | UsbTransportError::NoAdbInterface
        | UsbTransportError::MissingBulkEndpoint { .. }
        | UsbTransportError::InconsistentPacketSize { .. }
        | UsbTransportError::ZeroPacketSize { .. } => ErrorKind::InvalidData,
    };
    IoError::new(kind, error)
}

impl<T: UsbTransport> Read for UsbTransportAdapter<T> {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        if buffer.is_empty() { return Ok(0); }
        self.backend.bulk_read(self.endpoints.bulk_in_endpoint_address, buffer)
            .map_err(usb_io_error)
    }
}

impl<T: UsbTransport> Write for UsbTransportAdapter<T> {
    fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
        if buffer.is_empty() { return Ok(0); }
        let written = self.backend.bulk_write(self.endpoints.bulk_out_endpoint_address, buffer)
            .map_err(usb_io_error)?;
        if written > buffer.len() {
            return Err(IoError::new(ErrorKind::InvalidData, "USB bulk_write returned more bytes than requested"));
        }
        self.pending_out_bytes = self.pending_out_bytes.saturating_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> IoResult<()> {
        if should_send_zlp(self.pending_out_bytes, self.endpoints.out_max_packet_size) {
            self.backend.bulk_write(self.endpoints.bulk_out_endpoint_address, &[])
                .map_err(usb_io_error)?;
        }
        self.pending_out_bytes = 0;
        Ok(())
    }
}

impl<T: UsbTransport> Transport for UsbTransportAdapter<T> {
    fn flush_payload(&mut self, payload_len: usize) -> Result<(), crate::transport::TransportError> {
        // ADB's USB ZLP decision is based on the payload only. The 24-byte
        // ADB header is a separate transfer and must not affect the decision.
        if should_send_zlp(payload_len, self.endpoints.out_max_packet_size) {
            self.backend.bulk_write(self.endpoints.bulk_out_endpoint_address, &[])
                .map_err(usb_io_error)?;
        }
        self.pending_out_bytes = 0;
        Ok(())
    }
}

fn is_adb_interface(class: u8, subclass: u8, protocol: u8) -> bool {
    protocol == ADB_PROTOCOL
        && ((class == ADB_CLASS && subclass == ADB_SUBCLASS)
            || (class == ADB_DBC_CLASS && subclass == ADB_DBC_SUBCLASS))
}

/// Parse raw active-configuration descriptors and return the first complete
/// ADB interface with bulk IN and OUT endpoints.
///
/// Endpoint addresses and the interface number come from descriptors; no USB
/// endpoint or interface number is hard-coded.  This follows AOSP's
/// `is_adb_interface()` and `LibUsbDevice::FindAdbInterface()` rules.
pub fn parse_adb_interface_descriptors(
    descriptors: &[u8],
) -> Result<UsbEndpointInfo, UsbTransportError> {
    let mut offset = 0;
    let mut candidate: Option<(u8, Option<(u8, u16)>, Option<(u8, u16)>, Option<u16>)> = None;

    while offset < descriptors.len() {
        if descriptors.len() - offset < 2 {
            return Err(UsbTransportError::MalformedDescriptor {
                offset,
                reason: "descriptor header is truncated",
            });
        }
        let length = descriptors[offset] as usize;
        if length < 2 || offset + length > descriptors.len() {
            return Err(UsbTransportError::MalformedDescriptor {
                offset,
                reason: "invalid descriptor length",
            });
        }
        let descriptor = &descriptors[offset..offset + length];
        match descriptor[1] {
            INTERFACE_DESCRIPTOR => {
                if length < 9 {
                    return Err(UsbTransportError::MalformedDescriptor {
                        offset,
                        reason: "interface descriptor is shorter than 9 bytes",
                    });
                }
                if let Some((number, in_ep, out_ep, packet_size)) = candidate.take() {
                    // AOSP skips an ADB-looking interface that lacks one of
                    // the bulk directions and continues scanning interfaces.
                    // Missing-endpoint reporting is deferred until the final
                    // candidate, while malformed packet metadata remains an
                    // immediate error.
                    if let (Some(_), Some(_), Some(_)) = (in_ep, out_ep, packet_size) {
                        return Ok(complete_endpoint_info(number, in_ep, out_ep, packet_size)?.unwrap());
                    }
                }
                if is_adb_interface(descriptor[5], descriptor[6], descriptor[7]) {
                    candidate = Some((descriptor[2], None, None, None));
                }
            }
            ENDPOINT_DESCRIPTOR => {
                if length < 7 {
                    return Err(UsbTransportError::MalformedDescriptor {
                        offset,
                        reason: "endpoint descriptor is shorter than 7 bytes",
                    });
                }
                if let Some((number, ref mut in_ep, ref mut out_ep, ref mut packet_size)) = candidate {
                    let address = descriptor[2];
                    let attributes = descriptor[3] & 0x03;
                    if attributes == BULK_TRANSFER_TYPE {
                        let size = u16::from_le_bytes([descriptor[4], descriptor[5]]);
                        if size == 0 {
                            return Err(UsbTransportError::ZeroPacketSize {
                                interface_number: number,
                            });
                        }
                        if let Some(previous) = *packet_size {
                            if previous != size {
                                return Err(UsbTransportError::InconsistentPacketSize {
                                    interface_number: number,
                                });
                            }
                        } else {
                            *packet_size = Some(size);
                        }
                        if address & USB_DIRECTION_IN != 0 {
                            if in_ep.is_none() {
                                *in_ep = Some((address, size));
                            }
                        } else if out_ep.is_none() {
                            *out_ep = Some((address, size));
                        }
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }

    if let Some((number, in_ep, out_ep, packet_size)) = candidate {
        if let Some(info) = complete_endpoint_info(number, in_ep, out_ep, packet_size)? {
            return Ok(info);
        }
    }
    Err(UsbTransportError::NoAdbInterface)
}

fn complete_endpoint_info(
    interface_number: u8,
    in_ep: Option<(u8, u16)>,
    out_ep: Option<(u8, u16)>,
    packet_size: Option<u16>,
) -> Result<Option<UsbEndpointInfo>, UsbTransportError> {
    match (in_ep, out_ep, packet_size) {
        (Some((bulk_in_endpoint_address, _)), Some((bulk_out_endpoint_address, out_max_packet_size)), Some(_)) => {
            Ok(Some(UsbEndpointInfo {
                interface_number,
                bulk_in_endpoint_address,
                bulk_out_endpoint_address,
                out_max_packet_size,
            }))
        }
        (None, _, _) => Err(UsbTransportError::MissingBulkEndpoint {
            interface_number,
            missing: "IN",
        }),
        (_, None, _) => Err(UsbTransportError::MissingBulkEndpoint {
            interface_number,
            missing: "OUT",
        }),
        _ => Ok(None),
    }
}

/// Whether AOSP's USB writer must send an OUT zero-length packet.
pub fn should_send_zlp(payload_len: usize, out_max_packet_size: u16) -> bool {
    payload_len != 0
        && out_max_packet_size != 0
        && payload_len % out_max_packet_size as usize == 0
}

/// Real libusb/rusb backend. This is opt-in because it links to the system
/// libusb; the default build remains free of native USB dependencies.
#[cfg(feature = "usb-rusb")]
pub struct RusbUsbTransport {
    handle: rusb::DeviceHandle<rusb::Context>,
    endpoints: UsbEndpointInfo,
    timeout: std::time::Duration,
}

/// A real ADB USB device discovered by rusb. `serial` is None when the string
/// descriptor cannot be read; it is never synthesized from the bus address.
#[cfg(feature = "usb-rusb")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RusbAdbCandidate {
    pub serial: Option<String>,
    pub bus_number: u8,
    pub address: u8,
}

#[cfg(feature = "usb-rusb")]
impl RusbAdbCandidate {
    pub fn bus_address(&self) -> (u8, u8) { (self.bus_number, self.address) }
}

#[cfg(feature = "usb-rusb")]
#[derive(Debug, Error)]
pub enum RusbUsbTransportError {
    #[error("libusb initialization failed: {0}")]
    Init(#[source] rusb::Error),
    #[error("no ADB USB device was found")]
    NoDevice,
    #[error("libusb device access denied")]
    PermissionDenied,
    #[error("ADB USB descriptor error: {0}")]
    Descriptor(#[from] UsbTransportError),
    #[error("libusb I/O error: {0}")]
    Io(#[source] rusb::Error),
    #[error("no ADB USB device matched selector {selector}")]
    NoMatchingDevice { selector: String },
    #[error("multiple ADB USB devices matched selector {selector}")]
    AmbiguousDevice { selector: String },
}

#[cfg(feature = "usb-rusb")]
pub enum RusbAdbSelector<'a> {
    Serial(&'a str),
    BusAddress { bus_number: u8, address: u8 },
}

#[cfg(feature = "usb-rusb")]
impl std::fmt::Display for RusbAdbSelector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serial(serial) => write!(f, "serial={serial}"),
            Self::BusAddress { bus_number, address } => write!(f, "bus-address={bus_number}-{address}"),
        }
    }
}

#[cfg(feature = "usb-rusb")]
pub fn select_adb_candidate<'a>(candidates: &'a [RusbAdbCandidate], selector: RusbAdbSelector<'_>)
    -> Result<&'a RusbAdbCandidate, RusbUsbTransportError>
{
    let matches = candidates.iter().filter(|candidate| match selector {
        RusbAdbSelector::Serial(serial) => candidate.serial.as_deref() == Some(serial),
        RusbAdbSelector::BusAddress { bus_number, address } => candidate.bus_address() == (bus_number, address),
    }).collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(RusbUsbTransportError::NoMatchingDevice { selector: selector.to_string() }),
        [candidate] => Ok(candidate),
        _ => Err(RusbUsbTransportError::AmbiguousDevice { selector: selector.to_string() }),
    }
}

#[cfg(feature = "usb-rusb")]
impl RusbUsbTransport {
    /// Enumerate devices, match the ADB interface, open it, and claim it.
    pub fn open_first() -> Result<Self, RusbUsbTransportError> {
        Self::open_first_with_timeout(std::time::Duration::from_secs(10))
    }

    pub fn open_first_with_timeout(
        timeout: std::time::Duration,
    ) -> Result<Self, RusbUsbTransportError> {
        Self::open_with_selector(None, timeout)
    }

    pub fn enumerate_candidates() -> Result<Vec<RusbAdbCandidate>, RusbUsbTransportError> {
        let context = rusb::Context::new().map_err(RusbUsbTransportError::Init)?;
        let devices = rusb::UsbContext::devices(&context).map_err(map_rusb_open_error)?;
        let mut candidates = Vec::new();
        for device in devices.iter() {
            let config = match device.active_config_descriptor() { Ok(config) => config, _ => continue };
            if config.interfaces().flat_map(|i| i.descriptors()).any(|d| is_adb_interface(d.class_code(), d.sub_class_code(), d.protocol_code())) {
                let serial = device.open().ok().and_then(|handle| device.device_descriptor().ok().and_then(|d| handle.read_serial_number_string_ascii(&d).ok()));
                candidates.push(RusbAdbCandidate { serial, bus_number: device.bus_number(), address: device.address() });
            }
        }
        Ok(candidates)
    }

    pub fn open_by_serial(serial: &str) -> Result<Self, RusbUsbTransportError> {
        Self::open_with_selector(Some(RusbAdbSelector::Serial(serial)), std::time::Duration::from_secs(10))
    }

    pub fn open_by_bus_address(bus_number: u8, address: u8) -> Result<Self, RusbUsbTransportError> {
        Self::open_with_selector(Some(RusbAdbSelector::BusAddress { bus_number, address }), std::time::Duration::from_secs(10))
    }

    fn open_with_selector(selector: Option<RusbAdbSelector<'_>>, timeout: std::time::Duration) -> Result<Self, RusbUsbTransportError> {
        let context = rusb::Context::new().map_err(RusbUsbTransportError::Init)?;
        let devices = rusb::UsbContext::devices(&context).map_err(map_rusb_open_error)?;
        let mut saw_access_denied = false;
        for device in devices.iter() {
            let config = match device.active_config_descriptor() {
                Ok(config) => config,
                Err(rusb::Error::Access) => { saw_access_denied = true; continue; }
                Err(_) => continue,
            };
            let mut interface_number = None;
            for interface in config.interfaces() {
                for descriptor in interface.descriptors() {
                    if is_adb_interface(descriptor.class_code(), descriptor.sub_class_code(), descriptor.protocol_code()) {
                        interface_number = Some(descriptor.interface_number());
                        break;
                    }
                }
                if interface_number.is_some() { break; }
            }
            let Some(interface_number) = interface_number else { continue };
            if let Some(selector) = &selector {
                let candidate = RusbAdbCandidate {
                    serial: device.open().ok().and_then(|handle| device.device_descriptor().ok().and_then(|d| handle.read_serial_number_string_ascii(&d).ok())),
                    bus_number: device.bus_number(), address: device.address(),
                };
                let matches = match selector {
                    RusbAdbSelector::Serial(serial) => candidate.serial.as_deref() == Some(serial),
                    RusbAdbSelector::BusAddress { bus_number, address } => candidate.bus_address() == (*bus_number, *address),
                };
                if !matches { continue; }
            }
            let endpoints = descriptor_info(&config, interface_number)?;
            match device.open() {
                Ok(handle) => match handle.claim_interface(interface_number) {
                    Ok(()) => return Ok(Self { handle, endpoints, timeout }),
                    Err(rusb::Error::Access) => saw_access_denied = true,
                    Err(_) => continue,
                },
                Err(rusb::Error::Access) => saw_access_denied = true,
                Err(_) => continue,
            }
        }
        if let Some(selector) = selector {
            Err(RusbUsbTransportError::NoMatchingDevice { selector: selector.to_string() })
        } else if saw_access_denied { Err(RusbUsbTransportError::PermissionDenied) }
        else { Err(RusbUsbTransportError::NoDevice) }
    }
}

#[cfg(feature = "usb-rusb")]
fn descriptor_info(
    config: &rusb::ConfigDescriptor,
    interface_number: u8,
) -> Result<UsbEndpointInfo, RusbUsbTransportError> {
    let interface = config.interfaces().find(|i| i.number() == interface_number)
        .ok_or_else(|| RusbUsbTransportError::Descriptor(UsbTransportError::NoAdbInterface))?;
    let descriptor = interface.descriptors().find(|d| is_adb_interface(d.class_code(), d.sub_class_code(), d.protocol_code()))
        .ok_or_else(|| RusbUsbTransportError::Descriptor(UsbTransportError::NoAdbInterface))?;
    let mut bulk_in = None;
    let mut bulk_out = None;
    for endpoint in descriptor.endpoint_descriptors() {
        if endpoint.transfer_type() != rusb::TransferType::Bulk { continue; }
        let value = (endpoint.address(), endpoint.max_packet_size());
        if endpoint.direction() == rusb::Direction::In { bulk_in = Some(value); }
        else { bulk_out = Some(value); }
    }
    let (bulk_in, bulk_out) = match (bulk_in, bulk_out) {
        (Some(input), Some(output)) => (input, output),
        (None, _) => return Err(RusbUsbTransportError::Descriptor(UsbTransportError::MissingBulkEndpoint { interface_number, missing: "IN" })),
        (_, None) => return Err(RusbUsbTransportError::Descriptor(UsbTransportError::MissingBulkEndpoint { interface_number, missing: "OUT" })),
    };
    if bulk_in.1 == 0 || bulk_out.1 == 0 {
        return Err(RusbUsbTransportError::Descriptor(UsbTransportError::ZeroPacketSize { interface_number }));
    }
    if bulk_in.1 != bulk_out.1 {
        return Err(RusbUsbTransportError::Descriptor(UsbTransportError::InconsistentPacketSize { interface_number }));
    }
    Ok(UsbEndpointInfo { interface_number, bulk_in_endpoint_address: bulk_in.0, bulk_out_endpoint_address: bulk_out.0, out_max_packet_size: bulk_out.1 })
}

#[cfg(feature = "usb-rusb")]
impl UsbTransport for RusbUsbTransport {
    fn endpoint_info(&self) -> UsbEndpointInfo { self.endpoints }

    fn bulk_read(&mut self, endpoint: u8, buffer: &mut [u8]) -> Result<usize, UsbTransportError> {
        self.handle.read_bulk(endpoint, buffer, self.timeout).map_err(map_rusb_error)
    }

    fn bulk_write(&mut self, endpoint: u8, buffer: &[u8]) -> Result<usize, UsbTransportError> {
        self.handle.write_bulk(endpoint, buffer, self.timeout).map_err(map_rusb_error)
    }
}

#[cfg(feature = "usb-rusb")]
fn map_rusb_open_error(error: rusb::Error) -> RusbUsbTransportError {
    if error == rusb::Error::Access { RusbUsbTransportError::PermissionDenied }
    else { RusbUsbTransportError::Io(error) }
}

#[cfg(feature = "usb-rusb")]
fn map_rusb_error(error: rusb::Error) -> UsbTransportError {
    match error {
        rusb::Error::Access => UsbTransportError::PermissionDenied,
        rusb::Error::NoDevice => UsbTransportError::Disconnected,
        rusb::Error::Timeout => UsbTransportError::Timeout,
        other => UsbTransportError::Io(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::A_CNXN;
    use crate::header::AdbMessageHeader;
    use crate::transport::Transport;
    use std::collections::VecDeque;
    use std::io::{ErrorKind, Write};
    use std::sync::{Arc, Mutex};
    fn interface_and_endpoints() -> Vec<u8> {
        vec![
            9, 4, 3, 0, 2, 0xff, 0x42, 1, 0,
            7, 5, 0x83, 3, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
            7, 5, 0x84, 2, 64, 0, 0,
        ]
    }

    #[test]
    fn parses_adb_bulk_endpoints_without_hardcoded_addresses() {
        let info = parse_adb_interface_descriptors(&interface_and_endpoints()).unwrap();
        assert_eq!(info.interface_number, 3);
        assert_eq!(info.bulk_in_endpoint_address, 0x84);
        assert_eq!(info.bulk_out_endpoint_address, 0x02);
        assert_eq!(info.out_max_packet_size, 64);
    }

    #[test]
    fn rejects_non_bulk_only_interface() {
        let descriptors = vec![9, 4, 3, 0, 1, 0xff, 0x42, 1, 0, 7, 5, 0x81, 3, 64, 0, 0];
        assert_eq!(parse_adb_interface_descriptors(&descriptors), Err(UsbTransportError::MissingBulkEndpoint { interface_number: 3, missing: "IN" }));
    }

    #[test]
    fn rejects_truncated_endpoint_descriptor() {
        let descriptors = vec![9, 4, 3, 0, 1, 0xff, 0x42, 1, 0, 6, 5, 0x81, 2, 64, 0];
        assert!(matches!(parse_adb_interface_descriptors(&descriptors), Err(UsbTransportError::MalformedDescriptor { .. })));
    }

    #[test]
    fn zlp_only_for_nonzero_packet_aligned_payload() {
        assert!(should_send_zlp(64, 64));
        assert!(should_send_zlp(128, 64));
        assert!(!should_send_zlp(0, 64));
        assert!(!should_send_zlp(63, 64));
    }

    #[derive(Clone, Default)]
    struct FakeUsb {
        state: Arc<Mutex<FakeState>>,
    }

    struct FakeState {
        input: VecDeque<u8>,
        writes: Vec<Vec<u8>>,
        read_limit: usize,
        write_limit: usize,
        read_error: Option<UsbTransportError>,
        write_error: Option<UsbTransportError>,
    }

    impl Default for FakeState {
        fn default() -> Self {
            Self {
                input: VecDeque::new(), writes: Vec::new(), read_limit: usize::MAX,
                write_limit: usize::MAX, read_error: None, write_error: None,
            }
        }
    }

    impl UsbTransport for FakeUsb {
        fn endpoint_info(&self) -> UsbEndpointInfo {
            UsbEndpointInfo { interface_number: 1, bulk_in_endpoint_address: 0x81,
                bulk_out_endpoint_address: 0x02, out_max_packet_size: 64 }
        }

        fn bulk_read(&mut self, endpoint: u8, buffer: &mut [u8]) -> Result<usize, UsbTransportError> {
            assert_eq!(endpoint, 0x81);
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.read_error.take() { return Err(error); }
            let count = buffer.len().min(state.input.len()).min(state.read_limit);
            for byte in buffer.iter_mut().take(count) { *byte = state.input.pop_front().unwrap(); }
            Ok(count)
        }

        fn bulk_write(&mut self, endpoint: u8, buffer: &[u8]) -> Result<usize, UsbTransportError> {
            assert_eq!(endpoint, 0x02);
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.write_error.take() { return Err(error); }
            let count = buffer.len().min(state.write_limit);
            state.writes.push(buffer[..count].to_vec());
            Ok(count)
        }
    }

    fn fake() -> FakeUsb { FakeUsb { state: Arc::new(Mutex::new(FakeState::default())) } }

    #[cfg(feature = "usb-rusb")]
    #[test]
    fn selects_adb_candidate_by_serial_and_bus_address() {
        let candidates = vec![
            RusbAdbCandidate { serial: Some("one".into()), bus_number: 2, address: 3 },
            RusbAdbCandidate { serial: None, bus_number: 2, address: 4 },
        ];
        assert_eq!(select_adb_candidate(&candidates, RusbAdbSelector::Serial("one")).unwrap().bus_address(), (2, 3));
        assert_eq!(select_adb_candidate(&candidates, RusbAdbSelector::BusAddress { bus_number: 2, address: 4 }).unwrap().serial, None);
    }

    #[cfg(feature = "usb-rusb")]
    #[test]
    fn rejects_unmatched_adb_candidate_without_fabricating_serial() {
        let candidates = vec![RusbAdbCandidate { serial: None, bus_number: 1, address: 7 }];
        assert!(matches!(select_adb_candidate(&candidates, RusbAdbSelector::Serial("missing")), Err(RusbUsbTransportError::NoMatchingDevice { .. })));
    }

    #[test]
    fn adapter_reuses_adb_framing_and_handles_short_bulk_io() {
        let payload = b"hello";
        let header = AdbMessageHeader::new(A_CNXN, 7, 9, payload);
        let mut encoded_header = [0u8; 24];
        header.encode(&mut encoded_header);
        let mut wire = encoded_header.to_vec();
        wire.extend_from_slice(payload);
        let fake = fake();
        {
            let mut state = fake.state.lock().unwrap();
            state.input.extend(wire);
            state.read_limit = 2;
            state.write_limit = 5;
        }
        let state = fake.state.clone();
        let mut adapter = UsbTransportAdapter::new(fake);
        let sent = AdbMessageHeader::new(A_CNXN, 1, 2, payload);
        adapter.send_message(&sent, payload).unwrap();
        let (received, received_payload) = adapter.recv_message().unwrap();
        assert_eq!(received, header);
        assert_eq!(received_payload, payload);
        let writes = &state.lock().unwrap().writes;
        assert_ne!(writes.last(), Some(&Vec::new()));
        assert_eq!(writes.iter().map(Vec::len).sum::<usize>(), 29);
    }

    #[test]
    fn adapter_zlp_uses_payload_length_not_header_plus_payload() {
        for (payload_len, want_zlp) in [(40usize, false), (64, true)] {
            let fake = fake();
            let state = fake.state.clone();
            let mut adapter = UsbTransportAdapter::new(fake);
            let payload = vec![0u8; payload_len];
            let header = AdbMessageHeader::new(A_CNXN, 1, 2, &payload);
            adapter.send_message(&header, &payload).unwrap();

            let writes = &state.lock().unwrap().writes;
            assert_eq!(writes.iter().filter(|write| write.is_empty()).count(), usize::from(want_zlp));
        }
    }

    #[test]
    fn adapter_propagates_bulk_errors() {
        let fake_usb = fake();
        fake_usb.state.lock().unwrap().write_error = Some(UsbTransportError::Timeout);
        let mut adapter = UsbTransportAdapter::new(fake_usb);
        let header = AdbMessageHeader::new(A_CNXN, 0, 0, &[]);
        assert!(matches!(adapter.send_message(&header, &[]),
            Err(crate::transport::TransportError::Io(error)) if error.kind() == ErrorKind::TimedOut));

        let fake_usb = fake();
        fake_usb.state.lock().unwrap().read_error = Some(UsbTransportError::Disconnected);
        let mut adapter = UsbTransportAdapter::new(fake_usb);
        assert!(matches!(adapter.recv_message(),
            Err(crate::transport::TransportError::Io(error)) if error.kind() == ErrorKind::NotConnected));
    }

    #[test]
    fn adapter_propagates_zlp_error() {
        let fake = fake();
        let state = fake.state.clone();
        let mut adapter = UsbTransportAdapter::new(fake);
        adapter.write_all(&[0; 64]).unwrap();
        state.lock().unwrap().write_error = Some(UsbTransportError::PermissionDenied);
        assert!(matches!(adapter.flush(), Err(error) if error.kind() == ErrorKind::PermissionDenied));
    }
}
