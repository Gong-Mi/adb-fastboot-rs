//! Optional real libusb/rusb Fastboot backend.
//!
//! This module is only compiled with `usb-rusb`; the default crate remains free
//! of native USB dependencies and performs no device discovery.

use crate::usb::*;
use rusb::UsbContext;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// libusb/rusb implementation of the Fastboot bulk backend.
///
/// This is only available with the `usb-rusb` feature. It enumerates real USB
/// devices and never creates a simulated device.
pub struct RusbBulkIo {
    _context: rusb::Context,
    handle: rusb::DeviceHandle<rusb::Context>,
    descriptor: UsbDescriptor,
    timeout: Duration,
}

/// A rusb Fastboot candidate. Serial is None when the string descriptor is
/// unavailable; it is never inferred from bus/address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RusbFastbootCandidate {
    pub serial: Option<String>,
    pub bus_number: u8,
    pub address: u8,
}

impl RusbFastbootCandidate {
    pub fn bus_address(&self) -> (u8, u8) { (self.bus_number, self.address) }
}

#[derive(Clone, Copy, Debug)]
pub enum RusbFastbootSelector<'a> {
    Serial(&'a str),
    BusAddress { bus_number: u8, address: u8 },
}

impl std::fmt::Display for RusbFastbootSelector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serial(serial) => write!(f, "serial={serial}"),
            Self::BusAddress { bus_number, address } => write!(f, "bus-address={bus_number}-{address}"),
        }
    }
}

pub fn select_fastboot_candidate<'a>(candidates: &'a [RusbFastbootCandidate], selector: RusbFastbootSelector<'_>)
    -> Result<&'a RusbFastbootCandidate, UsbTransportError>
{
    candidates.iter().find(|candidate| match selector {
        RusbFastbootSelector::Serial(serial) => candidate.serial.as_deref() == Some(serial),
        RusbFastbootSelector::BusAddress { bus_number, address } => candidate.bus_address() == (bus_number, address),
    }).ok_or_else(|| UsbTransportError::NoMatchingDevice { selector: selector.to_string() })
}

impl std::fmt::Debug for RusbBulkIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusbBulkIo")
            .field("descriptor", &self.descriptor)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn map_error(operation: &'static str, error: rusb::Error) -> UsbTransportError {
    match error {
        rusb::Error::Timeout => UsbTransportError::Timeout { operation },
        rusb::Error::Access => UsbTransportError::PermissionDenied { operation },
        rusb::Error::NoDevice => UsbTransportError::NoDevice,
        other => UsbTransportError::Backend { operation, message: other.to_string() },
    }
}

fn endpoint_info(endpoint: &rusb::EndpointDescriptor) -> Option<UsbEndpointInfo> {
    if endpoint.transfer_type() != rusb::TransferType::Bulk { return None; }
    let direction = match endpoint.direction() {
        rusb::Direction::In => UsbEndpointDirection::In,
        rusb::Direction::Out => UsbEndpointDirection::Out,
    };
    Some(UsbEndpointInfo::new(endpoint.address(), direction, endpoint.max_packet_size()))
}

fn find_descriptor(
    device: &rusb::Device<rusb::Context>,
) -> Result<Option<UsbDescriptor>, UsbTransportError> {
    let device_descriptor = device.device_descriptor().map_err(|e| map_error("read device descriptor", e))?;
    for index in 0..device_descriptor.num_configurations() {
        let config = device.config_descriptor(index).map_err(|e| map_error("read configuration", e))?;
        for interface in config.interfaces() {
            for alternate in interface.descriptors() {
                if (alternate.class_code(), alternate.sub_class_code(), alternate.protocol_code())
                    != (FASTBOOT_INTERFACE_CLASS, FASTBOOT_INTERFACE_SUBCLASS, FASTBOOT_INTERFACE_PROTOCOL)
                { continue; }
                let mut bulk_in = None;
                let mut bulk_out = None;
                for endpoint in alternate.endpoint_descriptors() {
                    match endpoint_info(&endpoint) {
                        Some(info) if info.direction == UsbEndpointDirection::In && bulk_in.is_none() => bulk_in = Some(info),
                        Some(info) if info.direction == UsbEndpointDirection::Out && bulk_out.is_none() => bulk_out = Some(info),
                        _ => {}
                    }
                }
                let descriptor = UsbDescriptor {
                    interface_number: alternate.interface_number(),
                    alternate_setting: alternate.setting_number(),
                    interface_class: alternate.class_code(),
                    interface_subclass: alternate.sub_class_code(),
                    interface_protocol: alternate.protocol_code(),
                    bulk_in,
                    bulk_out,
                };
                if descriptor.validate().is_ok() { return Ok(Some(descriptor)); }
            }
        }
    }
    Ok(None)
}

impl RusbBulkIo {
    /// Enumerate and open the first device with a complete Fastboot interface.
    pub fn open() -> Result<Self, UsbTransportError> { Self::open_with_timeout(DEFAULT_TIMEOUT) }

    /// As [`open`](Self::open), with a timeout for every bulk transfer.
    pub fn open_with_timeout(timeout: Duration) -> Result<Self, UsbTransportError> {
        let context = rusb::Context::new().map_err(|e| map_error("create USB context", e))?;
        let devices = context.devices().map_err(|e| map_error("enumerate USB devices", e))?;
        for device in devices.iter() {
            let Some(descriptor) = find_descriptor(&device)? else { continue };
            let handle = device.open().map_err(|e| map_error("open Fastboot device", e))?;
            handle.claim_interface(descriptor.interface_number)
                .map_err(|e| map_error("claim Fastboot interface", e))?;
            if descriptor.alternate_setting != 0 {
                handle.set_alternate_setting(descriptor.interface_number, descriptor.alternate_setting)
                    .map_err(|e| map_error("set Fastboot alternate setting", e))?;
            }
            return Ok(Self { _context: context, handle, descriptor, timeout });
        }
        Err(UsbTransportError::NoDevice)
    }

    /// Enumerate candidates without opening a transport.
    pub fn enumerate_candidates() -> Result<Vec<RusbFastbootCandidate>, UsbTransportError> {
        let context = rusb::Context::new().map_err(|e| map_error("create USB context", e))?;
        let devices = context.devices().map_err(|e| map_error("enumerate USB devices", e))?;
        let mut candidates = Vec::new();
        for device in devices.iter() {
            if find_descriptor(&device)?.is_some() {
                let serial = device.open().ok().and_then(|handle| device.device_descriptor().ok().and_then(|d| handle.read_serial_number_string_ascii(&d).ok()));
                candidates.push(RusbFastbootCandidate { serial, bus_number: device.bus_number(), address: device.address() });
            }
        }
        Ok(candidates)
    }

    pub fn open_by_serial(serial: &str) -> Result<Self, UsbTransportError> {
        Self::open_selected(RusbFastbootSelector::Serial(serial), DEFAULT_TIMEOUT)
    }

    pub fn open_by_bus_address(bus_number: u8, address: u8) -> Result<Self, UsbTransportError> {
        Self::open_selected(RusbFastbootSelector::BusAddress { bus_number, address }, DEFAULT_TIMEOUT)
    }

    fn open_selected(selector: RusbFastbootSelector<'_>, timeout: Duration) -> Result<Self, UsbTransportError> {
        let context = rusb::Context::new().map_err(|e| map_error("create USB context", e))?;
        let devices = context.devices().map_err(|e| map_error("enumerate USB devices", e))?;
        for device in devices.iter() {
            let Some(descriptor) = find_descriptor(&device)? else { continue };
            let candidate = RusbFastbootCandidate {
                serial: device.open().ok().and_then(|handle| device.device_descriptor().ok().and_then(|d| handle.read_serial_number_string_ascii(&d).ok())),
                bus_number: device.bus_number(), address: device.address(),
            };
            let matches = match selector {
                RusbFastbootSelector::Serial(serial) => candidate.serial.as_deref() == Some(serial),
                RusbFastbootSelector::BusAddress { bus_number, address } => candidate.bus_address() == (bus_number, address),
            };
            if !matches { continue; }
            let handle = device.open().map_err(|e| map_error("open Fastboot device", e))?;
            handle.claim_interface(descriptor.interface_number).map_err(|e| map_error("claim Fastboot interface", e))?;
            if descriptor.alternate_setting != 0 { handle.set_alternate_setting(descriptor.interface_number, descriptor.alternate_setting).map_err(|e| map_error("set Fastboot alternate setting", e))?; }
            return Ok(Self { _context: context, handle, descriptor, timeout });
        }
        Err(UsbTransportError::NoMatchingDevice { selector: selector.to_string() })
    }

    /// Construct the existing `Read`/`Write` transport boundary over rusb.
    pub fn open_transport() -> Result<FastbootUsbTransport<Self>, UsbTransportError> {
        FastbootUsbTransport::new(Self::open()?)
    }
}

impl BulkIo for RusbBulkIo {
    fn descriptor(&self) -> &UsbDescriptor { &self.descriptor }

    fn bulk_read(&mut self, endpoint: UsbEndpointInfo, buf: &mut [u8]) -> Result<usize, UsbTransportError> {
        if endpoint.direction != UsbEndpointDirection::In {
            return Err(UsbTransportError::InvalidDescriptor { reason: "bulk read endpoint is not IN".into() });
        }
        self.handle.read_bulk(endpoint.address, buf, self.timeout)
            .map_err(|e| map_error("bulk read", e))
    }

    fn bulk_write(&mut self, endpoint: UsbEndpointInfo, buf: &[u8]) -> Result<usize, UsbTransportError> {
        if endpoint.direction != UsbEndpointDirection::Out {
            return Err(UsbTransportError::InvalidDescriptor { reason: "bulk write endpoint is not OUT".into() });
        }
        self.handle.write_bulk(endpoint.address, buf, self.timeout)
            .map_err(|e| map_error("bulk write", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_fastboot_candidate_by_serial_and_bus_address() {
        let candidates = vec![
            RusbFastbootCandidate { serial: Some("fb-one".into()), bus_number: 3, address: 5 },
            RusbFastbootCandidate { serial: None, bus_number: 3, address: 6 },
        ];
        assert_eq!(select_fastboot_candidate(&candidates, RusbFastbootSelector::Serial("fb-one")).unwrap().bus_address(), (3, 5));
        assert_eq!(select_fastboot_candidate(&candidates, RusbFastbootSelector::BusAddress { bus_number: 3, address: 6 }).unwrap().serial, None);
    }

    #[test]
    fn rejects_unmatched_fastboot_candidate() {
        let candidates = vec![RusbFastbootCandidate { serial: None, bus_number: 1, address: 1 }];
        assert!(matches!(select_fastboot_candidate(&candidates, RusbFastbootSelector::Serial("missing")), Err(UsbTransportError::NoMatchingDevice { .. })));
    }
}
