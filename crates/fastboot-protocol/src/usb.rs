//! Backend-neutral boundary for first-stage Fastboot USB bulk transport.
//!
//! This module deliberately does not enumerate devices or depend on a USB stack.
//! A platform backend supplies a descriptor and implements [`BulkIo`].

use std::io::{self, Read, Write};
use thiserror::Error;

/// Fastboot's required USB interface class tuple.
pub const FASTBOOT_INTERFACE_CLASS: u8 = 0xff;
pub const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;
pub const FASTBOOT_INTERFACE_PROTOCOL: u8 = 0x03;

/// Direction of a USB endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbEndpointDirection {
    In,
    Out,
}

/// Information needed by a bulk-I/O backend for one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbEndpointInfo {
    pub address: u8,
    pub direction: UsbEndpointDirection,
    pub max_packet_size: u16,
}

impl UsbEndpointInfo {
    pub const fn new(address: u8, direction: UsbEndpointDirection, max_packet_size: u16) -> Self {
        Self { address, direction, max_packet_size }
    }
}

/// Descriptor information selected by a platform-specific USB layer.
///
/// This is descriptive only: constructing it never discovers or opens a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDescriptor {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub bulk_in: Option<UsbEndpointInfo>,
    pub bulk_out: Option<UsbEndpointInfo>,
}

impl UsbDescriptor {
    /// Validate the descriptor boundary required by Fastboot.
    pub fn validate(&self) -> Result<(), UsbTransportError> {
        if (self.interface_class, self.interface_subclass, self.interface_protocol)
            != (FASTBOOT_INTERFACE_CLASS, FASTBOOT_INTERFACE_SUBCLASS, FASTBOOT_INTERFACE_PROTOCOL)
        {
            return Err(UsbTransportError::InvalidDescriptor {
                reason: format!(
                    "unsupported interface class tuple {:02x}/{:02x}/{:02x}",
                    self.interface_class, self.interface_subclass, self.interface_protocol
                ),
            });
        }
        let in_ep = self.bulk_in.ok_or(UsbTransportError::MissingEndpoint {
            direction: UsbEndpointDirection::In,
        })?;
        if in_ep.direction != UsbEndpointDirection::In {
            return Err(UsbTransportError::InvalidDescriptor { reason: "bulk_in has wrong direction".into() });
        }
        let out_ep = self.bulk_out.ok_or(UsbTransportError::MissingEndpoint {
            direction: UsbEndpointDirection::Out,
        })?;
        if out_ep.direction != UsbEndpointDirection::Out {
            return Err(UsbTransportError::InvalidDescriptor { reason: "bulk_out has wrong direction".into() });
        }
        Ok(())
    }
}

/// Structured errors exposed by the USB boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UsbTransportError {
    #[error("invalid Fastboot USB descriptor: {reason}")]
    InvalidDescriptor { reason: String },
    #[error("missing bulk {direction:?} endpoint")]
    MissingEndpoint { direction: UsbEndpointDirection },
    #[error("USB {operation} failed: {message}")]
    Backend { operation: &'static str, message: String },
    #[error("USB short read: requested {requested} bytes, received {received}")]
    ShortRead { requested: usize, received: usize },
    #[error("USB short write: requested {requested} bytes, transferred {transferred}")]
    ShortWrite { requested: usize, transferred: usize },
    #[error("USB {operation} timed out")]
    Timeout { operation: &'static str },
    #[error("USB permission denied during {operation}")]
    PermissionDenied { operation: &'static str },
    #[error("no Fastboot USB device found")]
    NoDevice,
    #[error("no Fastboot USB device matched selector {selector}")]
    NoMatchingDevice { selector: String },
    #[error("USB backend returned {received} bytes for a {capacity}-byte buffer")]
    InvalidTransfer { received: usize, capacity: usize },
}

/// Backend-neutral bulk I/O supplied by a USB implementation.
pub trait BulkIo: Send {
    fn descriptor(&self) -> &UsbDescriptor;
    fn bulk_read(&mut self, endpoint: UsbEndpointInfo, buf: &mut [u8]) -> Result<usize, UsbTransportError>;
    fn bulk_write(&mut self, endpoint: UsbEndpointInfo, buf: &[u8]) -> Result<usize, UsbTransportError>;
}

/// Adapter that exposes [`BulkIo`] with the existing `Read`/`Write` transport behavior.
pub struct FastbootUsbTransport<B> {
    backend: B,
    bulk_in: UsbEndpointInfo,
    bulk_out: UsbEndpointInfo,
}

impl<B: BulkIo> FastbootUsbTransport<B> {
    pub fn new(backend: B) -> Result<Self, UsbTransportError> {
        backend.descriptor().validate()?;
        let bulk_in = backend.descriptor().bulk_in.expect("validated bulk_in");
        let bulk_out = backend.descriptor().bulk_out.expect("validated bulk_out");
        Ok(Self { backend, bulk_in, bulk_out })
    }

    pub fn into_inner(self) -> B { self.backend }
}

fn io_error(error: UsbTransportError) -> io::Error {
    let kind = match error {
        UsbTransportError::ShortWrite { .. } => io::ErrorKind::WriteZero,
        UsbTransportError::InvalidDescriptor { .. } | UsbTransportError::MissingEndpoint { .. }
        | UsbTransportError::InvalidTransfer { .. } => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

impl<B: BulkIo> Read for FastbootUsbTransport<B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let received = self.backend.bulk_read(self.bulk_in, buf).map_err(io_error)?;
        if received > buf.len() {
            return Err(io_error(UsbTransportError::InvalidTransfer { received, capacity: buf.len() }));
        }
        Ok(received)
    }
}

impl<B: BulkIo> Write for FastbootUsbTransport<B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut transferred = 0;
        while transferred < buf.len() {
            let n = self.backend.bulk_write(self.bulk_out, &buf[transferred..]).map_err(io_error)?;
            if n == 0 {
                return Err(io_error(UsbTransportError::ShortWrite { requested: buf.len(), transferred }));
            }
            if n > buf.len() - transferred {
                return Err(io_error(UsbTransportError::InvalidTransfer { received: n, capacity: buf.len() - transferred }));
            }
            transferred += n;
        }
        Ok(transferred)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn descriptor() -> UsbDescriptor {
        UsbDescriptor {
            interface_number: 2, alternate_setting: 1,
            interface_class: FASTBOOT_INTERFACE_CLASS,
            interface_subclass: FASTBOOT_INTERFACE_SUBCLASS,
            interface_protocol: FASTBOOT_INTERFACE_PROTOCOL,
            bulk_in: Some(UsbEndpointInfo::new(0x81, UsbEndpointDirection::In, 512)),
            bulk_out: Some(UsbEndpointInfo::new(0x02, UsbEndpointDirection::Out, 512)),
        }
    }

    struct MockBulk {
        descriptor: UsbDescriptor,
        reads: VecDeque<Result<Vec<u8>, UsbTransportError>>,
        writes: Vec<usize>,
        output: Vec<u8>,
    }

    impl BulkIo for MockBulk {
        fn descriptor(&self) -> &UsbDescriptor { &self.descriptor }
        fn bulk_read(&mut self, _: UsbEndpointInfo, buf: &mut [u8]) -> Result<usize, UsbTransportError> {
            let data = self.reads.pop_front().unwrap().map_err(|e| e)?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(n)
        }
        fn bulk_write(&mut self, _: UsbEndpointInfo, buf: &[u8]) -> Result<usize, UsbTransportError> {
            let n = self.writes.remove(0).min(buf.len());
            self.output.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    #[test]
    fn validates_fastboot_descriptor_and_preserves_endpoint_info() {
        let mock = MockBulk { descriptor: descriptor(), reads: VecDeque::new(), writes: vec![], output: vec![] };
        let transport = FastbootUsbTransport::new(mock).unwrap();
        let backend = transport.into_inner();
        assert_eq!(backend.descriptor.interface_number, 2);
        assert_eq!(backend.descriptor.alternate_setting, 1);
        assert_eq!(backend.descriptor.bulk_in.unwrap().address, 0x81);
    }

    #[test]
    fn allows_short_bulk_read() {
        let mut reads = VecDeque::new();
        reads.push_back(Ok(b"abc".to_vec()));
        let mock = MockBulk { descriptor: descriptor(), reads, writes: vec![], output: vec![] };
        let mut transport = FastbootUsbTransport::new(mock).unwrap();
        let mut buf = [0; 8];
        assert_eq!(transport.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn loops_over_short_bulk_writes() {
        let mock = MockBulk { descriptor: descriptor(), reads: VecDeque::new(), writes: vec![2, 1, 99], output: vec![] };
        let mut transport = FastbootUsbTransport::new(mock).unwrap();
        assert_eq!(transport.write_all(b"hello").unwrap(), ());
        assert_eq!(transport.into_inner().output, b"hello");
    }

    #[test]
    fn propagates_backend_errors() {
        let mut reads = VecDeque::new();
        reads.push_back(Err(UsbTransportError::Backend { operation: "bulk read", message: "permission denied".into() }));
        let mock = MockBulk { descriptor: descriptor(), reads, writes: vec![], output: vec![] };
        let mut transport = FastbootUsbTransport::new(mock).unwrap();
        let err = transport.read(&mut [0; 4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn rejects_invalid_descriptor() {
        let mut d = descriptor();
        d.bulk_out = None;
        let mock = MockBulk { descriptor: d, reads: VecDeque::new(), writes: vec![], output: vec![] };
        assert!(matches!(FastbootUsbTransport::new(mock), Err(UsbTransportError::MissingEndpoint { direction: UsbEndpointDirection::Out })));
    }
}
