use std::io::{Read, Write, Result as IoResult};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use crate::header::{AdbMessageHeader, HeaderError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Header error: {0}")]
    Header(#[from] HeaderError),

    #[error("Connection failed to {addr}: {source}")]
    ConnectFailed {
        addr: String,
        source: std::io::Error,
    },

    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Device responded with A_STLS, indicating it requires TLS upgrade.
    /// The caller should wrap the transport in a TlsStream and retry the handshake.
    #[error("TLS handshake required: device requested A_STLS")]
    TlsHandshakeRequired,
}

/// Send, Recv, and I/O abstraction for ADB protocol transport
pub trait Transport: Read + Write + Send {
    /// Flush one ADB message. Transports that need message-level framing
    /// metadata (for example USB ZLP handling) can override this hook.
    fn flush_payload(&mut self, _payload_len: usize) -> Result<(), TransportError> {
        self.flush()?;
        Ok(())
    }

    /// Send an ADB message frame (24-byte header + payload)
    fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> Result<(), TransportError> {
        let mut hdr_buf = [0u8; 24];
        header.encode(&mut hdr_buf);
        self.write_all(&hdr_buf)?;
        if !payload.is_empty() {
            self.write_all(payload)?;
        }
        self.flush_payload(payload.len())
    }

    /// Receive an ADB message frame (24-byte header + payload)
    fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        let mut hdr_buf = [0u8; 24];
        self.read_exact(&mut hdr_buf)?;
        let header = AdbMessageHeader::decode(&hdr_buf)?;

        // AOSP: reject payloads larger than MAX_PAYLOAD_V2 to prevent OOM
        if header.data_length > crate::constants::MAX_PAYLOAD_V2 {
            return Err(TransportError::Protocol(format!(
                "Payload too large: {} bytes (max {})",
                header.data_length, crate::constants::MAX_PAYLOAD_V2
            )));
        }

        let mut payload = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            self.read_exact(&mut payload)?;
            header.verify_payload(&payload)?;
        }
        Ok((header, payload))
    }

    /// Attempt to clone this transport into a boxed trait object.
    /// Returns `None` by default; transports that support cloning
    /// (e.g. TcpTransport) override this to return a clone.
    fn try_clone_box(&self) -> Option<Box<dyn Transport>> {
        None
    }
}

/// Connect trait abstraction for establishing transport connections
pub trait Connect {
    type Target: Transport;
    fn connect(addr: &str) -> Result<Self::Target, TransportError>;
    fn connect_timeout(addr: &str, timeout: Duration) -> Result<Self::Target, TransportError>;
}

/// TCP Socket Transport implementation for ADB protocol
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn try_clone(&self) -> Result<Self, TransportError> {
        let stream = self.stream.try_clone().map_err(TransportError::Io)?;
        Ok(Self { stream })
    }

    pub fn connect<A: ToSocketAddrs + std::fmt::Display>(addr: A) -> Result<Self, TransportError> {
        let addr_str = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(|e| TransportError::ConnectFailed {
            addr: addr_str,
            source: e,
        })?;
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    pub fn connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        let addr_str = addr.to_string();
        let addrs: Vec<_> = addr.to_socket_addrs().map_err(|e| TransportError::ConnectFailed {
            addr: addr_str.clone(),
            source: e,
        })?.collect();

        let mut last_err = None;
        for socket_addr in addrs {
            match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Self { stream });
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(TransportError::ConnectFailed {
            addr: addr_str,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No socket address resolved")
            }),
        })
    }
}

impl Connect for TcpTransport {
    type Target = Self;

    fn connect(addr: &str) -> Result<Self::Target, TransportError> {
        TcpTransport::connect(addr)
    }

    fn connect_timeout(addr: &str, timeout: Duration) -> Result<Self::Target, TransportError> {
        TcpTransport::connect_timeout(addr, timeout)
    }
}

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buf)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.stream.flush()
    }
}

impl Transport for TcpTransport {}

impl Transport for Box<dyn Transport + '_> {
    fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> Result<(), TransportError> {
        (**self).send_message(header, payload)
    }
    fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        (**self).recv_message()
    }
    fn try_clone_box(&self) -> Option<Box<dyn Transport>> {
        (**self).try_clone_box()
    }
}

impl TcpTransport {
    /// Boxed clone support for `TcpTransport`
    pub fn try_clone_boxed(&self) -> Option<Box<dyn Transport>> {
        self.try_clone().ok().map(|t| Box::new(t) as Box<dyn Transport>)
    }
}

/// ADB Host Server (port 5037) Transport implementation using 4-byte hex length prefix protocol
pub struct AdbServerTransport {
    stream: TcpStream,
}

impl AdbServerTransport {
    pub fn connect<A: ToSocketAddrs + std::fmt::Display>(addr: A) -> Result<Self, TransportError> {
        let addr_str = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(|e| TransportError::ConnectFailed {
            addr: addr_str,
            source: e,
        })?;
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    pub fn connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        let addr_str = addr.to_string();
        let addrs: Vec<_> = addr.to_socket_addrs().map_err(|e| TransportError::ConnectFailed {
            addr: addr_str.clone(),
            source: e,
        })?.collect();

        let mut last_err = None;
        for socket_addr in addrs {
            match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Self { stream });
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(TransportError::ConnectFailed {
            addr: addr_str,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No socket address resolved")
            }),
        })
    }

    /// Construct from an existing TcpStream
    pub fn from_stream(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self { stream }
    }

    /// Extract inner TcpStream
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// Send a request string prefixed by 4-byte hex ASCII length (e.g. "000ehost:devices-l")
    pub fn send_host_request(&mut self, request: &str) -> Result<(), TransportError> {
        let payload = request.as_bytes();
        let header = format!("{:04x}", payload.len());
        self.stream.write_all(header.as_bytes())?;
        self.stream.write_all(payload)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read status response (4 bytes: OKAY or FAIL). If FAIL, reads hex length + error message.
    pub fn read_status(&mut self) -> Result<(), TransportError> {
        let mut status = [0u8; 4];
        self.stream.read_exact(&mut status)?;
        match &status {
            b"OKAY" => Ok(()),
            b"FAIL" => {
                let mut len_buf = [0u8; 4];
                self.stream.read_exact(&mut len_buf)?;
                let len_str = std::str::from_utf8(&len_buf)
                    .map_err(|_| TransportError::Protocol("Invalid hex length prefix in FAIL response".to_string()))?;
                let len = usize::from_str_radix(len_str, 16)
                    .map_err(|_| TransportError::Protocol(format!("Invalid hex length in FAIL response: {}", len_str)))?;
                let mut err_buf = vec![0u8; len];
                if len > 0 {
                    self.stream.read_exact(&mut err_buf)?;
                }
                let err_msg = String::from_utf8_lossy(&err_buf).to_string();
                Err(TransportError::Protocol(format!("ADB server error: {}", err_msg)))
            }
            other => {
                let s = String::from_utf8_lossy(other);
                Err(TransportError::Protocol(format!("Unexpected ADB server status response: {}", s)))
            }
        }
    }

    /// Read payload string/bytes prefixed by 4-byte hex ASCII length
    pub fn read_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len_str = std::str::from_utf8(&len_buf)
            .map_err(|_| TransportError::Protocol("Invalid hex length prefix".to_string()))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| TransportError::Protocol(format!("Invalid hex length: {}", len_str)))?;
        let mut buf = vec![0u8; len];
        if len > 0 {
            self.stream.read_exact(&mut buf)?;
        }
        Ok(buf)
    }

    /// Execute a host command expecting a data payload (e.g. "host:devices-l", "host:version")
    pub fn execute_host_command(&mut self, request: &str) -> Result<String, TransportError> {
        self.send_host_request(request)?;
        self.read_status()?;
        let payload = self.read_payload()?;
        Ok(String::from_utf8_lossy(&payload).to_string())
    }

    /// Switch connection to a specified host service (e.g. "host:transport:<serial>")
    pub fn switch_service(&mut self, service: &str) -> Result<(), TransportError> {
        self.send_host_request(service)?;
        self.read_status()?;
        Ok(())
    }

    /// Switch connection transport to target device serial or transport-any
    pub fn switch_transport(&mut self, serial: Option<&str>) -> Result<(), TransportError> {
        let req = match serial {
            Some(s) if s.starts_with("host:") => s.to_string(),
            Some(s) => format!("host:transport:{}", s),
            None => "host:transport-any".to_string(),
        };
        self.switch_service(&req)
    }
}

impl Connect for AdbServerTransport {
    type Target = Self;

    fn connect(addr: &str) -> Result<Self::Target, TransportError> {
        AdbServerTransport::connect(addr)
    }

    fn connect_timeout(addr: &str, timeout: Duration) -> Result<Self::Target, TransportError> {
        AdbServerTransport::connect_timeout(addr, timeout)
    }
}

impl Read for AdbServerTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buf)
    }
}

impl Write for AdbServerTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.stream.flush()
    }
}

impl Transport for AdbServerTransport {}

// ---------------------------------------------------------------------------
// TLS Transport wrapper
// ---------------------------------------------------------------------------

/// ADB TLS Transport wrapping a `rustls::StreamOwned` as a `Transport`.
///
/// Created during A_STLS upgrade: wraps the original transport inside a
/// TLS 1.3 encrypted stream. All subsequent ADB message I/O goes through
/// the encrypted channel.
///
/// Only available when the `tls` feature is enabled.
#[cfg(feature = "tls")]
pub struct AdbTlsTransport {
    stream: rustls::StreamOwned<rustls::ClientConnection, Box<dyn Transport>>,
}

#[cfg(feature = "tls")]
impl AdbTlsTransport {
    /// Create a new `AdbTlsTransport` by performing a TLS 1.3 client
    /// handshake over `transport`.
    ///
    /// # Parameters
    /// - `transport`: the underlying ADB transport (e.g. `TcpTransport`).
    /// - `cert_der`: DER-encoded X.509 client certificate.
    /// - `key_der`: DER-encoded private key.
    /// - `server_name`: SNI hostname (use `"adb"`).
    pub fn new(
        transport: Box<dyn Transport>,
        config: std::sync::Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<Self, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| TransportError::Protocol(format!("invalid TLS server name: {server_name}")))?;

        let connection = rustls::ClientConnection::new(config, server_name)
            .map_err(|e| TransportError::Protocol(format!("TLS connection creation failed: {e}")))?;

        let stream = rustls::StreamOwned::new(connection, transport);
        Ok(Self { stream })
    }
}

#[cfg(feature = "tls")]
impl Read for AdbTlsTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buf)
    }
}

#[cfg(feature = "tls")]
impl Write for AdbTlsTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.stream.flush()
    }
}

#[cfg(feature = "tls")]
impl Transport for AdbTlsTransport {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::A_CNXN;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_tcp_transport_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut hdr_buf = [0u8; 24];
            socket.read_exact(&mut hdr_buf).unwrap();
            let hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
            let mut payload = vec![0u8; hdr.data_length as usize];
            socket.read_exact(&mut payload).unwrap();

            // Echo back
            let resp_hdr = AdbMessageHeader::new(A_CNXN, 0, 0, b"OK");
            let mut resp_buf = [0u8; 24];
            resp_hdr.encode(&mut resp_buf);
            socket.write_all(&resp_buf).unwrap();
            socket.write_all(b"OK").unwrap();
        });

        let mut transport = TcpTransport::connect(local_addr.to_string()).unwrap();
        let payload = b"hello adb";
        let hdr = AdbMessageHeader::new(A_CNXN, 1, 2, payload);
        transport.send_message(&hdr, payload).unwrap();

        let (resp_hdr, resp_payload) = transport.recv_message().unwrap();
        assert_eq!(resp_hdr.command, A_CNXN);
        assert_eq!(resp_payload, b"OK");

        handle.join().unwrap();
    }

    #[test]
    fn test_tcp_transport_connect_failure() {
        let res = TcpTransport::connect_timeout("127.0.0.1:59999", Duration::from_millis(200));
        assert!(res.is_err());
        if let Err(TransportError::ConnectFailed { addr, .. }) = res {
            assert!(addr.contains("59999"));
        } else {
            panic!("Expected ConnectFailed error");
        }
    }

    #[test]
    fn test_adb_server_transport_execute_command() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut req_len_buf = [0u8; 4];
            socket.read_exact(&mut req_len_buf).unwrap();
            let len = usize::from_str_radix(std::str::from_utf8(&req_len_buf).unwrap(), 16).unwrap();
            let mut req_buf = vec![0u8; len];
            socket.read_exact(&mut req_buf).unwrap();

            assert_eq!(&req_buf, b"host:devices-l");

            // Send OKAY
            socket.write_all(b"OKAY").unwrap();
            let dev_list = b"emulator-5554 device product:sdk model:sdk\n";
            let resp_len_hdr = format!("{:04x}", dev_list.len());
            socket.write_all(resp_len_hdr.as_bytes()).unwrap();
            socket.write_all(dev_list).unwrap();
        });

        let mut transport = AdbServerTransport::connect(local_addr.to_string()).unwrap();
        let res = transport.execute_host_command("host:devices-l").unwrap();
        assert_eq!(res, "emulator-5554 device product:sdk model:sdk\n");

        handle.join().unwrap();
    }

    #[test]
    fn test_adb_server_transport_fail_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut req_len_buf = [0u8; 4];
            socket.read_exact(&mut req_len_buf).unwrap();
            let len = usize::from_str_radix(std::str::from_utf8(&req_len_buf).unwrap(), 16).unwrap();
            let mut req_buf = vec![0u8; len];
            socket.read_exact(&mut req_buf).unwrap();

            assert_eq!(&req_buf, b"host:transport:nonexistent");

            // Send FAIL + length + error msg
            socket.write_all(b"FAIL").unwrap();
            let err_msg = b"device 'nonexistent' not found";
            let resp_len_hdr = format!("{:04x}", err_msg.len());
            socket.write_all(resp_len_hdr.as_bytes()).unwrap();
            socket.write_all(err_msg).unwrap();
        });

        let mut transport = AdbServerTransport::connect(local_addr.to_string()).unwrap();
        let res = transport.switch_transport(Some("nonexistent"));
        assert!(res.is_err());
        if let Err(TransportError::Protocol(msg)) = res {
            assert!(msg.contains("device 'nonexistent' not found"));
        } else {
            panic!("Expected Protocol error");
        }

        handle.join().unwrap();
    }
}
