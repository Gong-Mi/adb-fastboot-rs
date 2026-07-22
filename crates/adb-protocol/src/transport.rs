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
}

/// Send, Recv, and I/O abstraction for ADB protocol transport
pub trait Transport: Read + Write + Send {
    /// Send an ADB message frame (24-byte header + payload)
    fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> Result<(), TransportError> {
        let mut hdr_buf = [0u8; 24];
        header.encode(&mut hdr_buf);
        self.write_all(&hdr_buf)?;
        if !payload.is_empty() {
            self.write_all(payload)?;
        }
        self.flush()?;
        Ok(())
    }

    /// Receive an ADB message frame (24-byte header + payload)
    fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        let mut hdr_buf = [0u8; 24];
        self.read_exact(&mut hdr_buf)?;
        let header = AdbMessageHeader::decode(&hdr_buf)?;
        let mut payload = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            self.read_exact(&mut payload)?;
            header.verify_payload(&payload)?;
        }
        Ok((header, payload))
    }
}

impl<T: Read + Write + Send> Transport for T {}

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
}
