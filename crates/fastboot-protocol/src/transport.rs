use std::io::{Read, Write, Result as IoResult};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use crate::response::{FastbootResponse, FastbootResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FastbootTransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Response parse error: {0}")]
    Response(#[from] FastbootResponseError),

    #[error("Connection failed to {addr}: {source}")]
    ConnectFailed {
        addr: String,
        source: std::io::Error,
    },

    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Send, Recv, and I/O abstraction for Fastboot protocol transport
pub trait FastbootTransport: Read + Write + Send {
    /// Send a fastboot command string (e.g., "getvar:all")
    fn send_cmd(&mut self, cmd: &str) -> Result<(), FastbootTransportError> {
        self.write_all(cmd.as_bytes())?;
        self.flush()?;
        Ok(())
    }

    /// Receive a fastboot status response
    fn recv_response(&mut self) -> Result<FastbootResponse, FastbootTransportError> {
        let mut buf = [0u8; 256];
        let n = self.read(&mut buf)?;
        if n == 0 {
            return Err(FastbootTransportError::Protocol(
                "Connection closed by target".to_string(),
            ));
        }
        let resp = FastbootResponse::parse(&buf[..n])?;
        Ok(resp)
    }
}

impl<T: Read + Write + Send> FastbootTransport for T {}

/// Connect trait abstraction for establishing Fastboot transport connections
pub trait Connect {
    type Target: FastbootTransport;
    fn connect(addr: &str) -> Result<Self::Target, FastbootTransportError>;
    fn connect_timeout(addr: &str, timeout: Duration) -> Result<Self::Target, FastbootTransportError>;
}

/// TCP Socket Transport implementation for Fastboot protocol
pub struct FastbootTcpTransport {
    stream: TcpStream,
}

impl FastbootTcpTransport {
    pub fn connect<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(|e| FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: e,
        })?;
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    pub fn connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let addrs: Vec<_> = addr.to_socket_addrs().map_err(|e| {
            FastbootTransportError::ConnectFailed {
                addr: addr_str.clone(),
                source: e,
            }
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

        Err(FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No socket address resolved")
            }),
        })
    }
}

impl Connect for FastbootTcpTransport {
    type Target = Self;

    fn connect(addr: &str) -> Result<Self::Target, FastbootTransportError> {
        FastbootTcpTransport::connect(addr)
    }

    fn connect_timeout(addr: &str, timeout: Duration) -> Result<Self::Target, FastbootTransportError> {
        FastbootTcpTransport::connect_timeout(addr, timeout)
    }
}

impl Read for FastbootTcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buf)
    }
}

impl Write for FastbootTcpTransport {
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
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_fastboot_tcp_transport_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 100];
            let n = socket.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"getvar:version");
            socket.write_all(b"OKAY0.1").unwrap();
        });

        let mut transport = FastbootTcpTransport::connect(local_addr.to_string()).unwrap();
        transport.send_cmd("getvar:version").unwrap();
        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));

        handle.join().unwrap();
    }

    #[test]
    fn test_fastboot_tcp_transport_connect_failure() {
        let res = FastbootTcpTransport::connect_timeout("127.0.0.1:59998", Duration::from_millis(200));
        assert!(res.is_err());
        if let Err(FastbootTransportError::ConnectFailed { addr, .. }) = res {
            assert!(addr.contains("59998"));
        } else {
            panic!("Expected ConnectFailed error");
        }
    }
}
