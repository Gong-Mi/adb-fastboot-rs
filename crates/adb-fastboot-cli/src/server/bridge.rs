//! TCP service bridges use a fresh connection per client (existing design).
//! All service frame I/O belongs to smart_socket's single duplex owner.
use crate::server::models::TransportRegistry;
use adb_protocol::Transport;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub(crate) fn bridge_to_device(
    client: std::net::TcpStream,
    serial: String,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<bool, String> {
    let running = std::sync::atomic::AtomicBool::new(true);
    crate::server::smart_socket::bridge_to_device_with_smart(client, &serial, registry, &running)?;
    // A service finishing does not disconnect the registered monitor transport.
    Ok(true)
}

/// Share production CNXN/AUTH/STLS/TLS implementation; never downgrade TLS.
pub(crate) fn tcp_auth_handshake(
    transport: Box<dyn Transport>,
    _serial: &str,
) -> Result<Box<dyn Transport>, String> {
    authenticated_tcp(transport).map(|(_, transport)| transport)
}

pub(crate) fn authenticated_tcp(
    mut transport: Box<dyn Transport>,
) -> Result<(crate::client::transport::DeviceInfo, Box<dyn Transport>), String> {
    let socket = transport
        .inner_tcp_mut()
        .ok_or("TCP handshake requires a TCP socket")?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let auth = crate::client::auth::default_auth();
    let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let bounded = HandshakeDeadline {
        transport,
        active: Arc::clone(&active),
        until: std::time::Instant::now() + std::time::Duration::from_secs(5),
    };
    let result = crate::client::transport::connect_and_handshake_with_tls_upgrade(
        bounded,
        &adb_protocol::host_cnxn_payload(),
        auth,
    )
    .map_err(|e| e.to_string());
    active.store(false, std::sync::atomic::Ordering::Release);
    let (info, mut transport) = result?;
    let socket = transport
        .inner_tcp_mut()
        .ok_or("handshake lost TCP socket controls")?;
    socket.set_read_timeout(None).map_err(|e| e.to_string())?;
    socket.set_write_timeout(None).map_err(|e| e.to_string())?;
    Ok((info, transport))
}

// An absolute budget, not a fresh five-second budget per read_exact fragment.
// TLS keeps this wrapper after upgrade; disarm after the shared handshake so
// a silent registry monitor is not falsely marked offline five seconds later.
struct HandshakeDeadline {
    transport: Box<dyn Transport>,
    active: Arc<std::sync::atomic::AtomicBool>,
    until: std::time::Instant,
}
impl HandshakeDeadline {
    fn budget(&mut self) -> std::io::Result<()> {
        if !self.active.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let left = self
            .until
            .checked_duration_since(std::time::Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "server handshake deadline")
            })?;
        let socket = self
            .transport
            .inner_tcp_mut()
            .ok_or_else(|| std::io::Error::other("missing TCP socket"))?;
        socket.set_read_timeout(Some(left))?;
        socket.set_write_timeout(Some(left))
    }
}
impl Read for HandshakeDeadline {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.budget()?;
        self.transport.read(bytes)
    }
}
impl Write for HandshakeDeadline {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.budget()?;
        self.transport.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.budget()?;
        self.transport.flush()
    }
}
impl Transport for HandshakeDeadline {
    fn inner_tcp_mut(&mut self) -> Option<&mut std::net::TcpStream> {
        self.transport.inner_tcp_mut()
    }
}
