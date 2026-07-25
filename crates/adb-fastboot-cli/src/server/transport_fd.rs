//! Raw file-descriptor transport — wraps a POSIX fd as an ADB `Transport`.
//!
//! Mirrors AOSP `vendor/adb/transport_fd.cpp` (FdConnection, TlsConnection).
//!
//! ## Overview
//!
//! - [`FdTransport`] — wraps a `RawFd` as `Read + Write + Transport`, using
//!   `libc::read` / `libc::write` syscalls.  The fd is *borrowed* by default
//!   (not closed on drop); call [`FdTransport::set_close_on_drop`] or use
//!   [`FdTransport::from_owned`] to take ownership.
//!
//! - [`TlsFdConnection`] — wraps an `FdTransport` (as `Box<dyn Transport>`)
//!   inside a TLS 1.3 encrypted stream (only with `--features tls`).
//!
//! - [`read_exact_fd`] / [`write_all_fd`] — raw fd read/write helpers that
//!   match AOSP's `ReadOrderly` / `WriteOrderly` semantics: retry on EINTR,
//!   handle partial reads/writes, and translate EAGAIN/EWOULDBLOCK to
//!   `WouldBlock` errors.
//!
//! ## AOSP correspondence
//!
//! | AOSP | Rust |
//! |------|------|
//! | `FdConnection::Read(void*, size_t)` | `read_exact_fd()` / `Read::read_exact()` |
//! | `FdConnection::Write(const void*, size_t)` | `write_all_fd()` / `Write::write_all()` |
//! | `TlsConnection` (wraps FdConnection) | [`TlsFdConnection`] (wraps FdTransport via AdbTlsTransport) |
//! | `FdConnection::Close()` | `FdTransport` dropped or explicitly closed |

use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;
use std::time::Duration;

use adb_protocol::{AdbMessageHeader, Transport, TransportError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reconnect / retry configuration (used by the module-level helpers).
const FD_READ_TIMEOUT: Duration = Duration::from_secs(30);
const FD_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Raw fd read/write helpers (match AOSP ReadOrderly / WriteOrderly)
// ---------------------------------------------------------------------------

/// Read exactly `buf.len()` bytes from `fd`, retrying on EINTR and handling
/// partial reads.  Returns `WouldBlock` if the fd is non-blocking and no data
/// is available; returns `UnexpectedEof` if the remote end closes the
/// connection before the buffer is filled.
///
/// Mirrors AOSP `ReadOrderly(FdConnection*, void*, size_t)`.
pub(crate) fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    let len = buf.len();
    while offset < len {
        // Safety: libc::read is safe to call with a valid fd and buffer.
        let result = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(offset) as *mut libc::c_void,
                len - offset,
            )
        };
        if result < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("read fd {fd} would block"),
                    ));
                }
                _ => return Err(err),
            }
        } else if result == 0 {
            // EOF — remote closed the connection before the full read
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read fd {fd}: unexpected EOF after {} of {} bytes",
                    offset,
                    len
                ),
            ));
        } else {
            offset += result as usize;
        }
    }
    Ok(())
}

/// Write exactly `buf.len()` bytes to `fd`, retrying on EINTR and handling
/// partial writes.  Mirrors AOSP `WriteOrderly(FdConnection*, const void*, size_t)`.
pub(crate) fn write_all_fd(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    let len = buf.len();
    while offset < len {
        // Safety: libc::write is safe to call with a valid fd and buffer.
        let result = unsafe {
            libc::write(
                fd,
                buf.as_ptr().add(offset) as *const libc::c_void,
                len - offset,
            )
        };
        if result < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("write fd {fd} would block"),
                    ));
                }
                _ => return Err(err),
            }
        } else if result == 0 {
            // Zero-length write on a non-blocking fd — return WouldBlock
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("write fd {fd} returned 0"),
            ));
        } else {
            offset += result as usize;
        }
    }
    Ok(())
}

/// Attempt a single non-blocking read from `fd`.  Returns `Ok(0)` on EOF.
/// Mirrors AOSP `FdConnection::Read(void*, size_t)` for the non-exact case.
pub(crate) fn read_some_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // Safety: libc::read is safe to call with a valid fd and buffer.
        let result = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(result as usize);
    }
}

// ---------------------------------------------------------------------------
// FdTransport
// ---------------------------------------------------------------------------

/// A raw file-descriptor transport that implements `Read + Write + Transport`
/// using POSIX `read()` / `write()` syscalls.
///
/// By default the fd is *borrowed* — dropping this transport does **not**
/// close the fd.  Call [`FdTransport::set_close_on_drop`] or use
/// [`FdTransport::from_owned`] to enable ownership semantics.
///
/// # Example
///
/// ```ignore
/// use adb_protocol::Transport;
/// let fd = open_device_socket();
/// let mut transport = FdTransport::from_owned(fd);
/// transport.send_message(&header, b"payload").unwrap();
/// ```
pub(crate) struct FdTransport {
    /// The raw file descriptor.
    fd: RawFd,
    /// If `true`, the fd is closed when this transport is dropped.
    close_on_drop: bool,
}

impl FdTransport {
    /// Wrap a borrowed file descriptor.  The caller is responsible for
    /// closing the fd when it is no longer needed.
    pub(crate) fn new(fd: RawFd) -> Self {
        Self {
            fd,
            close_on_drop: false,
        }
    }

    /// Wrap an owned file descriptor — the fd will be closed on drop.
    pub(crate) fn from_owned(fd: RawFd) -> Self {
        Self {
            fd,
            close_on_drop: true,
        }
    }

    /// Control whether the fd is closed when this transport is dropped.
    pub(crate) fn set_close_on_drop(&mut self, close: bool) {
        self.close_on_drop = close;
    }

    /// Borrow the raw file descriptor.
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Consume the transport and return the raw fd.
    /// The fd is no longer owned by the transport and will **not** be closed.
    pub(crate) fn into_raw_fd(mut self) -> RawFd {
        self.close_on_drop = false;
        self.fd
    }

    /// Read a single ADB message frame from the raw fd.
    /// Equivalent to AOSP `FdConnection::Read(header_24 + payload)`.
    pub(crate) fn read_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        let mut hdr_buf = [0u8; 24];
        read_exact_fd(self.fd, &mut hdr_buf)?;
        let header = AdbMessageHeader::decode(&hdr_buf)?;

        // AOSP: reject payloads larger than MAX_PAYLOAD_V2
        if header.data_length > adb_protocol::constants::MAX_PAYLOAD_V2 {
            return Err(TransportError::Protocol(format!(
                "Payload too large: {} bytes (max {})",
                header.data_length,
                adb_protocol::constants::MAX_PAYLOAD_V2
            )));
        }

        let mut payload = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            read_exact_fd(self.fd, &mut payload)?;
            header.verify_payload(&payload)?;
        }
        Ok((header, payload))
    }

    /// Write a single ADB message frame to the raw fd.
    /// Equivalent to AOSP `FdConnection::Write(header_24 + payload)`.
    pub(crate) fn write_message(
        &mut self,
        header: &AdbMessageHeader,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        let mut hdr_buf = [0u8; 24];
        header.encode(&mut hdr_buf);
        write_all_fd(self.fd, &hdr_buf)?;
        if !payload.is_empty() {
            write_all_fd(self.fd, payload)?;
        }
        Ok(())
    }
}

// SAFETY: FdTransport only holds a simple integer fd and does not share it
// across threads unsafely.  The caller must ensure exclusive access when
// reading/writing the same fd from multiple threads (typically via Arc<Mutex<>>).
unsafe impl Send for FdTransport {}
unsafe impl Sync for FdTransport {}

impl Drop for FdTransport {
    fn drop(&mut self) {
        if self.close_on_drop {
            // Safety: libc::close is safe with a valid fd.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Read for FdTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_some_fd(self.fd, buf)
    }
}

impl Write for FdTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // libc::write on a blocking fd may perform a partial write.
        // We mirror AOSP behaviour by attempting a single write syscall.
        loop {
            let result = unsafe {
                libc::write(
                    self.fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            };
            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(result as usize);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // For socket fds, flush is a no-op.  For regular files / pipes,
        // we could call fsync, but ADB transports are typically sockets.
        Ok(())
    }
}

impl Transport for FdTransport {
    fn send_message(
        &mut self,
        header: &AdbMessageHeader,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.write_message(header, payload)
    }

    fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        self.read_message()
    }

    fn try_clone_box(&self) -> Option<Box<dyn Transport>> {
        // Raw fds cannot be cloned without dup(); return None by default.
        // Callers that need a clone should use FdTransport::dup() first.
        None
    }
}

impl FdTransport {
    /// Duplicate the underlying fd via `libc::dup()` and return a new
    /// `FdTransport` that owns the duplicate.
    pub(crate) fn try_dup(&self) -> io::Result<Self> {
        let new_fd = unsafe { libc::dup(self.fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: new_fd,
            close_on_drop: true,
        })
    }

    /// Duplicate the fd and return a boxed Transport.
    pub(crate) fn try_clone_boxed(&self) -> Option<Box<dyn Transport>> {
        self.try_dup().ok().map(|t| Box::new(t) as Box<dyn Transport>)
    }
}

// ---------------------------------------------------------------------------
// TlsFdConnection — TLS 1.3 encrypted wrapper over FdTransport
// ---------------------------------------------------------------------------

/// TLS 1.3 encrypted transport over a raw fd.
///
/// Wraps an `FdTransport` inside a TLS 1.3 stream (via
/// `adb_protocol::transport::AdbTlsTransport`).  All ADB message I/O is
/// transparently encrypted.
///
/// Only available when the `tls` feature is enabled.
///
/// Mirrors AOSP `TlsConnection` (which wraps `FdConnection` inside a
/// BoringSSL `SSL` object, plus AOSP-specific pairing-key export).
#[cfg(feature = "tls")]
pub(crate) struct TlsFdConnection {
    /// The underlying TLS transport.
    inner: adb_protocol::AdbTlsTransport,
}

#[cfg(feature = "tls")]
impl TlsFdConnection {
    /// Create a new `TlsFdConnection` by wrapping `transport` inside a
    /// TLS 1.3 client connection.
    ///
    /// # Parameters
    /// - `fd_transport`: the raw fd transport to wrap.
    /// - `config`: TLS client configuration (from
    ///   `adb_protocol::tls::create_tls_config`).
    /// - `server_name`: SNI hostname (use `"adb"`).
    pub(crate) fn new(
        fd_transport: FdTransport,
        config: std::sync::Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<Self, TransportError> {
        let tls = adb_protocol::AdbTlsTransport::new(
            Box::new(fd_transport),
            config,
            server_name,
        )?;
        Ok(Self { inner: tls })
    }

    /// Create from an already-boxed transport (for use in generic TLS
    /// upgrade paths).
    pub(crate) fn from_boxed(
        transport: Box<dyn Transport>,
        config: std::sync::Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<Self, TransportError> {
        let tls = adb_protocol::AdbTlsTransport::new(transport, config, server_name)?;
        Ok(Self { inner: tls })
    }

    /// Read a single ADB message frame through the TLS layer.
    pub(crate) fn read_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        self.inner.recv_message()
    }

    /// Write a single ADB message frame through the TLS layer.
    pub(crate) fn write_message(
        &mut self,
        header: &AdbMessageHeader,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.inner.send_message(header, payload)
    }

    /// Get a reference to the inner TLS transport.
    pub(crate) fn inner(&self) -> &adb_protocol::AdbTlsTransport {
        &self.inner
    }

    /// Get a mutable reference to the inner TLS transport.
    pub(crate) fn inner_mut(&mut self) -> &mut adb_protocol::AdbTlsTransport {
        &mut self.inner
    }
}

#[cfg(feature = "tls")]
impl Read for TlsFdConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(feature = "tls")]
impl Write for TlsFdConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(feature = "tls")]
impl Transport for TlsFdConnection {
    fn send_message(
        &mut self,
        header: &AdbMessageHeader,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.inner.send_message(header, payload)
    }

    fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
        self.inner.recv_message()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::{AdbMessageHeader, A_CNXN, MAX_PAYLOAD_V2};

    /// Helper: create a connected pair of raw fds (socketpair).
    fn socket_pair() -> (RawFd, RawFd) {
        let mut fds = [-1i32; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed");
        (fds[0], fds[1])
    }

    #[test]
    fn test_fd_transport_send_recv() {
        let (fd_a, fd_b) = socket_pair();
        let mut tx = FdTransport::from_owned(fd_a);
        let mut rx = FdTransport::from_owned(fd_b);

        let payload = b"hello adb";
        let header = AdbMessageHeader::new(A_CNXN, 0x01000001, MAX_PAYLOAD_V2, payload);

        tx.send_message(&header, payload).unwrap();
        let (recv_hdr, recv_payload) = rx.recv_message().unwrap();

        assert_eq!(recv_hdr.command, A_CNXN);
        assert_eq!(recv_hdr.arg0, 0x01000001);
        assert_eq!(recv_hdr.arg1, MAX_PAYLOAD_V2);
        assert_eq!(&recv_payload, payload);
    }

    #[test]
    fn test_read_exact_fd_partial() {
        let (fd_a, fd_b) = socket_pair();
        let mut buf = [0u8; 10];

        // Write only 5 bytes
        let data = b"hello";
        unsafe {
            libc::write(fd_a, data.as_ptr() as *const libc::c_void, data.len());
        }

        // read_exact_fd should return WouldBlock (or we read 5 and wait for more)
        // Since the socket is blocking by default, this will block waiting for
        // more data.  Use non-blocking mode for the test.
        unsafe {
            let flags = libc::fcntl(fd_b, libc::F_GETFL, 0);
            libc::fcntl(fd_b, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let result = read_exact_fd(fd_b, &mut buf);
        assert!(
            result.is_err(),
            "non-blocking read with insufficient data should fail"
        );

        unsafe {
            libc::close(fd_a);
            libc::close(fd_b);
        }
    }

    #[test]
    fn test_write_all_fd() {
        let (fd_a, fd_b) = socket_pair();
        let data = b"test write_all";

        write_all_fd(fd_a, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        read_exact_fd(fd_b, &mut buf).unwrap();
        assert_eq!(&buf, data);

        unsafe {
            libc::close(fd_a);
            libc::close(fd_b);
        }
    }

    #[test]
    fn test_fd_transport_zero_payload() {
        let (fd_a, fd_b) = socket_pair();
        let mut tx = FdTransport::from_owned(fd_a);
        let mut rx = FdTransport::from_owned(fd_b);

        let header = AdbMessageHeader::new(A_CNXN, 0, 0, b"");

        tx.send_message(&header, b"").unwrap();
        let (recv_hdr, recv_payload) = rx.recv_message().unwrap();

        assert_eq!(recv_hdr.command, A_CNXN);
        assert!(recv_payload.is_empty());
    }

    #[test]
    fn test_fd_transport_close_on_drop() {
        let (fd_a, fd_b) = socket_pair();

        // fd_b should be closed when dropped
        {
            let _transport = FdTransport::from_owned(fd_b);
        }

        // Writing to fd_a should now fail (SIGPIPE or EPIPE on Linux)
        let result = unsafe {
            libc::write(fd_a, b"x".as_ptr() as *const libc::c_void, 1)
        };
        assert!(result < 0, "write to closed fd should fail");

        unsafe { libc::close(fd_a); }
    }

    #[test]
    fn test_fd_transport_try_dup() {
        let (fd_a, _fd_b) = socket_pair();
        let transport = FdTransport::new(fd_a);
        let dup = transport.try_dup().unwrap();
        assert_ne!(dup.as_raw_fd(), fd_a);
        assert!(dup.as_raw_fd() > 0);

        unsafe { libc::close(fd_a); }
        unsafe { libc::close(dup.as_raw_fd()); }
    }

    #[test]
    fn test_read_some_fd_basic() {
        let (fd_a, fd_b) = socket_pair();
        let data = b"partial";
        unsafe {
            libc::write(fd_a, data.as_ptr() as *const libc::c_void, data.len());
        }

        let mut buf = [0u8; 32];
        let n = read_some_fd(fd_b, &mut buf).unwrap();
        assert_eq!(&buf[..n], data);

        unsafe { libc::close(fd_a); }
        unsafe { libc::close(fd_b); }
    }
}
