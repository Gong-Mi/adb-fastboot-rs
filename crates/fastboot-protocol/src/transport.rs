use std::io::{Read, Write, Result as IoResult};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use crate::response::{FastbootResponse, FastbootResponseError};
use thiserror::Error;

/// Timeout for the FB01 handshake read — brief so vendor devices
/// that don't support the handshake fall back to raw mode quickly.
const FB_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum allowed payload size for LengthPrefixed mode (1GB) to prevent OOM vulnerabilities
pub const MAX_LENGTH_PREFIXED_PAYLOAD: usize = 1024 * 1024 * 1024;

/// Operating mode for the TCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FbMode {
    /// Raw fastboot protocol: commands/responses sent directly over TCP.
    Raw,
    /// AOSP length-prefixed protocol: every message is wrapped with
    /// an 8-byte big-endian length prefix (confirmed via FB01 handshake).
    LengthPrefixed,
}

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

// Valid 4-byte fastboot response prefixes
const FB_PREFIXES: &[&[u8; 4]] = &[b"OKAY", b"FAIL", b"DATA", b"INFO", b"TEXT"];

fn is_fb_prefix(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    FB_PREFIXES.iter().any(|p| &buf[..4] == *p)
}

fn is_partial_prefix(buf: &[u8]) -> bool {
    if buf.is_empty() || buf.len() >= 4 {
        return false;
    }
    FB_PREFIXES.iter().any(|p| p.starts_with(buf))
}

/// Parse one complete fastboot response from a buffer.
/// Returns the response and the number of bytes consumed.
/// For OKAY/FAIL/INFO/TEXT: scans ahead in the buffer to find the next
/// valid prefix (or partial prefix) which ends the current response's body.
fn parse_one_response(buf: &[u8]) -> Result<(FastbootResponse, usize), FastbootResponseError> {
    if buf.len() < 4 {
        return Err(FastbootResponseError::TooShort);
    }
    let prefix = match std::str::from_utf8(&buf[0..4]) {
        Ok(p) => p,
        Err(_) => return Err(FastbootResponseError::UnknownPrefix(format!("{:?}", &buf[0..4]))),
    };

    match prefix {
        "DATA" => {
            if buf.len() < 12 {
                return Err(FastbootResponseError::TooShort);
            }
            let resp = FastbootResponse::parse(&buf[..12])?;
            Ok((resp, 12))
        }
        "OKAY" | "FAIL" | "INFO" | "TEXT" => {
            let body = &buf[4..];
            let mut body_end = None;

            // Scan body for the next valid 4-byte prefix
            for i in 0..body.len().saturating_sub(3) {
                if is_fb_prefix(&body[i..]) {
                    body_end = Some(i);
                    break;
                }
            }

            // If no full prefix found, check if body ends with a partial prefix (1..3 bytes)
            if body_end.is_none() {
                for j in body.len().saturating_sub(3)..body.len() {
                    if is_partial_prefix(&body[j..]) {
                        body_end = Some(j);
                        break;
                    }
                }
            }

            let end = body_end.unwrap_or(body.len());
            let total = 4 + end;
            let resp = FastbootResponse::parse(&buf[..total])?;
            Ok((resp, total))
        }
        _ => Err(FastbootResponseError::UnknownPrefix(prefix.to_string())),
    }
}

/// Send, Recv, and I/O abstraction for Fastboot protocol transport
pub trait FastbootTransport: Read + Write + Send {
    /// Send a fastboot command string (e.g., "getvar:all")
    ///
    /// AOSP fastboot protocol limit: `FB_COMMAND_SZ = 4096`.
    fn send_cmd(&mut self, cmd: &str) -> Result<(), FastbootTransportError> {
        if cmd.len() > 4096 {
            return Err(FastbootTransportError::Protocol(format!(
                "Command too long: {} bytes (max 4096)",
                cmd.len()
            )));
        }
        self.write_all(cmd.as_bytes())?;
        self.flush()?;
        Ok(())
    }

    /// Receive a fastboot status response, automatically handling INFO/TEXT loops
    fn recv_response(&mut self) -> Result<FastbootResponse, FastbootTransportError> {
        let mut info_logs = Vec::new();
        self.recv_response_with_info(&mut info_logs)
    }

    /// Receive response with accumulated INFO/TEXT log output.
    ///
    /// Reads chunks into an internal accumulation buffer and parses out complete responses
    /// one at a time. Handles stream buffers cleanly without dropping bytes on partial reads
    /// or looping infinitely on non-prefix bytes.
    fn recv_response_with_info(
        &mut self,
        info_logs: &mut Vec<String>,
    ) -> Result<FastbootResponse, FastbootTransportError> {
        let mut accum = Vec::new();
        let mut tmp = [0u8; 4096];

        loop {
            loop {
                if accum.is_empty() {
                    break;
                }

                if !is_fb_prefix(&accum) {
                    let mut found_prefix_pos = None;
                    for i in 1..accum.len() {
                        if is_fb_prefix(&accum[i..]) {
                            found_prefix_pos = Some(i);
                            break;
                        }
                    }

                    if let Some(pos) = found_prefix_pos {
                        accum.drain(..pos);
                    } else {
                        let mut partial_pos = None;
                        for j in 0..accum.len() {
                            if accum.len() - j < 4 && is_partial_prefix(&accum[j..]) {
                                partial_pos = Some(j);
                                break;
                            }
                        }

                        if let Some(pos) = partial_pos {
                            accum.drain(..pos);
                        } else {
                            accum.clear();
                        }
                        break;
                    }
                }

                match parse_one_response(&accum) {
                    Ok((resp, consumed)) => {
                        accum.drain(..consumed);
                        match resp {
                            FastbootResponse::Info(ref msg) => {
                                info_logs.push(msg.clone());
                            }
                            FastbootResponse::Text(ref msg) => {
                                info_logs.push(msg.clone());
                            }
                            final_resp => return Ok(final_resp),
                        }
                    }
                    Err(FastbootResponseError::TooShort) => {
                        break;
                    }
                    Err(_) => {
                        accum.remove(0);
                    }
                }
            }

            let n = self.read(&mut tmp)?;
            if n == 0 {
                return Err(FastbootTransportError::Protocol(
                    "Connection closed by target".to_string(),
                ));
            }
            accum.extend_from_slice(&tmp[..n]);
        }
    }
}

impl<T: Read + Write + Send> FastbootTransport for T {}

/// Connect trait abstraction for establishing Fastboot transport connections
pub trait Connect {
    type Target: FastbootTransport;
    fn connect(addr: &str) -> Result<Self::Target, FastbootTransportError>;
    fn connect_timeout(
        addr: &str,
        timeout: Duration,
    ) -> Result<Self::Target, FastbootTransportError>;
}

/// TCP Socket Transport implementation for Fastboot protocol
///
/// Supports two modes:
/// - **Raw**: commands/responses sent directly over TCP (legacy/vendor devices).
/// - **LengthPrefixed**: AOSP standard fastboot TCP protocol with FB01 handshake
///   and 8-byte big-endian length prefix wrapping.
///
/// Mode is auto-detected during `connect`/`connect_timeout` via the FB01 handshake.
/// Use `raw_connect`/`raw_connect_timeout` to skip the handshake for vendor devices.
pub struct FastbootTcpTransport {
    stream: TcpStream,
    mode: FbMode,
    /// Buffer for storing leftover data (e.g. bytes read during handshake that
    /// turned out to be raw fastboot responses, or partially-consumed
    /// length-prefixed message payloads).
    read_buf: Vec<u8>,
    /// Current read position within `read_buf`.
    read_pos: usize,
}

impl FastbootTcpTransport {
    /// Perform the FB01 handshake to detect the protocol mode.
    ///
    /// Sends "FB01" (4 bytes), then attempts to read a 4-byte response
    /// with a short timeout (500ms).
    ///
    /// If the response starts with "FB" → LengthPrefixed mode.
    /// If the response is a raw fastboot prefix (OKAY/FAIL/INFO/DATA/TEXT)
    /// → Raw mode. Any additional bytes already buffered by the TCP stack
    /// are drained and returned as leftover so the caller can serve them
    /// on the first `read()` call. This handles the case where a device
    /// that doesn't understand FB01 replies with a complete raw fastboot
    /// response (e.g. "OKAYdevice_found") in a single TCP segment.
    ///
    /// Returns the detected mode and any leftover bytes to buffer.
    fn perform_handshake(stream: &mut TcpStream) -> (FbMode, Vec<u8>) {
        let _ = stream.set_nodelay(true);

        // Send "FB01" handshake (4 bytes)
        if stream.write_all(b"FB01").is_err() {
            return (FbMode::Raw, vec![]);
        }

        // Save original read timeout, set a short one for the handshake
        let orig_timeout = stream.read_timeout().ok().flatten();
        let _ = stream.set_read_timeout(Some(FB_HANDSHAKE_TIMEOUT));

        let (mode, leftover) = (|| {
            let mut handshake_buf = [0u8; 4];
            let mut bytes_read = 0;

            while bytes_read < 4 {
                match stream.read(&mut handshake_buf[bytes_read..]) {
                    Ok(0) => break,
                    Ok(n) => bytes_read += n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }

            if bytes_read >= 2 && &handshake_buf[..2] == b"FB" {
                (FbMode::LengthPrefixed, vec![])
            } else if bytes_read >= 4 && is_fb_prefix(&handshake_buf) {
                // Raw fastboot response — drain any additional bytes already buffered in TCP socket
                let _ = stream.set_read_timeout(Some(Duration::from_millis(10)));
                let mut extra = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => extra.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }

                let mut buf = handshake_buf.to_vec();
                buf.extend_from_slice(&extra);
                (FbMode::Raw, buf)
            } else if bytes_read > 0 {
                (FbMode::Raw, handshake_buf[..bytes_read].to_vec())
            } else {
                (FbMode::Raw, vec![])
            }
        })();

        let _ = stream.set_read_timeout(orig_timeout);
        (mode, leftover)
    }

    /// Create a new transport, optionally performing the FB01 handshake.
    fn new_internal(stream: TcpStream, with_handshake: bool) -> Self {
        if with_handshake {
            let mut stream = stream;
            let (mode, leftover) = Self::perform_handshake(&mut stream);
            Self {
                stream,
                mode,
                read_buf: leftover,
                read_pos: 0,
            }
        } else {
            let _ = stream.set_nodelay(true);
            Self {
                stream,
                mode: FbMode::Raw,
                read_buf: vec![],
                read_pos: 0,
            }
        }
    }

    /// Connect to a fastboot TCP endpoint, auto-detecting the protocol mode
    /// via the FB01 handshake.
    pub fn connect<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(|e| FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: e,
        })?;
        Ok(Self::new_internal(stream, true))
    }

    /// Connect to a fastboot TCP endpoint with a connection timeout,
    /// auto-detecting the protocol mode via the FB01 handshake.
    pub fn connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .map_err(|e| FastbootTransportError::ConnectFailed {
                addr: addr_str.clone(),
                source: e,
            })?
            .collect();

        let mut last_err = None;
        for socket_addr in addrs {
            match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => {
                    return Ok(Self::new_internal(stream, true));
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No socket address resolved",
                )
            }),
        })
    }

    /// Connect in raw mode (no FB01 handshake). Use for vendor devices
    /// that expect raw fastboot over TCP (e.g. MTK, Qualcomm EDL).
    pub fn raw_connect<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(|e| FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: e,
        })?;
        Ok(Self::new_internal(stream, false))
    }

    /// Connect in raw mode with a connection timeout (no FB01 handshake).
    pub fn raw_connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .map_err(|e| FastbootTransportError::ConnectFailed {
                addr: addr_str.clone(),
                source: e,
            })?
            .collect();

        let mut last_err = None;
        for socket_addr in addrs {
            match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => {
                    return Ok(Self::new_internal(stream, false));
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(FastbootTransportError::ConnectFailed {
            addr: addr_str,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No socket address resolved",
                )
            }),
        })
    }

    /// Returns the current mode of the transport.
    pub fn mode(&self) -> &'static str {
        match self.mode {
            FbMode::Raw => "raw",
            FbMode::LengthPrefixed => "length-prefixed",
        }
    }

    /// Receive response with accumulated INFO/TEXT log output, preserving leftover unparsed data in internal buffer.
    pub fn recv_response_with_info(
        &mut self,
        info_logs: &mut Vec<String>,
    ) -> Result<FastbootResponse, FastbootTransportError> {
        let mut accum = Vec::new();
        if self.read_pos < self.read_buf.len() {
            accum.extend_from_slice(&self.read_buf[self.read_pos..]);
            self.read_buf.clear();
            self.read_pos = 0;
        }

        let mut tmp = [0u8; 4096];

        loop {
            loop {
                if accum.is_empty() {
                    break;
                }

                if !is_fb_prefix(&accum) {
                    let mut found_prefix_pos = None;
                    for i in 1..accum.len() {
                        if is_fb_prefix(&accum[i..]) {
                            found_prefix_pos = Some(i);
                            break;
                        }
                    }

                    if let Some(pos) = found_prefix_pos {
                        accum.drain(..pos);
                    } else {
                        let mut partial_pos = None;
                        for j in 0..accum.len() {
                            if accum.len() - j < 4 && is_partial_prefix(&accum[j..]) {
                                partial_pos = Some(j);
                                break;
                            }
                        }

                        if let Some(pos) = partial_pos {
                            accum.drain(..pos);
                        } else {
                            accum.clear();
                        }
                        break;
                    }
                }

                match parse_one_response(&accum) {
                    Ok((resp, consumed)) => {
                        accum.drain(..consumed);
                        match resp {
                            FastbootResponse::Info(ref msg) => {
                                info_logs.push(msg.clone());
                            }
                            FastbootResponse::Text(ref msg) => {
                                info_logs.push(msg.clone());
                            }
                            final_resp => {
                                if !accum.is_empty() {
                                    self.read_buf = accum;
                                    self.read_pos = 0;
                                }
                                return Ok(final_resp);
                            }
                        }
                    }
                    Err(FastbootResponseError::TooShort) => {
                        break;
                    }
                    Err(_) => {
                        accum.remove(0);
                    }
                }
            }

            let n = self.read(&mut tmp)?;
            if n == 0 {
                return Err(FastbootTransportError::Protocol(
                    "Connection closed by target".to_string(),
                ));
            }
            accum.extend_from_slice(&tmp[..n]);
        }
    }

    /// Receive a fastboot status response, automatically handling INFO/TEXT loops
    pub fn recv_response(&mut self) -> Result<FastbootResponse, FastbootTransportError> {
        let mut info_logs = Vec::new();
        self.recv_response_with_info(&mut info_logs)
    }
}

impl Connect for FastbootTcpTransport {
    type Target = Self;

    fn connect(addr: &str) -> Result<Self::Target, FastbootTransportError> {
        FastbootTcpTransport::connect(addr)
    }

    fn connect_timeout(
        addr: &str,
        timeout: Duration,
    ) -> Result<Self::Target, FastbootTransportError> {
        FastbootTcpTransport::connect_timeout(addr, timeout)
    }
}

impl Read for FastbootTcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.mode {
            FbMode::Raw => {
                // If we have buffered data (from handshake or prior partial reads),
                // serve from buffer first
                if self.read_pos < self.read_buf.len() {
                    let n =
                        std::cmp::min(buf.len(), self.read_buf.len() - self.read_pos);
                    buf[..n].copy_from_slice(
                        &self.read_buf[self.read_pos..self.read_pos + n],
                    );
                    self.read_pos += n;
                    if self.read_pos >= self.read_buf.len() {
                        self.read_buf.clear();
                        self.read_pos = 0;
                    }
                    return Ok(n);
                }
                self.stream.read(buf)
            }
            FbMode::LengthPrefixed => {
                // Serve from internal buffer first
                if self.read_pos < self.read_buf.len() {
                    let n =
                        std::cmp::min(buf.len(), self.read_buf.len() - self.read_pos);
                    buf[..n].copy_from_slice(
                        &self.read_buf[self.read_pos..self.read_pos + n],
                    );
                    self.read_pos += n;
                    if self.read_pos >= self.read_buf.len() {
                        self.read_buf.clear();
                        self.read_pos = 0;
                    }
                    return Ok(n);
                }

                // Read 8-byte big-endian length prefix
                let mut len_buf = [0u8; 8];
                self.stream.read_exact(&mut len_buf)?;
                let msg_len = u64::from_be_bytes(len_buf) as usize;

                if msg_len > MAX_LENGTH_PREFIXED_PAYLOAD {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "LengthPrefixed payload size {} exceeds maximum allowed limit ({})",
                            msg_len, MAX_LENGTH_PREFIXED_PAYLOAD
                        ),
                    ));
                }

                // Read the message payload
                self.read_buf.resize(msg_len, 0);
                self.stream.read_exact(&mut self.read_buf)?;
                self.read_pos = 0;

                // Copy to caller's buffer
                let n = std::cmp::min(buf.len(), msg_len);
                buf[..n].copy_from_slice(&self.read_buf[..n]);
                self.read_pos = n;
                // Don't clear buffer — subsequent reads consume more
                Ok(n)
            }
        }
    }
}

impl Write for FastbootTcpTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match self.mode {
            FbMode::Raw => self.stream.write(buf),
            FbMode::LengthPrefixed => {
                // Prepend 8-byte big-endian length
                let len_buf = (buf.len() as u64).to_be_bytes();
                self.stream.write_all(&len_buf)?;
                self.stream.write_all(buf)?;
                Ok(buf.len())
            }
        }
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

    /// Test raw fastboot send/recv (no FB01 handshake).
    /// This is the primary mode for vendor devices.
    #[test]
    fn test_fastboot_tcp_transport_send_recv_raw() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 100];
            let n = socket.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"getvar:version");
            socket.write_all(b"OKAY0.1").unwrap();
        });

        let mut transport =
            FastbootTcpTransport::raw_connect(local_addr.to_string()).unwrap();
        transport.send_cmd("getvar:version").unwrap();
        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));

        handle.join().unwrap();
    }

    /// Test that FB01 handshake auto-detects length-prefixed mode when
    /// the server responds "FB01".
    #[test]
    fn test_fb01_handshake_detects_length_prefixed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Read the FB01 handshake
            let mut handshake_buf = [0u8; 4];
            socket.read_exact(&mut handshake_buf).unwrap();
            assert_eq!(&handshake_buf[..], b"FB01");
            // Respond with "FB01" to confirm length-prefixed mode
            socket.write_all(b"FB01").unwrap();

            // Now expect length-prefixed command
            let mut len_buf = [0u8; 8];
            socket.read_exact(&mut len_buf).unwrap();
            let cmd_len = u64::from_be_bytes(len_buf) as usize;
            let mut cmd_buf = vec![0u8; cmd_len];
            socket.read_exact(&mut cmd_buf).unwrap();
            assert_eq!(cmd_buf, b"getvar:version");

            // Send length-prefixed response
            let resp = b"OKAY0.1";
            let resp_len = (resp.len() as u64).to_be_bytes();
            socket.write_all(&resp_len).unwrap();
            socket.write_all(resp).unwrap();
        });

        let mut transport =
            FastbootTcpTransport::connect(local_addr.to_string()).unwrap();
        assert_eq!(transport.mode(), "length-prefixed");
        transport.send_cmd("getvar:version").unwrap();
        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));

        handle.join().unwrap();
    }

    /// Test that FB01 handshake auto-detects raw mode when the server
    /// responds with a fastboot prefix (OKAY) immediately.
    #[test]
    fn test_fb01_handshake_detects_raw_via_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Read the FB01 handshake
            let mut handshake_buf = [0u8; 4];
            socket.read_exact(&mut handshake_buf).unwrap();
            assert_eq!(&handshake_buf[..], b"FB01");
            // Respond immediately with a raw fastboot OKAY — this simulates
            // a device that doesn't understand FB01 but sends data anyway.
            socket.write_all(b"OKAYdevice_found").unwrap();

            // The client now thinks it's in raw mode and already buffered "OKAY"
            // The next write from client should be raw "getvar:version"
            let mut buf = [0u8; 100];
            let n = socket.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"getvar:version");
            // No need to respond again — the OKAY was already sent
        });

        let mut transport =
            FastbootTcpTransport::connect(local_addr.to_string()).unwrap();
        assert_eq!(transport.mode(), "raw");
        // The OKAY was already buffered during handshake; recv_response
        // should read from the buffer.
        transport.send_cmd("getvar:version").unwrap();
        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("device_found".to_string()));

        handle.join().unwrap();
    }

    /// Test that FB01 handshake falls back to raw mode on timeout
    /// (server doesn't respond to the handshake).
    #[test]
    fn test_fb01_handshake_fallback_raw_on_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Don't respond to the FB01 handshake — let it time out.
            // Read the FB01 bytes first to consume them from the stream.
            let mut handshake_buf = [0u8; 4];
            socket.read_exact(&mut handshake_buf).unwrap();
            assert_eq!(&handshake_buf[..], b"FB01");
            // After the client times out and falls back to raw mode,
            // it will send the command directly.
            let mut buf = [0u8; 100];
            let n = socket.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"getvar:version");
            socket.write_all(b"OKAY0.1").unwrap();
        });

        let mut transport =
            FastbootTcpTransport::connect(local_addr.to_string()).unwrap();
        assert_eq!(transport.mode(), "raw");
        transport.send_cmd("getvar:version").unwrap();
        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));

        handle.join().unwrap();
    }

    #[test]
    fn test_fastboot_tcp_transport_connect_failure() {
        let res = FastbootTcpTransport::connect_timeout(
            "127.0.0.1:59998",
            Duration::from_millis(200),
        );
        assert!(res.is_err());
        if let Err(FastbootTransportError::ConnectFailed { addr, .. }) = res {
            assert!(addr.contains("59998"));
        } else {
            panic!("Expected ConnectFailed error");
        }
    }

    #[test]
    fn test_parse_one_response_okay() {
        let (resp, consumed) = parse_one_response(b"OKAY0.1").unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_one_response_data() {
        let (resp, consumed) = parse_one_response(b"DATA00100000").unwrap();
        assert_eq!(resp, FastbootResponse::Data(0x00100000));
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_one_response_info_followed_by_okay() {
        // INFO body ends at the next valid prefix (OKAY)
        // "writing data...\n" = 16 chars, "OKAY" at body[16..20]
        let data = b"INFOwriting data...\nOKAY";
        let (resp, consumed) = parse_one_response(data).unwrap();
        assert_eq!(
            resp,
            FastbootResponse::Info("writing data...\n".to_string())
        );
        assert_eq!(consumed, 20); // 4 prefix + 16 body chars
    }

    #[test]
    fn test_parse_one_response_info_followed_by_fail() {
        // "some info...\n" = 13 chars, "FAIL" at body[13..17]
        let data = b"INFOsome info...\nFAILerror!";
        let (resp, consumed) = parse_one_response(data).unwrap();
        assert_eq!(
            resp,
            FastbootResponse::Info("some info...\n".to_string())
        );
        assert_eq!(consumed, 17); // 4 prefix + 13 body chars
    }

    #[test]
    fn test_parse_one_response_partial_prefix_at_end() {
        // "writing..." = 10 chars, followed by partial prefix "OK"
        let data = b"INFOwriting...OK";
        let (resp, consumed) = parse_one_response(data).unwrap();
        assert_eq!(
            resp,
            FastbootResponse::Info("writing...".to_string())
        );
        assert_eq!(consumed, 14); // 4 prefix + 10 body chars (leaving "OK" unconsumed)
    }

    #[test]
    fn test_recv_response_retains_leftover() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 100];
            let _ = socket.read(&mut buf);
            // Send OKAY followed immediately by another response in the same socket write
            socket.write_all(b"OKAYfirst\nOKAYsecond\n").unwrap();
        });

        let mut transport =
            FastbootTcpTransport::raw_connect(local_addr.to_string()).unwrap();
        transport.send_cmd("test").unwrap();

        let resp1 = transport.recv_response().unwrap();
        assert_eq!(resp1, FastbootResponse::Okay("first\n".to_string()));

        let resp2 = transport.recv_response().unwrap();
        assert_eq!(resp2, FastbootResponse::Okay("second\n".to_string()));

        handle.join().unwrap();
    }

    #[test]
    fn test_recv_response_split_stream_partial_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 100];
            let _ = socket.read(&mut buf);
            // Send INFO and partial prefix "OK"
            socket.write_all(b"INFOstep1\nOK").unwrap();
            thread::sleep(Duration::from_millis(50));
            // Send remaining "AY0.1"
            socket.write_all(b"AY0.1").unwrap();
        });

        let mut transport =
            FastbootTcpTransport::raw_connect(local_addr.to_string()).unwrap();
        transport.send_cmd("test").unwrap();

        let mut info_logs = Vec::new();
        let resp = transport.recv_response_with_info(&mut info_logs).unwrap();
        assert_eq!(info_logs, vec!["step1\n".to_string()]);
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));

        handle.join().unwrap();
    }

    #[test]
    fn test_recv_response_non_prefix_garbage() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 100];
            let _ = socket.read(&mut buf);
            // Send non-prefix garbage before a valid response
            socket.write_all(b"JUNK123OKAYvalid").unwrap();
        });

        let mut transport =
            FastbootTcpTransport::raw_connect(local_addr.to_string()).unwrap();
        transport.send_cmd("test").unwrap();

        let resp = transport.recv_response().unwrap();
        assert_eq!(resp, FastbootResponse::Okay("valid".to_string()));

        handle.join().unwrap();
    }

    #[test]
    fn test_length_prefixed_oversized_payload_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Read FB01 handshake
            let mut handshake_buf = [0u8; 4];
            socket.read_exact(&mut handshake_buf).unwrap();
            assert_eq!(&handshake_buf[..], b"FB01");
            // Confirm length-prefixed mode
            socket.write_all(b"FB01").unwrap();

            // Read length-prefixed command
            let mut len_buf = [0u8; 8];
            socket.read_exact(&mut len_buf).unwrap();
            let cmd_len = u64::from_be_bytes(len_buf) as usize;
            let mut cmd_buf = vec![0u8; cmd_len];
            socket.read_exact(&mut cmd_buf).unwrap();

            // Send oversized length prefix exceeding MAX_LENGTH_PREFIXED_PAYLOAD (2GB)
            let oversized_len = (2u64 * 1024 * 1024 * 1024).to_be_bytes();
            socket.write_all(&oversized_len).unwrap();
        });

        let mut transport =
            FastbootTcpTransport::connect(local_addr.to_string()).unwrap();
        assert_eq!(transport.mode(), "length-prefixed");
        transport.send_cmd("getvar:version").unwrap();

        let mut buf = [0u8; 100];
        let err = transport.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("exceeds maximum allowed limit"));

        handle.join().unwrap();
    }
}
