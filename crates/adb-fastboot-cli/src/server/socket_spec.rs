//! ADB Socket Spec — parsing, connecting, and listening on socket specifications.
//!
//! Mirrors AOSP `vendor/adb/socket_spec.cpp` (475 lines).
//!
//! A socket spec is an ADB convention for identifying how to connect to or
//! listen for ADB traffic.  Supported forms:
//!
//! - `tcp:<port>`               — TCP on localhost
//! - `tcp:<host>:<port>`        — TCP on any host
//! - `local:<path>`             — Unix domain socket (filesystem namespace on host)
//! - `localreserved:<path>`     — Unix domain socket (reserved namespace; host-only in AOSP)
//! - `localabstract:<path>`     — Unix abstract socket (Linux only)
//! - `localfilesystem:<path>`   — Unix filesystem socket
//! - `vsock:<cid>:<port>`       — VM socket (Linux only, **not yet implemented**)
//! - `acceptfd:<fd>`            — Inherited fd (**not yet implemented**)

use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Global config
// ---------------------------------------------------------------------------

/// When true, TCP listeners bind on `INADDR_ANY` (all interfaces) instead of
/// the default loopback.  Mirrors AOSP `gListenAll`.
pub static G_LISTEN_ALL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ---------------------------------------------------------------------------
// LocalSocketType
// ---------------------------------------------------------------------------

/// Describes a local (Unix-domain) socket type understood by ADB.
///
/// Mirrors AOSP's anonymous `LocalSocketType` struct in `socket_spec.cpp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSocketType {
    /// `local:` — filesystem namespace on host, reserved namespace on device.
    Local,
    /// `localreserved:` — reserved namespace (host-side only in AOSP).
    LocalReserved,
    /// `localabstract:` — abstract namespace (Linux only).
    LocalAbstract,
    /// `localfilesystem:` — filesystem namespace.
    LocalFilesystem,
}

impl LocalSocketType {
    /// All known local socket type prefix strings.
    pub const ALL_PREFIXES: &'static [&'static str] =
        &["local:", "localreserved:", "localabstract:", "localfilesystem:"];

    /// Returns the ADB spec prefix for this type (with colon).
    pub fn prefix(&self) -> &'static str {
        match self {
            LocalSocketType::Local => "local:",
            LocalSocketType::LocalReserved => "localreserved:",
            LocalSocketType::LocalAbstract => "localabstract:",
            LocalSocketType::LocalFilesystem => "localfilesystem:",
        }
    }

    /// Returns `true` if this socket type is available on the current platform.
    ///
    /// - `LocalAbstract` is only available on Linux.
    /// - All other types are available on any Unix.
    /// - On non-Unix platforms nothing is available.
    pub fn is_available(&self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            LocalSocketType::LocalAbstract => true,
            #[cfg(not(target_os = "linux"))]
            LocalSocketType::LocalAbstract => false,
            #[cfg(unix)]
            _ => true,
            #[cfg(not(unix))]
            _ => false,
        }
    }
}

/// Detect a local socket type from a spec string.  Returns `None` if the spec
/// does not match any local socket prefix.
pub fn detect_local_socket_type(spec: &str) -> Option<LocalSocketType> {
    if spec.starts_with("local:") {
        Some(LocalSocketType::Local)
    } else if spec.starts_with("localreserved:") {
        Some(LocalSocketType::LocalReserved)
    } else if spec.starts_with("localabstract:") {
        Some(LocalSocketType::LocalAbstract)
    } else if spec.starts_with("localfilesystem:") {
        Some(LocalSocketType::LocalFilesystem)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the argument starts with a recognised socket spec prefix.
///
/// Recognised prefixes: `tcp:`, `local:`, `localreserved:`, `localabstract:`,
/// `localfilesystem:`, `acceptfd:`, `vsock:`.
///
/// Mirrors AOSP `is_socket_spec()`.
pub fn is_socket_spec(spec: &str) -> bool {
    if spec.starts_with("tcp:") || spec.starts_with("acceptfd:") || spec.starts_with("vsock:") {
        return true;
    }
    detect_local_socket_type(spec).is_some()
}

/// Returns `true` if the spec refers to a local (loopback / Unix-domain) socket.
///
/// A spec is considered local if:
/// - It matches a local socket prefix (`local:`, `localreserved:`, etc.),
/// - OR it is a `tcp:` spec where the host is empty, `localhost`, or `127.0.0.1`.
///
/// Mirrors AOSP `is_local_socket_spec()`.
pub fn is_local_socket_spec(spec: &str) -> bool {
    // Check local socket prefixes first
    if detect_local_socket_type(spec).is_some() {
        return true;
    }

    // For tcp: specs, check if the host is local
    if let Ok((host, _port)) = parse_tcp_socket_spec_inner(spec) {
        return tcp_host_is_local(&host);
    }

    false
}

/// Returns `true` if `hostname` refers to the local machine.
fn tcp_host_is_local(hostname: &str) -> bool {
    hostname.is_empty() || hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
}

// ---------------------------------------------------------------------------
// TCP spec parsing
// ---------------------------------------------------------------------------

/// Parse a `tcp:` socket spec into `(host, port)`.
///
/// Accepts the forms:
/// - `tcp:<port>`          → host = `""`, port = parsed integer
/// - `tcp:<host>:<port>`   → host = parsed, port = parsed
///
/// Returns an error if the spec is not a valid TCP spec.
///
/// Mirrors AOSP `parse_tcp_socket_spec()`.
pub fn parse_tcp_socket_spec(spec: &str) -> Result<(String, u16), String> {
    parse_tcp_socket_spec_inner(spec)
}

fn parse_tcp_socket_spec_inner(spec: &str) -> Result<(String, u16), String> {
    let rest = spec
        .strip_prefix("tcp:")
        .ok_or_else(|| format!("specification is not tcp: {spec}"))?;

    // If the rest is just a port number, host is empty.
    if let Ok(port) = rest.parse::<u16>() {
        if port == 0 {
            return Err("port 0 is not valid in a socket spec".to_string());
        }
        return Ok((String::new(), port));
    }

    // Otherwise parse as host:port — split on last ':' to handle IPv6
    // (bracketed IPv6 is handled by the caller in socket_spec_connect).
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid tcp spec (no port): {spec}"))?;

    if host.is_empty() {
        return Err(format!("invalid tcp spec (empty host): {spec}"));
    }

    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port in tcp spec: '{port_str}'"))?;

    if port == 0 {
        return Err("port 0 is not valid in a socket spec".to_string());
    }

    Ok((host.to_string(), port))
}

// ---------------------------------------------------------------------------
// Port extraction
// ---------------------------------------------------------------------------

/// Extract the port number from a socket spec string.
///
/// Supports `tcp:` and `vsock:` specs.  Returns an error for unknown specs.
///
/// Mirrors AOSP `get_host_socket_spec_port()`.
pub fn get_host_socket_spec_port(spec: &str) -> Result<u16, String> {
    if let Some(rest) = spec.strip_prefix("tcp:") {
        // If rest is just a port number
        if let Ok(port) = rest.parse::<u16>() {
            if port == 0 {
                return Err("port 0 is not valid".to_string());
            }
            return Ok(port);
        }
        // Otherwise parse as host:port and extract port
        let (_host, port) = parse_tcp_socket_spec(spec)?;
        Ok(port)
    } else if spec.starts_with("vsock:") {
        // vsock:<cid>:<port> or vsock:<port>
        let parts: Vec<&str> = spec.split(':').collect();
        let port_str = match parts.len() {
            2 => parts[1],
            3 => parts[2],
            _ => return Err("given vsock server socket string was invalid".to_string()),
        };
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("could not parse vsock port: '{port_str}'"))?;
        if port == 0 {
            return Err("vsock port was 0".to_string());
        }
        Ok(port)
    } else {
        Err("given socket spec string was invalid: not tcp: or vsock:".to_string())
    }
}

// ---------------------------------------------------------------------------
// socket_spec_connect
// ---------------------------------------------------------------------------

/// Result of a `socket_spec_connect` call.
#[derive(Debug)]
pub enum ConnectedStream {
    /// A TCP connection.
    Tcp(TcpStream),
    /// A Unix-domain socket connection (Unix only).
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl std::io::Read for ConnectedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ConnectedStream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            ConnectedStream::Unix(s) => s.read(buf),
        }
    }
}

impl std::io::Write for ConnectedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ConnectedStream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            ConnectedStream::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ConnectedStream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            ConnectedStream::Unix(s) => s.flush(),
        }
    }
}

/// Connect to the given socket spec.
///
/// Returns a `ConnectedStream` (either `Tcp` or `Unix`) and optionally the
/// resolved port and serial string.
///
/// Mirrors AOSP `socket_spec_connect()` — simplified for Rust:
/// - No `acceptfd:` support.
/// - No `vsock:` support yet.
/// - No raw fd / unique_fd interface: returns owned stream types.
pub fn socket_spec_connect(
    spec: &str,
    _port_hint: Option<u16>,
    connect_timeout: Duration,
) -> Result<(ConnectedStream, Option<u16>, Option<String>), String> {
    if spec.starts_with("tcp:") {
        let (hostname, parsed_port) = parse_tcp_socket_spec(spec)?;
        let port_value = parsed_port;

        // Build address string for the resolver
        let addr_str = if hostname.is_empty() || tcp_host_is_local(&hostname) {
            // Local connection
            format!("127.0.0.1:{port_value}")
        } else if hostname.contains(':') {
            // IPv6 literal — needs brackets for resolution
            format!("[{hostname}]:{port_value}")
        } else {
            format!("{hostname}:{port_value}")
        };

        let serial = if hostname.is_empty() {
            format!("127.0.0.1:{port_value}")
        } else {
            addr_str.clone()
        };

        // Resolve and connect
        let sock_addrs: Vec<std::net::SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("resolve failed for '{addr_str}': {e}"))?
            .collect();

        let addr = sock_addrs
            .first()
            .ok_or_else(|| format!("no address resolved for '{addr_str}'"))?
            .to_owned();

        let stream = TcpStream::connect_timeout(&addr, connect_timeout)
            .map_err(|e| format!("connect to {addr} failed: {e}"))?;

        // Set TCP_NODELAY (disable Nagle)
        let _ = stream.set_nodelay(true);

        Ok((
            ConnectedStream::Tcp(stream),
            Some(port_value),
            Some(serial),
        ))
    } else if spec.starts_with("vsock:") {
        Err("vsock is not yet supported".to_string())
    } else if spec.starts_with("acceptfd:") {
        Err("cannot connect to acceptfd".to_string())
    } else if let Some(local_type) = detect_local_socket_type(spec) {
        // Local socket — use Unix domain sockets
        #[cfg(unix)]
        {
            if !local_type.is_available() {
                return Err(format!(
                    "socket type {} is unavailable on this platform",
                    local_type.prefix().trim_end_matches(':')
                ));
            }

            let path = &spec[local_type.prefix().len()..];
            if path.is_empty() {
                return Err(format!(
                    "empty path in local socket spec: {spec}"
                ));
            }

            let stream = if local_type == LocalSocketType::LocalAbstract {
                // Abstract socket: path is prefixed with a null byte on Linux
                // std::os::unix::net::UnixStream::connect_abstract is unstable,
                // so we use a platform-specific approach.
                connect_abstract_unix(path)?
            } else {
                // Filesystem socket
                std::os::unix::net::UnixStream::connect(path)
                    .map_err(|e| format!("connect to '{path}' failed: {e}"))?
            };

            Ok((
                ConnectedStream::Unix(stream),
                None,
                Some(spec.to_string()),
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = local_type;
            Err(format!(
                "local socket type '{}' is not supported on this platform",
                local_type.prefix().trim_end_matches(':')
            ))
        }
    } else {
        Err(format!("unknown socket specification: {spec}"))
    }
}

/// Connect to a Linux abstract Unix socket.
///
/// Abstract sockets use the Linux abstract namespace: the path begins with a
/// null byte (`\0`), which distinguishes them from filesystem sockets.
#[cfg(target_os = "linux")]
fn connect_abstract_unix(path: &str) -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::unix::net::UnixStream;
    use std::os::unix::io::FromRawFd;
    use libc;

    // Build a sockaddr_un with an abstract path
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err("failed to create abstract Unix socket".to_string());
        }

        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        // Abstract: first byte is \0, then the path
        let path_bytes = path.as_bytes();
        let max_path_len = path_bytes.len().min(107); // 108 - 1 for leading \0
        let sun_path_slice =
            std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr() as *mut u8, 108);

        // Write \0 + path into sun_path
        sun_path_slice[0] = 0;
        sun_path_slice[1..=max_path_len].copy_from_slice(&path_bytes[..max_path_len]);

        let addr_len = std::mem::size_of::<libc::sa_family_t>() + 1 + max_path_len;

        let ret = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        );
        if ret < 0 {
            libc::close(fd);
            return Err(format!("connect to abstract '{path}' failed"));
        }

        Ok(UnixStream::from_raw_fd(fd))
    }
}

/// Bogus implementation for non-Linux — abstract sockets don't exist there.
#[cfg(not(target_os = "linux"))]
fn connect_abstract_unix(path: &str) -> Result<std::os::unix::net::UnixStream, String> {
    let _ = path;
    Err("abstract Unix sockets are only supported on Linux".to_string())
}

// ---------------------------------------------------------------------------
// socket_spec_listen
// ---------------------------------------------------------------------------

/// Result of a `socket_spec_listen` call.
#[derive(Debug)]
pub enum ListenerStream {
    /// A TCP listener.
    Tcp(TcpListener),
    /// A Unix-domain socket listener (Unix only).
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}

/// Listen on the given socket spec.
///
/// Returns a `ListenerStream` and the resolved port (for `tcp:` specs with
/// port 0).
///
/// Mirrors AOSP `socket_spec_listen()` — simplified for Rust:
/// - No `acceptfd:` support.
/// - No `vsock:` support yet.
/// - Returns owned `TcpListener` / `UnixListener` instead of raw fd.
pub fn socket_spec_listen(
    spec: &str,
) -> Result<(ListenerStream, Option<u16>), String> {
    if spec.starts_with("tcp:") {
        let (hostname, port) = parse_tcp_socket_spec(spec)?;

        let listen_all = G_LISTEN_ALL.load(std::sync::atomic::Ordering::Relaxed);

        let addr_str = if hostname.is_empty() && listen_all {
            format!("0.0.0.0:{port}")
        } else if hostname.is_empty() || tcp_host_is_local(&hostname) {
            format!("127.0.0.1:{port}")
        } else if hostname == "::1" {
            format!("[::1]:{port}")
        } else {
            return Err("listening on specified hostname currently unsupported".to_string());
        };

        let listener = TcpListener::bind(&addr_str)
            .map_err(|e| format!("cannot bind listener for '{addr_str}': {e}"))?;

        let resolved_port = listener
            .local_addr()
            .map(|a| a.port())
            .ok();

        Ok((ListenerStream::Tcp(listener), resolved_port))
    } else if spec.starts_with("vsock:") {
        Err("vsock listening is not yet supported".to_string())
    } else if spec.starts_with("acceptfd:") {
        Err("acceptfd listening is not yet supported".to_string())
    } else if let Some(local_type) = detect_local_socket_type(spec) {
        // Local socket — use Unix domain sockets
        #[cfg(unix)]
        {
            if !local_type.is_available() {
                return Err(format!(
                    "attempted to listen on unavailable socket type: {spec}"
                ));
            }

            let path = &spec[local_type.prefix().len()..];
            if path.is_empty() {
                return Err(format!(
                    "empty path in local socket spec: {spec}"
                ));
            }

            let listener = if local_type == LocalSocketType::LocalAbstract {
                // Abstract socket
                listen_abstract_unix(path)?
            } else {
                // Filesystem socket — remove any existing file first
                let _ = std::fs::remove_file(path);
                std::os::unix::net::UnixListener::bind(path)
                    .map_err(|e| format!("cannot bind Unix socket '{path}': {e}"))?
            };

            Ok((ListenerStream::Unix(listener), None))
        }
        #[cfg(not(unix))]
        {
            let _ = local_type;
            Err(format!(
                "local socket is not supported on this platform"
            ))
        }
    } else {
        Err(format!("unknown socket specification: {spec}"))
    }
}

/// Listen on a Linux abstract Unix socket.
#[cfg(target_os = "linux")]
fn listen_abstract_unix(path: &str) -> Result<std::os::unix::net::UnixListener, String> {
    use std::os::unix::io::FromRawFd;
    use libc;

    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err("failed to create abstract Unix socket for listening".to_string());
        }

        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

        let path_bytes = path.as_bytes();
        let max_path_len = path_bytes.len().min(107);
        let sun_path_slice =
            std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr() as *mut u8, 108);

        sun_path_slice[0] = 0;
        sun_path_slice[1..=max_path_len].copy_from_slice(&path_bytes[..max_path_len]);

        let addr_len = std::mem::size_of::<libc::sa_family_t>() + 1 + max_path_len;

        let ret = libc::bind(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        );
        if ret < 0 {
            libc::close(fd);
            return Err(format!("bind abstract '{path}' failed"));
        }

        let ret = libc::listen(fd, 4);
        if ret < 0 {
            libc::close(fd);
            return Err(format!("listen on abstract '{path}' failed"));
        }

        Ok(std::os::unix::net::UnixListener::from_raw_fd(fd))
    }
}

/// Bogus for non-Linux.
#[cfg(not(target_os = "linux"))]
fn listen_abstract_unix(path: &str) -> Result<std::os::unix::net::UnixListener, String> {
    let _ = path;
    Err("abstract Unix sockets are only supported on Linux".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_socket_spec ----------------------------------------------------

    #[test]
    fn test_is_socket_spec_tcp() {
        assert!(is_socket_spec("tcp:5555"));
        assert!(is_socket_spec("tcp:host:5555"));
    }

    #[test]
    fn test_is_socket_spec_local() {
        assert!(is_socket_spec("local:mysocket"));
        assert!(is_socket_spec("localreserved:mysocket"));
        assert!(is_socket_spec("localabstract:mysocket"));
        assert!(is_socket_spec("localfilesystem:/tmp/adb.sock"));
    }

    #[test]
    fn test_is_socket_spec_other() {
        assert!(is_socket_spec("acceptfd:3"));
        assert!(is_socket_spec("vsock:1234"));
    }

    #[test]
    fn test_is_socket_spec_rejects_unknown() {
        assert!(!is_socket_spec("unknown:123"));
        assert!(!is_socket_spec("plainport"));
        assert!(!is_socket_spec(""));
    }

    // -- is_local_socket_spec ---------------------------------------------

    #[test]
    fn test_is_local_socket_spec_local_prefixes() {
        assert!(is_local_socket_spec("local:mysocket"));
        assert!(is_local_socket_spec("localreserved:mysocket"));
        assert!(is_local_socket_spec("localabstract:mysocket"));
        assert!(is_local_socket_spec("localfilesystem:/tmp/adb.sock"));
    }

    #[test]
    fn test_is_local_socket_spec_tcp_localhost() {
        assert!(is_local_socket_spec("tcp:5555"));
        assert!(is_local_socket_spec("tcp:localhost:5555"));
        assert!(is_local_socket_spec("tcp:127.0.0.1:5555"));
        assert!(is_local_socket_spec("tcp:::1:5555"));
    }

    #[test]
    fn test_is_local_socket_spec_tcp_remote() {
        assert!(!is_local_socket_spec("tcp:192.168.1.100:5555"));
        assert!(!is_local_socket_spec("tcp:example.com:5555"));
    }

    // -- parse_tcp_socket_spec --------------------------------------------

    #[test]
    fn test_parse_tcp_socket_spec_port_only() {
        let (host, port) = parse_tcp_socket_spec("tcp:5555").unwrap();
        assert_eq!(host, "");
        assert_eq!(port, 5555);
    }

    #[test]
    fn test_parse_tcp_socket_spec_host_port() {
        let (host, port) = parse_tcp_socket_spec("tcp:192.168.1.1:5555").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 5555);
    }

    #[test]
    fn test_parse_tcp_socket_spec_hostname() {
        let (host, port) = parse_tcp_socket_spec("tcp:localhost:5555").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 5555);
    }

    #[test]
    fn test_parse_tcp_socket_spec_rejects_port_zero() {
        assert!(parse_tcp_socket_spec("tcp:0").is_err());
    }

    #[test]
    fn test_parse_tcp_socket_spec_rejects_bad_port() {
        assert!(parse_tcp_socket_spec("tcp:notaporta").is_err());
    }

    #[test]
    fn test_parse_tcp_socket_spec_rejects_no_prefix() {
        assert!(parse_tcp_socket_spec("5555").is_err());
    }

    // -- get_host_socket_spec_port ----------------------------------------

    #[test]
    fn test_get_host_socket_spec_port_tcp() {
        assert_eq!(get_host_socket_spec_port("tcp:5555").unwrap(), 5555);
        assert_eq!(get_host_socket_spec_port("tcp:localhost:5555").unwrap(), 5555);
    }

    #[test]
    fn test_get_host_socket_spec_port_vsock() {
        assert_eq!(get_host_socket_spec_port("vsock:3:5555").unwrap(), 5555);
        assert_eq!(get_host_socket_spec_port("vsock:5555").unwrap(), 5555);
    }

    #[test]
    fn test_get_host_socket_spec_port_rejects_unknown() {
        assert!(get_host_socket_spec_port("local:mysocket").is_err());
        assert!(get_host_socket_spec_port("").is_err());
    }

    // -- LocalSocketType --------------------------------------------------

    #[test]
    fn test_detect_local_socket_type() {
        assert_eq!(detect_local_socket_type("local:x"), Some(LocalSocketType::Local));
        assert_eq!(detect_local_socket_type("localreserved:x"), Some(LocalSocketType::LocalReserved));
        assert_eq!(detect_local_socket_type("localabstract:x"), Some(LocalSocketType::LocalAbstract));
        assert_eq!(detect_local_socket_type("localfilesystem:x"), Some(LocalSocketType::LocalFilesystem));
        assert_eq!(detect_local_socket_type("tcp:5555"), None);
    }

    #[test]
    fn test_local_socket_type_prefix() {
        assert_eq!(LocalSocketType::Local.prefix(), "local:");
        assert_eq!(LocalSocketType::LocalReserved.prefix(), "localreserved:");
        assert_eq!(LocalSocketType::LocalAbstract.prefix(), "localabstract:");
        assert_eq!(LocalSocketType::LocalFilesystem.prefix(), "localfilesystem:");
    }

    // -- socket_spec_listen (TCP) -----------------------------------------

    #[test]
    fn test_socket_spec_listen_tcp_port_zero() {
        // Bind on port 0 should auto-assign
        let (listener, resolved) = socket_spec_listen("tcp:0").unwrap();
        assert!(matches!(listener, ListenerStream::Tcp(_)));
        assert!(resolved.is_some());
        assert!(resolved.unwrap() > 0);
    }

    #[test]
    fn test_socket_spec_listen_tcp_specific_port() {
        let (listener, resolved) = socket_spec_listen("tcp:0").unwrap();
        assert!(matches!(listener, ListenerStream::Tcp(_)));
        assert!(resolved.is_some());
    }

    #[test]
    fn test_socket_spec_listen_tcp_localhost() {
        let (listener, resolved) = socket_spec_listen("tcp:localhost:0").unwrap();
        assert!(matches!(listener, ListenerStream::Tcp(_)));
        assert!(resolved.is_some());
    }

    // -- socket_spec_connect (TCP) ----------------------------------------

    #[test]
    fn test_socket_spec_connect_tcp_connect_refused() {
        // Connecting to a port where nothing is listening should fail
        let result = socket_spec_connect(
            "tcp:19999",
            None,
            Duration::from_secs(2),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_socket_spec_connect_tcp_roundtrip() {
        // Start a listener on port 0, then connect to it
        let (listener, resolved_port) = socket_spec_listen("tcp:0").unwrap();
        let port = resolved_port.expect("should have resolved port");
        drop(listener); // release the listener

        // Connection should fail since listener was dropped
        let result = socket_spec_connect(
            &format!("tcp:{port}"),
            None,
            Duration::from_secs(2),
        );
        assert!(result.is_err());
    }

    // -- G_LISTEN_ALL ----------------------------------------------------

    #[test]
    fn test_g_listen_all_default() {
        assert!(!G_LISTEN_ALL.load(std::sync::atomic::Ordering::Relaxed));
    }

    // -- tcp_host_is_local ------------------------------------------------

    #[test]
    fn test_tcp_host_is_local_variants() {
        assert!(tcp_host_is_local(""));
        assert!(tcp_host_is_local("localhost"));
        assert!(tcp_host_is_local("127.0.0.1"));
        assert!(tcp_host_is_local("::1"));
        assert!(!tcp_host_is_local("192.168.1.1"));
        assert!(!tcp_host_is_local("example.com"));
    }
}
