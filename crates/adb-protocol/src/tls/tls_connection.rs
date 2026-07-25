//! TLS 1.3 connection support for ADB's A_STLS protocol,
//! mirroring AOSP `vendor/adb/tls/tls_connection.cpp`.
//!
//! Provides:
//! - `ReadFully` / `WriteFully` — exact I/O helpers
//! - `TlsConnection` — wrapper with `new(stream, mode, config)` constructor
//! - `perform_tls_handshake` — convenience to build a `TlsConnection` from a key PEM

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use thiserror::Error;

use crate::crypto::x509_generator::generate_self_signed_cert;
use crate::tls::adb_ca_list::AcceptAnyCertVerifier;

/// Convenience alias for `rustls::StreamOwned`.
pub use rustls::StreamOwned as TlsStream;
/// Convenience alias for `rustls::ClientConnection`.
pub use rustls::ClientConnection;
/// Convenience alias for `rustls::ServerConnection`.
pub use rustls::ServerConnection;

/// Errors that can occur during TLS certificate generation and handshaking.
#[derive(Error, Debug)]
pub enum TlsError {
    /// Error from `rcgen` during certificate generation.
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// Error from `rustls` during configuration or handshake.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// The provided RSA private key PEM could not be parsed.
    #[error("invalid private key PEM: {0}")]
    InvalidPrivateKey(String),

    /// The TLS handshake itself failed.
    #[error("TLS handshake error: {0}")]
    Handshake(String),

    /// Wrapper for `std::io::Error`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate generation error.
    #[error("certificate generation error: {0}")]
    Cert(#[from] crate::crypto::x509_generator::CertError),
}

// ---------------------------------------------------------------------------
// ReadFully / WriteFully — exact I/O helpers (mirror AOSP `ReadFully` / `WriteFully`)
// ---------------------------------------------------------------------------

/// Read exactly `buf.len()` bytes from `reader`, retrying on partial reads.
///
/// Returns `UnexpectedEof` if the reader is exhausted before filling `buf`.
/// This is a TLS‑aware equivalent of `read_exact`, usable with any `Read` impl
/// (including `rustls::StreamOwned`).
///
/// # Errors
/// - `io::ErrorKind::UnexpectedEof` if fewer bytes than `buf.len()` are available.
/// - Any other `io::Error` from the underlying reader.
#[allow(non_snake_case)]
pub fn ReadFully<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = reader.read(&mut buf[offset..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ReadFully: unexpected EOF",
            ));
        }
        offset += n;
    }
    Ok(())
}

/// Write all bytes from `data` to `writer`, retrying on partial writes.
///
/// This is a convenience wrapper around `write_all` exposed for symmetry with
/// `ReadFully` and to match the AOSP API surface.
///
/// # Errors
/// - `io::ErrorKind::WriteZero` if the writer accepts zero bytes.
/// - Any other `io::Error` from the underlying writer.
#[allow(non_snake_case)]
pub fn WriteFully<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    writer.write_all(data)
}

// ---------------------------------------------------------------------------
// TlsMode
// ---------------------------------------------------------------------------

/// TLS connection mode matching AOSP's `TlsMode::{Client, Server}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// ADB host connecting to ADB server (TLS client).
    Client,
    /// ADB server accepting an incoming TLS connection (TLS server).
    Server,
}

// ---------------------------------------------------------------------------
// TlsConnection — unified wrapper for client / server TLS connections
// ---------------------------------------------------------------------------

/// A TLS 1.3 connection wrapping an underlying I/O stream, mirroring AOSP's
/// `TlsConnection` class in `vendor/adb/tls/tls_connection.h`.
///
/// Supports both client and server modes via an internal enum, so callers
/// do not need to specialise on the connection type.
///
/// # Example (client)
/// ```ignore
/// let stream = TcpStream::connect(addr)?;
/// let config = create_tls_config(cert_der, key_der)?;
/// let mut tls = TlsConnection::new(stream, config, TlsMode::Client)?;
/// tls.WriteFully(b"hello")?;
/// let mut buf = [0u8; 5];
/// tls.ReadFully(&mut buf)?;
/// ```
#[derive(Debug)]
pub enum TlsConnection<IO: Read + Write> {
    /// Client-mode connection.
    Client(TlsStream<rustls::ClientConnection, IO>),
    /// Server-mode connection.
    Server(TlsStream<rustls::ServerConnection, IO>),
}

impl<IO: Read + Write> TlsConnection<IO> {
    /// Create a new TLS connection over the given I/O stream.
    ///
    /// # Arguments
    /// - `stream` — the raw (unencrypted) I/O stream, typically a `TcpStream`.
    /// - `config` — the TLS configuration:
    ///   - For `TlsMode::Client`: pass an `Arc<rustls::ClientConfig>` (see
    ///     [`create_tls_config`]).
    ///   - For `TlsMode::Server`: pass an `Arc<rustls::ServerConfig>` (see
    ///     [`create_server_config`]).
    /// - `mode` — client or server.
    ///
    /// # Errors
    /// Returns [`TlsError::Rustls`] if the connection cannot be created
    /// (e.g. invalid TLS configuration).
    ///
    /// # Panics
    /// The `config` argument **must** match `mode` (pass a `ClientConfig` for
    /// `TlsMode::Client`, a `ServerConfig` for `TlsMode::Server`). A mismatch
    /// will panic at runtime via the `downcast_arc` call inside `rustls`.
    pub fn new(
        stream: IO,
        config: Arc<dyn std::any::Any + Send + Sync>,
        mode: TlsMode,
        server_name: &str,
    ) -> Result<Self, TlsError> {
        match mode {
            TlsMode::Client => {
                let cfg: Arc<rustls::ClientConfig> = config
                    .downcast::<rustls::ClientConfig>()
                    .map_err(|_| {
                        TlsError::Handshake(
                            "expected Arc<ClientConfig> for TlsMode::Client".into(),
                        )
                    })?;
                let name = ServerName::try_from(server_name.to_string())
                    .map_err(|_| TlsError::Handshake(format!("invalid server name: {server_name}")))?;
                let conn = rustls::ClientConnection::new(cfg, name)?;
                Ok(TlsConnection::Client(TlsStream::new(conn, stream)))
            }
            TlsMode::Server => {
                let cfg: Arc<rustls::ServerConfig> = config
                    .downcast::<rustls::ServerConfig>()
                    .map_err(|_| {
                        TlsError::Handshake(
                            "expected Arc<ServerConfig> for TlsMode::Server".into(),
                        )
                    })?;
                let conn = rustls::ServerConnection::new(cfg)?;
                Ok(TlsConnection::Server(TlsStream::new(conn, stream)))
            }
        }
    }

    /// Read exactly `buf.len()` bytes, retrying on partial reads.
    ///
    /// Delegates to [`ReadFully`] on the inner TLS stream.
    #[allow(non_snake_case)]
    pub fn ReadFully(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            TlsConnection::Client(ref mut s) => ReadFully(s, buf),
            TlsConnection::Server(ref mut s) => ReadFully(s, buf),
        }
    }

    /// Write all bytes from `data`, retrying on partial writes.
    ///
    /// Delegates to [`WriteFully`] on the inner TLS stream.
    #[allow(non_snake_case)]
    pub fn WriteFully(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            TlsConnection::Client(ref mut s) => WriteFully(s, data),
            TlsConnection::Server(ref mut s) => WriteFully(s, data),
        }
    }

    /// Drive the TLS handshake to completion.
    ///
    /// `rustls::StreamOwned` performs the handshake lazily on the first
    /// read/write. This method forces it to complete immediately.
    ///
    /// # Errors
    /// Returns any I/O or TLS error encountered during the handshake.
    pub fn complete_handshake(&mut self) -> io::Result<()> {
        match self {
            TlsConnection::Client(ref mut s) => {
                while s.conn.is_handshaking() {
                    s.conn.complete_io(&mut s.sock)?;
                }
            }
            TlsConnection::Server(ref mut s) => {
                while s.conn.is_handshaking() {
                    s.conn.complete_io(&mut s.sock)?;
                }
            }
        }
        Ok(())
    }

    /// Return a reference to the inner I/O stream.
    pub fn inner_stream(&mut self) -> &mut IO {
        match self {
            TlsConnection::Client(ref mut s) => &mut s.sock,
            TlsConnection::Server(ref mut s) => &mut s.sock,
        }
    }
}

// ---------------------------------------------------------------------------
// perform_tls_handshake helpers (key‑based overload)
// ---------------------------------------------------------------------------

/// Perform a TLS 1.3 client handshake over the given stream, driving it to
/// completion, and return the encrypted stream with the 64‑byte AOSP pairing
/// exporter output.
///
/// This is the **full‑handshake** variant — it loops until the TLS handshake
/// is complete, then returns the established stream together with the pairing
/// key material exported via `adb-label`.
pub fn perform_tls_handshake_with_pairing_export<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> Result<(TlsStream<rustls::ClientConnection, IO>, [u8; 64]), TlsError> {
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| TlsError::Handshake(format!("invalid server name: {server_name}")))?;
    let mut connection = rustls::ClientConnection::new(config, server_name)?;
    let mut io = stream;
    while connection.is_handshaking() {
        connection.complete_io(&mut io)?;
    }
    let exported = export_pairing_key_material(&connection)?;
    Ok((rustls::StreamOwned::new(connection, io), exported))
}

/// Construct a TLS client stream. The handshake is driven lazily by the first
/// read/write, matching `rustls::StreamOwned` semantics.
pub fn perform_tls_handshake<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> Result<TlsStream<rustls::ClientConnection, IO>, TlsError> {
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| TlsError::Handshake(format!("invalid server name: {server_name}")))?;
    let connection = rustls::ClientConnection::new(config, server_name)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

/// Perform a TLS 1.3 handshake using an RSA private key PEM string.
///
/// This is the **convenience overload** matching AOSP's
/// `perform_tls_handshake(unique_fd, std::string key)`:
/// 1. Generates a self‑signed X.509 certificate from the RSA key PEM.
/// 2. Creates a TLS 1.3 client config with `create_tls_config`.
/// 3. Drives the handshake to completion.
/// 4. Returns a [`TlsConnection`] wrapping the encrypted stream.
///
/// # Arguments
/// - `stream` — the raw (unencrypted) I/O stream.
/// - `key_pem` — an RSA private key in PEM format (see
///   `crate::auth::export_private_key_to_pem`).
/// - `server_name` — the TLS SNI server name (typically `"adb"`).
///
/// # Errors
/// Returns [`TlsError::Cert`] if the key PEM cannot be parsed.
/// Returns [`TlsError::Rustls`] if the TLS config or handshake fails.
/// Returns [`TlsError::Io`] for underlying I/O errors.
pub fn perform_tls_handshake_with_key<IO: Read + Write>(
    stream: IO,
    key_pem: &str,
    server_name: &str,
) -> Result<TlsConnection<IO>, TlsError> {
    let (cert_der, key_der) = generate_self_signed_cert(key_pem)?;
    let config = create_tls_config(cert_der, key_der)?;

    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| TlsError::Handshake(format!("invalid server name: {server_name}")))?;
    let mut connection = rustls::ClientConnection::new(config, name)?;
    let mut io = stream;
    while connection.is_handshaking() {
        connection.complete_io(&mut io)?;
    }
    Ok(TlsConnection::Client(TlsStream::new(connection, io)))
}

/// Accept an incoming TLS 1.3 connection on the given stream.
pub fn accept_tls_handshake<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ServerConfig>,
) -> Result<TlsStream<rustls::ServerConnection, IO>, TlsError> {
    let connection = rustls::ServerConnection::new(config)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

// ---------------------------------------------------------------------------
// Other helpers
// ---------------------------------------------------------------------------

/// Export the 64-byte AOSP pairing secret after a completed TLS 1.3 handshake.
/// AOSP uses exporter label `adb-label`, no context, and 64 bytes.
pub fn export_pairing_key_material(
    connection: &rustls::ClientConnection,
) -> Result<[u8; 64], TlsError> {
    let mut output = [0u8; 64];
    connection.export_keying_material(&mut output, b"adb-label", None)?;
    Ok(output)
}

/// Create a TLS 1.3 [`ClientConfig`](rustls::ClientConfig) from DER-encoded
/// certificate and private key.
pub fn create_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
        .with_client_auth_cert(vec![cert], key)?;

    Ok(Arc::new(config))
}

/// Create a TLS 1.3 [`ServerConfig`](rustls::ServerConfig) from DER-encoded
/// certificate and private key.
pub fn create_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    Ok(Arc::new(config))
}
