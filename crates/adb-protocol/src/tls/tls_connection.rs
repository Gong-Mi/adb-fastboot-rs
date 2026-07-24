//! TLS 1.3 connection support for ADB's A_STLS protocol,
//! mirroring AOSP `vendor/adb/tls/tls_connection.cpp`.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use thiserror::Error;

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
}

/// Create a TLS 1.3 [`ClientConfig`](rustls::ClientConfig) from DER-encoded
/// certificate and private key.
///
/// # Configuration
/// - **TLS 1.3 only** — no TLS 1.2 fallback
/// - **Custom certificate verifier** — accepts any valid certificate chain,
///   appropriate for ADB's self-signed / trust-on-first-use model
/// - **Mutual TLS** — sends the provided client certificate when the server
///   requests one
///
/// # Errors
/// Returns [`TlsError::Rustls`] if the config cannot be built (e.g. invalid
/// certificate/key).
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
///
/// This is needed for the ADB server side of A_STLS (device as server, or
/// host as server depending on connection direction).
///
/// # Configuration
/// - **TLS 1.3 only**
/// - **No client auth required** — ADB relies on the RSA AUTH layer for
///   peer authentication, not TLS client certificates
///
/// # Errors
/// Returns [`TlsError::Rustls`] if the config cannot be built.
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

/// Export the 64-byte AOSP pairing secret after a completed TLS 1.3 handshake.
/// AOSP uses exporter label `adb-label`, no context, and 64 bytes.
pub fn export_pairing_key_material(
    connection: &rustls::ClientConnection,
) -> Result<[u8; 64], TlsError> {
    let mut output = [0u8; 64];
    connection.export_keying_material(&mut output, b"adb-label", None)?;
    Ok(output)
}

/// Perform a TLS 1.3 client handshake over the given stream, driving it to
/// completion, and return the encrypted stream with the 64-byte AOSP pairing
/// exporter output.
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

/// Accept an incoming TLS 1.3 connection on the given stream.
pub fn accept_tls_handshake<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ServerConfig>,
) -> Result<TlsStream<rustls::ServerConnection, IO>, TlsError> {
    let connection = rustls::ServerConnection::new(config)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}
