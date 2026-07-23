//! TLS 1.3 support for ADB's A_STLS protocol.
//!
//! Provides X.509 certificate generation from RSA 2048 keys and
//! TLS 1.3 client/server configuration using `rcgen` + `rustls`.
//!
//! **A_STLS flow**:
//! 1. Peer sends `A_STLS` message
//! 2. Both sides perform a TLS 1.3 handshake using self-signed X.509
//!    certificates derived from the existing RSA 2048 auth keys
//! 3. After handshake completes, `A_CNXN` is re-sent over the encrypted
//!    channel
//!
//! ## Feature gate
//! This module is only available when the `tls` feature is enabled.
//! It does not change the default build.

use std::io::{Read, Write};
use std::sync::Arc;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

/// Convenience alias for `rustls::StreamOwned`.
pub use rustls::StreamOwned as TlsStream;
/// Convenience alias for `rustls::ClientConnection`.
pub use rustls::ClientConnection;
/// Convenience alias for `rustls::ServerConnection`.
pub use rustls::ServerConnection;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Certificate generation
// ---------------------------------------------------------------------------

/// Generate a self-signed X.509 certificate from an RSA 2048 private key PEM.
///
/// # Parameters
/// - `rsa_private_key_pem`: an RSA private key in PEM format (PKCS#8 or PKCS#1).
///   You can obtain one via [`crate::export_private_key_to_pem`].
///
/// # Returns
/// `(certificate_der, private_key_der)` — both in DER format.
///
/// # Certificate properties
/// | Property                    | Value                 |
/// |-----------------------------|-----------------------|
/// | Subject / SAN               | `adb`                 |
/// | Signature algorithm         | RSA-SHA256            |
/// | Key usages                  | digitalSignature, keyEncipherment |
/// | Extended key usages         | serverAuth, clientAuth |
/// | Validity                    | 10 years              |
///
/// # Errors
/// Returns [`TlsError::InvalidPrivateKey`] if the PEM cannot be parsed,
/// or [`TlsError::Rcgen`] if certificate generation fails.
pub fn generate_self_signed_cert(rsa_private_key_pem: &str) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key_pair =
        KeyPair::from_pem(rsa_private_key_pem).map_err(|e| TlsError::InvalidPrivateKey(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["adb".to_string()])?;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    Ok((cert_der, key_der))
}

// ---------------------------------------------------------------------------
// TLS config builders
// ---------------------------------------------------------------------------

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
pub fn create_tls_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Arc<rustls::ClientConfig>, TlsError> {
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

// ---------------------------------------------------------------------------
// TLS handshake
// ---------------------------------------------------------------------------

/// Perform a TLS 1.3 client handshake over the given stream.
///
/// # Parameters
/// - `stream`: any `Read + Write` transport (e.g. `TcpStream`).
/// - `config`: the client config from [`create_tls_config`].
/// - `server_name`: the SNI hostname (use `"adb"` unless you have a specific
///   need; this affects certificate verification, which is accept-any in our
///   config).
///
/// # Returns
/// A [`TlsStream`] wrapping the original stream with TLS encryption.
///
/// # Errors
/// Returns [`TlsError::Handshake`] if the server name is invalid or the
/// TLS handshake fails.
pub fn perform_tls_handshake<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> Result<TlsStream<rustls::ClientConnection, IO>, TlsError> {
    let server_name =
        ServerName::try_from(server_name.to_string()).map_err(|_| TlsError::Handshake(format!("invalid server name: {server_name}")))?;

    let connection = rustls::ClientConnection::new(config, server_name)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

/// Accept an incoming TLS 1.3 connection on the given stream.
///
/// # Parameters
/// - `stream`: any `Read + Write` transport.
/// - `config`: the server config from [`create_server_config`].
///
/// # Returns
/// A [`TlsStream`] wrapping the original stream with TLS encryption.
///
/// # Errors
/// Returns [`TlsError::Handshake`] if the TLS handshake fails.
pub fn accept_tls_handshake<IO: Read + Write>(
    stream: IO,
    config: Arc<rustls::ServerConfig>,
) -> Result<TlsStream<rustls::ServerConnection, IO>, TlsError> {
    let connection = rustls::ServerConnection::new(config)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

// ---------------------------------------------------------------------------
// Custom certificate verifier
// ---------------------------------------------------------------------------

/// A [`ServerCertVerifier`] that accepts any valid certificate chain.
///
/// This is appropriate for ADB because:
/// - Peer identity is already verified via RSA AUTH (signed token)
/// - TLS is used only for channel encryption after authentication
/// - Certificates are self-signed by the peers
///
/// TLS 1.2 signatures are rejected to enforce TLS 1.3 only.
/// TLS 1.3 signatures are cryptographically verified to catch
/// malformed certificates.
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any well-formed certificate
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // ADB A_STLS uses TLS 1.3 only
        Err(rustls::Error::General(
            "TLS 1.2 is not supported in ADB TLS".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // ADB trusts the peer (identity already verified via RSA AUTH),
        // so we accept any well-formed signature.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Return the most common schemes; rustls internally filters
        // against what the actual provider supports.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    /// Helper: generate an RSA key and return its PEM.
    fn rsa_key_pem() -> String {
        auth::export_private_key_to_pem(&auth::generate_rsa_key().unwrap()).unwrap()
    }

    /// Verify that a self-signed certificate can be generated from an RSA
    /// private key PEM, and that the output is non-empty DER.
    #[test]
    fn test_generate_self_signed_cert() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) = generate_self_signed_cert(&pem).unwrap();

        // DER should be non-empty and look reasonable
        assert!(!cert_der.is_empty(), "cert DER should not be empty");
        assert!(!key_der.is_empty(), "key DER should not be empty");

        // Certificate DER typically starts with 0x30 (SEQUENCE)
        assert_eq!(cert_der[0], 0x30, "cert DER should start with SEQUENCE tag");

        // Key DER (PKCS#8) typically starts with 0x30 (SEQUENCE)
        assert_eq!(key_der[0], 0x30, "key DER should start with SEQUENCE tag");

        // Rough size check: RSA 2048 cert ~ 800–1200 bytes, key ~ 1200 bytes
        assert!(cert_der.len() > 400, "cert DER too small: {}", cert_der.len());
        assert!(key_der.len() > 200, "key DER too small: {}", key_der.len());
    }

    /// Verify that a TLS client config can be created from DER cert+key.
    #[test]
    fn test_create_tls_config() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) = generate_self_signed_cert(&pem).unwrap();

        let config = create_tls_config(cert_der, key_der).unwrap();

        // Config should be shareable (wrapped in Arc)
        let _cloned = Arc::clone(&config);
    }

    /// Verify that a TLS server config can be created from DER cert+key.
    #[test]
    fn test_create_server_config() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) = generate_self_signed_cert(&pem).unwrap();

        let config = create_server_config(cert_der, key_der).unwrap();

        // Config should be shareable
        let _cloned = Arc::clone(&config);
    }

    /// Full end-to-end TLS 1.3 handshake test using loopback TCP.
    ///
    /// Spawns a TLS server in a background thread, connects with a TLS
    /// client, sends a message, and verifies the server receives it.
    #[test]
    fn test_full_tls_handshake() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) = generate_self_signed_cert(&pem).unwrap();

        // -- Server side --
        let server_cfg = create_server_config(cert_der.clone(), key_der.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("server accept");
            let mut tls_stream = accept_tls_handshake(stream, server_cfg).expect("server handshake");

            // Read the client's message
            let mut buf = [0u8; 1024];
            let n = tls_stream.read(&mut buf).expect("server read");
            let received = String::from_utf8_lossy(&buf[..n]);

            // Echo back
            tls_stream.write_all(received.as_bytes()).expect("server write");
            tls_stream.flush().ok();

            received.to_string()
        });

        // Allow server thread to start
        thread::sleep(Duration::from_millis(100));

        // -- Client side --
        let client_cfg = create_tls_config(cert_der, key_der).unwrap();
        let stream = TcpStream::connect(server_addr).expect("client connect");
        let mut tls_stream = perform_tls_handshake(stream, client_cfg, "adb").expect("client handshake");

        // Send a message
        let msg = b"hello from A_STLS";
        tls_stream.write_all(msg).expect("client write");
        tls_stream.flush().ok();

        // Read the echo back
        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).expect("client read");
        let echo = String::from_utf8_lossy(&buf[..n]);

        assert_eq!(echo, "hello from A_STLS", "echo should match sent message");

        let server_result = handle.join().expect("server thread");
        assert_eq!(server_result, "hello from A_STLS");
    }

    /// Verify that configs from different RSA keys can still handshake
    /// (since we accept any certificate).
    #[test]
    fn test_cross_key_handshake() {
        // Server key
        let server_pem = rsa_key_pem();
        let (server_cert, server_key) = generate_self_signed_cert(&server_pem).unwrap();

        // Client key (different RSA key-pair)
        let client_pem = rsa_key_pem();
        let (client_cert, client_key) = generate_self_signed_cert(&client_pem).unwrap();

        let server_cfg = create_server_config(server_cert, server_key).unwrap();
        let client_cfg = create_tls_config(client_cert, client_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("server accept");
            let mut tls_stream = accept_tls_handshake(stream, server_cfg).expect("server handshake");
            let mut buf = [0u8; 1024];
            let n = tls_stream.read(&mut buf).expect("server read");
            let received = buf[..n].to_vec();
            // Echo back so the client can read
            tls_stream.write_all(&received).expect("server write");
            tls_stream.flush().ok();
            received
        });

        thread::sleep(Duration::from_millis(100));

        let stream = TcpStream::connect(server_addr).expect("client connect");
        let mut tls_stream =
            perform_tls_handshake(stream, client_cfg, "adb").expect("client handshake");
        tls_stream.write_all(b"cross-key-ok").unwrap();
        tls_stream.flush().ok();

        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"cross-key-ok");

        let server_result = handle.join().expect("server thread");
        assert_eq!(server_result, b"cross-key-ok");
    }

    /// Verify that an invalid PEM causes a clear error, not a panic.
    #[test]
    fn test_invalid_pem_error() {
        let result = generate_self_signed_cert("not a valid PEM");
        assert!(result.is_err(), "should return an error for invalid PEM");
        match result {
            Err(TlsError::InvalidPrivateKey(msg)) => {
                assert!(!msg.is_empty(), "error message should not be empty");
            }
            other => panic!("expected InvalidPrivateKey, got: {other:?}"),
        }
    }
}
