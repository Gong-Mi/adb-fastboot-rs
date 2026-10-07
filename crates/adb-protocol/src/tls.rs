//! TLS 1.3 support for ADB's A_STLS protocol.
//!
//! Module root for the AOSP-mirror layout:
//!
//! - `tls::tls_connection` — TLS config, handshake, TlsError
//! - `tls::adb_ca_list` — custom certificate verifier
//! - `crate::crypto::x509_generator` — X.509 certificate generation
//!
//! ## Feature gate
//! This module is only available when the `tls` feature is enabled.
//! It does not change the default build.

pub mod adb_ca_list;
pub mod tls_connection;

// Re-export TLS connection types
pub use tls_connection::{
    accept_tls_handshake, create_server_config, create_tls_config, export_pairing_key_material,
    perform_tls_handshake, perform_tls_handshake_with_key,
    perform_tls_handshake_with_pairing_export, ClientConnection, ReadFully, ServerConnection,
    TlsConnection, TlsError, TlsMode, TlsStream, WriteFully,
};
// re-export X.509 cert generation (moved to crypto::x509_generator)
pub use crate::crypto::x509_generator::generate_self_signed_cert;

/// AOSP adb.cpp:318-325 / 447-453: reply to device STLS in plaintext before
/// starting TLS. This is deliberately separate from generic TLS stream setup.
pub fn send_tls_request(transport: &mut dyn crate::Transport) -> Result<(), crate::TransportError> {
    let header = crate::AdbMessageHeader::new(crate::A_STLS, crate::A_STLS_VERSION, 0, &[]);
    transport.send_message(&header, &[])
}

/// AOSP client/auth.cpp:487-505: upgrade after the host STLS reply and wait
/// for the device's encrypted CNXN. Never resend host CNXN or return a plaintext
/// transport after a certificate/configuration/handshake failure.
pub fn adb_auth_tls_handshake(
    transport: Box<dyn crate::Transport>,
    rsa_key_pem: &str,
) -> Result<(Vec<u8>, Box<dyn crate::Transport>), Box<dyn std::error::Error>> {
    let (cert, key) = generate_self_signed_cert(rsa_key_pem)
        .map_err(|error| format!("Failed to generate TLS certificate: {error}"))?;
    let config = create_adb_tls_config(cert, key)
        .map_err(|error| format!("Failed to create TLS config: {error}"))?;
    let mut transport: Box<dyn crate::Transport> =
        Box::new(crate::AdbTlsTransport::new(transport, config, "adb")?);
    // The first read drives rustls's lazy handshake without emitting an ADB
    // application packet. A successful TLS session alone is not ADB online.
    let (header, banner) = transport
        .recv_message()
        .map_err(|error| format!("TLS upgrade failed while waiting for CNXN: {error}"))?;
    if header.command != crate::A_CNXN {
        return Err(format!(
            "Unexpected handshake response after TLS upgrade: cmd={:#x}",
            header.command
        )
        .into());
    }
    Ok((banner, transport))
}

/// ADB trusts self-signed peer chains, not fabricated CertificateVerify proofs.
/// Keep this production ADB config separate from the generic TLS echo helpers.
/// TLS 1.3 only, with provider-backed verification of the server's key ownership.
pub fn create_adb_tls_config(
    cert: Vec<u8>,
    key: Vec<u8>,
) -> Result<std::sync::Arc<rustls::ClientConfig>, TlsError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AdbServerCertVerifier))
    .with_client_auth_cert(
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
    )?;
    Ok(std::sync::Arc::new(config))
}

#[derive(Debug)]
struct AdbServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AdbServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // AOSP host-side ADB has no WebPKI server-name/root trust requirement.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("ADB requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
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
        let (cert_der, key_der) =
            crate::crypto::x509_generator::generate_self_signed_cert(&pem).unwrap();

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
        let (cert_der, key_der) =
            crate::crypto::x509_generator::generate_self_signed_cert(&pem).unwrap();

        let config = create_tls_config(cert_der, key_der).unwrap();

        // Config should be shareable (wrapped in Arc)
        let _cloned = Arc::clone(&config);
    }

    /// Verify that a TLS server config can be created from DER cert+key.
    #[test]
    fn test_create_server_config() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) =
            crate::crypto::x509_generator::generate_self_signed_cert(&pem).unwrap();

        let config = create_server_config(cert_der, key_der).unwrap();

        // Config should be shareable
        let _cloned = Arc::clone(&config);
    }

    /// Full end-to-end TLS 1.3 handshake test using loopback TCP.
    #[test]
    fn test_full_tls_handshake() {
        let pem = rsa_key_pem();
        let (cert_der, key_der) =
            crate::crypto::x509_generator::generate_self_signed_cert(&pem).unwrap();

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
        let (mut tls_stream, pairing_export) =
            perform_tls_handshake_with_pairing_export(stream, client_cfg, "adb")
                .expect("client handshake");
        assert!(pairing_export.iter().any(|byte| *byte != 0));

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
        let (server_cert, server_key) =
            crate::crypto::x509_generator::generate_self_signed_cert(&server_pem).unwrap();

        // Client key (different RSA key-pair)
        let client_pem = rsa_key_pem();
        let (client_cert, client_key) =
            crate::crypto::x509_generator::generate_self_signed_cert(&client_pem).unwrap();

        let server_cfg = create_server_config(server_cert, server_key).unwrap();
        let client_cfg = create_tls_config(client_cert, client_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("server accept");
            let mut tls_stream =
                accept_tls_handshake(stream, server_cfg).expect("server handshake");
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

    /// Certificate generation errors must consume the transport, not expose
    /// a successful plaintext connection with an empty banner.
    #[test]
    fn test_adb_tls_cert_failure_consumes_transport() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct DropProbe(Arc<AtomicBool>);
        impl Read for DropProbe {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("certificate failure must precede TLS I/O")
            }
        }
        impl Write for DropProbe {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                panic!("certificate failure must not write plaintext")
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::Transport for DropProbe {}
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let result =
            adb_auth_tls_handshake(Box::new(DropProbe(Arc::clone(&dropped))), "invalid PEM");
        assert!(result.is_err(), "must not return a plaintext transport");
        let error = result.err().unwrap().to_string();
        assert!(
            error.contains("Failed to generate TLS certificate"),
            "{error}"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "failed transport must be dropped"
        );
    }

    #[test]
    fn test_adb_tls_invalid_config_is_error() {
        let (cert, _) = generate_self_signed_cert(&rsa_key_pem()).unwrap();
        assert!(create_adb_tls_config(cert, vec![1, 2, 3]).is_err());
    }

    /// Verify that an invalid PEM causes a clear error, not a panic.
    #[test]
    fn test_invalid_pem_error() {
        let result = crate::crypto::x509_generator::generate_self_signed_cert("not a valid PEM");
        assert!(result.is_err(), "should return an error for invalid PEM");
        match result {
            Err(crate::crypto::x509_generator::CertError::InvalidPrivateKey(msg)) => {
                assert!(!msg.is_empty(), "error message should not be empty");
            }
            other => panic!("expected InvalidPrivateKey, got: {other:?}"),
        }
    }
}
