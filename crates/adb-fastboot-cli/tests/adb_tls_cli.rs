//! Real CLI STLS/TLS tests with independent public host/server keys.
//! AOSP adb.cpp:318-325,447-453; client/auth.cpp:487-505; daemon/auth.cpp:341-384.
//! Disposable persisted HOME identity; no user keys, device or system server.
#![cfg(feature = "tls")]
#[path = "support/adb_tls.rs"]
#[allow(dead_code)]
mod support;
use support::*;

fn run_cli(addr: std::net::SocketAddr, home: &Home) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .env("HOME", &home.0)
        .env_remove("ADB_VENDOR_KEYS")
        .args(["-s", &addr.to_string(), "reboot", "tls-fixture"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("CLI TLS timeout: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn identity_oracle_rejects_valid_certificate_for_other_host_key() {
    use rustls::server::danger::ClientCertVerifier;
    let (cert, _, _) = server_identity();
    assert_ne!(certificate_spki(cert).unwrap(), public_spki(HOST_PEM));
    let verifier = RequireClientCertificate {
        reject: false,
        authorized_spki: public_spki(HOST_PEM),
    };
    assert!(
        verifier
            .verify_client_cert(
                &rustls::pki_types::CertificateDer::from(cert.clone()),
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1)),
            )
            .is_err(),
        "valid cert for an unauthorized key must be rejected, not just counted"
    );
}

#[test]
fn identity_oracle_persisted_key_matches_upstream_spki_and_rejects_bad_der() {
    use base64::Engine;
    use rustls::server::danger::ClientCertVerifier;
    let home = Home::new("spki-vector");
    let pem = std::fs::read_to_string(home.0.join(".android/adbkey")).unwrap();
    let expected = base64::engine::general_purpose::STANDARD
        .decode(include_str!("fixtures/public-rsa2048-host-spki.b64").trim())
        .unwrap();
    assert_eq!(
        public_spki(&pem),
        expected,
        "independent upstream public DER vector"
    );
    let (cert, _) = tls::generate_self_signed_cert(&pem).unwrap();
    assert_eq!(certificate_spki(&cert).unwrap(), expected);
    let verifier = RequireClientCertificate {
        reject: false,
        authorized_spki: expected.clone(),
    };
    let verify = |cert: Vec<u8>| {
        verifier.verify_client_cert(
            &rustls::pki_types::CertificateDer::from(cert),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1)),
        )
    };
    assert!(verify(cert.clone()).is_ok());
    assert!(
        verify(vec![0x30, 0x80, 0, 0]).is_err(),
        "indefinite DER length"
    );
    assert!(
        verify(vec![0x30, 0xff]).is_err(),
        "truncated/oversize DER length"
    );
    for end in [0, 1, cert.len() / 2, cert.len() - 1] {
        assert!(
            verify(cert[..end].to_vec()).is_err(),
            "truncated cert {end}"
        );
    }
    let mut containing_authorized_key = server_identity().0.clone();
    containing_authorized_key.extend_from_slice(&expected);
    assert!(
        verify(containing_authorized_key).is_err(),
        "bytes-contains is not authorization"
    );
}

#[test]
fn other_host_has_valid_tls_certificate_verify_but_is_not_authorized() {
    use rustls::pki_types::CertificateDer;
    use rustls::server::danger::ClientCertVerifier;
    let (wrong_cert, wrong_key, wrong_pem) = server_identity();
    // Positive cryptographic control only: authorize exactly this other key.
    // Never disable/relax the identity verifier or signature checks.
    let config = server_config_for(false, public_spki(wrong_pem));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).unwrap();
        }
        assert_eq!(
            connection.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"P");
        stream.write_all(b"K").unwrap();
        stream.flush().unwrap();
    });
    let client_config = tls::create_tls_config(wrong_cert.clone(), wrong_key.clone()).unwrap();
    let socket = TcpStream::connect(addr).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    let connection =
        rustls::ClientConnection::new(client_config, "adb".try_into().unwrap()).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream.write_all(b"P").unwrap();
    stream.flush().unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"K");
    peer.join().unwrap();
    let verifier = RequireClientCertificate {
        reject: false,
        authorized_spki: public_spki(HOST_PEM),
    };
    assert!(verifier
        .verify_client_cert(
            &CertificateDer::from(wrong_cert.clone()),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1))
        )
        .is_err());
    eprintln!("generic TLS proof control: other key completes TLS1.3 + application exchange; authorized-host SPKI oracle rejects same cert");
}

#[test]
fn adb_tls_cli_wrong_persisted_host_identity_is_rejected_during_handshake() {
    let home = Home::with_pem("wrong-host-identity", &server_identity().2);
    let config = server_config(); // authorizes HOST_PEM, NOT this child's HOME key
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let mut socket = accept_stls(listener);
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        let error = loop {
            match connection.complete_io(&mut socket) {
                Err(error) => break error,
                Ok(_) => assert!(
                    connection.is_handshaking(),
                    "unauthorized identity completed TLS"
                ),
            }
        };
        assert!(
            error.to_string().contains("ApplicationVerificationFailure"),
            "{error}"
        );
        eprintln!("adbd rejected wrong host SPKI: {error}; no encrypted CNXN/OPEN");
    });
    let output = run_cli(addr, &home);
    peer.join().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("TLS upgrade failed"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Reboot request sent"));
    eprintln!(
        "wrong persisted host identity: CLI rc={:?}, stderr={stderr}",
        output.status.code()
    );
}

#[test]
fn adb_tls_cli_stls_then_encrypted_cnxn_and_open() {
    let home = Home::new("success");
    let persisted_pem = std::fs::read_to_string(home.0.join(".android/adbkey")).unwrap();
    let authorized_spki = public_spki(&persisted_pem);
    let expected_spki = authorized_spki.clone();
    let config = server_config_for(false, authorized_spki);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let socket = accept_stls(listener);
        let mut stream = tls::accept_tls_handshake(socket, config).unwrap();
        // Device sends CNXN immediately. Never ask for another host CNXN.
        send_frame(&mut stream, A_CNXN, adb_protocol::ADB_VERSION, BANNER);
        assert_eq!(
            stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            stream.conn.peer_certificates().unwrap().len(),
            1,
            "host TLS client certificate required"
        );
        assert_eq!(
            certificate_spki(stream.conn.peer_certificates().unwrap()[0].as_ref()).unwrap(),
            expected_spki,
            "actual CLI cert identity equals persisted authorized adbkey"
        );
        let (command, local, remote, payload) = recv_frame(&mut stream).unwrap();
        assert_eq!(
            command, A_OPEN,
            "first encrypted host packet must be OPEN, not CNXN"
        );
        assert_eq!((local, remote), (1, 0));
        assert_eq!(payload, b"reboot:tls-fixture");
    });
    let output = run_cli(addr, &home);
    let peer_result = peer.join();
    assert!(output.status.success(), "production CLI: {output:?}");
    peer_result.expect("fake adbd protocol contract");
    eprintln!("CLI success: rc={:?}; plaintext CNXN/STLS/STLS; mutually authenticated TLS1.3; encrypted CNXN/OPEN", output.status.code());
}

#[test]
fn adb_tls_cli_peer_disconnect_fails_closed() {
    let home = Home::new("disconnect");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || drop(accept_stls(listener)));
    let output = run_cli(addr, &home);
    let peer_result = peer.join();
    assert_eq!(
        output.status.code(),
        Some(1),
        "TLS failure must fail CLI: {output:?}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Reboot request sent"));
    peer_result.expect("plaintext STLS reply before disconnect");
}

fn assert_error_case(tag: &str, action: impl FnOnce(TcpStream) + Send + 'static) -> Output {
    let home = Home::new(tag);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || action(accept_stls(listener)));
    let output = run_cli(addr, &home);
    let peer_result = peer.join();
    assert_eq!(
        output.status.code(),
        Some(1),
        "TLS error must fail CLI: {output:?}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Reboot request sent"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("falling back"));
    peer_result.expect("fake adbd TLS error contract");
    output
}

#[test]
fn adb_tls_cli_plaintext_cnxn_after_stls_is_not_success() {
    let output = assert_error_case("plaintext-cnxn", |mut socket| {
        send_frame(&mut socket, A_CNXN, adb_protocol::ADB_VERSION, BANNER);
    });
    assert!(String::from_utf8_lossy(&output.stderr).contains("TLS upgrade failed"));
}

#[test]
fn adb_tls_cli_unexpected_encrypted_packet_is_not_online() {
    let config = server_config();
    let output = assert_error_case("wrong-encrypted-packet", move |socket| {
        let mut stream = tls::accept_tls_handshake(socket, config).unwrap();
        send_frame(&mut stream, A_OPEN, 73, b"not-CNXN");
        assert_eq!(
            stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let mut byte = [0];
        let closed = match stream.read(&mut byte) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ),
            _ => false,
        };
        assert!(
            closed,
            "host must close, not send a service after bad TLS CNXN"
        );
    });
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Unexpected handshake response after TLS upgrade"));
}

#[derive(Debug)]
struct FixedCert(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn bad_certificate_config(malformed: bool) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert, _, _) = server_identity();
    // Generate another fixture identity, then bypass ServerConfig's normal
    // key/certificate consistency check ONLY on the adversarial fake peer.
    // CertificateVerify is signed with the wrong private key (or bad DER).
    let key = tls::generate_self_signed_cert(HOST_PEM).unwrap().1;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::from(
        PrivatePkcs8KeyDer::from(key.clone()),
    ))
    .unwrap();
    let cert = if malformed {
        vec![1, 2, 3]
    } else {
        cert.clone()
    };
    let certified_key =
        rustls::sign::CertifiedKey::new(vec![CertificateDer::from(cert)], signing_key);
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified_key)))),
    )
}

fn rejected_certificate(tag: &str, malformed: bool) {
    let config = bad_certificate_config(malformed);
    let output = assert_error_case(tag, move |mut socket| {
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        let failure = loop {
            match connection.complete_io(&mut socket) {
                Err(error) => break error,
                Ok(_) => assert!(
                    connection.is_handshaking(),
                    "host incorrectly accepted bad server certificate"
                ),
            }
        };
        // rustls can close without flushing its alert when the ADB read fails.
        // Require rejection/EOF, not a timeout; verify the certificate error on
        // the actual client below so a mere disconnect cannot make this green.
        assert!(
            failure.to_string().contains("alert")
                || failure.kind() == std::io::ErrorKind::UnexpectedEof,
            "expected client TLS rejection, got {failure}"
        );
    });
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{tag}: rc={:?}, stderr={stderr}", output.status.code());
    assert!(stderr.contains("TLS upgrade failed"), "{output:?}");
    assert!(stderr.contains("invalid peer certificate"), "{output:?}");
}

#[test]
fn adb_tls_cli_wrong_certificate_key_fails_closed() {
    rejected_certificate("wrong-cert-key", false);
}

#[test]
fn adb_tls_cli_malformed_certificate_fails_closed() {
    rejected_certificate("malformed-cert", true);
}

#[test]
fn adb_tls_cli_adbd_rejects_client_certificate_fails_closed() {
    let config = client_auth_server_config(true);
    let output = assert_error_case("client-cert-rejected", move |mut socket| {
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        let error = loop {
            match connection.complete_io(&mut socket) {
                Err(error) => break error,
                Ok(_) => assert!(
                    connection.is_handshaking(),
                    "adbd must reject client certificate"
                ),
            }
        };
        assert!(
            error.to_string().contains("ApplicationVerificationFailure"),
            "{error}"
        );
    });
    assert!(String::from_utf8_lossy(&output.stderr).contains("TLS upgrade failed"));
}
