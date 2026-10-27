//! Production ADB STLS tests, not a generic TLS echo test. The independent
//! fake adbd follows AOSP adb.cpp:318-325,447-453 and client/auth.cpp:487-505:
//! host CNXN -> device STLS -> host STLS -> TLS 1.3 -> device CNXN -> host OPEN.
//! No server process, USB, real device, or persisted host identity is used.
#![cfg(feature = "tls")]

use adb_protocol::{tls, AdbAuth, A_CNXN, A_OPEN, A_STLS, A_STLS_VERSION};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(15);
const BANNER: &[u8] = b"device::features=cmd,shell_v2\0";

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// Intentionally independent of the production Transport codec.
fn recv_frame(io: &mut (impl Read + ?Sized)) -> std::io::Result<(u32, u32, u32, Vec<u8>)> {
    let mut header = [0; 24];
    io.read_exact(&mut header)?;
    let command = word(&header);
    assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
    let length = word(&header[12..]) as usize;
    assert!(length <= 1024 * 1024, "bounded ADB payload");
    let mut payload = vec![0; length];
    io.read_exact(&mut payload)?;
    Ok((command, word(&header[4..]), word(&header[8..]), payload))
}

fn send_frame(io: &mut (impl Write + ?Sized), command: u32, arg0: u32, payload: &[u8]) {
    for field in [
        command,
        arg0,
        0,
        payload.len() as u32,
        payload.iter().map(|&b| u32::from(b)).sum(),
        command ^ u32::MAX,
    ] {
        io.write_all(&field.to_le_bytes()).unwrap();
    }
    io.write_all(payload).unwrap();
    io.flush().unwrap();
}

fn fixture_identity() -> &'static (Vec<u8>, Vec<u8>, String) {
    static IDENTITY: OnceLock<(Vec<u8>, Vec<u8>, String)> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let auth = AdbAuth::generate("fake-adbd-stls").unwrap();
        let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key()).unwrap();
        let (cert, key) = tls::generate_self_signed_cert(&pem).unwrap();
        (cert, key, pem)
    })
}

#[derive(Debug)]
struct RequireClientCertificate {
    reject: bool,
}
impl rustls::server::danger::ClientCertVerifier for RequireClientCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if self.reject {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Fixture trust is not Android pairing. Require a real certificate and
        // verify CertificateVerify cryptographically below, like adbd's TLS.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("fixture requires TLS 1.3".into()))
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

fn server_config() -> Arc<rustls::ServerConfig> {
    client_auth_server_config(false)
}

fn client_auth_server_config(reject: bool) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert, key, _) = fixture_identity();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(RequireClientCertificate { reject }))
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.clone())),
        )
        .unwrap(),
    )
}

fn accept_stls(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "CLI never connected");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    let (command, _, _, payload) = recv_frame(&mut socket).unwrap();
    assert_eq!(command, A_CNXN, "initial plaintext host CNXN");
    assert!(payload.starts_with(b"host::"));
    send_frame(&mut socket, A_STLS, A_STLS_VERSION, &[]);
    // Check the first four bytes before decoding: a ClientHello in place of
    // this reply is the missing-host-STLS regression, not a TLS setup error.
    let mut command = [0; 4];
    socket.read_exact(&mut command).expect("host STLS reply");
    assert_eq!(
        &command, b"STLS",
        "host must reply STLS before TLS ClientHello"
    );
    let mut rest = [0; 20];
    socket.read_exact(&mut rest).unwrap();
    assert_eq!(word(&rest), A_STLS_VERSION);
    assert_eq!(word(&rest[4..]), 0, "STLS arg1");
    assert_eq!(word(&rest[8..]), 0, "STLS has no payload");
    assert_eq!(word(&rest[12..]), 0, "empty STLS checksum");
    assert_eq!(word(&rest[16..]), A_STLS ^ u32::MAX);
    socket
}

struct Home(PathBuf);
impl Home {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("adb-stls-{tag}-{}", std::process::id()));
        let android = path.join(".android");
        std::fs::create_dir_all(&android).unwrap();
        // Generated test-only key, never read from the user's HOME or committed.
        // Preload it so RSA generation is outside socket/CLI deadlines.
        use std::os::unix::fs::OpenOptionsExt;
        let mut key = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(android.join("adbkey"))
            .unwrap();
        key.write_all(fixture_identity().2.as_bytes()).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
fn adb_tls_cli_stls_then_encrypted_cnxn_and_open() {
    let config = server_config();
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
        let (command, local, remote, payload) = recv_frame(&mut stream).unwrap();
        assert_eq!(
            command, A_OPEN,
            "first encrypted host packet must be OPEN, not CNXN"
        );
        assert_eq!((local, remote), (1, 0));
        assert_eq!(payload, b"reboot:tls-fixture");
    });
    let home = Home::new("success");
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
    let (cert, _, _) = fixture_identity();
    // Generate another fixture identity, then bypass ServerConfig's normal
    // key/certificate consistency check ONLY on the adversarial fake peer.
    // CertificateVerify is signed with the wrong private key (or bad DER).
    static OTHER_KEY: OnceLock<Vec<u8>> = OnceLock::new();
    let key = OTHER_KEY.get_or_init(|| {
        let auth = AdbAuth::generate("fake-adbd-wrong-cert-key").unwrap();
        let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key()).unwrap();
        tls::generate_self_signed_cert(&pem).unwrap().1
    });
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
