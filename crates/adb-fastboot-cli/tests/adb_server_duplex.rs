//! Real adb-rs server process, independent smart-socket and fake-adbd wire codec.
//! AOSP adb.cpp:499-624 / protocol.txt: OPEN/OKAY/WRTE/CLSE (legacy ACK mode).
//! No USB build, installed adb, or device is used in the local acceptance command.
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CNXN: u32 = u32::from_le_bytes(*b"CNXN");
const OPEN: u32 = u32::from_le_bytes(*b"OPEN");
const OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const WRTE: u32 = u32::from_le_bytes(*b"WRTE");
const CLSE: u32 = u32::from_le_bytes(*b"CLSE");
const TIMEOUT: Duration = Duration::from_secs(15);

fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let auth = adb_protocol::AdbAuth::generate("server-duplex-test").unwrap();
        adb_protocol::auth::export_private_key_to_pem(auth.private_key()).unwrap()
    })
}
fn listener() -> TcpListener {
    // Expensive fixture RSA generation must precede starting peer deadlines.
    // Never load the user's real key through the /sdcard fallback.
    let _ = test_key();
    TcpListener::bind("127.0.0.1:0").unwrap()
}

type Frame = (u32, u32, u32, Vec<u8>);
fn recv(io: &mut (impl Read + ?Sized)) -> std::io::Result<Frame> {
    let mut h = [0; 24];
    io.read_exact(&mut h)?;
    let w = |i| u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
    assert_eq!(w(20), w(0) ^ u32::MAX);
    assert!(w(12) <= 1024 * 1024);
    let mut p = vec![0; w(12) as usize];
    io.read_exact(&mut p)?;
    Ok((w(0), w(4), w(8), p))
}
fn send(io: &mut (impl Write + ?Sized), cmd: u32, a: u32, b: u32, p: &[u8]) {
    for w in [
        cmd,
        a,
        b,
        p.len() as u32,
        p.iter().map(|b| *b as u32).sum(),
        !cmd,
    ] {
        io.write_all(&w.to_le_bytes()).unwrap();
    }
    io.write_all(p).unwrap();
    io.flush().unwrap();
}
fn accept(l: &TcpListener) -> TcpStream {
    l.set_nonblocking(true).unwrap();
    let until = Instant::now() + TIMEOUT;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_read_timeout(Some(TIMEOUT)).unwrap();
                s.set_write_timeout(Some(TIMEOUT)).unwrap();
                return s;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < until,
                    "server never connected to fake adbd"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}
fn handshake(s: &mut (impl Read + Write + ?Sized)) {
    assert_eq!(recv(s).unwrap().0, CNXN);
    // No delayed_ack feature: host must use one outstanding WRTE per stream.
    send(s, CNXN, 0x01000001, 1024 * 1024, b"device::features=cmd\0");
}
fn request(s: &mut TcpStream, cmd: &str) {
    s.write_all(format!("{:04x}{cmd}", cmd.len()).as_bytes())
        .unwrap();
}
fn status(s: &mut TcpStream) {
    let mut b = [0; 4];
    s.read_exact(&mut b).unwrap();
    if &b == b"FAIL" {
        panic!("server FAIL: {}", String::from_utf8_lossy(&payload(s)));
    }
    assert_eq!(&b, b"OKAY");
}
fn payload(s: &mut TcpStream) -> Vec<u8> {
    let mut b = [0; 4];
    s.read_exact(&mut b).unwrap();
    let n = usize::from_str_radix(std::str::from_utf8(&b).unwrap(), 16).unwrap();
    let mut p = vec![0; n];
    s.read_exact(&mut p).unwrap();
    p
}
struct Server {
    child: Child,
    port: u16,
    home: std::path::PathBuf,
}
impl Server {
    fn start() -> Self {
        let l = listener();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let home =
            std::env::temp_dir().join(format!("adb-server-duplex-{}-{port}", std::process::id()));
        let keys = home.join(".android");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("adbkey"), test_key()).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
            .args(["-P", &port.to_string(), "server", "nodaemon"])
            .env("HOME", &home)
            .env_remove("ADB_SERVER_SOCKET")
            .env_remove("ANDROID_ADB_SERVER_PORT")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut this = Self { child, port, home };
        let until = Instant::now() + TIMEOUT;
        loop {
            assert!(
                this.child.try_wait().unwrap().is_none(),
                "server exited during startup"
            );
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
                s.set_read_timeout(Some(TIMEOUT)).unwrap();
                request(&mut s, "host:version");
                status(&mut s);
                assert!(!payload(&mut s).is_empty());
                break;
            }
            assert!(Instant::now() < until, "server not ready");
            thread::sleep(Duration::from_millis(10));
        }
        this
    }
    fn socket(&self) -> TcpStream {
        let s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(TIMEOUT)).unwrap();
        s.set_write_timeout(Some(TIMEOUT)).unwrap();
        s
    }
    fn register(&self, addr: std::net::SocketAddr) {
        let mut s = self.socket();
        request(&mut s, &format!("host:connect:{addr}"));
        status(&mut s);
        assert_eq!(payload(&mut s), format!("connected to {addr}").as_bytes());
    }
    fn service(&self, addr: std::net::SocketAddr) -> TcpStream {
        let mut s = self.socket();
        request(&mut s, &format!("host:transport:{addr}"));
        status(&mut s);
        request(&mut s, "exec:cat");
        status(&mut s);
        s
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[test]
fn real_server_device_waiting_for_client_and_interleaved_output() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        // Existing design: registration monitor and each client have distinct TCP connections.
        let mut monitor = accept(&l);
        handshake(&mut monitor);
        let mut io = accept(&l);
        handshake(&mut io);
        let (cmd, local, zero, name) = recv(&mut io).unwrap();
        assert_eq!((cmd, zero), (OPEN, 0));
        assert_ne!(local, 0);
        assert_eq!(name.strip_suffix(&[0]).unwrap_or(&name), b"exec:cat");
        let remote = 73;
        send(&mut io, OKAY, remote, local, &[]);
        // No device output until client input: a mutex-held blocking recv deadlocks here.
        assert_eq!(
            recv(&mut io).unwrap(),
            (WRTE, local, remote, b"input".to_vec())
        );
        // Output before input ACK must be delivered, not stolen by an ACK reader.
        send(&mut io, WRTE, remote, local, b"output");
        assert_eq!(recv(&mut io).unwrap(), (OKAY, local, remote, vec![]));
        send(&mut io, OKAY, remote, local, &[]);
        send(&mut io, CLSE, remote, local, &[]);
        assert_eq!(recv(&mut io).unwrap(), (CLSE, local, remote, vec![]));
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.service(addr);
    s.write_all(b"input").unwrap();
    let mut result = Vec::new();
    s.read_to_end(&mut result)
        .expect("bounded client EOF after device CLSE");
    assert_eq!(result, b"output");
    fake.join().unwrap();
}

trait PeerIo: Read + Write {}
impl<T: Read + Write> PeerIo for T {}

#[cfg(feature = "tls")]
fn tls_config() -> std::sync::Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ServerConfig>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let auth = adb_protocol::AdbAuth::generate("fake-adbd-server").unwrap();
            let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key()).unwrap();
            let (cert, key) = adb_protocol::tls::generate_self_signed_cert(&pem).unwrap();
            std::sync::Arc::new(
                rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(std::sync::Arc::new(RequireCertificate))
                .with_single_cert(
                    vec![CertificateDer::from(cert)],
                    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
                )
                .unwrap(),
            )
        })
        .clone()
}
#[cfg(feature = "tls")]
#[derive(Debug)]
struct RequireCertificate;
#[cfg(feature = "tls")]
impl rustls::server::danger::ClientCertVerifier for RequireCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Isolated fixture trust, not pairing. CertificateVerify is checked below.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("requires TLS 1.3".into()))
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
fn peer(l: &TcpListener, encrypted: bool) -> Box<dyn PeerIo> {
    let mut s = accept(l);
    if !encrypted {
        handshake(&mut s);
        return Box::new(s);
    }
    #[cfg(feature = "tls")]
    {
        assert_eq!(recv(&mut s).unwrap().0, CNXN, "plaintext initial CNXN");
        let stls = u32::from_le_bytes(*b"STLS");
        send(&mut s, stls, 0x01000000, 0, &[]);
        assert_eq!(
            recv(&mut s).unwrap(),
            (stls, 0x01000000, 0, vec![]),
            "plaintext host STLS before TLS"
        );
        let c = rustls::ServerConnection::new(tls_config()).unwrap();
        let mut io = rustls::StreamOwned::new(c, s);
        send(
            &mut io,
            CNXN,
            0x01000001,
            1024 * 1024,
            b"device::features=cmd\0",
        );
        assert_eq!(
            io.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert!(!io.conn.peer_certificates().unwrap().is_empty());
        Box::new(io)
    }
    #[cfg(not(feature = "tls"))]
    panic!("TLS test requires tls feature");
}
fn open_peer(io: &mut dyn PeerIo, remote: u32) -> u32 {
    let (cmd, local, zero, name) = recv(io).unwrap();
    assert_eq!((cmd, zero), (OPEN, 0));
    assert!(local != 0);
    assert_eq!(name, b"exec:cat\0");
    send(io, OKAY, remote, local, &[]);
    local
}
fn eof(s: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    s.read_to_end(&mut data)
        .expect("server must close client within timeout");
    data
}

fn duplex_tls_or_plain(encrypted: bool) {
    #[cfg(feature = "tls")]
    if encrypted {
        let _ = tls_config();
    } // fixture RSA setup is not protocol latency
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, encrypted);
        // Same registered target, two consecutive services, second local ID != 1.
        let mut previous = 0;
        for pass in 0..2 {
            let mut io = peer(&l, encrypted);
            let remote = 91 + pass;
            let local = open_peer(&mut *io, remote);
            assert_ne!(local, previous);
            if pass == 1 {
                assert_ne!(local, 1);
            }
            previous = local;
            assert_eq!(
                recv(&mut *io).unwrap(),
                (WRTE, local, remote, b"in".to_vec())
            );
            // Coalesce two complete frames into one TLS record/plain write;
            // the next output is already in rustls's buffer when ACK releases credit.
            let mut coalesced = Vec::new();
            send(&mut coalesced, WRTE, remote, local, b"first");
            send(&mut coalesced, OKAY, remote, local, &[]);
            io.write_all(&coalesced).unwrap();
            io.flush().unwrap();
            assert_eq!(recv(&mut *io).unwrap(), (OKAY, local, remote, vec![]));
            let mut fragmented = Vec::new();
            send(&mut fragmented, WRTE, remote, local, b"second");
            for chunk in fragmented.chunks(3) {
                io.write_all(chunk).unwrap();
                io.flush().unwrap();
            }
            assert_eq!(recv(&mut *io).unwrap(), (OKAY, local, remote, vec![]));
            send(&mut *io, CLSE, remote, local, &[]);
            assert_eq!(recv(&mut *io).unwrap(), (CLSE, local, remote, vec![]));
        }
    });
    let server = Server::start();
    server.register(addr);
    for _ in 0..2 {
        let mut s = server.service(addr);
        s.write_all(b"in").unwrap();
        assert_eq!(eof(&mut s), b"firstsecond");
    }
    fake.join().unwrap();
}
#[test]
fn real_server_consecutive_services_fragmented_coalesced_frames() {
    duplex_tls_or_plain(false);
}
#[cfg(feature = "tls")]
#[test]
fn real_server_stls_mutual_tls_bidirectional_services() {
    duplex_tls_or_plain(true);
}

#[test]
fn real_server_wrong_ids_cannot_leak_output_close_or_release_credit() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut io = accept(&l);
        handshake(&mut io);
        let local = open_peer(&mut io, 37);
        let first = recv(&mut io).unwrap();
        assert_eq!(
            (first.0, first.1, first.2, first.3.len()),
            (WRTE, local, 37, 4096)
        );
        send(&mut io, OKAY, 38, local, &[]);
        send(&mut io, OKAY, 37, local + 100, &[]);
        send(&mut io, WRTE, 38, local, b"wrong-remote");
        send(&mut io, WRTE, 37, local + 100, b"wrong-local");
        send(&mut io, CLSE, 38, local, &[]);
        io.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let mut b = [0];
        let e = io.read(&mut b).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "wrong IDs released credit"
        );
        io.set_read_timeout(Some(TIMEOUT)).unwrap();
        send(&mut io, WRTE, 37, local, b"valid");
        assert_eq!(recv(&mut io).unwrap(), (OKAY, local, 37, vec![]));
        send(&mut io, OKAY, 37, local, &[]);
        let second = recv(&mut io).unwrap();
        assert_eq!(
            (second.0, second.1, second.2, second.3.len()),
            (WRTE, local, 37, 4096)
        );
        assert!(first.3.iter().chain(second.3.iter()).all(|b| *b == b'x'));
        send(&mut io, OKAY, 37, local, &[]);
        send(&mut io, CLSE, 37, local, &[]);
        assert_eq!(recv(&mut io).unwrap(), (CLSE, local, 37, vec![]));
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.service(addr);
    s.write_all(&vec![b'x'; 8192]).unwrap();
    assert_eq!(eof(&mut s), b"valid");
    fake.join().unwrap();
}

#[test]
fn real_server_client_eof_while_device_silent_after_wrte() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let (sent, ready) = std::sync::mpsc::channel();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut io = peer(&l, false);
        let local = open_peer(&mut *io, 44);
        assert_eq!(
            recv(&mut *io).unwrap(),
            (WRTE, local, 44, b"cancel".to_vec())
        );
        sent.send(()).unwrap();
        assert_eq!(recv(&mut *io).unwrap(), (CLSE, local, 44, vec![]));
        assert!(
            recv(&mut *io).is_err(),
            "owner must close device without waiting for CLSE reply"
        );
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.service(addr);
    s.write_all(b"cancel").unwrap();
    ready.recv_timeout(TIMEOUT).unwrap();
    let start = Instant::now();
    s.shutdown(Shutdown::Write).unwrap();
    assert!(eof(&mut s).is_empty());
    assert!(start.elapsed() < Duration::from_secs(2));
    fake.join().unwrap();
}

fn device_eof(partial: bool) {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let (go, wait) = std::sync::mpsc::channel();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut io = peer(&l, false);
        open_peer(&mut *io, 65);
        wait.recv_timeout(TIMEOUT).unwrap();
        if partial {
            io.write_all(b"WRTEpartial").unwrap();
            io.flush().unwrap();
        }
        // Drop service connection only, keep monitor until test acknowledges EOF.
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.service(addr);
    go.send(()).unwrap();
    assert!(eof(&mut s).is_empty());
    fake.join().unwrap();
}
#[test]
fn real_server_device_eof_wakes_idle_client() {
    device_eof(false);
}
#[test]
fn real_server_partial_frame_eof_wakes_idle_client() {
    device_eof(true);
}

#[test]
fn real_server_rejected_open_returns_fail_not_okay() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut io = peer(&l, false);
        let (_, local, _, _) = recv(&mut *io).unwrap();
        send(&mut *io, CLSE, 0, local, &[]);
        assert!(recv(&mut *io).is_err());
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.socket();
    request(&mut s, &format!("host:transport:{addr}"));
    status(&mut s);
    request(&mut s, "exec:cat");
    let mut b = [0; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"FAIL");
    assert!(String::from_utf8_lossy(&payload(&mut s)).contains("rejected service"));
    assert!(eof(&mut s).is_empty());
    fake.join().unwrap();
}

#[test]
fn real_server_concurrent_clients_have_independent_io_owners() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut a = peer(&l, false);
        let id_a = open_peer(&mut *a, 155);
        let mut b = peer(&l, false);
        let id_b = open_peer(&mut *b, 156);
        assert_ne!(id_a, id_b);
        assert!(id_a != 1 || id_b != 1);
        // Device A waits for client A while B can already send data.
        let input_b = recv(&mut *b).unwrap();
        send(&mut *b, WRTE, 156, id_b, b"prompt");
        assert_eq!(recv(&mut *b).unwrap(), (OKAY, id_b, 156, vec![]));
        let input_a = recv(&mut *a).unwrap();
        for (io, local, remote, frame) in
            [(&mut *a, id_a, 155, input_a), (&mut *b, id_b, 156, input_b)]
        {
            assert_eq!((frame.0, frame.1, frame.2), (WRTE, local, remote));
            assert!(frame.3 == b"A" || frame.3 == b"B");
            send(io, WRTE, remote, local, &frame.3); // output before input credit ACK
            assert_eq!(recv(io).unwrap(), (OKAY, local, remote, vec![]));
            send(io, OKAY, remote, local, &[]);
            send(io, CLSE, remote, local, &[]);
            assert_eq!(recv(io).unwrap(), (CLSE, local, remote, vec![]));
        }
    });
    let server = Server::start();
    server.register(addr);
    thread::scope(|scope| {
        let mut jobs = Vec::new();
        for input in [b"A", b"B"] {
            let server = &server;
            jobs.push(scope.spawn(move || {
                let mut s = server.service(addr);
                s.write_all(input).unwrap();
                let out = eof(&mut s);
                assert!(out == input || out == [b"prompt".as_slice(), input.as_slice()].concat());
            }));
        }
        for job in jobs {
            job.join().unwrap();
        }
    });
    fake.join().unwrap();
}

#[cfg(feature = "tls")]
#[test]
fn real_server_failed_tls_service_handshake_returns_fail_without_plaintext_open() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut s = accept(&l);
        assert_eq!(recv(&mut s).unwrap().0, CNXN);
        let stls = u32::from_le_bytes(*b"STLS");
        send(&mut s, stls, 0x01000000, 0, &[]);
        assert_eq!(recv(&mut s).unwrap().0, stls);
        s.write_all(b"definitely-not-TLS").unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        s.read_to_end(&mut bytes).unwrap();
        assert!(
            !bytes.windows(4).any(|b| b == b"OPEN"),
            "TLS failure must not start plaintext service"
        );
    });
    let server = Server::start();
    server.register(addr);
    let mut s = server.socket();
    request(&mut s, &format!("host:transport:{addr}"));
    status(&mut s);
    request(&mut s, "exec:cat");
    let mut b = [0; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"FAIL");
    assert!(String::from_utf8_lossy(&payload(&mut s)).contains("TLS"));
    assert!(eof(&mut s).is_empty());
    fake.join().unwrap();
}

#[test]
fn real_server_host_kill_closes_active_service_and_process() {
    let l = listener();
    let addr = l.local_addr().unwrap();
    let fake = thread::spawn(move || {
        let _monitor = peer(&l, false);
        let mut io = peer(&l, false);
        let local = open_peer(&mut *io, 62);
        // Owner may flush CLSE before the process exits. Either way no reader
        // thread can retain this connection after exact server process exit.
        match recv(&mut *io) {
            Ok(frame) => {
                assert_eq!(frame, (CLSE, local, 62, vec![]));
                assert!(recv(&mut *io).is_err());
            }
            Err(_) => {}
        }
    });
    let mut server = Server::start();
    server.register(addr);
    let mut s = server.service(addr);
    let mut control = server.socket();
    request(&mut control, "host:kill");
    status(&mut control);
    let start = Instant::now();
    assert!(eof(&mut s).is_empty());
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "server process failed bounded shutdown"
        );
        thread::sleep(Duration::from_millis(5));
    }
    fake.join().unwrap();
}
