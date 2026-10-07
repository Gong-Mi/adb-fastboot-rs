//! Device-free regressions that launch the actual adb-rs binary, not a test client.
//! `-s 127.0.0.1:PORT` is the CLI's direct adbd transport selector. These commands
//! do not touch the system ADB server, USB, real devices, or real host keys.
use std::io::{self, Read, Write};
use std::collections::BTreeMap;
use std::fs;
use std::net::{Shutdown, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const REMOTE_ID: u32 = 73;
const A_CNXN: u32 = u32::from_le_bytes(*b"CNXN");
const A_OPEN: u32 = u32::from_le_bytes(*b"OPEN");
const A_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const A_WRTE: u32 = u32::from_le_bytes(*b"WRTE");
const A_CLSE: u32 = u32::from_le_bytes(*b"CLSE");
const SYNC_SEND: u32 = u32::from_le_bytes(*b"SEND");
const SYNC_DATA: u32 = u32::from_le_bytes(*b"DATA");
const SYNC_DONE: u32 = u32::from_le_bytes(*b"DONE");
const SYNC_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const SYNC_FAIL: u32 = u32::from_le_bytes(*b"FAIL");
const SYNC_DATA_MAX: usize = 64 * 1024;

fn word(bytes: &[u8]) -> u32 { u32::from_le_bytes(bytes[..4].try_into().unwrap()) }

// An independent daemon-side codec avoids sharing the client's serialization
// oracle. It only implements fake adbd responses; the client is CARGO_BIN_EXE.
struct AdbMessageHeader { command: u32, arg0: u32, arg1: u32 }
impl AdbMessageHeader {
    fn new(command: u32, arg0: u32, arg1: u32, _: &[u8]) -> Self { Self { command, arg0, arg1 } }
}
struct SyncMessageHeader { id: u32, length: u32 }
impl SyncMessageHeader {
    fn new(id: u32, length: u32) -> Self { Self { id, length } }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 8 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        Ok(Self { id: word(bytes), length: word(&bytes[4..]) })
    }
    fn encode(&self, bytes: &mut [u8; 8]) {
        bytes[..4].copy_from_slice(&self.id.to_le_bytes());
        bytes[4..].copy_from_slice(&self.length.to_le_bytes());
    }
}
struct FakeAdbd(std::net::TcpStream);
impl FakeAdbd {
    fn from_stream(socket: std::net::TcpStream) -> Self { Self(socket) }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> { self.0.set_read_timeout(timeout) }
    fn recv_message(&mut self) -> io::Result<(AdbMessageHeader, Vec<u8>)> {
        let mut header = [0u8; 24];
        self.0.read_exact(&mut header)?;
        let command = word(&header);
        assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
        let length = word(&header[12..]) as usize;
        assert!(length <= 1024 * 1024);
        let mut payload = vec![0; length];
        self.0.read_exact(&mut payload)?;
        let checksum = payload.iter().fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        assert!(word(&header[16..]) == 0 || word(&header[16..]) == checksum, "ADB checksum (v2 permits zero)");
        Ok((AdbMessageHeader { command, arg0: word(&header[4..]), arg1: word(&header[8..]) }, payload))
    }
    fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> io::Result<()> {
        let checksum = payload.iter().fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        for word in [header.command, header.arg0, header.arg1, payload.len() as u32, checksum, header.command ^ u32::MAX] {
            self.0.write_all(&word.to_le_bytes())?;
        }
        self.0.write_all(payload)
    }
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Okay,
    Fail,
    Eof,
}

fn send(peer: &mut FakeAdbd, command: u32, local_id: u32, payload: &[u8]) {
    peer.send_message(&AdbMessageHeader::new(command, REMOTE_ID, local_id, payload), payload)
        .unwrap();
}

fn receive(peer: &mut FakeAdbd, command: u32, local_id: u32) -> Vec<u8> {
    let (header, payload) = peer.recv_message().unwrap_or_else(|error| {
        panic!("strict adbd expected {command:#x} (DATA/DONE must follow SEND without SYNC_OKAY): {error}")
    });
    assert_eq!(header.command, command);
    assert_eq!((header.arg0, header.arg1), (local_id, REMOTE_ID));
    payload
}

fn open(peer: &mut FakeAdbd, service: &str) -> u32 {
    let (header, payload) = peer.recv_message().unwrap();
    assert_eq!(header.command, A_OPEN);
    assert_eq!(header.arg1, 0);
    assert_eq!(payload.strip_suffix(b"\0").unwrap_or(&payload), service.as_bytes());
    send(peer, A_OKAY, header.arg0, &[]);
    header.arg0
}

fn exec_success(peer: &mut FakeAdbd, service: &str) {
    let local_id = open(peer, service);
    send(peer, A_WRTE, local_id, b"Success\n");
    assert!(receive(peer, A_OKAY, local_id).is_empty());
    send(peer, A_CLSE, local_id, &[]);
    assert!(receive(peer, A_CLSE, local_id).is_empty());
}

fn sync_send(
    peer: &mut FakeAdbd,
    expected: &mut BTreeMap<String, Vec<u8>>,
    install: bool,
    outcome: Outcome,
) {
    let local_id = open(peer, "sync:");
    let payload = receive(peer, A_WRTE, local_id);
    let header = SyncMessageHeader::decode(&payload).unwrap();
    assert_eq!(header.id, SYNC_SEND);
    assert_eq!(header.length as usize, payload.len() - 8);
    let destination = std::str::from_utf8(&payload[8..]).unwrap();
    let (path, mode) = destination.rsplit_once(',').unwrap();
    assert_eq!(mode.parse::<u32>().unwrap(), if install { 0x81a4 } else { 0o644 });
    let bytes = expected.remove(path).expect("unexpected or repeated remote SEND path");
    // This is only a WRTE transport acknowledgement, not a SYNC result.
    send(peer, A_OKAY, local_id, &[]);
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let mut received = Vec::new();
    loop {
        let payload = receive(peer, A_WRTE, local_id);
        let header = SyncMessageHeader::decode(&payload).unwrap();
        match header.id {
            SYNC_DATA => {
                assert_eq!(header.length as usize, payload.len() - 8);
                assert!(header.length as usize <= SYNC_DATA_MAX);
                received.extend_from_slice(&payload[8..]);
                assert!(received.len() <= bytes.len());
                assert_eq!(received.as_slice(), &bytes[..received.len()]);
                send(peer, A_OKAY, local_id, &[]);
            }
            SYNC_DONE => {
                assert_eq!(payload.len(), 8);
                assert_eq!(header.length, if install { 0 } else { u32::MAX });
                assert_eq!(received, bytes, "DONE before complete DATA");
                send(peer, A_OKAY, local_id, &[]);
                break;
            }
            other => panic!("unexpected SYNC id {other:#x}"),
        }
    }

    let (id, message): (u32, &[u8]) = match outcome {
        Outcome::Okay => (SYNC_OKAY, b""),
        Outcome::Fail => (SYNC_FAIL, b"strict adbd rejected file"),
        Outcome::Eof => {
            peer.0.shutdown(Shutdown::Both).unwrap();
            return;
        }
    };
    let mut header = [0u8; 8];
    SyncMessageHeader::new(id, message.len() as u32).encode(&mut header);
    send(peer, A_WRTE, local_id, &[header.as_slice(), message].concat());
    assert!(receive(peer, A_OKAY, local_id).is_empty());
    if matches!(outcome, Outcome::Okay) {
        assert!(receive(peer, A_CLSE, local_id).is_empty());
        send(peer, A_CLSE, local_id, &[]);
    } else {
        // FAIL must stop the command: no subsequent SEND, install, or commit.
        assert!(matches!(peer.recv_message(), Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof));
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// This suite exercises SYNC, not RSA prime generation. Use the already-public
// BoringSSL CRL test identity in a private, disposable HOME, never the user's
// adbkey. Random 2048-bit key generation before CNXN can exceed the protocol
// deadline on a loaded Android debug build and make the wrong layer fail.
fn seed_public_test_identity(home: &std::path::Path) {
    use std::os::unix::fs::OpenOptionsExt;
    let source = include_str!("../../../vendor/boringssl/crypto/x509/x509_test.cc");
    let (_, note) = source.split_once(
        "// kCRLTestRoot is a test root certificate. It has private key:",
    ).expect("vendored public BoringSSL test identity");
    let mut pem = String::new();
    for line in note.lines().filter_map(|line| line.strip_prefix("//     ")) {
        if line == "-----BEGIN RSA PRIVATE KEY-----" || !pem.is_empty() {
            pem.push_str(line);
            pem.push('\n');
            if line == "-----END RSA PRIVATE KEY-----" { break; }
        }
    }
    assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END RSA PRIVATE KEY-----\n"));
    let directory = home.join(".android");
    fs::create_dir_all(&directory).unwrap();
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(directory.join("adbkey")).unwrap();
    file.write_all(pem.as_bytes()).unwrap();
}

fn run_cli(install: bool, outcome: Outcome) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = Fixture(std::env::temp_dir().join(format!(
        "adb-sync-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    let source = root.0.join("source");
    fs::create_dir_all(&source).unwrap();
    seed_public_test_identity(&root.0);
    let apk = source.join("base.apk");
    let bytes: Vec<u8> = (0..SYNC_DATA_MAX * 2 + 17).map(|index| (index % 251) as u8).collect();
    fs::write(&apk, &bytes).unwrap();
    let mut expected = BTreeMap::from([(
        if install { "/data/local/tmp/base.apk" } else { "/remote/base.apk" }.to_string(), bytes
    )]);
    if !install && matches!(outcome, Outcome::Okay) {
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/empty"), b"").unwrap();
        expected.insert("/remote/nested/empty".into(), Vec::new());
    }
    let expected_count = expected.len();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI never connected to strict fake adbd");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        socket.set_nodelay(true).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = FakeAdbd::from_stream(socket);
        let (header, _) = peer.recv_message().unwrap();
        assert_eq!(header.command, A_CNXN);
        let banner = b"device::ro.product.name=strict-peer;features=cmd";
        let reply = AdbMessageHeader::new(A_CNXN, 0x0100_0001, 1024 * 1024, banner);
        peer.send_message(&reply, banner).unwrap();
        for _ in 0..expected_count {
            sync_send(&mut peer, &mut expected, install, outcome);
        }
        assert!(expected.is_empty());
        if install && matches!(outcome, Outcome::Okay) {
            // --no-streaming must override the advertised cmd feature.
            exec_success(&mut peer, "exec:pm install -r '/data/local/tmp/base.apk'");
            exec_success(&mut peer, "exec:rm '/data/local/tmp/base.apk' </dev/null");
        }
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command.arg("-s").arg(address.to_string());
    if install {
        command.args(["install", "--no-streaming"]).arg(&apk);
    } else {
        command.arg("sync").arg(&source).arg("/remote");
    }
    let mut child = command.env("HOME", &root.0).stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            let _ = peer.join();
            panic!("CLI hung waiting for a nonexistent SEND response: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let peer_result = peer.join();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(peer_result.is_ok(), "strict fake adbd failed; CLI exit={:?}, stdout={stdout}, stderr={stderr}", output.status.code());
    match outcome {
        Outcome::Okay => {
            assert_eq!(output.status.code(), Some(0), "{stderr}");
            assert!(stdout.contains(if install { "Push install succeeded" } else { "Sync complete" }), "{stdout}");
        }
        Outcome::Fail => {
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr.contains("strict adbd rejected file"), "{stderr}");
        }
        Outcome::Eof => {
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr.contains("fill whole buffer") || stderr.contains("closed"), "{stderr}");
        }
    }
}

#[test]
fn sync_cli_sends_complete_data_and_done_before_result() { run_cli(false, Outcome::Okay); }
#[test]
fn sync_cli_reports_final_fail() { run_cli(false, Outcome::Fail); }
#[test]
fn sync_cli_rejects_eof_after_done_transport_ack() { run_cli(false, Outcome::Eof); }
#[test]
fn staged_install_cli_sends_complete_apk_then_installs_and_cleans_up() { run_cli(true, Outcome::Okay); }
#[test]
fn staged_install_cli_stops_on_sync_fail() { run_cli(true, Outcome::Fail); }
#[test]
fn staged_install_cli_rejects_eof_after_done_transport_ack() { run_cli(true, Outcome::Eof); }
