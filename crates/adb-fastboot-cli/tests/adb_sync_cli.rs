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
const SYNC_RECV: u32 = u32::from_le_bytes(*b"RECV");
const SYNC_SEND: u32 = u32::from_le_bytes(*b"SEND");
const SYNC_STAT: u32 = u32::from_le_bytes(*b"STAT");
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

#[derive(Clone, Copy)]
struct StatReply { mode: u32, size: u32, mtime: u32 }

/// Independent AOSP vector: `sync_stat_v1` is exactly four little-endian u32s
/// (`vendor/adb/file_sync_protocol.h:48-53`), i.e. 16 bytes with NO length word.
/// A 20-byte `[STAT, length, mode, size, mtime]` frame is this port's old
/// invention and must never be treated as the wire truth again.
fn stat_wire(st: StatReply) -> Vec<u8> {
    [
        b"STAT".as_slice(),
        &st.mode.to_le_bytes(),
        &st.size.to_le_bytes(),
        &st.mtime.to_le_bytes(),
    ]
    .concat()
}

fn reply_stat(peer: &mut FakeAdbd, local_id: u32, path: &str, st: StatReply) {
    let payload = receive(peer, A_WRTE, local_id);
    let header = SyncMessageHeader::decode(&payload).unwrap();
    assert_eq!(header.id, SYNC_STAT, "push --sync must lstat the remote path first");
    assert_eq!(header.length as usize, payload.len() - 8);
    assert_eq!(&payload[8..], path.as_bytes());
    let response = stat_wire(st);
    assert_eq!(response.len(), 16, "V1 STAT has no length field");
    // Real adbd acks the STAT WRTE before writing the result back.
    send(peer, A_OKAY, local_id, &[]);
    send(peer, A_WRTE, local_id, &response);
    assert!(receive(peer, A_OKAY, local_id).is_empty());
}

fn expect_recv(peer: &mut FakeAdbd, local_id: u32, remote: &str) {
    let payload = receive(peer, A_WRTE, local_id);
    let header = SyncMessageHeader::decode(&payload).unwrap();
    assert_eq!(header.id, SYNC_RECV, "pull must open RECV, got {:#x}", header.id);
    assert_eq!(header.length as usize, payload.len() - 8);
    assert_eq!(&payload[8..], remote.as_bytes());
}

fn run_push_sync(remote_mtime_matches: bool) {
    use std::os::unix::fs::MetadataExt;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = Fixture(std::env::temp_dir().join(format!(
        "adb-push-sync-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    seed_public_test_identity(&root.0);
    let source = root.0.join("payload.bin");
    let bytes: Vec<u8> = (0..(SYNC_DATA_MAX + 31)).map(|i| (i % 249) as u8).collect();
    fs::write(&source, &bytes).unwrap();
    let local_mtime = fs::metadata(&source).unwrap().mtime() as u32;
    let remote_mtime = if remote_mtime_matches { local_mtime } else { local_mtime.wrapping_add(10) };
    let remote_path = "/remote/payload.bin";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected = bytes.clone();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI never connected");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        socket.set_nodelay(true).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut peer = FakeAdbd::from_stream(socket);
        let (header, _) = peer.recv_message().unwrap();
        assert_eq!(header.command, A_CNXN);
        let banner = b"device::ro.product.name=sync-peer;features=cmd";
        peer.send_message(&AdbMessageHeader::new(A_CNXN, 0x0100_0001, 1024 * 1024, banner), banner).unwrap();
        let local_id = open(&mut peer, "sync:");
        // do_sync_push stats the destination, then sync_send stats the resolved
        // path. Both are the same path here: the destination is a plain file.
        for _ in 0..2 {
            reply_stat(&mut peer, local_id, remote_path, StatReply {
                mode: 0o100644, size: expected.len() as u32, mtime: remote_mtime,
            });
        }

        if remote_mtime_matches {
            // AOSP sync_send: equal mtime means no SEND/DATA/DONE at all.
            assert!(matches!(peer.recv_message(), Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof));
            return;
        }

        let payload = receive(&mut peer, A_WRTE, local_id);
        let header = SyncMessageHeader::decode(&payload).unwrap();
        assert_eq!(header.id, SYNC_SEND);
        assert_eq!(&payload[8..], format!("{remote_path},{}", 0o644).as_bytes());
        send(&mut peer, A_OKAY, local_id, &[]);

        let mut received = Vec::new();
        loop {
            let payload = receive(&mut peer, A_WRTE, local_id);
            let header = SyncMessageHeader::decode(&payload).unwrap();
            match header.id {
                SYNC_DATA => {
                    received.extend_from_slice(&payload[8..]);
                    assert_eq!(received.as_slice(), &expected[..received.len()]);
                    send(&mut peer, A_OKAY, local_id, &[]);
                }
                SYNC_DONE => {
                    assert_eq!(header.length, local_mtime, "DONE must carry the local mtime");
                    assert_eq!(received, expected);
                    send(&mut peer, A_OKAY, local_id, &[]);
                    break;
                }
                other => panic!("unexpected SYNC id {other:#x}"),
            }
        }
        let mut ok = [0u8; 8];
        SyncMessageHeader::new(SYNC_OKAY, 0).encode(&mut ok);
        send(&mut peer, A_WRTE, local_id, &ok);
        assert!(receive(&mut peer, A_OKAY, local_id).is_empty());
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command.arg("-s").arg(address.to_string())
        .arg("push").arg("--sync").arg(&source).arg(remote_path)
        .env("HOME", &root.0)
        .env("ANDROID_ADB_SERVER_PORT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(peer.join().is_ok(), "fake adbd failed; stdout={stdout} stderr={stderr}");
    assert_eq!(output.status.code(), Some(0), "stdout={stdout} stderr={stderr}");
    if remote_mtime_matches {
        assert!(stdout.contains("Skipped"), "stdout={stdout}");
    } else {
        assert!(stdout.contains("Pushing"), "stdout={stdout}");
    }
}

#[test]
fn push_sync_skips_when_remote_mtime_matches() { run_push_sync(true); }

#[test]
fn push_sync_sends_when_remote_mtime_differs() { run_push_sync(false); }

// ---------------------------------------------------------------------------
// do_sync_push destination resolution (AOSP client/file_sync_client.cpp:1454-1486)
//
// One `adb push` run per case against a scripted fake adbd. `stats` is the
// exact STAT sequence the client must emit, so the resolved path is asserted on
// the wire, not inferred from stdout.
// ---------------------------------------------------------------------------

struct PushTargetCase {
    remote: &'static str,
    sync: bool,
    /// STAT script in wire order, given the real local mtime of the fixture.
    stats: fn(u32) -> Vec<(&'static str, StatReply)>,
    /// Exact SEND path the CLI must use; `None` = the CLI must abort, no SEND.
    send_path: Option<&'static str>,
    exit_code: i32,
    stdout_contains: Vec<&'static str>,
    stderr_contains: Vec<&'static str>,
}

const DIR: u32 = 0o040755;
const FILE: u32 = 0o100644;
const ABSENT: StatReply = StatReply { mode: 0, size: 0, mtime: 0 };

fn run_push_target_case(case: PushTargetCase) {
    use std::os::unix::fs::MetadataExt;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let PushTargetCase { remote, sync, stats, send_path, exit_code, stdout_contains, stderr_contains } = case;

    let root = Fixture(std::env::temp_dir().join(format!(
        "adb-push-target-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    seed_public_test_identity(&root.0);
    let source = root.0.join("payload.bin");
    let bytes: Vec<u8> = (0..4096).map(|index| (index % 253) as u8).collect();
    fs::write(&source, &bytes).unwrap();
    let local_mtime = fs::metadata(&source).unwrap().mtime() as u32;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected = bytes.clone();
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
        let banner = b"device::ro.product.name=push-target;features=cmd";
        peer.send_message(&AdbMessageHeader::new(A_CNXN, 0x0100_0001, 1024 * 1024, banner), banner).unwrap();
        let local_id = open(&mut peer, "sync:");

        // Wire-order STAT script; reply_stat asserts the requested path.
        for (path, reply) in stats(local_mtime) {
            reply_stat(&mut peer, local_id, path, reply);
        }

        let Some(send_path) = send_path else {
            // Negative control: the CLI must abort before any SEND frame.
            match peer.recv_message() {
                Err(_) => {}
                Ok((header, payload)) => panic!(
                    "client kept talking after a failed destination resolution: command={:#x} payload={:?}",
                    header.command,
                    String::from_utf8_lossy(&payload)
                ),
            }
            return;
        };

        let payload = receive(&mut peer, A_WRTE, local_id);
        let header = SyncMessageHeader::decode(&payload).unwrap();
        assert_eq!(header.id, SYNC_SEND, "expected SEND, got {:#x}", header.id);
        assert_eq!(header.length as usize, payload.len() - 8);
        assert_eq!(&payload[8..], format!("{send_path},{}", 0o644).as_bytes());
        send(&mut peer, A_OKAY, local_id, &[]);

        let mut received = Vec::new();
        loop {
            let payload = receive(&mut peer, A_WRTE, local_id);
            let header = SyncMessageHeader::decode(&payload).unwrap();
            match header.id {
                SYNC_DATA => {
                    received.extend_from_slice(&payload[8..]);
                    assert_eq!(received.as_slice(), &expected[..received.len()]);
                    send(&mut peer, A_OKAY, local_id, &[]);
                }
                SYNC_DONE => {
                    assert_eq!(header.length, local_mtime, "DONE must carry the local mtime");
                    assert_eq!(received, expected);
                    send(&mut peer, A_OKAY, local_id, &[]);
                    break;
                }
                other => panic!("unexpected SYNC id {other:#x}"),
            }
        }
        let mut okay = [0u8; 8];
        SyncMessageHeader::new(SYNC_OKAY, 0).encode(&mut okay);
        send(&mut peer, A_WRTE, local_id, &okay);
        assert!(receive(&mut peer, A_OKAY, local_id).is_empty());
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command.arg("-s").arg(address.to_string()).arg("push");
    if sync {
        command.arg("--sync");
    }
    command.arg(&source).arg(remote)
        .env("HOME", &root.0)
        .env("ANDROID_ADB_SERVER_PORT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(peer.join().is_ok(), "strict fake adbd failed; stdout={stdout} stderr={stderr}");

    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "stdout={stdout} stderr={stderr}"
    );
    for needle in &stdout_contains {
        assert!(stdout.contains(needle), "stdout missing {needle:?}: {stdout}");
    }
    for needle in &stderr_contains {
        assert!(stderr.contains(needle), "stderr missing {needle:?}: {stderr}");
    }
    if send_path.is_none() {
        assert!(!stdout.contains("Pushing"), "no transfer may start: {stdout}");
    }
}

#[test]
fn push_to_existing_remote_directory_appends_basename() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/dir",
        sync: false,
        stats: |_| vec![("/remote/dir", StatReply { mode: DIR, size: 0, mtime: 1_600_000_000 })],
        send_path: Some("/remote/dir/payload.bin"),
        exit_code: 0,
        stdout_contains: vec!["Pushing", "/remote/dir/payload.bin"],
        stderr_contains: vec![],
    });
}

#[test]
fn push_to_existing_remote_file_uses_exact_path() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/payload.bin",
        sync: false,
        stats: |_| vec![("/remote/payload.bin", StatReply { mode: FILE, size: 12, mtime: 1_600_000_000 })],
        send_path: Some("/remote/payload.bin"),
        exit_code: 0,
        stdout_contains: vec!["Pushing", "-> '/remote/payload.bin'"],
        stderr_contains: vec![],
    });
}

// AOSP client/file_sync_client.cpp:1479-1484 — "a path that ends with a slash
// doesn't have to be a directory if it doesn't exist yet", so :1481 only fails
// when dst_exists. A missing target keeps the path (and its slash) verbatim
// (:1489 `dst_path = dst`).
#[test]
fn push_to_missing_target_with_trailing_slash_keeps_path_verbatim() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/missing/",
        sync: false,
        stats: |_| vec![("/remote/missing/", ABSENT)],
        send_path: Some("/remote/missing/"),
        exit_code: 0,
        stdout_contains: vec!["Pushing", "'/remote/missing/'"],
        stderr_contains: vec![],
    });
}

// Negative control: the destination exists as a regular file, so a trailing
// slash must abort with AOSP's message and never open a SEND.
#[test]
fn push_to_existing_file_with_trailing_slash_fails_without_send() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/payload.bin/",
        sync: false,
        stats: |_| vec![("/remote/payload.bin/", StatReply { mode: FILE, size: 12, mtime: 1_600_000_000 })],
        send_path: None,
        exit_code: 1,
        stdout_contains: vec![],
        stderr_contains: vec!["push failed", "failed to access '/remote/payload.bin/': Not a directory"],
    });
}

// `--sync` must compare the *resolved* path: the directory's own mtime is
// irrelevant, only /remote/dir/payload.bin decides the skip.
#[test]
fn push_sync_skips_on_the_resolved_remote_path() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/dir",
        sync: true,
        stats: |local_mtime| vec![
            ("/remote/dir", StatReply { mode: DIR, size: 0, mtime: local_mtime.wrapping_add(99) }),
            ("/remote/dir/payload.bin", StatReply { mode: FILE, size: 4096, mtime: local_mtime }),
        ],
        send_path: None,
        exit_code: 0,
        stdout_contains: vec!["Skipped", "/remote/dir/payload.bin"],
        stderr_contains: vec![],
    });
}

#[test]
fn push_sync_sends_to_resolved_path_when_mtime_differs() {
    run_push_target_case(PushTargetCase {
        remote: "/remote/dir",
        sync: true,
        stats: |local_mtime| vec![
            ("/remote/dir", StatReply { mode: DIR, size: 0, mtime: local_mtime }),
            ("/remote/dir/payload.bin", StatReply { mode: FILE, size: 4096, mtime: local_mtime.wrapping_add(7) }),
        ],
        send_path: Some("/remote/dir/payload.bin"),
        exit_code: 0,
        stdout_contains: vec!["Pushing", "/remote/dir/payload.bin"],
        stderr_contains: vec![],
    });
}

// ---------------------------------------------------------------------------
// `adb pull` / `adb pull -a`: one SYNC channel is a byte stream
// ---------------------------------------------------------------------------
//
// AOSP writes SYNC messages into a socket; ADB WRTE boundaries carry no
// protocol meaning, so a DATA header may straddle two WRTEs and two DATA
// frames may share one. The fake adbd below is deliberately free to split and
// coalesce, and the CLI must still produce the exact remote bytes.

struct PullOutcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// (contents, mtime, mode & 0o777) of the pulled file, if it was created.
    file: Option<(Vec<u8>, i64, u32)>,
}

fn run_pull_case<F>(preserve: bool, remote: &'static str, peer_body: F) -> PullOutcome
where
    F: FnOnce(&mut FakeAdbd) + Send + 'static,
{
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = Fixture(std::env::temp_dir().join(format!(
        "adb-pull-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    seed_public_test_identity(&root.0);
    let destination = root.0.join("pulled.bin");
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
        let banner = b"device::ro.product.name=pull-peer;features=cmd";
        peer.send_message(&AdbMessageHeader::new(A_CNXN, 0x0100_0001, 1024 * 1024, banner), banner).unwrap();
        peer_body(&mut peer);
    });

    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command.arg("-s").arg(address.to_string()).arg("pull");
    if preserve {
        command.arg("-a");
    }
    command.arg(remote).arg(&destination)
        .env("HOME", &root.0)
        .env("ANDROID_ADB_SERVER_PORT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = command.output().unwrap();
    assert!(
        peer.join().is_ok(),
        "strict fake adbd failed; CLI exit={:?}, stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let file = fs::metadata(&destination).ok().map(|metadata| {
        (
            fs::read(&destination).unwrap(),
            metadata.mtime(),
            metadata.permissions().mode() & 0o777,
        )
    });
    PullOutcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        file,
    }
}

/// A real adbd answers `pull -a` with a 16-byte STAT, then streams RECV. Split
/// the DATA header itself across WRTEs: the CLI must buffer the channel, not
/// assume one message per WRTE.
#[test]
fn pull_a_reads_16_byte_stat_and_reassembles_a_header_split_across_wrtes() {
    let body: Vec<u8> = (0..SYNC_DATA_MAX + 4321).map(|index| (index % 241) as u8).collect();
    let expected = body.clone();
    let outcome = run_pull_case(true, "/remote/file", move |peer| {
        let local_id = open(peer, "sync:");
        reply_stat(peer, local_id, "/remote/file", StatReply {
            mode: 0o100600, size: expected.len() as u32, mtime: 1_600_000_123,
        });
        expect_recv(peer, local_id, "/remote/file");
        send(peer, A_OKAY, local_id, &[]);

        // Two legal 64 KiB-bounded DATA frames, concatenated exactly as adbd
        // would write them into one stream.
        let mut data = Vec::new();
        adb_protocol_data(&mut data, &expected[..SYNC_DATA_MAX]);
        adb_protocol_data(&mut data, &expected[SYNC_DATA_MAX..]);
        // "DAT" + "A" + length bytes + body: every WRTE below is a transport
        // fragment, never a SYNC message boundary.
        let mut rest = data.as_slice();
        for size in [3usize, 4, 16, 300, 40_000] {
            let take = size.min(rest.len());
            let (piece, tail) = rest.split_at(take);
            send(peer, A_WRTE, local_id, piece);
            assert!(receive(peer, A_OKAY, local_id).is_empty(), "fragment ack");
            rest = tail;
        }
        while !rest.is_empty() {
            let take = rest.len().min(1000);
            let (piece, tail) = rest.split_at(take);
            send(peer, A_WRTE, local_id, piece);
            assert!(receive(peer, A_OKAY, local_id).is_empty());
            rest = tail;
        }
        let mut done = [0u8; 8];
        SyncMessageHeader::new(SYNC_DONE, 0).encode(&mut done);
        send(peer, A_WRTE, local_id, &done[..5]);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        send(peer, A_WRTE, local_id, &done[5..]);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        // The CLI exits after DONE; it must not invent more framing.
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });
    assert_eq!(outcome.code, Some(0), "stderr={}", outcome.stderr);
    let (contents, mtime, mode) = outcome.file.expect("pulled file");
    assert_eq!(contents, body);
    assert_eq!(mtime, 1_600_000_123, "-a must restore the remote mtime");
    assert_eq!(mode, 0o600, "-a must restore the remote mode");
}

fn adb_protocol_data(out: &mut Vec<u8>, bytes: &[u8]) {
    let mut header = [0u8; 8];
    SyncMessageHeader::new(SYNC_DATA, bytes.len() as u32).encode(&mut header);
    out.extend_from_slice(&header);
    out.extend_from_slice(bytes);
}

/// adbd may coalesce several SYNC frames into one WRTE. Two DATA frames plus
/// DONE in a single write must still be split exactly at the SYNC framing.
#[test]
fn pull_splits_coalesced_data_frames_sharing_one_wrte() {
    let outcome = run_pull_case(false, "/remote/file", |peer| {
        let local_id = open(peer, "sync:");
        expect_recv(peer, local_id, "/remote/file");
        send(peer, A_OKAY, local_id, &[]);
        let mut payload = Vec::new();
        adb_protocol_data(&mut payload, b"first-");
        adb_protocol_data(&mut payload, b"second");
        let mut done = [0u8; 8];
        SyncMessageHeader::new(SYNC_DONE, 0).encode(&mut done);
        payload.extend_from_slice(&done);
        send(peer, A_WRTE, local_id, &payload);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });
    assert_eq!(outcome.code, Some(0), "stderr={}", outcome.stderr);
    let (contents, _, _) = outcome.file.expect("pulled file");
    assert_eq!(contents, b"first-second");
}

/// An early result may arrive before the transport ACK for RECV. It is data,
/// not a reply to the request: keep it and drain the ACK afterwards.
#[test]
fn pull_keeps_a_data_frame_that_arrives_before_the_recv_ack() {
    let outcome = run_pull_case(false, "/remote/file", |peer| {
        let local_id = open(peer, "sync:");
        expect_recv(peer, local_id, "/remote/file");
        let mut payload = Vec::new();
        adb_protocol_data(&mut payload, b"early");
        let mut done = [0u8; 8];
        SyncMessageHeader::new(SYNC_DONE, 0).encode(&mut done);
        payload.extend_from_slice(&done);
        send(peer, A_WRTE, local_id, &payload);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        send(peer, A_OKAY, local_id, &[]);
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });
    assert_eq!(outcome.code, Some(0), "stderr={}", outcome.stderr);
    let (contents, _, _) = outcome.file.expect("pulled file");
    assert_eq!(contents, b"early");
}

/// A DATA length above the 64 KiB SYNC chunk bound must fail before the client
/// allocates or blocks; a torn stream must not look like a short file.
#[test]
fn pull_rejects_a_data_length_above_64k_before_allocating() {
    let outcome = run_pull_case(false, "/remote/file", |peer| {
        let local_id = open(peer, "sync:");
        expect_recv(peer, local_id, "/remote/file");
        send(peer, A_OKAY, local_id, &[]);
        let mut header = [0u8; 8];
        SyncMessageHeader::new(SYNC_DATA, 64 * 1024 + 1).encode(&mut header);
        send(peer, A_WRTE, local_id, &header);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        peer.0.shutdown(Shutdown::Both).unwrap();
    });
    assert_eq!(outcome.code, Some(1), "stdout={} stderr={}", outcome.stdout, outcome.stderr);
    assert!(outcome.stderr.contains("64 KiB"), "stderr={}", outcome.stderr);
    assert!(!outcome.stdout.contains("Pull complete"), "no success may be printed: {}", outcome.stdout);
    assert!(outcome.file.is_none(), "a rejected transfer must not publish a file");
}

#[test]
fn pull_reports_the_remote_fail_message_and_publishes_nothing() {
    let outcome = run_pull_case(false, "/remote/file", |peer| {
        let local_id = open(peer, "sync:");
        expect_recv(peer, local_id, "/remote/file");
        send(peer, A_OKAY, local_id, &[]);
        let mut fail = Vec::new();
        let mut header = [0u8; 8];
        SyncMessageHeader::new(SYNC_FAIL, 13).encode(&mut header);
        fail.extend_from_slice(&header);
        fail.extend_from_slice(b"no such file:");
        send(peer, A_WRTE, local_id, &fail);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        assert!(matches!(peer.recv_message(), Err(error)
            if error.kind() == std::io::ErrorKind::UnexpectedEof));
    });
    assert_eq!(outcome.code, Some(1));
    assert!(outcome.stderr.contains("no such file:"), "stderr={}", outcome.stderr);
    assert!(outcome.file.is_none(), "a failed pull must not write a partial file");
}

#[test]
fn pull_fails_when_the_stream_ends_before_done() {
    let outcome = run_pull_case(false, "/remote/file", |peer| {
        let local_id = open(peer, "sync:");
        expect_recv(peer, local_id, "/remote/file");
        send(peer, A_OKAY, local_id, &[]);
        let mut payload = Vec::new();
        adb_protocol_data(&mut payload, b"torn");
        send(peer, A_WRTE, local_id, &payload);
        assert!(receive(peer, A_OKAY, local_id).is_empty());
        peer.0.shutdown(Shutdown::Both).unwrap();
    });
    assert_eq!(outcome.code, Some(1), "stdout={}", outcome.stdout);
    assert!(
        outcome.stderr.contains("fill whole buffer") || outcome.stderr.contains("closed"),
        "stderr={}",
        outcome.stderr
    );
    assert!(outcome.file.is_none(), "a truncated pull must not publish a file");
}

/// `pull -a` must not fabricate metadata when the remote stat cannot succeed.
#[test]
fn pull_a_fails_closed_when_the_remote_stat_is_all_zero() {
    let outcome = run_pull_case(true, "/remote/missing", |peer| {
        let local_id = open(peer, "sync:");
        reply_stat(peer, local_id, "/remote/missing", ABSENT);
        peer.0.shutdown(Shutdown::Both).unwrap();
    });
    assert_eq!(outcome.code, Some(1), "stdout={}", outcome.stdout);
    assert!(outcome.file.is_none(), "no file may be created from a failed stat");
}
