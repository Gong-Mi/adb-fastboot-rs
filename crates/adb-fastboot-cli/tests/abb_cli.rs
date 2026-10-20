//! `adb abb` regressions. Launches the real `adb-rs` binary against a strict
//! in-test fake adbd — no system ADB server, USB, or real device is touched.
//!
//! The contract under test is AOSP `adb_abb`
//! (`client/commandline.cpp:799-822`):
//!
//! * the `abb` device feature gates the command *before* any service is
//!   opened (`CanUseFeature(*features, kFeatureAbb)`);
//! * the service string is `abb:` + args joined with `ABB_ARG_DELIMITER`
//!   (`'\0'`, `adb.h:205`) — NUL-separated, never space-separated, no
//!   `shell,v2,raw:` prefix;
//! * the reply is framed as ShellV2 (`RemoteShell(use_shell_protocol=true,
//!   kShellServiceArgRaw, ...)`).
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

const REMOTE_ID: u32 = 91;
const A_CNXN: u32 = u32::from_le_bytes(*b"CNXN");
const A_OPEN: u32 = u32::from_le_bytes(*b"OPEN");
const A_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const A_WRTE: u32 = u32::from_le_bytes(*b"WRTE");
const A_CLSE: u32 = u32::from_le_bytes(*b"CLSE");

/// ShellV2 stream ids (`shell_protocol.h`).
const SHELL_ID_STDOUT: u8 = 1;
const SHELL_ID_EXIT: u8 = 3;
const SHELL_ID_STDIN: u8 = 0;
const SHELL_ID_CLOSE_STDIN: u8 = 4;

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// Independent daemon-side codec: the fake adbd never shares the client's
// serialization oracle.
struct AdbMessageHeader {
    command: u32,
    arg0: u32,
    arg1: u32,
}

struct FakeAdbd(TcpStream);

impl FakeAdbd {
    fn from_stream(socket: TcpStream) -> Self {
        Self(socket)
    }

    fn recv_message(&mut self) -> io::Result<(AdbMessageHeader, Vec<u8>)> {
        let mut header = [0u8; 24];
        self.0.read_exact(&mut header)?;
        let command = word(&header);
        assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
        let length = word(&header[12..]) as usize;
        assert!(length <= 1024 * 1024);
        let mut payload = vec![0; length];
        self.0.read_exact(&mut payload)?;
        let checksum = payload
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        assert!(
            word(&header[16..]) == 0 || word(&header[16..]) == checksum,
            "ADB checksum (v2 permits zero)"
        );
        Ok((
            AdbMessageHeader {
                command,
                arg0: word(&header[4..]),
                arg1: word(&header[8..]),
            },
            payload,
        ))
    }

    fn send_message(&mut self, header: &AdbMessageHeader, payload: &[u8]) -> io::Result<()> {
        let checksum = payload
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        for word in [
            header.command,
            header.arg0,
            header.arg1,
            payload.len() as u32,
            checksum,
            header.command ^ u32::MAX,
        ] {
            self.0.write_all(&word.to_le_bytes())?;
        }
        self.0.write_all(payload)
    }
}

fn send(peer: &mut FakeAdbd, command: u32, local_id: u32, payload: &[u8]) {
    peer.send_message(
        &AdbMessageHeader {
            command,
            arg0: REMOTE_ID,
            arg1: local_id,
        },
        payload,
    )
    .unwrap();
}

fn receive(peer: &mut FakeAdbd, command: u32, local_id: u32) -> Vec<u8> {
    let (header, payload) = peer
        .recv_message()
        .unwrap_or_else(|error| panic!("fake adbd expected {command:#x}: {error}"));
    assert_eq!(header.command, command);
    assert_eq!((header.arg0, header.arg1), (local_id, REMOTE_ID));
    payload
}

/// `[id:u8][length:u32 LE][payload]` — ShellV2 framing (`shell_protocol.h`).
fn shell_v2_frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn announce(peer: &mut FakeAdbd, banner: &[u8]) {
    peer.send_message(
        &AdbMessageHeader {
            command: A_CNXN,
            arg0: 0x0100_0001,
            arg1: 1024 * 1024,
        },
        banner,
    )
    .unwrap();
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nodelay(true).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "CLI never connected to fake adbd");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

/// A disposable HOME holding a pre-built private key: this suite exercises the
/// abb service string, not RSA prime generation, and the key must never be the
/// user's real `adbkey`. The identity is generated once per test binary and
/// then just loaded by each CLI process.
fn seeded_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        use std::os::unix::fs::OpenOptionsExt;
        let home = std::env::temp_dir().join(format!("adb-abb-cli-{}", std::process::id()));
        let directory = home.join(".android");
        fs::create_dir_all(&directory).unwrap();
        let auth = adb_protocol::AdbAuth::generate("adb-abb-test@localhost").unwrap();
        let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key()).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("adbkey"))
            .unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        home
    })
    .clone()
}

fn run_cli(home: &std::path::Path, address: std::net::SocketAddr, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .args(args)
        .env("HOME", home)
        // No ADB server in this suite: the direct adbd path is the subject.
        .env("ANDROID_ADB_SERVER_PORT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "CLI hung: exit={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn abb_rejected_without_device_feature() {
    let home = seeded_home();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let peer = thread::spawn(move || {
        let socket = accept(&listener);
        let mut peer = FakeAdbd::from_stream(socket);
        let (header, _) = peer.recv_message().unwrap();
        assert_eq!(header.command, A_CNXN, "CLI must start with CNXN");
        // Device without `abb` (but with cmd/shell_v2, i.e. a device that
        // could otherwise offer shell services).
        announce(&mut peer, b"device::ro.product.name=no-abb;features=cmd,shell_v2");

        // The gate is client-side and pre-service: the only acceptable
        // follow-up is the connection ending without any A_OPEN.
        match peer.recv_message() {
            Err(error) => assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "expected EOF after the gated CNXN, got {error}"
            ),
            Ok((header, payload)) => panic!(
                "device without the abb feature must not receive a service, got command={:#x} payload={:?}",
                header.command,
                String::from_utf8_lossy(&payload)
            ),
        }
    });

    let output = run_cli(&home, address, &["abb", "echo", "hi"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        peer.join().is_ok(),
        "strict fake adbd failed; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(output.status.code(), Some(1), "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("abb is not supported by the device"),
        "stderr={stderr}"
    );
}

#[test]
fn abb_opens_nul_joined_service_and_streams_shell_v2() {
    let home = seeded_home();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let peer = thread::spawn(move || {
        let socket = accept(&listener);
        let mut peer = FakeAdbd::from_stream(socket);
        let (header, _) = peer.recv_message().unwrap();
        assert_eq!(header.command, A_CNXN, "CLI must start with CNXN");
        announce(&mut peer, b"device::ro.product.name=abb-peer;features=cmd,shell_v2,abb");

        // Core wire contract: two CLI arguments become one NUL-joined service
        // string, with no `shell,v2,raw:` prefix and no spaces.
        let (open, payload) = peer.recv_message().unwrap();
        assert_eq!(open.command, A_OPEN, "expected the abb service to be opened");
        assert_eq!(open.arg1, 0, "A_OPEN carries no remote id yet");
        assert_eq!(
            payload,
            b"abb:echo\0hi",
            "abb args must be ABB_ARG_DELIMITER ('\\0')-joined, got {:?}",
            String::from_utf8_lossy(&payload)
        );
        assert!(
            !payload.contains(&b' '),
            "NUL joining, not space joining: {:?}",
            String::from_utf8_lossy(&payload)
        );
        let local_id = open.arg0;
        send(&mut peer, A_OKAY, local_id, &[]);

        // ShellV2 stdout, then the exit code — the same framing `adb shell`
        // uses, because AOSP runs abb through RemoteShell(use_shell_protocol).
        send(&mut peer, A_WRTE, local_id, &shell_v2_frame(SHELL_ID_STDOUT, b"hi\n"));
        assert!(receive(&mut peer, A_OKAY, local_id).is_empty());
        send(&mut peer, A_WRTE, local_id, &shell_v2_frame(SHELL_ID_EXIT, &[0]));
        assert!(receive(&mut peer, A_OKAY, local_id).is_empty());

        send(&mut peer, A_CLSE, local_id, &[]);
        assert!(receive(&mut peer, A_CLSE, local_id).is_empty());
    });

    let output = run_cli(&home, address, &["abb", "echo", "hi"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        peer.join().is_ok(),
        "strict fake adbd failed; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(output.status.code(), Some(0), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("hi"), "stdout={stdout}");
    assert!(
        !stderr.contains("abb is not supported"),
        "the device advertised abb; stderr={stderr}"
    );
}

fn read_hex_request(stream: &mut TcpStream) -> String {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let len = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    String::from_utf8(payload).unwrap()
}

fn write_status(stream: &mut TcpStream) {
    stream.write_all(b"OKAY").unwrap();
    stream.flush().unwrap();
}

fn write_payload(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(format!("{:04x}", payload.len()).as_bytes()).unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn read_shell_packet(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).unwrap();
    let len = word(&header[1..]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    (header[0], payload)
}

#[test]
fn abb_server_path_forwards_stdin_as_shell_v2_packets() {
    let home = seeded_home();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let peer = thread::spawn(move || {
        // The CLI opens the outer server connection first, then the separate
        // feature query connection (query_server_features).
        let mut outer = accept(&listener);
        let mut features = accept(&listener);
        features
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(read_hex_request(&mut features), "host:features");
        write_status(&mut features);
        write_payload(&mut features, b"abb,shell_v2");
        drop(features);

        outer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(read_hex_request(&mut outer), "host:transport-any");
        write_status(&mut outer);
        assert_eq!(read_hex_request(&mut outer), "abb:");
        write_status(&mut outer);

        // Interactive abb: local stdin must arrive as ShellV2 stdin packets,
        // then CloseStdin on EOF.
        let mut stdin = Vec::new();
        loop {
            let (id, payload) = read_shell_packet(&mut outer);
            match id {
                SHELL_ID_STDIN => stdin.extend_from_slice(&payload),
                SHELL_ID_CLOSE_STDIN => break,
                other => panic!("unexpected ShellV2 id {other} from client"),
            }
        }
        assert_eq!(stdin, b"hi\n");

        outer
            .write_all(&shell_v2_frame(SHELL_ID_STDOUT, b"ok\n"))
            .unwrap();
        outer
            .write_all(&shell_v2_frame(SHELL_ID_EXIT, &[0]))
            .unwrap();
        outer.flush().unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("abb")
        .env("HOME", &home)
        .env("ANDROID_ADB_SERVER_PORT", address.port().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hi\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        peer.join().is_ok(),
        "fake ADB server failed; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(output.status.code(), Some(0), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("ok"), "stdout={stdout}");
}
