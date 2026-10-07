//! End-to-end CLI test for `adb install --incremental`: the real adb-rs binary
//! runs against a fake adbd that also plays `pm` (the abb_exec service), and
//! the whole pipeline is exercised — database service string, pump + inc-server
//! spawn, "OKAY" handshake, device text forwarding, block serving AFTER the CLI
//! process has exited, and the DESTROY → EOF shutdown chain.
//!
//! `-s 127.0.0.1:PORT` is the CLI's direct adbd transport selector; no ADB
//! server, USB, or real device is involved.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const REMOTE_ID: u32 = 73;
const A_CNXN: u32 = u32::from_le_bytes(*b"CNXN");
const A_OPEN: u32 = u32::from_le_bytes(*b"OPEN");
const A_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const A_WRTE: u32 = u32::from_le_bytes(*b"WRTE");
const A_CLSE: u32 = u32::from_le_bytes(*b"CLSE");
const INCR: u32 = 0x494e_4352;
const BLOCK_MISSING: i16 = 1;
const DESTROY: i16 = 3;
const BLOCK_SIZE: usize = 4096;

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// An independent daemon-side codec (mirrors tests/adb_sync_cli.rs).
struct FakeAdbd(TcpStream);
impl FakeAdbd {
    fn from_stream(socket: TcpStream) -> Self {
        Self(socket)
    }
    fn recv_message(&mut self) -> std::io::Result<(u32, u32, u32, Vec<u8>)> {
        let mut header = [0u8; 24];
        self.0.read_exact(&mut header)?;
        let command = word(&header);
        assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
        let length = word(&header[12..]) as usize;
        assert!(length <= 1024 * 1024);
        let mut payload = vec![0; length];
        self.0.read_exact(&mut payload)?;
        Ok((command, word(&header[4..]), word(&header[8..]), payload))
    }
    fn send_message(&mut self, command: u32, arg0: u32, arg1: u32, payload: &[u8]) {
        for field in [
            command,
            arg0,
            arg1,
            payload.len() as u32,
            0,
            command ^ u32::MAX,
        ] {
            self.0.write_all(&field.to_le_bytes()).unwrap();
        }
        self.0.write_all(payload).unwrap();
    }
    fn send(&mut self, command: u32, local_id: u32, payload: &[u8]) {
        self.send_message(command, REMOTE_ID, local_id, payload);
    }
    fn expect(&mut self, command: u32, local_id: u32) -> Vec<u8> {
        let (got, arg0, arg1, payload) = self.recv_message().unwrap();
        assert_eq!(got, command, "expected command {command:#x}");
        assert_eq!((arg0, arg1), (local_id, REMOTE_ID));
        payload
    }
}

fn encode_request(request_type: i16, file_id: i16, block_idx: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&INCR.to_be_bytes());
    out.extend_from_slice(&request_type.to_be_bytes());
    out.extend_from_slice(&file_id.to_be_bytes());
    out.extend_from_slice(&block_idx.to_be_bytes());
    out
}

/// 8192 bytes of LCG stream (incompressible → uncompressed wire path) plus a
/// minimal valid `.idsig` (treeSize = verity_tree_size_for_file(8192) = 4096),
/// which makes `build_database` classify the APK as v4-signed.
fn make_fixture(tag: &str) -> PathBuf {
    // Unique per test: these tests run in parallel in the same process.
    let dir = std::env::temp_dir().join(format!("incr-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("base.apk");
    let mut state = 0x1234_ABCDu32;
    let data: Vec<u8> = (0..8192)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
        .collect();
    std::fs::write(&apk, data).unwrap();

    let mut idsig = Vec::new();
    idsig.extend_from_slice(&2i32.to_le_bytes());
    idsig.extend_from_slice(&4i32.to_le_bytes());
    idsig.extend_from_slice(b"abcd");
    idsig.extend_from_slice(&3i32.to_le_bytes());
    idsig.extend_from_slice(b"xyz");
    idsig.extend_from_slice(&4096i32.to_le_bytes());
    std::fs::write(dir.join("base.apk.idsig"), idsig).unwrap();
    apk
}

/// An unsigned companion file (`.dm` does not require a v4 signature). Its
/// bytes are streamed inline over the transport before the inc-server starts,
/// so the fake device must read them as A_WRTE frames.
fn make_unsigned_companion(apk: &PathBuf) -> (PathBuf, Vec<u8>) {
    let mut state = 0x0BAD_F00Du32;
    let data: Vec<u8> = (0..3000)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
        .collect();
    let dm = apk.parent().unwrap().join("base.dm");
    std::fs::write(&dm, &data).unwrap();
    (dm, data)
}

/// Parse block records out of a raw chunk stream (`[be32 size][records...]`),
/// returning (file_id, block_type, compression, block_idx, payload) per
/// record — file_id -1 marks the done marker, block_type 1 marks verity-tree
/// (hash) blocks.
fn parse_blocks(stream: &[u8]) -> Vec<(i16, i8, i8, i32, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= stream.len() {
        let size = i32::from_be_bytes(stream[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let chunk_end = cursor + size;
        if chunk_end > stream.len() {
            break;
        }
        while cursor + 10 <= chunk_end {
            let file_id = i16::from_be_bytes(stream[cursor..cursor + 2].try_into().unwrap());
            let block_type = stream[cursor + 2] as i8;
            let compression = stream[cursor + 3] as i8;
            let block_idx =
                i32::from_be_bytes(stream[cursor + 4..cursor + 8].try_into().unwrap());
            let block_size =
                i16::from_be_bytes(stream[cursor + 8..cursor + 10].try_into().unwrap()) as usize;
            cursor += 10;
            let payload = stream[cursor..cursor + block_size].to_vec();
            cursor += block_size;
            blocks.push((file_id, block_type, compression, block_idx, payload));
        }
    }
    blocks
}

fn decode_payload(compression: i8, payload: &[u8], file_len: usize, block_idx: i32) -> Vec<u8> {
    match compression {
        0 => payload.to_vec(),
        1 => {
            let offset = block_idx as usize * BLOCK_SIZE;
            let size = std::cmp::min(BLOCK_SIZE, file_len - offset);
            lz4_flex::block::decompress(payload, size).unwrap()
        }
        other => panic!("unexpected compression type {other}"),
    }
}

/// Serve the incremental-by-default probe (`settings get global
/// enable_adb_incremental_install_default`): reply `value`, then close.
fn serve_probe(peer: &mut FakeAdbd, value: &[u8]) {
    let (command, local_id, _, payload) = peer.recv_message().unwrap();
    assert_eq!(command, A_OPEN);
    let service = String::from_utf8_lossy(&payload);
    assert_eq!(
        service,
        "abb_exec:settings\u{0}get\u{0}global\u{0}enable_adb_incremental_install_default"
    );
    peer.send(A_OKAY, local_id, &[]);
    peer.send(A_WRTE, local_id, value);
    peer.expect(A_OKAY, local_id);
    peer.send(A_CLSE, local_id, &[]);
    peer.expect(A_CLSE, local_id);
}

/// Serve one streamed install: assert the abb_exec install service, take the
/// file bytes, report Success and close the stream.
fn serve_streamed_install(peer: &mut FakeAdbd, expected_size: usize) {
    let (command, local_id, _, payload) = peer.recv_message().unwrap();
    assert_eq!(command, A_OPEN);
    let service = String::from_utf8_lossy(&payload);
    assert!(
        service.starts_with("abb_exec:package\u{0}install\u{0}"),
        "streamed service: {service}"
    );
    assert!(
        service.ends_with(&format!("\u{0}-S\u{0}{expected_size}")),
        "streamed service: {service}"
    );
    peer.send(A_OKAY, local_id, &[]);
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while received.len() < expected_size {
        assert!(
            Instant::now() < deadline,
            "streamed install truncated: {} of {expected_size}",
            received.len()
        );
        let payload = peer.expect(A_WRTE, local_id);
        peer.send(A_OKAY, local_id, &[]);
        received.extend_from_slice(&payload);
    }
    peer.send(A_WRTE, local_id, b"Performing Streamed Install\nSuccess\n");
    peer.expect(A_OKAY, local_id);
    peer.send(A_CLSE, local_id, &[]);
    peer.expect(A_CLSE, local_id);
}

#[test]
fn incremental_install_serves_blocks_after_cli_exit() {
    let apk = make_fixture("serve");
    let apk_bytes = std::fs::read(&apk).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg("--incremental")
        .arg(&apk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The fake thread releases the block request only after the main thread
    // has observed the CLI exit, proving the pump + inc-server keep serving.
    let (cli_exited_tx, cli_exited_rx) = std::sync::mpsc::channel::<()>();

    let fake = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) => {
                    assert!(Instant::now() < deadline, "CLI never connected: {error}");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        socket.set_nodelay(true).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = FakeAdbd::from_stream(socket);

        // 1. CNXN handshake.
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        let banner = b"device::ro.product.name=fake-incr;features=cmd,shell_v2,abb_exec";
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, banner);

        // 2. The abb_exec service with the incremental database.
        let (command, local_id, arg1, payload) = peer.recv_message().unwrap();
        assert_eq!(command, A_OPEN);
        assert_eq!(arg1, 0);
        let service = String::from_utf8_lossy(&payload);
        assert!(
            service.starts_with("abb_exec:package\0install-incremental\0"),
            "service string: {service}"
        );
        assert!(
            service.contains("base.apk:8192:0:"),
            "database entry missing from {service}"
        );
        peer.send(A_OKAY, local_id, &[]);

        // 3. The inc-server handshake arrives through the pump: "OKAY" as an
        //    A_WRTE; ack it to open the pump's send window.
        let payload = peer.expect(A_WRTE, local_id);
        assert_eq!(payload, b"OKAY");
        peer.send(A_OKAY, local_id, &[]);

        // 4. Device output (>256 bytes so the CLI returns without waiting for
        //    EOF) is forwarded through the pump and the inc-server.
        let mut text = b"Performing Streamed Install\nSuccess\n".to_vec();
        text.extend_from_slice(&[b'.'; 240]);
        peer.send(A_WRTE, local_id, &text);
        peer.expect(A_OKAY, local_id);

        // 5. Block requests are only made after the CLI process is gone.
        cli_exited_rx.recv().unwrap();
        peer.send(A_WRTE, local_id, &encode_request(BLOCK_MISSING, 0, 0));
        peer.expect(A_OKAY, local_id);

        let mut stream = Vec::new();
        let mut blocks = parse_blocks(&stream);
        let block_deadline = Instant::now() + Duration::from_secs(15);
        while !blocks.iter().any(|(file_id, ..)| *file_id == -1) {
            assert!(
                Instant::now() < block_deadline,
                "no done marker; got {blocks:?}"
            );
            let payload = peer.expect(A_WRTE, local_id);
            peer.send(A_OKAY, local_id, &[]);
            stream.extend_from_slice(&payload);
            blocks = parse_blocks(&stream);
        }

        // All DATA blocks must decode back to the APK bytes (the tree/hash
        // records — block_type 1 — carry the verity tree, not file content).
        let mut reassembled = Vec::new();
        let mut data_blocks = 0;
        for (file_id, block_type, compression, block_idx, payload) in &blocks {
            if *file_id == -1 || *block_type != 0 {
                continue;
            }
            assert_eq!(*file_id, 0);
            data_blocks += 1;
            reassembled.extend_from_slice(&decode_payload(
                *compression,
                payload,
                apk_bytes.len(),
                *block_idx,
            ));
        }
        assert_eq!(data_blocks, 2);
        assert_eq!(reassembled, apk_bytes);

        // 6. DESTROY tears the chain down: inc-server exits, the pump sees
        //    channel EOF and exits, and the transport reaches EOF.
        peer.send(A_WRTE, local_id, &encode_request(DESTROY, 0, 0));
        peer.expect(A_OKAY, local_id);
        let eof_deadline = Instant::now() + Duration::from_secs(15);
        let mut sink = [0u8; 64];
        loop {
            match peer.0.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        assert!(Instant::now() < eof_deadline, "no EOF after DESTROY");
                    }
                    other => panic!("fake adbd read: {other}"),
                },
            }
        }
    });

    // The CLI must exit while the pump/inc-server pair keeps running.
    let exit_deadline = Instant::now() + Duration::from_secs(25);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            panic!("CLI did not exit after the 256-byte output window");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0));

    cli_exited_tx.send(()).unwrap();
    fake.join().unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Performing Incremental Install"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Performing Streamed Install") && stdout.contains("Success"),
        "forwarded device output missing; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Install command complete"),
        "stdout: {stdout}"
    );
    assert!(
        stderr.contains("All files should be loaded"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

#[test]
fn incremental_install_failure_kills_the_pair_and_exits_nonzero() {
    let apk = make_fixture("fail");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg("--incremental")
        .arg(&apk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fake = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) => {
                    assert!(Instant::now() < deadline, "CLI never connected: {error}");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        socket.set_nodelay(true).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut peer = FakeAdbd::from_stream(socket);

        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        let banner = b"device::ro.product.name=fake-incr;features=cmd,shell_v2,abb_exec";
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, banner);

        let (command, local_id, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_OPEN);
        peer.send(A_OKAY, local_id, &[]);

        // The inc-server handshake ("OKAY") is never acked; instead the
        // device reports a failure, padded past the 256-byte window so the
        // CLI returns immediately and kills the pair.
        let payload = peer.expect(A_WRTE, local_id);
        assert_eq!(payload, b"OKAY");

        let mut text = b"Failure [INSTALL_FAILED_TEST]\n".to_vec();
        text.extend_from_slice(&[b'.'; 240]);
        peer.send(A_WRTE, local_id, &text);
        peer.expect(A_OKAY, local_id);

        // The CLI SIGTERMs the pump + inc-server; the transport closes.
        let eof_deadline = Instant::now() + Duration::from_secs(15);
        let mut sink = [0u8; 64];
        loop {
            match peer.0.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        assert!(Instant::now() < eof_deadline, "no EOF after failure");
                    }
                    other => panic!("fake adbd read: {other}"),
                },
            }
        }
    });

    let exit_deadline = Instant::now() + Duration::from_secs(25);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            panic!("CLI did not exit after the failure window");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(1));

    fake.join().unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("adb: Install failed"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

#[test]
fn install_multiple_incremental_sends_unsigned_then_serves_signed() {
    let apk = make_fixture("multi");
    let apk_bytes = std::fs::read(&apk).unwrap();
    let (dm, dm_bytes) = make_unsigned_companion(&apk);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install-multiple")
        .arg("--incremental")
        .arg(&apk)
        .arg(&dm)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (cli_exited_tx, cli_exited_rx) = std::sync::mpsc::channel::<()>();

    let fake = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(25);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) => {
                    assert!(Instant::now() < deadline, "CLI never connected: {error}");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        socket.set_nodelay(true).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut peer = FakeAdbd::from_stream(socket);

        // CNXN.
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        let banner = b"device::ro.product.name=fake-incr;features=cmd,shell_v2,abb_exec";
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, banner);

        // The abb_exec service carries both entries: the v4-signed APK first
        // (id 0), the unsigned companion second (id 1).
        let (command, local_id, _, payload) = peer.recv_message().unwrap();
        assert_eq!(command, A_OPEN);
        let service = String::from_utf8_lossy(&payload);
        let apk_entry = service.find("base.apk:8192:0:").expect("signed entry");
        let dm_entry = service.find("base.dm:3000:1").expect("unsigned entry");
        assert!(apk_entry < dm_entry, "signed files come first: {service}");
        peer.send(A_OKAY, local_id, &[]);

        // send_unsigned_files: the companion's bytes arrive inline as A_WRTE
        // frames (acked one by one) before the inc-server is spawned.
        let mut received = Vec::new();
        let unsigned_deadline = Instant::now() + Duration::from_secs(15);
        while received.len() < dm_bytes.len() {
            assert!(
                Instant::now() < unsigned_deadline,
                "unsigned file truncated: {} of {} bytes",
                received.len(),
                dm_bytes.len()
            );
            let payload = peer.expect(A_WRTE, local_id);
            peer.send(A_OKAY, local_id, &[]);
            received.extend_from_slice(&payload);
        }
        assert_eq!(received, dm_bytes);

        // Now the pump + inc-server come up: "OKAY" handshake.
        let payload = peer.expect(A_WRTE, local_id);
        assert_eq!(payload, b"OKAY");
        peer.send(A_OKAY, local_id, &[]);

        // Device text past the 256-byte window → CLI returns and exits.
        let mut text = b"Performing Streamed Install\nSuccess\n".to_vec();
        text.extend_from_slice(&[b'.'; 240]);
        peer.send(A_WRTE, local_id, &text);
        peer.expect(A_OKAY, local_id);

        // Blocks are requested after the CLI is gone; block 0 must match the
        // signed APK bytes.
        cli_exited_rx.recv().unwrap();
        peer.send(A_WRTE, local_id, &encode_request(BLOCK_MISSING, 0, 0));
        peer.expect(A_OKAY, local_id);

        let mut stream = Vec::new();
        let mut blocks = parse_blocks(&stream);
        let block_deadline = Instant::now() + Duration::from_secs(15);
        while !blocks.iter().any(|(file_id, ..)| *file_id == -1) {
            assert!(
                Instant::now() < block_deadline,
                "no done marker; got {blocks:?}"
            );
            let payload = peer.expect(A_WRTE, local_id);
            peer.send(A_OKAY, local_id, &[]);
            stream.extend_from_slice(&payload);
            blocks = parse_blocks(&stream);
        }
        let (_file_id, block_type, compression, block_idx, payload) = blocks
            .iter()
            .find(|(file_id, block_type, _, block_idx, _)| {
                *file_id == 0 && *block_type == 0 && *block_idx == 0
            })
            .expect("data block 0 of the signed APK");
        assert_eq!(*block_type, 0);
        assert_eq!(*compression, 0);
        assert_eq!(
            decode_payload(*compression, payload, apk_bytes.len(), *block_idx),
            apk_bytes[..BLOCK_SIZE]
        );

        // DESTROY → chain shutdown → transport EOF.
        peer.send(A_WRTE, local_id, &encode_request(DESTROY, 0, 0));
        peer.expect(A_OKAY, local_id);
        let eof_deadline = Instant::now() + Duration::from_secs(15);
        let mut sink = [0u8; 64];
        loop {
            match peer.0.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        assert!(Instant::now() < eof_deadline, "no EOF after DESTROY");
                    }
                    other => panic!("fake adbd read: {other}"),
                },
            }
        }
    });

    let exit_deadline = Instant::now() + Duration::from_secs(25);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            panic!("CLI did not exit after the 256-byte output window");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0));

    cli_exited_tx.send(()).unwrap();
    fake.join().unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Performing Incremental Install") && stdout.contains("Success"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Install command complete"),
        "stdout: {stdout}"
    );
    assert!(
        stderr.contains("All files should be loaded"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

fn accept_with_deadline(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error) => {
                assert!(Instant::now() < deadline, "CLI never connected: {error}");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn prepare_peer(socket: TcpStream) -> FakeAdbd {
    socket.set_nodelay(true).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    FakeAdbd::from_stream(socket)
}

fn read_until_eof(peer: &mut FakeAdbd) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut sink = [0u8; 64];
    loop {
        match peer.0.read(&mut sink) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(error) => match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    assert!(Instant::now() < deadline, "no EOF");
                }
                other => panic!("fake adbd read: {other}"),
            },
        }
    }
}

fn wait_child(child: &mut std::process::Child, seconds: u64) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("CLI did not exit in time");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

const DEFAULT_BANNER: &[u8] = b"device::ro.product.name=fake-incr;features=cmd,shell_v2,abb_exec";

#[test]
fn install_auto_defaults_to_incremental_with_device_probe() {
    // A v4-signed APK with no flags: the gates pass, the device probe runs
    // on the live connection, and the silent incremental attempt streams.
    let apk = make_fixture("auto");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg(&apk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fake = thread::spawn(move || {
        let mut peer = prepare_peer(accept_with_deadline(&listener));
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, DEFAULT_BANNER);

        // Incremental-by-default device probe; "null" (unset) keeps it on.
        serve_probe(&mut peer, b"null\n");

        // The silent attempt opens install-incremental on the same connection.
        let (command, local_id, _, payload) = peer.recv_message().unwrap();
        assert_eq!(command, A_OPEN);
        let service = String::from_utf8_lossy(&payload);
        assert!(
            service.starts_with("abb_exec:package\u{0}install-incremental\u{0}"),
            "service: {service}"
        );
        peer.send(A_OKAY, local_id, &[]);

        let payload = peer.expect(A_WRTE, local_id);
        assert_eq!(payload, b"OKAY");
        peer.send(A_OKAY, local_id, &[]);

        let mut text = b"Performing Streamed Install\nSuccess\n".to_vec();
        text.extend_from_slice(&[b'.'; 240]);
        peer.send(A_WRTE, local_id, &text);
        peer.expect(A_OKAY, local_id);

        // DESTROY tears the background pair down.
        peer.send(A_WRTE, local_id, &encode_request(DESTROY, 0, 0));
        peer.expect(A_OKAY, local_id);
        read_until_eof(&mut peer);
    });

    let status = wait_child(&mut child, 25);
    assert_eq!(status.code(), Some(0));
    fake.join().unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Performing Incremental Install"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Install command complete"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Success"), "stdout: {stdout}");
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

#[test]
fn install_auto_falls_back_to_streamed_for_unsigned_apk() {
    // No .idsig → should_use_incremental_by_default fails inside the silent
    // attempt; the fallback streamed install dials a fresh connection.
    let apk = make_fixture("auto-fallback");
    std::fs::remove_file(apk.with_file_name("base.apk.idsig")).unwrap();
    let size = std::fs::metadata(&apk).unwrap().len() as usize;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg(&apk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fake = thread::spawn(move || {
        // Connection A: handshake + probe, then the CLI reconnects.
        let mut peer = prepare_peer(accept_with_deadline(&listener));
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, DEFAULT_BANNER);
        serve_probe(&mut peer, b"null\n");

        // Connection B: the fallback streamed install.
        let mut peer = prepare_peer(accept_with_deadline(&listener));
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, DEFAULT_BANNER);
        serve_streamed_install(&mut peer, size);
    });

    let status = wait_child(&mut child, 25);
    assert_eq!(status.code(), Some(0));
    fake.join().unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Performing Incremental Install"),
        "silent precheck must not print the incremental banner; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Performing Streamed Install"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Streamed install succeeded"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

#[test]
fn install_auto_honors_device_probe_false() {
    // The device says `enable_adb_incremental_install_default = false`
    // (trailing newline included): skip incremental entirely and stream on
    // the same connection — no probe-free reconnect.
    let apk = make_fixture("auto-probe-off");
    let size = std::fs::metadata(&apk).unwrap().len() as usize;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg(&apk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let fake = thread::spawn(move || {
        let mut peer = prepare_peer(accept_with_deadline(&listener));
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, DEFAULT_BANNER);
        serve_probe(&mut peer, b"false\n");
        serve_streamed_install(&mut peer, size);
    });

    let status = wait_child(&mut child, 25);
    assert_eq!(status.code(), Some(0));
    fake.join().unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Performing Incremental Install"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Streamed install succeeded"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}

#[test]
fn incremental_install_fork_server_serves_and_outlives_cli() {
    // ADB_INCREMENTAL_TRANSPORT_SERVE forces the fork-continue path (the
    // transport-serve server child, used for userspace-TLS transports) even
    // on this raw-socket transport; the dialogue is identical from the
    // device's point of view.
    let apk = make_fixture("fork");
    let apk_bytes = std::fs::read(&apk).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .arg("--incremental")
        .arg(&apk)
        .env("ADB_INCREMENTAL_TRANSPORT_SERVE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (cli_exited_tx, cli_exited_rx) = std::sync::mpsc::channel::<()>();

    let fake = thread::spawn(move || {
        let mut peer = prepare_peer(accept_with_deadline(&listener));
        let (command, _, _, _) = peer.recv_message().unwrap();
        assert_eq!(command, A_CNXN);
        peer.send_message(A_CNXN, 0x0100_0001, 1024 * 1024, DEFAULT_BANNER);

        // Explicit --incremental: no probe, straight to the service.
        let (command, local_id, _, payload) = peer.recv_message().unwrap();
        assert_eq!(command, A_OPEN);
        let service = String::from_utf8_lossy(&payload);
        assert!(
            service.starts_with("abb_exec:package\u{0}install-incremental\u{0}"),
            "service: {service}"
        );
        peer.send(A_OKAY, local_id, &[]);

        // The forked server's "OKAY", then text past the 256-byte window.
        let payload = peer.expect(A_WRTE, local_id);
        assert_eq!(payload, b"OKAY");
        peer.send(A_OKAY, local_id, &[]);

        let mut text = b"Performing Streamed Install\nSuccess\n".to_vec();
        text.extend_from_slice(&[b'.'; 240]);
        peer.send(A_WRTE, local_id, &text);
        peer.expect(A_OKAY, local_id);

        // Blocks are requested only after the CLI is gone: the fork child
        // must still be serving over the inherited transport.
        cli_exited_rx.recv().unwrap();
        peer.send(A_WRTE, local_id, &encode_request(BLOCK_MISSING, 0, 0));
        peer.expect(A_OKAY, local_id);

        let mut stream = Vec::new();
        let mut blocks = parse_blocks(&stream);
        let block_deadline = Instant::now() + Duration::from_secs(15);
        while !blocks.iter().any(|(file_id, ..)| *file_id == -1) {
            assert!(
                Instant::now() < block_deadline,
                "no done marker; got {blocks:?}"
            );
            let payload = peer.expect(A_WRTE, local_id);
            peer.send(A_OKAY, local_id, &[]);
            stream.extend_from_slice(&payload);
            blocks = parse_blocks(&stream);
        }
        let mut reassembled = Vec::new();
        for (file_id, block_type, compression, block_idx, payload) in &blocks {
            if *file_id == -1 || *block_type != 0 {
                continue;
            }
            reassembled.extend_from_slice(&decode_payload(
                *compression,
                payload,
                apk_bytes.len(),
                *block_idx,
            ));
        }
        assert_eq!(reassembled, apk_bytes);

        // DESTROY stops the fork child; the transport then reaches EOF.
        peer.send(A_WRTE, local_id, &encode_request(DESTROY, 0, 0));
        peer.expect(A_OKAY, local_id);
        read_until_eof(&mut peer);
    });

    let status = wait_child(&mut child, 25);
    assert_eq!(status.code(), Some(0));
    cli_exited_tx.send(()).unwrap();
    fake.join().unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Performing Incremental Install"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Serving..."), "stdout: {stdout}");
    assert!(stdout.contains("Success"), "stdout: {stdout}");
    assert!(
        stderr.contains("All files should be loaded"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(apk.parent().unwrap());
}
