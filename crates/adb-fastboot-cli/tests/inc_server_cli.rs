//! End-to-end CLI test for the hidden `adb-rs inc-server` command: the real
//! binary is spawned with inherited fds (exactly like the install launcher
//! does) and driven through the incremental wire protocol by a fake device.
//!
//! AOSP references: client/incremental_server.cpp (Serve / SkipToRequest) and
//! client/commandline.cpp:2213-2238 (inc-server argument contract).

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

/// INCR request magic + opcodes (incremental_server.cpp:69-75).
const INCR: u32 = 0x494e_4352;
const BLOCK_MISSING: i16 = 1;
const DESTROY: i16 = 3;
const BLOCK_SIZE: usize = 4096;

struct Block {
    file_id: i16,
    compression_type: i8,
    block_idx: i32,
    payload: Vec<u8>,
}

fn encode_request(request_type: i16, file_id: i16, block_idx: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&INCR.to_be_bytes());
    out.extend_from_slice(&request_type.to_be_bytes());
    out.extend_from_slice(&file_id.to_be_bytes());
    out.extend_from_slice(&block_idx.to_be_bytes());
    out
}

/// socketpair with both fds forced >= 3 (the child validates that).
fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed");
    let mut raised = [0i32; 2];
    for (slot, fd) in fds.iter().enumerate() {
        raised[slot] = if *fd >= 3 {
            *fd
        } else {
            let dup = unsafe { libc::fcntl(*fd, libc::F_DUPFD, 3) };
            assert!(dup >= 3);
            unsafe { libc::close(*fd) };
            dup
        };
    }
    (raised[0], raised[1])
}

/// One framed chunk ([be32 size][block records...]).
fn read_chunk(stream: &mut impl Read) -> Vec<u8> {
    let mut size_buf = [0u8; 4];
    stream.read_exact(&mut size_buf).unwrap();
    let size = i32::from_be_bytes(size_buf) as usize;
    let mut framed = size_buf.to_vec();
    framed.resize(4 + size, 0);
    stream.read_exact(&mut framed[4..]).unwrap();
    framed
}

fn parse_chunk(framed: &[u8]) -> Vec<Block> {
    let size = i32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
    let data = &framed[4..4 + size];
    let mut cursor = 0usize;
    let mut blocks = Vec::new();
    while cursor + 10 <= data.len() {
        let file_id = i16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let compression_type = data[cursor + 3] as i8;
        let block_idx = i32::from_be_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]);
        let block_size = i16::from_be_bytes([data[cursor + 8], data[cursor + 9]]) as usize;
        cursor += 10;
        let payload = data[cursor..cursor + block_size].to_vec();
        cursor += block_size;
        blocks.push(Block {
            file_id,
            compression_type,
            block_idx,
            payload,
        });
    }
    blocks
}

/// Decode a block payload (raw or LZ4); `file_len` sizes the final block.
fn decode_payload(block: &Block, file_len: usize) -> Vec<u8> {
    match block.compression_type {
        0 => block.payload.clone(),
        1 => {
            let offset = block.block_idx as usize * BLOCK_SIZE;
            let size = std::cmp::min(BLOCK_SIZE, file_len - offset);
            lz4_flex::block::decompress(&block.payload, size).unwrap()
        }
        other => panic!("unexpected compression type {other}"),
    }
}

/// 4096 + 100 bytes of LCG stream (incompressible full block → raw path).
fn make_fixture(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("inc-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("base.apk");
    let mut state = 0xABCD_1234u32;
    let data: Vec<u8> = (0..BLOCK_SIZE + 100)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
        .collect();
    std::fs::write(&path, data).unwrap();
    path
}

#[test]
fn inc_server_cli_serves_blocks_over_inherited_fds() {
    let fixture = make_fixture("serve");
    let data = std::fs::read(&fixture).unwrap();

    let (conn_child, conn_peer) = socketpair();
    let (out_child, out_peer) = socketpair();
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("inc-server")
        .arg(conn_child.to_string())
        .arg(out_child.to_string())
        .arg(&fixture)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Parent's copies of the child-side fds.
    unsafe {
        libc::close(conn_child);
        libc::close(out_child);
    }

    let mut conn = unsafe { UnixStream::from_raw_fd(conn_peer) };
    let mut out = unsafe { UnixStream::from_raw_fd(out_peer) };
    conn.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    out.set_read_timeout(Some(Duration::from_secs(15))).unwrap();

    // Handshake.
    let mut okay = [0u8; 4];
    conn.read_exact(&mut okay).unwrap();
    assert_eq!(&okay, b"OKAY");

    // Device text followed by a request for file 0 / block 0.
    let mut first = b"Performing Streamed Install\n".to_vec();
    first.extend_from_slice(&encode_request(BLOCK_MISSING, 0, 0));
    conn.write_all(&first).unwrap();

    // The text is forwarded verbatim to the output fd.
    let mut text = [0u8; 28];
    out.read_exact(&mut text).unwrap();
    assert_eq!(&text, b"Performing Streamed Install\n");

    // Collect blocks until the done marker.
    let mut blocks = Vec::new();
    let mut done = false;
    while !done {
        let framed = read_chunk(&mut conn);
        for block in parse_chunk(&framed) {
            if block.file_id == -1 {
                done = true;
            } else {
                blocks.push(block);
            }
        }
    }

    assert_eq!(blocks.len(), 2, "expected both blocks");
    assert_eq!(blocks[0].block_idx, 0);
    assert_eq!(blocks[1].block_idx, 1);
    let mut reassembled = Vec::new();
    for block in &blocks {
        reassembled.extend_from_slice(&decode_payload(block, data.len()));
    }
    assert_eq!(reassembled, data);

    // DESTROY → clean stop.
    conn.write_all(&encode_request(DESTROY, 0, 0)).unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Serving..."), "stdout: {stdout}");
    assert!(
        stderr.contains("All files should be loaded"),
        "stderr: {stderr}"
    );
}

#[test]
fn inc_server_cli_handshakes_with_no_signed_files() {
    let (conn_child, conn_peer) = socketpair();
    let (out_child, out_peer) = socketpair();
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("inc-server")
        .arg(conn_child.to_string())
        .arg(out_child.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unsafe {
        libc::close(conn_child);
        libc::close(out_child);
    }

    let mut conn = unsafe { UnixStream::from_raw_fd(conn_peer) };
    conn.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let _out_peer = unsafe { UnixStream::from_raw_fd(out_peer) };

    let mut okay = [0u8; 4];
    conn.read_exact(&mut okay).unwrap();
    assert_eq!(&okay, b"OKAY");

    // Straight to the done marker: nothing to stream.
    let framed = read_chunk(&mut conn);
    let blocks = parse_chunk(&framed);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].file_id, -1);

    conn.write_all(&encode_request(DESTROY, 0, 0)).unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
}

#[test]
fn inc_server_cli_rejects_invalid_fds() {
    // connection_fd < 3 is rejected before anything else.
    let output = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .args(["inc-server", "1", "2"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Invalid connection_fd number given: 1"));

    // A valid connection fd with output_fd = 1 (stdio) is rejected next.
    let (conn_child, conn_peer) = socketpair();
    let output = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("inc-server")
        .arg(conn_child.to_string())
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    unsafe {
        libc::close(conn_child);
        libc::close(conn_peer);
    }
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Invalid output_fd number given: 1"));
}
