//! Executable-CLI regressions for `adb-rs shell` over a *raw* direct transport.
//!
//! No device and no ADB server: each test binds an ephemeral loopback listener
//! that speaks the ADB message protocol (A_CNXN / A_OPEN / A_OKAY / A_WRTE /
//! A_CLSE) and carries ShellV2 (id + LE u32 length) payloads exactly like
//! adbd's `shell_service_protocol.cpp`. The real `adb-rs` binary is spawned as
//! a child process, so the assertions cover the actual CLI exit code and the
//! real stdout/stderr routing.
//!
//! AOSP semantics being pinned (vendor/adb/client/commandline.cpp
//! read_and_dump_protocol): the process exit code is the remote kIdExit byte,
//! stdout/stderr are demultiplexed, and a ShellV2 packet split across WRTE
//! frames is reassembled (never mistaken for raw bytes).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, ShellV2Packet, ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_WRTE,
    MAX_PAYLOAD_V2,
};

/// Point `-P` at a port nothing listens on, so the CLI's "Priority 1" ADB
/// server attempt fails fast and the direct raw transport (our fake adbd) is
/// exercised. Port 1 is privileged and guaranteed dead for a non-root test.
fn dead_server_port() -> u16 {
    1
}

/// Spawn a minimal adbd: CNXN handshake, accept one `shell,v2,raw:` A_OPEN,
/// then emit `frames` as consecutive A_WRTE messages followed by A_CLSE.
fn spawn_fake_adbd(frames: Vec<Vec<u8>>) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut hdr_buf = [0u8; 24];
        let mut resp_buf = [0u8; 24];

        // 1. Consume client A_CNXN, answer with a shell_v2-capable banner.
        socket.read_exact(&mut hdr_buf).unwrap();
        let cnxn = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut cnxn_payload = vec![0u8; cnxn.data_length as usize];
        socket.read_exact(&mut cnxn_payload).unwrap();

        let banner = b"device::features=shell_v2";
        AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, banner)
            .encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(banner).unwrap();

        // 2. Expect A_OPEN(shell,v2,raw:...), reply A_OKAY.
        socket.read_exact(&mut hdr_buf).unwrap();
        let open = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut open_payload = vec![0u8; open.data_length as usize];
        socket.read_exact(&mut open_payload).unwrap();
        assert!(
            open_payload.starts_with(b"shell,v2,raw:"),
            "expected shell,v2,raw service, got {:?}",
            String::from_utf8_lossy(&open_payload)
        );

        AdbMessageHeader::new(A_OKAY, 2, open.arg0, &[]).encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 3. Emit the caller-supplied ShellV2 byte-stream as separate WRTE frames.
        for frame in &frames {
            AdbMessageHeader::new(A_WRTE, 2, open.arg0, frame).encode(&mut resp_buf);
            socket.write_all(&resp_buf).unwrap();
            socket.write_all(frame).unwrap();
        }

        // 4. End the stream with A_CLSE.
        AdbMessageHeader::new(A_CLSE, 2, open.arg0, &[]).encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        let _ = socket.flush();

        // Drain the client's A_OKAY/A_CLSE acks until it closes or times out.
        let mut sink = [0u8; 256];
        while let Ok(n) = socket.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    });
    (port, handle)
}

fn run_cli_shell(adbd_port: u16, command: &[&str]) -> Output {
    let server_port = dead_server_port();
    let serial = format!("127.0.0.1:{adbd_port}");
    let mut args: Vec<String> = vec![
        "-P".into(),
        server_port.to_string(),
        "-s".into(),
        serial,
        "shell".into(),
    ];
    args.extend(command.iter().map(|s| s.to_string()));

    Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn adb-rs")
}

fn encode(pkt: &ShellV2Packet) -> Vec<u8> {
    let mut v = Vec::new();
    pkt.encode(&mut v);
    v
}

/// One logical Stdout ShellV2 packet split across two WRTE frames must be
/// reassembled byte-exactly: no header bytes leaked to stdout, no data lost.
#[test]
fn shell_reassembles_stdout_packet_split_across_write_frames() {
    let payload: Vec<u8> = (0..64u8).map(|b| b'A' + (b % 26)).collect();
    let full = encode(&ShellV2Packet::Stdout(&payload));
    let exit0 = encode(&ShellV2Packet::ExitCode(0));

    // Split *inside* the 5-byte header + payload so frame 1 is an incomplete
    // packet. A per-frame parser misreads this; a cross-frame accumulator does not.
    let frames = vec![
        full[..7].to_vec(),
        full[7..].to_vec(),
        exit0,
    ];

    let (port, handle) = spawn_fake_adbd(frames);
    let out = run_cli_shell(port, &["cat"]);
    handle.join().unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "unexpected exit; stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, payload,
        "stdout must be exactly the reassembled payload (got {} bytes)",
        out.stdout.len()
    );
}

/// The remote kIdExit byte must become the CLI's process exit code, and the
/// legacy fixed-text error must not be used.
#[test]
fn shell_propagates_remote_nonzero_exit_code() {
    let frames = vec![
        encode(&ShellV2Packet::Stdout(b"hello\n")),
        encode(&ShellV2Packet::ExitCode(3)),
    ];

    let (port, handle) = spawn_fake_adbd(frames);
    let out = run_cli_shell(port, &["exit-three"]);
    handle.join().unwrap();

    assert_eq!(
        out.status.code(),
        Some(3),
        "CLI must exit with the remote code; stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hello\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("remote shell exited with code"),
        "must not fold the exit code into fixed error text; stderr={stderr:?}"
    );
}

/// stdout and stderr in the same WRTE frame stay demultiplexed, and a nonzero
/// exit code still propagates.
#[test]
fn shell_splits_stdout_and_stderr_and_keeps_nonzero_exit() {
    let mut frame = Vec::new();
    ShellV2Packet::Stdout(b"out\n").encode(&mut frame);
    ShellV2Packet::Stderr(b"err\n").encode(&mut frame);

    let frames = vec![frame, encode(&ShellV2Packet::ExitCode(2))];

    let (port, handle) = spawn_fake_adbd(frames);
    let out = run_cli_shell(port, &["mixed"]);
    handle.join().unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "CLI must exit with the remote code; stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"out\n", "stdout must carry only Stdout packets");
    assert_eq!(out.stderr, b"err\n", "stderr must carry only Stderr packets");
}
