//! Executable-CLI regressions for trailing arguments on `shell`, `exec-out`
//! and `exec-in`.
//!
//! AOSP anchors:
//! * `adb shell` parses only its own short options with `getopt("+e:ntTx")`.
//!   The leading `+` stops option parsing at the first non-option, so
//!   `adb shell ls -l` forwards `-l` to the remote shell
//!   (`client/commandline.cpp:714-715, 777-792`).
//! * `adb exec-in` / `adb exec-out` do no option parsing at all: argv[1] is
//!   the program name (raw, even if it starts with `-`), and every following
//!   argument is appended after `escape_arg` (`client/commandline.cpp:1802-1813`).
//!
//! These tests launch the real `adb-rs` binary against a strict fake ADB
//! server. They assert the exact host-service wire strings, not a helper's
//! return value. No system ADB server, USB device or adbd is touched.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const SHELL_ID_STDOUT: u8 = 1;
const SHELL_ID_EXIT: u8 = 3;

fn shell_v2_frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn accept_with_deadline(listener: &TcpListener) -> Result<TcpStream, String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nodelay(true).map_err(|e| e.to_string())?;
                socket
                    .set_read_timeout(Some(Duration::from_secs(8)))
                    .map_err(|e| e.to_string())?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(8)))
                    .map_err(|e| e.to_string())?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("CLI never connected to the fake ADB server".to_string());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("accept: {error}")),
        }
    }
}

/// Read one `<4 hex length><payload>` host-service request.
fn read_host_request(socket: &mut TcpStream) -> Result<String, String> {
    let mut length = [0u8; 4];
    socket
        .read_exact(&mut length)
        .map_err(|e| format!("read length: {e}"))?;
    let length = std::str::from_utf8(&length)
        .map_err(|e| format!("non-UTF8 length: {e}"))?;
    let length = usize::from_str_radix(length, 16)
        .map_err(|e| format!("invalid hex length {length:?}: {e}"))?;
    let mut payload = vec![0u8; length];
    socket
        .read_exact(&mut payload)
        .map_err(|e| format!("read payload: {e}"))?;
    String::from_utf8(payload).map_err(|e| format!("non-UTF8 request: {e}"))
}

/// A fake ADB server that accepts exactly `expected_services` in order, then
/// streams `reply` as the device-service byte stream and closes its write side.
/// Returns the requests it actually saw so failures can be attributed.
fn start_fake_server(
    listener: TcpListener,
    expected_services: Vec<String>,
    reply: Vec<u8>,
) -> (thread::JoinHandle<()>, mpsc::Receiver<(Result<(), String>, Vec<String>)>) {
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut observed = Vec::new();
        let result = (|| -> Result<(), String> {
            let mut socket = accept_with_deadline(&listener)?;
            for expected in &expected_services {
                let got = read_host_request(&mut socket)?;
                observed.push(got.clone());
                if &got != expected {
                    return Err(format!("expected service {expected:?}, got {got:?}"));
                }
                socket
                    .write_all(b"OKAY")
                    .map_err(|e| format!("write OKAY: {e}"))?;
                socket.flush().map_err(|e| format!("flush OKAY: {e}"))?;
            }
            socket
                .write_all(&reply)
                .map_err(|e| format!("write reply: {e}"))?;
            socket
                .flush()
                .map_err(|e| format!("flush reply: {e}"))?;
            // Let the client observe clean EOF instead of waiting forever.
            let _ = socket.shutdown(Shutdown::Write);
            Ok(())
        })();
        let _ = tx.send((result, observed));
    });
    (handle, rx)
}

fn run_cli(args: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .args(args)
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

fn assert_wire_case(
    label: &str,
    cli_args: &[&str],
    expected_services: &[&str],
    reply: Vec<u8>,
) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let expected: Vec<String> = expected_services
        .iter()
        .map(|service| (*service).to_string())
        .collect();
    let (peer, observed) = start_fake_server(listener, expected, reply);

    let mut args: Vec<String> = vec!["-P".to_string(), port.to_string()];
    args.extend(cli_args.iter().map(|arg| (*arg).to_string()));
    let output = run_cli(&args);

    let (peer_result, requests) = observed
        .recv_timeout(Duration::from_secs(15))
        .unwrap_or_else(|e| panic!("{label}: fake server did not finish: {e}"));
    let _ = peer.join();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        peer_result.is_ok(),
        "{label}: wire mismatch: {:?}; observed={requests:?}; exit={:?}; stdout={stdout}; stderr={stderr}",
        peer_result.err(),
        output.status.code()
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{label}: CLI failed; observed={requests:?}; stdout={stdout}; stderr={stderr}"
    );
    output
}

#[test]
fn shell_forwards_trailing_flag_arguments() {
    let mut reply = shell_v2_frame(SHELL_ID_STDOUT, b"total 0\n");
    reply.extend_from_slice(&shell_v2_frame(SHELL_ID_EXIT, &[0]));
    let output = assert_wire_case(
        "shell ls -l",
        &["shell", "ls", "-l"],
        &["host:transport-any", "shell,v2,raw:ls -l"],
        reply,
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "total 0\n");
}

#[test]
fn shell_double_dash_separator_is_not_forwarded() {
    let mut reply = shell_v2_frame(SHELL_ID_STDOUT, b"ok\n");
    reply.extend_from_slice(&shell_v2_frame(SHELL_ID_EXIT, &[0]));
    let output = assert_wire_case(
        "shell -- ls -l",
        &["shell", "--", "ls", "-l"],
        &["host:transport-any", "shell,v2,raw:ls -l"],
        reply,
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");
}

#[test]
fn shell_leading_option_still_fails_loudly() {
    // AOSP shell options are not implemented in this CLI. The first token
    // starting with '-' must be rejected, not silently forwarded as a remote
    // command. No fake server is needed: rejection happens before connecting.
    let output = run_cli(&[
        "-P".to_string(),
        "1".to_string(),
        "shell".to_string(),
        "-l".to_string(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("adb shell: option '-l' is not supported"),
        "stderr={stderr}"
    );
}

#[test]
fn exec_out_escapes_arguments_after_the_program_name() {
    let output = assert_wire_case(
        "exec-out screencap -p",
        &["exec-out", "screencap", "-p"],
        &["host:transport-any", "exec:screencap '-p'"],
        b"PNGDATA".to_vec(),
    );
    assert_eq!(output.stdout, b"PNGDATA");
}

#[test]
fn exec_in_escapes_arguments_after_the_program_name() {
    // Deliberately a different command shape from exec-out: both commands use
    // the same AOSP construction, but this test pins exec-in's own wire bytes
    // rather than asserting the two CLI paths are equal.
    let output = assert_wire_case(
        "exec-in sh -c 'echo hi'",
        &["exec-in", "sh", "-c", "echo hi"],
        &["host:transport-any", "exec:sh '-c' 'echo hi'"],
        b"hi\n".to_vec(),
    );
    assert_eq!(output.stdout, b"hi\n");
}

#[test]
fn exec_out_accepts_a_leading_dash_as_the_program_name() {
    // AOSP has no option parser for exec-in/exec-out; argv[1] may begin with
    // '-' and is appended raw. Only later arguments are escape_arg-quoted.
    let output = assert_wire_case(
        "exec-out -weird-prog -p",
        &["exec-out", "-weird-prog", "-p"],
        &["host:transport-any", "exec:-weird-prog '-p'"],
        b"X".to_vec(),
    );
    assert_eq!(output.stdout, b"X");
}
