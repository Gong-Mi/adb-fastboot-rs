//! Service-string parity with the AOSP client for commands that talk to the
//! ADB server directly.
//!
//! AOSP anchors:
//!   client/commandline.cpp:1906-1955  forward/reverse host-prefix + cmd
//!   client/commandline.cpp:1917-1927  host_prefix = "host:" / "reverse:"
//!   client/commandline.cpp:2121-2122  jdwp -> adb_connect_command("jdwp")
//!   services.cpp:159-258              wait_service (host:wait-for-*)
//!   adb.cpp:1133-1155                 list-forward / killforward-all framing
//!
//! Every case boots a fake ADB server on an ephemeral port, runs the real
//! `adb-rs` binary against it with `-P <port>`, and asserts the exact service
//! strings the client put on the wire.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_adb-rs");

/// One scripted server reply: the request it answers, the bytes to write, and
/// whether the connection is closed afterwards (the client treats EOF as the
/// end of the service).
struct Step {
    request: &'static str,
    reply: Vec<u8>,
    close_after: bool,
}

fn step(request: &'static str, reply: Vec<u8>) -> Step {
    Step { request, reply, close_after: true }
}

fn step_keep_open(request: &'static str, reply: Vec<u8>) -> Step {
    Step { request, reply, close_after: false }
}

fn ok_payload(payload: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"OKAY");
    out.extend_from_slice(format!("{:04x}", payload.len()).as_bytes());
    out.extend_from_slice(payload.as_bytes());
    out
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = usize::from_str_radix(std::str::from_utf8(&len_buf).ok()?, 16).ok()?;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Spawn a fake ADB server that answers each request from `steps` and records
/// every request string it saw. Unknown requests are answered with FAIL.
fn spawn_server(steps: Vec<Step>) -> (u16, Arc<Mutex<Vec<String>>>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let seen_srv = Arc::clone(&seen);
    let stop_srv = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            // One client connection can carry several requests: a transport
            // switch is followed by the device service on the same socket.
            while !stop_srv.load(Ordering::Relaxed) {
                let Some(request) = read_request(&mut socket) else { break };
                seen_srv.lock().unwrap().push(request.clone());
                match steps.iter().find(|s| s.request == request) {
                    Some(found) => {
                        let _ = socket.write_all(&found.reply);
                        if found.close_after {
                            let _ = socket.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    }
                    None => {
                        let mut fail = b"FAIL".to_vec();
                        fail.extend_from_slice(b"000a");
                        fail.extend_from_slice(b"unexpected");
                        let _ = socket.write_all(&fail);
                        let _ = socket.shutdown(std::net::Shutdown::Both);
                        break;
                    }
                }
            }
        }
    });
    (port, seen, stop)
}

struct Outcome {
    success: bool,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

/// Run the CLI with a hard deadline so a client that never returns fails the
/// test instead of hanging the suite.
fn run_cli(port: u16, args: &[&str], deadline: Duration) -> Outcome {
    let started = Instant::now();
    let mut child: Child = Command::new(BIN)
        .arg("-P")
        .arg(port.to_string())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adb-rs");
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break Some(status),
            None if started.elapsed() >= deadline => {
                let _ = child.kill();
                break None;
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    let _ = child.wait();
    Outcome {
        success: status.map(|s| s.success()).unwrap_or(false),
        stdout,
        stderr,
        elapsed: started.elapsed(),
    }
}

fn requests(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    seen.lock().unwrap().clone()
}

#[test]
fn forward_list_sends_host_list_forward() {
    // AOSP: `forward --list` -> adb_query_command("host:" + "list-forward").
    let (port, seen, stop) = spawn_server(vec![step("host:list-forward", ok_payload(""))]);
    let out = run_cli(port, &["forward", "--list"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(seen, vec!["host:list-forward".to_string()]);
    assert!(out.success, "forward --list failed: {}", out.stderr);
}

#[test]
fn forward_remove_all_sends_host_killforward_all() {
    // AOSP: `forward --remove-all` -> adb_connect("host:" + "killforward-all"),
    // "1st OKAY is connect, 2nd OKAY is status" (adb.cpp:1146-1155).
    let (port, seen, stop) = spawn_server(vec![step("host:killforward-all", b"OKAYOKAY".to_vec())]);
    let out = run_cli(port, &["forward", "--remove-all"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(seen, vec!["host:killforward-all".to_string()]);
    assert!(out.success, "forward --remove-all failed: {}", out.stderr);
}

#[test]
fn reverse_list_sends_device_service_after_transport_selection() {
    // AOSP: reverse uses host_prefix "reverse:" (commandline.cpp:1917-1927), so
    // `reverse --list` is the *device* service "reverse:list-forward" reached
    // after host:transport-any, not the host service "host:reverse:list".
    let (port, seen, stop) = spawn_server(vec![
        step_keep_open("host:transport-any", b"OKAY".to_vec()),
        step(
            "reverse:list-forward",
            ok_payload("emulator-5554 tcp:8080 tcp:9000\n"),
        ),
    ]);
    let out = run_cli(port, &["reverse", "--list"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(
        seen,
        vec!["host:transport-any".to_string(), "reverse:list-forward".to_string()]
    );
    assert!(out.success, "reverse --list failed: {}", out.stderr);
    assert!(
        out.stdout.contains("emulator-5554 tcp:8080 tcp:9000"),
        "reverse --list dropped the listener list; stdout: {:?}",
        out.stdout
    );
}

#[test]
fn jdwp_sends_device_service_after_transport_selection() {
    // AOSP: `jdwp` -> adb_connect_command("jdwp") (commandline.cpp:2121-2122),
    // a device service streaming raw PIDs to stdout.
    let mut pid_stream = b"OKAY".to_vec();
    pid_stream.extend_from_slice(b"4242\n7777\n");
    let (port, seen, stop) = spawn_server(vec![
        step_keep_open("host:transport-any", b"OKAY".to_vec()),
        step("jdwp", pid_stream),
    ]);
    let out = run_cli(port, &["jdwp"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(
        seen,
        vec!["host:transport-any".to_string(), "jdwp".to_string()]
    );
    assert!(out.success, "jdwp failed: {}", out.stderr);
    assert!(
        out.stdout.contains("4242") && out.stdout.contains("7777"),
        "jdwp dropped the device PID list; stdout: {:?}",
        out.stdout
    );
}

#[test]
fn wait_for_device_uses_host_wait_service() {
    // AOSP: `wait-for-device` -> adb_command("host:wait-for-any-device"); the
    // server holds the request in wait_service and answers OKAY twice.
    let (port, seen, stop) =
        spawn_server(vec![step("host:wait-for-any-device", b"OKAYOKAY".to_vec())]);
    let out = run_cli(port, &["wait-for-device"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(
        seen,
        vec!["host:wait-for-any-device".to_string()],
        "wait-for-device must not poll host:get-state"
    );
    assert!(out.success, "wait-for-device failed: {}", out.stderr);
}

#[test]
fn wait_for_disconnect_uses_host_wait_service_and_returns() {
    // AOSP: `wait-for-disconnect` -> "host:wait-for-any-disconnect". A server
    // that answers OKAY twice means "already disconnected"; the client must
    // return instead of polling get-state (which never reports a disconnect).
    let (port, seen, stop) =
        spawn_server(vec![step("host:wait-for-any-disconnect", b"OKAYOKAY".to_vec())]);
    let out = run_cli(port, &["wait-for-disconnect"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(
        seen,
        vec!["host:wait-for-any-disconnect".to_string()],
        "wait-for-disconnect must not poll host:get-state"
    );
    assert!(
        out.success,
        "wait-for-disconnect did not return successfully after {:.1}s: {}",
        out.elapsed.as_secs_f64(),
        out.stderr
    );
}

#[test]
fn wait_for_usb_device_keeps_the_transport_inside_the_service_name() {
    // AOSP: components are joined into "wait-for-<transport>-<state>", so the
    // transport token lives in the service name (services.cpp:159-196).
    let (port, seen, stop) =
        spawn_server(vec![step("host:wait-for-usb-device", b"OKAYOKAY".to_vec())]);
    let out = run_cli(port, &["wait-for", "usb-device"], Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    let seen = requests(&seen);
    assert_eq!(seen, vec!["host:wait-for-usb-device".to_string()]);
    assert!(out.success, "wait-for usb-device failed: {}", out.stderr);
}
