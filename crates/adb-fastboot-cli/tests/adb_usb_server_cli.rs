//! Real executable client -> production smart-socket dispatcher -> fake URB
//! completion peer. No fake server protocol or device I/O acceptance claim.
#![cfg(feature = "usb")]
#![allow(dead_code, unused_imports, unused_variables)]
#[path = "../src/client/auth.rs"]
pub mod client_auth;
#[path = "../src/client/transport.rs"]
pub mod client_transport;
mod client {
    pub use crate::client_auth as auth;
    pub use crate::client_transport as transport;
}
#[cfg(target_os = "android")]
use client_auth::persist_adb_pubkey;
use server::models::TransportRegistry;
#[path = "../src/server/mod.rs"]
mod server;
use server::smart_socket::{bridge_to_device_with_smart, run_smart_socket_loop};
use std::{
    io::{Read, Write},
    net::TcpStream,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
#[path = "../src/server/usb_dispatch_tests.rs"]
mod fixtures;

#[test]
fn executable_exec_out_reaches_usb_urb_dispatcher() {
    run_executable(false);
}
#[test]
fn executable_usb_rejected_open_returns_nonzero() {
    run_executable(true);
}
fn run_executable(fail_open: bool) {
    let (reg, trace, closed) = if fail_open {
        fixtures::setup(true)
    } else {
        fixtures::setup_cli()
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let active = running.clone();
    let r = reg.clone();
    let server = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(15);
        let mut handlers = vec![];
        while active.load(Ordering::Acquire) && Instant::now() < until {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let reg = r.clone();
                    let flag = active.clone();
                    handlers.push(std::thread::spawn(move || {
                        run_smart_socket_loop(s, &reg, &flag)
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("{e}"),
            }
        }
        for h in handlers {
            let _ = h.join().unwrap();
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .args(["-P", &port.to_string(), "-s", "fake-urb", "exec-out", "cat"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let timed_out = child.try_wait().unwrap().is_none();
    if timed_out {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    running.store(false, Ordering::Release);
    server.join().unwrap();
    assert!(
        !timed_out,
        "CLI blocked: {} trace {:?} stdout {:?}",
        String::from_utf8_lossy(&output.stderr),
        trace.lock().unwrap(),
        output.stdout
    );
    if fail_open {
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("device rejected service"));
    } else {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, [b'x'; 64]);
    }
    assert!(trace.lock().unwrap().iter().any(|b| b == b"exec:cat\0"));
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(!reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
}
