//! ADB Server entry points — run_server, run_server_fork, run_server_on_port,
//! run_server_with_listener.  Mirrors AOSP `adb.cpp` → adb_server_main().

use std::io::{self, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::server::handler::handle_client;
use crate::server::models::{TransportRegistry, ADB_SERVER_PORT, SERVER_VERSION};
use crate::server::watcher::usb_device_watcher;

pub fn run_server() -> ! {
    run_server_fork(None, ADB_SERVER_PORT);
    #[allow(unreachable_code)]
    {
        std::process::exit(0);
    }
}

/// Start the ADB server in fork-server mode.
///
/// `ack_reply_fd` is the write-end of a pipe from the parent process.
/// After USB scan completes, the server writes "OK\n" to this fd to
/// signal the parent that it's ready, then closes it.
/// Only after that are client connections accepted.
pub fn run_server_fork(ack_reply_fd: Option<i32>, port: u16) -> ! {
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[adb-server] Cannot bind to 127.0.0.1:{ADB_SERVER_PORT}: {e}");
            std::process::exit(1);
        }
    };
    run_server_with_listener(listener, ack_reply_fd);
    std::process::exit(0);
}

pub fn run_server_on_port(port: u16) {
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[adb-server] Cannot bind to 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    run_server_with_listener(listener, None);
}

pub fn run_server_with_listener(listener: TcpListener, ack_reply_fd: Option<i32>) {
    let running = Arc::new(AtomicBool::new(true));
    let registry = Arc::new(Mutex::new(TransportRegistry::new()));

    // AOSP packages/modules/adb starts zero-config discovery independently
    // of USB hotplug; callbacks feed Create/Update/Delete into this registry.
    crate::server::mdns_backend::start_discovery(Arc::clone(&registry));

    let port = listener.local_addr().map(|a| a.port()).unwrap_or(ADB_SERVER_PORT);
    eprintln!(
        "[adb-server] Listening on 127.0.0.1:{port} (version {:08x})",
        SERVER_VERSION
    );

    // USB device watcher: try inotify (event-driven), fall back to polling
    let reg_for_poll = Arc::clone(&registry);
    let running_poll = Arc::clone(&running);
    thread::spawn(move || {
        usb_device_watcher(reg_for_poll, running_poll);
    });

    // Give the USB watcher a brief moment for its initial scan, then
    // signal the parent (fork-server mode) that we're ready.
    // AOSP's adb_server_main does the same via adb_wait_for_device_initialization.
    thread::sleep(Duration::from_millis(500));
    if let Some(reply_fd) = ack_reply_fd {
        use std::os::unix::io::FromRawFd;
        let mut f = unsafe { std::fs::File::from_raw_fd(reply_fd) };
        let _ = f.write_all(b"OK\n");
        // f is dropped here, closing the fd
    }

    // Accept loop
    listener.set_nonblocking(true).ok();
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                let reg = Arc::clone(&registry);
                let running_flag = Arc::clone(&running);
                thread::spawn(move || {
                    if let Err(e) = handle_client(client, &reg, &running_flag) {
                        eprintln!("[adb-server] Client error: {e}");
                    }
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[adb-server] Accept error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    eprintln!("[adb-server] Shut down.");
}
