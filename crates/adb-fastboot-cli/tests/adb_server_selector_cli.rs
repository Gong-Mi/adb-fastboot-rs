//! Real CLI selector+STAT+RECV contract on disposable smart servers A and B.
//! CLI -P/-L must override environment A; neither peer touches a real device.
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

fn request(stream: &mut TcpStream) -> String {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let size = usize::from_str_radix(std::str::from_utf8(&header).unwrap(), 16).unwrap();
    assert!(size <= 4096);
    let mut data = vec![0; size];
    stream.read_exact(&mut data).unwrap();
    String::from_utf8(data).unwrap()
}

fn sync_request(stream: &mut TcpStream, expected: &[u8; 4]) {
    let mut header = [0; 8];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..4], expected);
    let size = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
    assert!(size <= 1024);
    let mut path = vec![0; size];
    stream.read_exact(&mut path).unwrap();
    assert_eq!(path, b"/remote/selector");
}

fn peer(
    listener: TcpListener,
    selected: bool,
    stop: Arc<AtomicBool>,
    reached: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    reached.store(true, Ordering::Release);
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    assert_eq!(request(&mut socket), "host:transport:selector-fixture");
                    if !selected {
                        let message = "wrong environment server A";
                        socket
                            .write_all(format!("FAIL{:04x}{message}", message.len()).as_bytes())
                            .unwrap();
                        return;
                    }
                    socket.write_all(b"OKAY").unwrap();
                    assert_eq!(request(&mut socket), "sync:");
                    socket.write_all(b"OKAY").unwrap();
                    sync_request(&mut socket, b"STAT");
                    // Independent AOSP v1 structure, deliberately no length.
                    let data = b"server-B";
                    let stat = [
                        b"STAT".as_slice(),
                        &0o100640u32.to_le_bytes(),
                        &(data.len() as u32).to_le_bytes(),
                        &1_720_000_001u32.to_le_bytes(),
                    ]
                    .concat();
                    socket.write_all(&stat).unwrap();
                    sync_request(&mut socket, b"RECV");
                    let transfer = [
                        b"DATA".as_slice(),
                        &(data.len() as u32).to_le_bytes(),
                        data,
                        b"DONE",
                        &0u32.to_le_bytes(),
                    ]
                    .concat();
                    socket.write_all(&transfer).unwrap();
                    socket.shutdown(Shutdown::Write).unwrap();
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    })
}

struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn run_selector(option: &str) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let fixture = Fixture(std::env::temp_dir().join(format!(
        "adb-selector-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir_all(&fixture.0).unwrap();
    let destination = fixture.0.join("pulled");
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let a_port = a.local_addr().unwrap().port();
    let b_port = b.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let reached_a = Arc::new(AtomicBool::new(false));
    let reached_b = Arc::new(AtomicBool::new(false));
    let peer_a = peer(a, false, stop.clone(), reached_a.clone());
    let peer_b = peer(b, true, stop.clone(), reached_b.clone());
    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command.arg(option).arg(if option == "-P" {
        b_port.to_string()
    } else {
        format!("tcp:127.0.0.1:{b_port}")
    });
    command
        .args(["-s", "selector-fixture", "pull", "-a", "/remote/selector"])
        .arg(&destination)
        .env("HOME", &fixture.0)
        .env("ADB_SERVER_SOCKET", format!("tcp:127.0.0.1:{a_port}"))
        .env_remove("ANDROID_ADB_SERVER_PORT")
        .env_remove("ANDROID_SERIAL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // AOSP set_time_and_mode applies the child process umask. Fix this
    // subprocess-only precondition without changing the parallel test runner's
    // global umask or weakening the remote metadata assertion.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o027);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    stop.store(true, Ordering::Release);
    peer_a.join().unwrap();
    peer_b.join().unwrap();
    assert!(
        !reached_a.load(Ordering::Acquire),
        "{option} was ignored: CLI reached environment server A; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        reached_b.load(Ordering::Acquire),
        "{option} never reached selected server B"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&destination).unwrap(), b"server-B");
    let metadata = fs::metadata(&destination).unwrap();
    assert_eq!(metadata.mtime(), 1_720_000_001);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
}

#[test]
#[cfg(unix)]
fn pull_cli_port_overrides_environment_without_other_target_io() {
    run_selector("-P");
}
#[test]
#[cfg(unix)]
fn pull_cli_listen_socket_overrides_environment_without_other_target_io() {
    run_selector("-L");
}
