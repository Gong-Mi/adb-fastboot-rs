//! Executable CLI + isolated fake smart-socket peer. No real USB is opened.
//! Legacy selector and raw SYNC V1 bytes are pinned from AOSP docs/dev/services.md
//! and file_sync_protocol.h, not from the implementation under test.
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("adb-sync-usb-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

fn host(socket: &mut TcpStream) -> String {
    let mut len = [0; 4];
    socket.read_exact(&mut len).unwrap();
    let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
    let mut data = vec![0; n];
    socket.read_exact(&mut data).unwrap();
    String::from_utf8(data).unwrap()
}
fn sync_message(socket: &mut TcpStream) -> ([u8; 4], Vec<u8>) {
    let mut hdr = [0u8; 8];
    socket.read_exact(&mut hdr).unwrap();
    let id: [u8; 4] = hdr[..4].try_into().unwrap();
    let n = u32::from_le_bytes(hdr[4..].try_into().unwrap()) as usize;
    assert!(n <= 65536, "oversized fake request");
    let mut data = vec![0; n];
    socket.read_exact(&mut data).unwrap();
    (id, data)
}
fn run(case: &'static str, denied: bool) {
    let tmp = Temp::new();
    let local = tmp.0.join("input.bin");
    let folder = tmp.0.join("folder");
    let output = tmp.0.join("output.bin");
    fs::write(&local, b"USB fixture bytes").unwrap();
    if case == "push-dir" {
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("input.bin"), b"USB fixture bytes").unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(format!("fake-server accept failed: {e}")),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        let selector = host(&mut socket);
        if selector != "host:transport-usb" { return Err(format!("wrong selector {selector}")); }
        if denied {
            socket.write_all(b"FAIL0018more than one USB device").unwrap();
            let mut extra = [0u8; 1];
            assert_eq!(socket.read(&mut extra).unwrap(), 0, "must not send sync after selector failure");
            return Ok(());
        }
        socket.write_all(b"OKAY").unwrap();
        assert_eq!(host(&mut socket), "sync:");
        socket.write_all(b"OKAY").unwrap();
        if case == "push" || case == "push-dir" {
            if case == "push" {
                let (id, data) = sync_message(&mut socket);
                assert_eq!(&id, b"STAT");
                assert_eq!(data, b"/remote/file");
                socket.write_all(b"STAT\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
            }
            let (id, data) = sync_message(&mut socket);
            assert_eq!(&id, b"SEND");
            let expected = if case == "push-dir" { b"/remote/dir/input.bin,".as_slice() } else { b"/remote/file,".as_slice() };
            assert!(data.starts_with(expected), "wrong path: {data:?}");
            let (id, data) = sync_message(&mut socket);
            assert_eq!(&id, b"DATA");
            assert_eq!(data, b"USB fixture bytes");
            let mut done = [0u8; 8];
            socket.read_exact(&mut done).unwrap();
            assert_eq!(&done[..4], b"DONE");
            socket.write_all(b"OKAY\0\0\0\0").unwrap();
        } else {
            if case == "pull-a" {
                let (id, data) = sync_message(&mut socket);
                assert_eq!(&id, b"STAT");
                assert_eq!(data, b"/remote/file");
                socket.write_all(b"STAT").unwrap();
                for word in [0o100644u32, 8, 42] { socket.write_all(&word.to_le_bytes()).unwrap(); }
            }
            let (id, data) = sync_message(&mut socket);
            assert_eq!(&id, b"RECV");
            assert_eq!(data, b"/remote/file");
            socket.write_all(b"DATA\x08\0\0\0pulldataDONE\0\0\0\0").unwrap();
        }
        Ok(())
    });
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    let subcommand = match case { "push-dir" => "push", "pull-a" => "pull", _ => case };
    cmd.arg("-P").arg(port.to_string()).arg("-d").arg(subcommand);
    if case == "pull-a" { cmd.arg("-a"); }
    if case == "push" { cmd.arg(&local).arg("/remote/file"); }
    else if case == "push-dir" { cmd.arg(&folder).arg("/remote/dir"); }
    else { cmd.arg("/remote/file").arg(&output); }
    if case == "pull-a" {
        // Attribute preservation follows the child process umask. Make the
        // expected mode independent of the parent runner's umask.
        use std::os::unix::process::CommandExt;
        unsafe { cmd.pre_exec(|| { libc::umask(0o022); Ok(()) }); }
    }
    // -P must win over the deliberately different environment port.
    let result = cmd.env("ANDROID_ADB_SERVER_PORT", "1").stdin(Stdio::null()).output().unwrap();
    let transcript = peer.join().unwrap();
    assert!(transcript.is_ok(), "{}", transcript.unwrap_err());
    if denied {
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("more than one USB device"));
        assert!(!output.exists());
    } else {
        assert!(result.status.success(), "stderr={}", String::from_utf8_lossy(&result.stderr));
        if case == "pull" || case == "pull-a" {
            assert_eq!(fs::read(&output).unwrap(), b"pulldata");
            if case == "pull-a" {
                use std::os::unix::fs::MetadataExt;
                let attrs = fs::metadata(&output).unwrap();
                assert_eq!(attrs.mode() & 0o777, 0o644);
                assert_eq!(attrs.mtime(), 42);
            }
        }
    }
}
#[test] fn push_selects_usb_and_transfers_sync_bytes() { run("push", false); }
#[test] fn pull_selects_usb_and_transfers_sync_bytes() { run("pull", false); }
#[test] fn pull_preserves_metadata_on_selected_usb_server() { run("pull-a", false); }
#[test] fn push_selector_fail_stops_before_sync() { run("push", true); }
#[test] fn pull_selector_fail_stops_before_sync() { run("pull", true); }
#[test] fn directory_push_uses_same_selected_usb_connection() { run("push-dir", false); }
#[test] fn directory_push_selector_fail_stops_before_sync() { run("push-dir", true); }

#[test]
fn missing_server_rejects_usb_without_creating_pull_output() {
    let tmp = Temp::new();
    let input = tmp.0.join("input");
    let output = tmp.0.join("output");
    fs::write(&input, b"fixture").unwrap();
    for case in ["push", "pull"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
        command.args(["-P", "1", "-d", case]);
        if case == "push" { command.arg(&input).arg("/remote/file"); }
        else { command.arg("/remote/file").arg(&output); }
        let result = command.env("ANDROID_ADB_SERVER_PORT", "1").stdin(Stdio::null()).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("requires an ADB server"));
        assert!(!output.exists());
    }
}
