//! CLI test for the hidden `adb-rs inc-pump` command: the real binary is
//! spawned with inherited fds and must bridge raw A_WRTE frames (transport
//! side) and a plain byte channel (inc-server side), with A_OKAY flow control.

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use adb_protocol::{A_CLSE, A_OKAY, A_WRTE};

struct Frame {
    command: u32,
    arg0: u32,
    arg1: u32,
    payload: Vec<u8>,
}

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
        // CLOEXEC by default so spawned children never inherit the peer
        // ends; `spawn_pump` re-enables only the two fds the pump needs.
        unsafe { libc::fcntl(raised[slot], libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    (raised[0], raised[1])
}

fn read_frame(stream: &mut UnixStream) -> Frame {
    let mut hdr = [0u8; 24];
    stream.read_exact(&mut hdr).unwrap();
    let command = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let arg0 = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let arg1 = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    Frame {
        command,
        arg0,
        arg1,
        payload,
    }
}

fn write_frame(stream: &mut UnixStream, command: u32, arg0: u32, arg1: u32, payload: &[u8]) {
    let mut hdr = [0u8; 24];
    hdr[0..4].copy_from_slice(&command.to_le_bytes());
    hdr[4..8].copy_from_slice(&arg0.to_le_bytes());
    hdr[8..12].copy_from_slice(&arg1.to_le_bytes());
    hdr[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[16..20].copy_from_slice(&0u32.to_le_bytes());
    hdr[20..24].copy_from_slice(&(command ^ 0xFFFF_FFFF).to_le_bytes());
    stream.write_all(&hdr).unwrap();
    stream.write_all(payload).unwrap();
}

fn spawn_pump(transport_fd: RawFd, channel_fd: RawFd, local_id: u32, remote_id: u32) -> Child {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(env!("CARGO_BIN_EXE_adb-rs"));
    command
        .arg("inc-pump")
        .arg(transport_fd.to_string())
        .arg(channel_fd.to_string())
        .arg(local_id.to_string())
        .arg(remote_id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // The child only inherits the two fds the pump needs (everything else,
    // including the peer ends this test keeps, is CLOEXEC).
    unsafe {
        command.pre_exec(move || {
            for fd in [transport_fd, channel_fd] {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

fn wait_exit(child: &mut Child) -> i32 {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "inc-pump did not exit in time"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn inc_pump_cli_bridges_frames_and_bytes_with_flow_control() {
    const LOCAL: u32 = 1;
    const REMOTE: u32 = 0x4242;

    let (t_child, t_peer) = socketpair();
    let (c_child, c_peer) = socketpair();
    let mut child = spawn_pump(t_child, c_child, LOCAL, REMOTE);
    unsafe {
        libc::close(t_child);
        libc::close(c_child);
    }

    let mut device = unsafe { UnixStream::from_raw_fd(t_peer) };
    let mut channel = unsafe { UnixStream::from_raw_fd(c_peer) };
    device
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Byte → frame: the channel's first bytes become an A_WRTE to the device.
    channel.write_all(b"OKAY").unwrap();
    let frame = read_frame(&mut device);
    assert_eq!(frame.command, A_WRTE);
    assert_eq!(frame.arg0, LOCAL);
    assert_eq!(frame.arg1, REMOTE);
    assert_eq!(frame.payload, b"OKAY");

    // While that frame is unacked, more channel bytes are queued, not sent.
    channel.write_all(b"queued-chunk").unwrap();
    // Give the pump a moment to (not) send it: the device has nothing ready.
    device.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let mut probe = [0u8; 24];
    assert!(device.read(&mut probe).is_err(), "unacked frame must gate the channel");
    device.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    // Ack frees the window: the queued bytes go out.
    write_frame(&mut device, A_OKAY, REMOTE, LOCAL, &[]);
    let frame = read_frame(&mut device);
    assert_eq!(frame.command, A_WRTE);
    assert_eq!(frame.payload, b"queued-chunk");

    // Frame → byte: device payloads are acked and forwarded to the channel.
    write_frame(&mut device, A_WRTE, REMOTE, LOCAL, b"hello from pm\n");
    let ack = read_frame(&mut device);
    assert_eq!(ack.command, A_OKAY);
    assert_eq!(ack.arg0, LOCAL);
    assert_eq!(ack.arg1, REMOTE);
    let mut text = [0u8; 14];
    channel.read_exact(&mut text).unwrap();
    assert_eq!(&text, b"hello from pm\n");

    // CLSE stops the pump.
    write_frame(&mut device, A_CLSE, REMOTE, LOCAL, &[]);
    assert_eq!(wait_exit(&mut child), 0);
}

#[test]
fn inc_pump_cli_exits_when_channel_reaches_eof() {
    let (t_child, t_peer) = socketpair();
    let (c_child, c_peer) = socketpair();
    let mut child = spawn_pump(t_child, c_child, 1, 2);
    unsafe {
        libc::close(t_child);
        libc::close(c_child);
    }

    let _device = unsafe { UnixStream::from_raw_fd(t_peer) };
    let channel = unsafe { UnixStream::from_raw_fd(c_peer) };
    // Closing the channel write end (inc-server exited) ends the pump.
    drop(channel);
    assert_eq!(wait_exit(&mut child), 0);
}
