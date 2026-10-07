//! `inc-pump` — the AOSP client↔device byte-channel bridge for incremental
//! installs.
//!
//! In AOSP the inc-server inherits a raw connection fd whose bytes are the
//! plain `pm` stream; the local adb server process does the A_WRTE framing on
//! the other side of that fd. This port has no local server — the transport
//! speaks A_WRTE directly to adbd — so `inc-pump` bridges the two worlds:
//!
//! ```text
//!   transport fd (A_WRTE frames)  ←→  channel fd (plain pm byte stream)
//! ```
//!
//! It is spawned as a separate process (like AOSP's inc-server) so it can
//! outlive the adb client, and exits when either side reaches EOF.
//!
//! Framing follows the same discipline as `write_exec_payload` /
//! `read_exec_output` (adb_install.rs): one in-flight A_WRTE at a time,
//! A_OKAY completes it, incoming A_WRTEs are acked and forwarded, incoming
//! payloads during a send are queued.

use std::collections::VecDeque;
use std::os::unix::io::RawFd;

use adb_protocol::{AdbMessageHeader, A_CLSE, A_OKAY, A_WRTE, MAX_PAYLOAD_V2};

use crate::server::sysdeps_unix::{adb_read, adb_write};

/// Max plain bytes per A_WRTE frame (AOSP `MAX_PAYLOAD_V2` minus the frame
/// header), mirroring the send chunking in adb_install.rs.
const MAX_FRAME_DATA: usize = MAX_PAYLOAD_V2 as usize - 24;

enum PumpEvent {
    /// One decoded frame from the transport fd.
    Frame(AdbMessageHeader, Vec<u8>),
    /// The transport fd reached EOF (device disconnected).
    Disconnected,
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> Result<bool, String> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = adb_read(fd, &mut buf[filled..]).map_err(|e| format!("inc-pump: read: {e}"))?;
        if read == 0 {
            return Ok(false);
        }
        filled += read;
    }
    Ok(true)
}

fn write_all(fd: RawFd, buf: &[u8]) -> Result<(), String> {
    let mut written = 0;
    while written < buf.len() {
        let n = adb_write(fd, &buf[written..]).map_err(|e| format!("inc-pump: write: {e}"))?;
        if n == 0 {
            return Err("inc-pump: write returned 0".to_string());
        }
        written += n;
    }
    Ok(())
}

fn send_frame(
    transport_fd: RawFd,
    local_id: u32,
    remote_id: u32,
    payload: &[u8],
) -> Result<(), String> {
    let header = AdbMessageHeader::new(A_WRTE, local_id, remote_id, payload);
    let mut hdr_buf = [0u8; 24];
    header.encode(&mut hdr_buf);
    write_all(transport_fd, &hdr_buf)?;
    if !payload.is_empty() {
        write_all(transport_fd, payload)?;
    }
    Ok(())
}

fn recv_frame(transport_fd: RawFd) -> Result<PumpEvent, String> {
    let mut hdr_buf = [0u8; 24];
    if !read_all(transport_fd, &mut hdr_buf)? {
        return Ok(PumpEvent::Disconnected);
    }
    let header = AdbMessageHeader::decode(&hdr_buf)
        .map_err(|e| format!("inc-pump: bad frame header: {e}"))?;
    if header.data_length > MAX_PAYLOAD_V2 {
        return Err(format!(
            "inc-pump: payload too large: {} bytes",
            header.data_length
        ));
    }
    let mut payload = vec![0u8; header.data_length as usize];
    if !payload.is_empty() {
        if !read_all(transport_fd, &mut payload)? {
            return Ok(PumpEvent::Disconnected);
        }
        header
            .verify_payload(&payload)
            .map_err(|e| format!("inc-pump: bad frame payload: {e}"))?;
    }
    Ok(PumpEvent::Frame(header, payload))
}

/// Run the pump until either side disconnects.
///
/// `transport_fd` carries A_WRTE frames to/from adbd (the inherited socket of
/// the caller's transport); `channel_fd` carries the plain `pm` byte stream to
/// and from the inc-server process.
pub fn run(
    transport_fd: RawFd,
    channel_fd: RawFd,
    local_id: u32,
    remote_id: u32,
) -> Result<(), String> {
    let mut outbox: VecDeque<Vec<u8>> = VecDeque::new();
    let mut in_flight = false;

    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: transport_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: channel_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("inc-pump: poll: {error}"));
        }

        // inc-server → device.
        if poll_fds[1].revents & libc::POLLIN != 0 {
            let mut buf = vec![0u8; MAX_FRAME_DATA];
            let read = adb_read(channel_fd, &mut buf).map_err(|e| format!("inc-pump: read: {e}"))?;
            if read == 0 {
                // inc-server exited; nothing left to pump.
                return Ok(());
            }
            buf.truncate(read);
            if in_flight {
                outbox.push_back(buf);
            } else {
                send_frame(transport_fd, local_id, remote_id, &buf)?;
                in_flight = true;
            }
        }

        // Device → inc-server.
        if poll_fds[0].revents & libc::POLLIN != 0 {
            match recv_frame(transport_fd)? {
                PumpEvent::Disconnected => return Ok(()),
                PumpEvent::Frame(header, payload) => match header.command {
                    A_WRTE if header.arg0 == remote_id && header.arg1 == local_id => {
                        let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                        let mut ack_buf = [0u8; 24];
                        ack.encode(&mut ack_buf);
                        write_all(transport_fd, &ack_buf)?;
                        if !payload.is_empty() {
                            write_all(channel_fd, &payload)?;
                        }
                    }
                    A_OKAY if header.arg0 == remote_id && header.arg1 == local_id => {
                        in_flight = false;
                    }
                    A_CLSE => return Ok(()),
                    other => {
                        return Err(format!("inc-pump: unexpected frame command {other:#x}"));
                    }
                },
            }
        }

        // Window is open: move queued channel bytes onto the wire.
        while !in_flight {
            match outbox.pop_front() {
                Some(data) => {
                    send_frame(transport_fd, local_id, remote_id, &data)?;
                    in_flight = true;
                }
                None => break,
            }
        }
    }
}
