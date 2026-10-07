//! ADB shell client: ShellV2 streaming, raw shell execution, and direct adbd shell.
//!
//! Maps to AOSP `vendor/adb/client/` shell command handling.
//! These functions operate over a raw `Transport` (direct USB/TCP to adbd)
//! or through the ADB server forwarding mode.

use std::io::Write;
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, ShellV2Error, ShellV2Packet, Transport, TransportError,
    A_CLSE, A_OKAY, A_WRTE,
};

use super::protocol::open_service;
use super::auth::default_auth;
#[allow(unused_imports)]
use super::transport::connect_and_handshake_with_tls_upgrade;

/// Reassemble a ShellV2 byte stream and demultiplex it into stdout/stderr,
/// recording the remote exit code.
///
/// The buffer is deliberately *accumulated* across ADB WRTE frames: a single
/// ShellV2 packet can span several frames, so parsing each frame in isolation
/// would split a real packet and (previously) leak its header bytes to stdout.
/// AOSP `shell_service_protocol.cpp` frames as 1-byte id + little-endian u32
/// length, and `read_and_dump_protocol` only ever acts on stdout/stderr/exit.
///
/// Incomplete trailing bytes are left in `remainder` for the caller to extend
/// with the next frame. An unrecognized-but-complete id is consumed and
/// ignored (never surfaced as raw output).
fn drain_shell_v2_stream(
    remainder: &mut Vec<u8>,
    captured: &mut Option<Vec<u8>>,
    exit_code: &mut Option<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match ShellV2Packet::parse(remainder) {
            Ok((pkt, consumed)) => {
                match pkt {
                    ShellV2Packet::Stdout(data) => {
                        if let Some(buf) = captured.as_mut() {
                            buf.extend_from_slice(data);
                        }
                        std::io::stdout().write_all(data)?;
                        std::io::stdout().flush()?;
                    }
                    ShellV2Packet::Stderr(data) => {
                        if let Some(buf) = captured.as_mut() {
                            buf.extend_from_slice(data);
                        }
                        std::io::stderr().write_all(data)?;
                        std::io::stderr().flush()?;
                    }
                    ShellV2Packet::ExitCode(code) => {
                        *exit_code = Some(code);
                    }
                    _ => {}
                }
                remainder.drain(..consumed);
            }
            // Incomplete packet: wait for the remainder of the frame(s).
            Err(ShellV2Error::HeaderTooShort) | Err(ShellV2Error::PayloadTooShort { .. }) => {
                break;
            }
            // Complete packet with an unknown id: skip it (AOSP ignores it)
            // rather than dumping it to stdout as raw bytes.
            Err(ShellV2Error::UnknownStreamId(_)) => {
                let len = u32::from_le_bytes([
                    remainder[1],
                    remainder[2],
                    remainder[3],
                    remainder[4],
                ]) as usize;
                remainder.drain(..5 + len);
            }
        }
    }
    Ok(())
}

/// Stream shell output (Shell v2 packets) to stdout/stderr until exit or CLSE,
/// returning the captured bytes plus the remote exit code.
///
/// `exit_code` is `None` when the stream ended without an ExitCode packet
/// (matching AOSP, which reserves 255 for unexpected disconnection). This is
/// the entry point for callers that must relay the remote code as their own
/// process status; use [`stream_shell_v2`] for the legacy error-on-nonzero
/// contract.
pub fn stream_shell_v2_exit(
    transport: &mut dyn Transport,
    local_id: u32,
    mut _remote_id: u32,
    capture: bool,
) -> Result<(Option<Vec<u8>>, Option<u8>), Box<dyn std::error::Error>> {
    let mut captured = if capture { Some(Vec::new()) } else { None };
    let mut exit_code = None;
    let mut remainder: Vec<u8> = Vec::new();
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break
            }
            Err(e) => {
                return Err(format!("Stream error: {e}").into());
            }
        };

        match hdr.command {
            A_OKAY => {
                _remote_id = hdr.arg0;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Accumulate this frame's payload with any bytes left over from
                // a previous frame so cross-frame packets are reassembled.
                remainder.extend_from_slice(&payload);
                drain_shell_v2_stream(&mut remainder, &mut captured, &mut exit_code)?;
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }
    Ok((captured, exit_code))
}

/// Stream shell output (Shell v2 packets) to stdout/stderr until exit or CLSE.
///
/// Legacy contract: a non-zero remote exit code is reported as an error whose
/// text is `remote shell exited with code N`. Callers that need the real remote
/// code as their own exit status should use [`stream_shell_v2_exit`].
pub fn stream_shell_v2(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let (captured, exit_code) = stream_shell_v2_exit(transport, local_id, remote_id, capture)?;
    if let Some(code) = exit_code {
        if code != 0 {
            return Err(format!("remote shell exited with code {code}").into());
        }
    }
    Ok(captured)
}

/// Stream shell output via ADB server forwarding mode.
///
/// After `send_host_request("shell,v2,raw:...")` + `read_status()` OKAY,
/// the server returns the shell output as a raw byte stream (no ADB
/// WRTE framing), followed by a CLSE or connection close.
///
/// The stream is still ShellV2-framed, so it is reassembled across reads and
/// demultiplexed into stdout/stderr; the remote exit code is returned so the
/// caller can relay it.
pub fn stream_shell_v2_server(
    transport: &mut dyn Transport,
    capture: bool,
) -> Result<(Option<Vec<u8>>, Option<u8>), Box<dyn std::error::Error>> {

    let mut captured = if capture { Some(Vec::new()) } else { None };
    let mut exit_code = None;
    let mut buf = [0u8; 8192];
    let mut remainder = Vec::new();

    loop {
        let n = match transport.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset
                {
                    break;
                }
                return Err(e.into());
            }
        };

        remainder.extend_from_slice(&buf[..n]);
        drain_shell_v2_stream(&mut remainder, &mut captured, &mut exit_code)?;
    }

    Ok((captured, exit_code))
}

/// Open shell connection and stream output to stdout.
pub fn run_shell(
    transport: &mut dyn Transport,
    cmd: &str,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, remote_id) = open_service(transport, &dest, 1)?;
    stream_shell_v2(transport, local_id, remote_id, capture)
}

/// Connect to adbd, handshake, run shell, return captured output.
#[allow(dead_code)]
pub fn shell_over_adbd(cmd: &str, addr: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use adb_protocol::TcpTransport;

    let transport = TcpTransport::connect_timeout(addr, Duration::from_secs(3))
        .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::features=shell_v2,cmd", default_auth())?;
    let captured = run_shell(&mut transport, cmd, true)?;
    Ok(captured.unwrap_or_default())
}
