//! ADB shell client: ShellV2 streaming, raw shell execution, and direct adbd shell.
//!
//! Maps to AOSP `vendor/adb/client/` shell command handling.
//! These functions operate over a raw `Transport` (direct USB/TCP to adbd)
//! or through the ADB server forwarding mode.

use std::io::{Read, Write};
use std::time::Duration;

use adb_protocol::{
    AdbMessageHeader, ShellV2Packet, Transport, TransportError,
    A_CLSE, A_OKAY, A_WRTE,
};

use super::protocol::open_service;
use super::auth::default_auth;
#[allow(unused_imports)]
use super::transport::connect_and_handshake_with_tls_upgrade;

/// Stream shell output (Shell v2 packets) to stdout/stderr until exit or CLSE.
pub fn stream_shell_v2(
    transport: &mut dyn Transport,
    local_id: u32,
    mut _remote_id: u32,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut captured = if capture { Some(Vec::new()) } else { None };
    let mut exit_code = None;
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break
            }
            Err(e) => {
                eprintln!("Error: Stream error: {}", e);
                std::process::exit(1);
            }
        };

        match hdr.command {
            A_OKAY => {
                _remote_id = hdr.arg0;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                let mut rest = payload.as_slice();
                while !rest.is_empty() {
                    match ShellV2Packet::parse(rest) {
                        Ok((pkt, consumed)) => {
                            match pkt {
                                ShellV2Packet::Stdout(data) => {
                                    if let Some(ref mut buf) = captured {
                                        buf.extend_from_slice(data);
                                    }
                                    std::io::stdout().write_all(data)?;
                                    std::io::stdout().flush()?;
                                }
                                ShellV2Packet::Stderr(data) => {
                                    if let Some(ref mut buf) = captured {
                                        buf.extend_from_slice(data);
                                    }
                                    std::io::stderr().write_all(data)?;
                                    std::io::stderr().flush()?;
                                }
                                ShellV2Packet::ExitCode(code) => {
                                    exit_code = Some(code);
                                }
                                _ => {}
                            }
                            rest = &rest[consumed..];
                        }
                        Err(_) => {
                            // Raw bytes (non-shell v2 format)
                            if let Some(ref mut buf) = captured {
                                buf.extend_from_slice(rest);
                            }
                            std::io::stdout().write_all(rest)?;
                            std::io::stdout().flush()?;
                            break;
                        }
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                if let Some(code) = exit_code {
                    if code != 0 {
                        return Err(format!("remote shell exited with code {code}").into());
                    }
                    std::thread::sleep(Duration::from_millis(500));
                    return Ok(captured);
                }
                break;
            }
            _ => {}
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
/// The server sends the full ShellV2 packet stream as raw bytes;
/// we parse and strip the ShellV2 framing to produce clean stdout.
pub fn stream_shell_v2_server(
    transport: &mut dyn Transport,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {

    let mut captured = if capture { Some(Vec::new()) } else { None };
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

        // Parse ShellV2 packets from the accumulated buffer
        while !remainder.is_empty() {
            match ShellV2Packet::parse(&remainder) {
                Ok((pkt, consumed)) => {
                    match pkt {
                        ShellV2Packet::Stdout(data) | ShellV2Packet::Stderr(data) => {
                            if let Some(ref mut buf) = captured {
                                buf.extend_from_slice(data);
                            }
                            std::io::stdout().write_all(data)?;
                            std::io::stdout().flush()?;
                        }
                        ShellV2Packet::ExitCode(_) => {
                            // Don't print exit codes to stdout
                        }
                        _ => {}
                    }
                    remainder.drain(..consumed);
                }
                Err(_) => {
                    // Incomplete packet — wait for more data
                    break;
                }
            }
        }
    }

    Ok(captured)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StdinEscape {
    StartOfLine,
    MidFlow,
    InEscape,
}

fn stdin_state_after(ch: u8) -> StdinEscape {
    if ch == b'\n' || ch == b'\r' {
        StdinEscape::StartOfLine
    } else {
        StdinEscape::MidFlow
    }
}

/// AOSP `stdin_read_thread_loop` escape handling (commandline.cpp:545-585).
/// Returns the next state, the bytes to forward, and whether `~.` was seen.
fn escape_stdin_byte(state: StdinEscape, ch: u8) -> (StdinEscape, Vec<u8>, bool) {
    match (state, ch) {
        (StdinEscape::InEscape, b'.') => (StdinEscape::StartOfLine, Vec::new(), true),
        (StdinEscape::InEscape, b'~') => (StdinEscape::MidFlow, vec![b'~'], false),
        (StdinEscape::InEscape, _) => {
            // Swallowed escape char was not part of a valid sequence: emit both.
            (stdin_state_after(ch), vec![b'~', ch], false)
        }
        (StdinEscape::StartOfLine, b'~') => (StdinEscape::InEscape, Vec::new(), false),
        (_, b'~') => (StdinEscape::MidFlow, vec![b'~'], false),
        _ => (stdin_state_after(ch), vec![ch], false),
    }
}

/// Stream ShellV2 output through ADB server forwarding mode while forwarding
/// local stdin as ShellV2 `Stdin` packets.
///
/// Only safe in server forwarding mode: there the connection is a raw byte
/// stream (no ADB WRTE/A_OKAY on this socket), so a dup'd write side cannot
/// steal the single reader's frames. Direct USB/TCP keeps the output-only path.
pub fn stream_shell_v2_server_with_stdin(
    transport: &mut dyn Transport,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if let Some(mut writer) = transport.try_clone_box() {
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let mut state = StdinEscape::StartOfLine;
            let mut byte = [0u8; 1];
            loop {
                match stdin.read(&mut byte) {
                    Ok(0) => {
                        let mut packet = Vec::new();
                        ShellV2Packet::CloseStdin.encode(&mut packet);
                        let _ = writer.write_all(&packet);
                        let _ = writer.flush();
                        break;
                    }
                    Ok(_) => {
                        let (next, out, disconnect) = escape_stdin_byte(state, byte[0]);
                        state = next;
                        if disconnect {
                            eprintln!("\r\n[ disconnected ]\r\n");
                            std::process::exit(0);
                        }
                        if out.is_empty() {
                            continue;
                        }
                        let mut packet = Vec::new();
                        ShellV2Packet::Stdin(&out).encode(&mut packet);
                        if writer.write_all(&packet).is_err() || writer.flush().is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
    }
    stream_shell_v2_server(transport, capture)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> (Vec<u8>, bool) {
        let mut state = StdinEscape::StartOfLine;
        let mut out = Vec::new();
        let mut disconnected = false;
        for &byte in bytes {
            let (next, emitted, disc) = escape_stdin_byte(state, byte);
            state = next;
            disconnected |= disc;
            out.extend_from_slice(&emitted);
        }
        (out, disconnected)
    }

    #[test]
    fn plain_stdin_is_forwarded_byte_for_byte() {
        let (out, disconnected) = run(b"hello\nworld");
        assert_eq!(out, b"hello\nworld");
        assert!(!disconnected);
    }

    #[test]
    fn tilde_dot_disconnects_without_forwarding() {
        let (out, disconnected) = run(b"~.");
        assert!(disconnected);
        assert!(out.is_empty());
    }

    #[test]
    fn doubled_tilde_emits_one_literal_tilde() {
        let (out, disconnected) = run(b"~~");
        assert_eq!(out, b"~");
        assert!(!disconnected);
    }

    #[test]
    fn invalid_escape_emits_tilde_and_the_byte() {
        let (out, disconnected) = run(b"~x");
        assert_eq!(out, b"~x");
        assert!(!disconnected);
    }

    #[test]
    fn escape_only_applies_at_start_of_line() {
        // A tilde mid-line is a normal character; only the leading one is eaten.
        let (out, _) = run(b"a~.");
        assert_eq!(out, b"a~.");
    }
}
