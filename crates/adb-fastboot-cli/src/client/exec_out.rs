//! ADB exec-out client: raw stdout streaming from the `exec:` service.
//!
//! Unlike `shell,v2,raw:` which wraps output in ShellV2 packets with
//! stderr and exit code, the `exec:` service provides pure Unix stdout
//! bytes directly in WRTE payloads with no framing.

use std::io::Write;

use adb_protocol::{AdbMessageHeader, Transport, TransportError, A_CLSE, A_OKAY, A_WRTE};

use super::protocol::open_service;

/// Stream raw exec: service output to stdout.
///
/// Unlike `shell,v2,raw:` which uses ShellV2 framing, the `exec:` service
/// provides raw Unix stdout bytes directly in WRTE payloads with no framing.
/// There is no stderr or exit code — just pure process stdout piped through
/// as raw WRTE payloads until A_CLSE.
pub fn stream_exec_out_raw(
    transport: &mut dyn Transport,
    local_id: u32,
    mut remote_id: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Err(e) => {
                eprintln!("Error: Stream error: {e}");
                std::process::exit(1);
            }
        };

        match hdr.command {
            A_OKAY => {
                remote_id = hdr.arg0;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Raw bytes — write directly to stdout without ShellV2 parsing
                std::io::stdout().write_all(&payload)?;
                std::io::stdout().flush()?;
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Open exec: service and stream raw output to stdout.
pub fn run_exec_out(
    transport: &mut dyn Transport,
    cmd: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest = format!("exec:{cmd}");
    let (local_id, remote_id) = open_service(transport, &dest, 1)?;
    stream_exec_out_raw(transport, local_id, remote_id)
}

/// Open an already-built exec: service string and stream raw output to
/// stdout. Use after `adb_protocol::exec_service_string()` escaping.
pub fn run_exec_out_service(
    transport: &mut dyn Transport,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (local_id, remote_id) = open_service(transport, service, 1)?;
    stream_exec_out_raw(transport, local_id, remote_id)
}

/// Open an already-built exec: service string, feed local stdin to the
/// remote process's raw stdin, and stream its raw stdout back (AOSP
/// `adb exec-in` semantics — commandline.cpp:1802).
pub fn run_exec_in(
    transport: &mut dyn Transport,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (local_id, remote_id) = open_service(transport, service, 1)?;

    // Thread 1: stdin → remote (A_WRTE + A_OKAY flow per chunk).
    let stdin_reader = {
        // Read local stdin on a separate thread so the WRTE/OKAY handshake
        // with the device can proceed independently of stdout streaming.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        rx
    };

    // Main loop: interleave stdin chunks (when available) with device output.
    // A_WRTE must be acked with A_OKAY (arg0 = sender's local_id) before the
    // peer sends more data; each stdin chunk is one A_WRTE.
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        };

        match hdr.command {
            A_OKAY => {
                // Ready for more input: forward one stdin chunk if we have one.
                if let Ok(chunk) = stdin_reader.try_recv() {
                    let wrte = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &chunk);
                    transport.send_message(&wrte, &chunk)?;
                }
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                std::io::stdout().write_all(&payload)?;
                std::io::stdout().flush()?;
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Stream raw bytes from ADB server forwarding mode to stdout.
///
/// After `send_host_request("exec:<cmd>")` + `read_status()` OKAY,
/// the server enters raw forwarding mode, passing WRTE payloads as
/// raw bytes (no ADB WRTE framing). Unlike shell v2, `exec:` does
/// NOT wrap output in ShellV2 packets — it's pure Unix stdout.
pub fn stream_raw_server(
    transport: &mut dyn Transport,
    _capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {

    let mut buf = [0u8; 8192];

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

        std::io::stdout().write_all(&buf[..n])?;
        std::io::stdout().flush()?;
    }

    Ok(None)
}

/// exec-in over ADB-server forwarding mode: feed local stdin to the
/// bridged remote stdin while relaying raw device output to stdout.
pub fn stream_raw_from_server(
    transport: &mut dyn Transport,
) -> Result<(), Box<dyn std::error::Error>> {
    // After the server's OKAY the TCP stream is a raw byte pipe in both
    // directions — same forwarding mode as exec-out, plus our stdin.
    let mut out_buf = [0u8; 8192];

    // Stdin reader thread (owned channel, no shared transport access).
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    loop {
        // Drain whatever the device sent so far.
        match transport.read(&mut out_buf) {
            Ok(0) => break,
            Ok(n) => {
                std::io::stdout().write_all(&out_buf[..n])?;
                std::io::stdout().flush()?;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Nothing to read right now — try to forward one stdin chunk.
                match rx.try_recv() {
                    Ok(chunk) => transport.write_all(&chunk)?,
                    Err(std::sync::mpsc::TryRecvError::Empty) => continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset
                {
                    break;
                }
                return Err(e.into());
            }
        }
    }
    Ok(())
}
