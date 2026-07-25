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
