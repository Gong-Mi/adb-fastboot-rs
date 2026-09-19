use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbAuth, AdbMessageHeader, AdbServerTransport, AuthType, ShellV2Packet, TcpTransport,
    Transport, TransportError,
    A_AUTH, ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_STLS, A_WRTE, MAX_PAYLOAD_V2,
    build_sync_data_chunk, build_sync_done, build_sync_recv_req, build_sync_send_req,
    host_cnxn_payload, saturating_mtime_u32, SYNC_FAIL, SYNC_OKAY,
};

mod server;

const ADBD_PORT: u16 = 5555;
const ADB_SERVER_PORT: u16 = 5037;

#[derive(Parser)]
#[command(name = "adb-rs", author, version, about = "Rust ADB Command-Line Interface")]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub serial: Option<String>,

    /// Direct connection to USB device
    #[arg(short = 'd', global = true)]
    pub d: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List connected devices
    Devices,
    /// Run remote shell command
    Shell {
        command: Vec<String>,
    },
    /// Run remote command with raw stdout stream (no PTY / shell-v2 framing;
    /// binary output stays byte-exact, like AOSP `adb exec-out`)
    ExecOut {
        command: Vec<String>,
    },
    /// Run remote command feeding local stdin to its raw stdin
    /// (AOSP `adb exec-in`)
    ExecIn {
        command: Vec<String>,
    },
    /// Push local file to device
    Push {
        local: String,
        remote: String,
    },
    /// Pull remote file from device
    Pull {
        remote: String,
        local: String,
    },
    /// Reboot device (bootloader, recovery, etc.)
    Reboot {
        target: Option<String>,
    },
    /// Forward socket connections (uses ADB server on port 5037)
    Forward {
        #[arg(long)]
        list: bool,
        #[arg(long)]
        remove: Option<String>,
        #[arg(long)]
        remove_all: bool,
        #[arg(long)]
        no_rebind: bool,
        local: Option<String>,
        remote: Option<String>,
    },
    /// Reverse socket connections (uses ADB server on port 5037)
    Reverse {
        #[arg(long)]
        list: bool,
        #[arg(long)]
        remove: Option<String>,
        #[arg(long)]
        remove_all: bool,
        #[arg(long)]
        no_rebind: bool,
        remote: Option<String>,
        local: Option<String>,
    },
    /// Push a single APK to device and install it
    Install {
        apk: String,
    },
    /// Uninstall a package from device
    Uninstall {
        package: String,
    },
    /// Show log output from device
    Logcat {
        args: Vec<String>,
    },
    /// Generate a bugreport and save to file
    Bugreport {
        output: Option<String>,
    },
    /// List JDWP PIDs (uses ADB server on port 5037)
    Jdwp,
    /// Start the ADB server (listens on 127.0.0.1:5037)
    Serve,
    /// Start the ADB server daemon
    #[command(name = "start-server")]
    StartServer,
    /// Kill the running ADB server daemon
    #[command(name = "kill-server")]
    KillServer,
    /// Pair with wireless device using 6-digit code
    Pair {
        /// Target device address (host:port)
        addr: String,
        /// 6-digit pairing code (prompted if omitted)
        code: Option<String>,
    },
}

fn resolve_target_addr(serial: Option<&str>, default_port: u16) -> String {
    match serial {
        Some(s) if s.contains(':') => s.to_string(),
        Some(s) => format!("{}:{}", s, default_port),
        None => format!("127.0.0.1:{}", default_port),
    }
}

/// Resolve transport for ADB commands based on CLI parameters (`serial`, `-d`) and device availability.
///
/// Dynamic resolution & fallback logic:
/// 1. If `serial` contains `:` or is explicitly a TCP socket address, use `TcpTransport`.
/// 2. If `use_usb` (-d) is true:
///    - If `cfg(feature = "usb")`, open USB device (by `serial` if provided, else first device) via `UsbfsAdbDevice` and wrap in `UsbTransportAdapter`.
///    - If `cfg(not(feature = "usb"))`, return error indicating USB support is not built in.
/// 3. If `use_usb` is false and target is not explicitly TCP:
///    - If `cfg(feature = "usb")`, attempt to open USB device.
///    - If USB open succeeds, return USB transport adapter.
///    - If USB open fails or no USB device is present, fall back to `TcpTransport` at `resolve_target_addr(serial, ADBD_PORT)`.
pub fn open_adb_transport(
    serial: Option<&str>,
    use_usb: bool,
    timeout: Duration,
) -> Result<Box<dyn Transport>, Box<dyn std::error::Error>> {
    let is_tcp_spec = serial.map_or(false, |s| s.contains(':'));
    let addr = resolve_target_addr(serial, ADBD_PORT);

    if is_tcp_spec {
        let t = TcpTransport::connect_timeout(&addr, timeout)?;
        return Ok(Box::new(t));
    }

    if use_usb {
        #[cfg(feature = "usb")]
        {
            let dev = if let Some(s) = serial {
                adb_protocol::UsbfsAdbDevice::open_by_serial(s)
            } else {
                adb_protocol::UsbfsAdbDevice::open_first()
            }
            .map_err(|e| format!("Failed to open ADB USB device: {e}"))?;
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }
        #[cfg(not(feature = "usb"))]
        {
            return Err("USB support is not enabled; rebuild with `--features usb`".into());
        }
    }

    #[cfg(feature = "usb")]
    {
        let usb_res = if let Some(s) = serial {
            adb_protocol::UsbfsAdbDevice::open_by_serial(s)
        } else {
            adb_protocol::UsbfsAdbDevice::open_first()
        };
        if let Ok(dev) = usb_res {
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }
    }

    let t = TcpTransport::connect_timeout(&addr, timeout)?;
    Ok(Box::new(t))
}

/// Information about the device received in the CNXN response banner.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub banner: String,
}

/// Get or create the persistent ADB auth key (singleton).
/// AOSP semantics: `$HOME/.android/adbkey`, generated on first use and
/// reused afterwards (adb_auth_init/load_userkey). Falls back to an
/// ephemeral key only if the persistent store cannot be created/read.
fn default_auth() -> &'static AdbAuth {
    static AUTH: OnceLock<AdbAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        AdbAuth::load_persistent()
            .unwrap_or_else(|_| AdbAuth::generate("adb-rs@localhost").expect("Failed to generate ADB auth key"))
    })
}

/// Connect to adbd, perform CNXN handshake with RSA AUTH and A_STLS TLS upgrade support.
///
/// AOSP client semantics (adb.cpp handle_packet → A_AUTH/TOKEN, auth.cpp
/// send_auth_response): answer each A_AUTH TOKEN with a SIGNATURE from the
/// next key; when keys are exhausted send RSAPUBLICKEY once and wait. After
/// successful auth (or no-auth), the device answers CNXN. If the device
/// responds A_STLS, the transport is upgraded to TLS and CNXN is resent.
#[cfg(feature = "tls")]
fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    use adb_protocol::tls;
    use adb_protocol::AdbTlsTransport;

    let mut transport: Box<dyn Transport> = Box::new(transport);

    // AOSP adb_auth_init() key order: user key first, then ADB_VENDOR_KEYS.
    // The caller-supplied auth IS the user key (default_auth loads the
    // persistent identity); vendor keys are appended for rotation.
    let mut responder = adb_protocol::AuthResponder::from_key_list({
        let mut keys = vec![auth.clone()];
        keys.extend(adb_protocol::auth::load_vendor_keys_only());
        keys
    });

    // Send initial CNXN
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    loop {
        // Read response
        let (resp_hdr, payload) = transport.recv_message()?;

        match resp_hdr.command {
            A_CNXN => {
                // Normal path — no TLS required
                let banner = String::from_utf8_lossy(&payload).to_string();
                return Ok((DeviceInfo { banner }, transport));
            }
            A_AUTH if resp_hdr.auth_type() == Some(AuthType::Token) => {
                // Device demands RSA auth: respond with SIGNATURE (or
                // RSAPUBLICKEY after key exhaustion) and wait for CNXN.
                if let Some((hdr, payload)) = responder.respond_to_token(&payload)? {
                    transport.send_message(&hdr, &payload)?;
                }
                continue;
            }
            A_STLS => {
                // TLS upgrade path
                let rsa_pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())
                    .map_err(|e| format!("Failed to export RSA key: {e}"))?;
                let (cert_der, key_der) = tls::generate_self_signed_cert(&rsa_pem)
                    .map_err(|e| format!("Failed to generate self-signed cert: {e}"))?;
                let config = tls::create_tls_config(cert_der, key_der)
                    .map_err(|e| format!("Failed to create TLS config: {e}"))?;

                let tls_transport = AdbTlsTransport::new(transport, config, "adb")
                    .map_err(|e| format!("TLS upgrade failed: {e}"))?;

                // Re-send CNXN over TLS
                let cnxn_hdr =
                    AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
                let mut tls_box: Box<dyn Transport> = Box::new(tls_transport);
                tls_box.send_message(&cnxn_hdr, cnxn_payload)?;

                let (resp_hdr2, payload2) = tls_box.recv_message()?;
                if resp_hdr2.command != A_CNXN {
                    return Err(format!(
                        "Unexpected handshake response after TLS upgrade: cmd={:#x}",
                        resp_hdr2.command
                    )
                    .into());
                }

                let banner = String::from_utf8_lossy(&payload2).to_string();
                return Ok((DeviceInfo { banner }, tls_box));
            }
            other => {
                return Err(format!(
                    "Unexpected handshake response: cmd={:#x}",
                    other
                )
                .into());
            }
        }
    }
}

/// Non-TLS fallback — A_STLS will return an error if the device requires TLS.
/// RSA AUTH still works without the TLS feature.
#[cfg(not(feature = "tls"))]
fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let mut transport: Box<dyn Transport> = Box::new(transport);
    let mut responder = adb_protocol::AuthResponder::single(auth.clone());
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    loop {
        let (resp_hdr, payload) = transport.recv_message()?;
        if resp_hdr.command == A_STLS {
            return Err("Device requires TLS (A_STLS) but the `tls` feature is not enabled. \
                        Rebuild with --features tls"
                .into());
        }
        if resp_hdr.command == A_AUTH && resp_hdr.auth_type() == Some(AuthType::Token) {
            if let Some((hdr, payload)) = responder.respond_to_token(&payload)? {
                transport.send_message(&hdr, &payload)?;
            }
            continue;
        }
        if resp_hdr.command != A_CNXN {
            return Err(format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into());
        }

        let banner = String::from_utf8_lossy(&payload).to_string();
        return Ok((DeviceInfo { banner }, transport));
    }
}

/// Open an adbd service (shell:, sync:, reboot:, etc.) via A_OPEN.
/// Returns (local_id, remote_id) after A_OKAY.
fn open_service(
    transport: &mut dyn Transport,
    dest: &str,
    local_id: u32,
) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, dest.as_bytes());
    transport.send_message(&open_hdr, dest.as_bytes())?;

    // Read until we get A_OKAY with our local_id
    loop {
        let (hdr, _) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {
                return Ok((local_id, hdr.arg0));
            }
            A_CLSE => {
                return Err(format!("Service '{}' closed immediately", dest).into());
            }
            _ => {
                // Keep reading
            }
        }
    }
}

/// Send a WRTE frame and wait for OKAY ack
fn send_wrte(transport: &mut dyn Transport, local_id: u32, remote_id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, local_id, remote_id, payload);
    transport.send_message(&wrte_hdr, payload)?;
    // Wait for OKAY ack
    loop {
        let (hdr, _) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => return Ok(()),
            A_WRTE => {
                // Device sent data; ack it
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                // Don't consume it, let caller handle — but for sync we don't expect this
            }
            A_CLSE => return Err("Connection closed by peer".into()),
            _ => {}
        }
    }
}

/// Read WRTE frames until CLSE or EOF. Returns collected payload bytes.
#[allow(dead_code)]
fn recv_wrte_all(transport: &mut dyn Transport, local_id: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut collected = Vec::new();
    loop {
        let (hdr, payload) = transport.recv_message()?;
        match hdr.command {
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                collected.extend_from_slice(&payload);
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            A_OKAY => {}
            _ => break,
        }
    }
    Ok(collected)
}

/// Stream shell output (Shell v2 packets) to stdout/stderr until exit or CLSE.
fn stream_shell_v2(
    transport: &mut dyn Transport,
    local_id: u32,
    mut remote_id: u32,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut captured = if capture { Some(Vec::new()) } else { None };
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                eprintln!("Error: Stream error: {}", e);
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
                                    if code != 0 {
                                        std::process::exit(code as i32);
                                    }
                                    return Ok(captured);
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
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }
    Ok(captured)
}

/// Stream a raw (non-shell-v2) service until EOF/CLSE, writing bytes to a
/// sink, mirroring AOSP `copy_to_file` for `exec:` streams
/// (client/commandline.cpp:1802-1827; daemon side `StartSubprocess(...,
/// kRaw, kNone)` at services.cpp:360-363 — payload is the program's raw
/// stdout, no framing, so binary output stays byte-exact).
///
/// Each WRTE is ACKed immediately (AOSP `local_socket_ready` per-frame
/// semantics). Returns the total bytes written.
fn stream_raw_to<W: std::io::Write>(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    sink: &mut W,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut remote_id = remote_id;
    let mut total = 0usize;
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(TransportError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("stream error: {e}").into()),
        };
        match hdr.command {
            A_OKAY => {
                remote_id = hdr.arg0;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                transport.send_message(&ack, &[])?;
                sink.write_all(&payload)?;
                total += payload.len();
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            _ => {}
        }
    }
    sink.flush()?;
    Ok(total)
}

/// Feed stdin to the service until EOF, mirroring AOSP `exec-in`'s
/// `copy_to_file(STDIN_FILENO, fd)`: each chunk is a WRTE awaiting an
/// OKAY ack (flow control), then a final A_CLSE signals EOF to the device.
/// Reading stops at a 0-length read (real EOF) — never on WouldBlock, which
/// would truncate piped data that has not arrived yet.
fn stream_raw_from<R: std::io::Read>(
    transport: &mut dyn Transport,
    local_id: u32,
    remote_id: u32,
    source: &mut R,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; MAX_PAYLOAD_V2 as usize];
    loop {
        let n = match source.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("stdin read error: {e}").into()),
        };
        let wrte = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &buf[..n]);
        transport.send_message(&wrte, &buf[..n])?;
        // wait for the OKAY before the next chunk (AOSP local_socket_ready);
        // the reply's arg0 is the *peer's* id, so match on any OKAY like the
        // existing send_wrte does, not on our local_id.
        loop {
            let (hdr, _) = transport.recv_message()?;
            match hdr.command {
                A_OKAY => break,
                A_CLSE => return Ok(()),
                _ => {}
            }
        }
    }
    let clse = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
    let _ = transport.send_message(&clse, &[]);
    Ok(())
}

/// Open shell connection and stream output to stdout.
fn run_shell(
    transport: &mut dyn Transport,
    banner: &str,
    cmd: &str,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let dest = shell_service_string(banner, cmd)?;
    let (local_id, remote_id) = open_service(transport, &dest, 1)?;
    stream_shell_v2(transport, local_id, remote_id, capture)
}

/// Build the shell service string gated on the device's advertised feature
/// set, mirroring AOSP `CanUseFeature(*features, kFeatureShell2)`
/// (commandline.cpp:704, 1138). This client only speaks shell v2; when the
/// device banner lacks `shell_v2` we must not silently open `shell,v2,raw:`
/// (adbd would just CLSE it) — fail with an actionable message instead.
/// (V1 shell fallback is a tracked gap.)
fn shell_service_string(banner: &str, cmd: &str) -> Result<String, String> {
    let feats = adb_protocol::features::parse_banner_features(banner);
    if !adb_protocol::features::can_use_feature(&feats, "shell_v2") {
        return Err(format!(
            "device does not advertise shell_v2 (banner: {banner}); shell V1 fallback is not implemented"
        ));
    }
    Ok(format!("shell,v2,raw:{cmd}"))
}

// ---------------------------------------------------------------------------
// SYNC file transfer (AOSP client/file_sync_client.cpp parity, V1 protocol)
// ---------------------------------------------------------------------------

use adb_protocol::constants::{SYNC_DATA, SYNC_DONE, SYNC_QUIT};
use byteorder::{ByteOrder as _, LittleEndian};

/// Stream sync-protocol messages over an already-opened `sync:` service.
/// Handles the WRTE/OKAY flow internally (each WRTE is ACKed immediately,
/// AOSP `local_socket_ready_notify` semantics).
pub struct SyncStream<'a> {
    transport: &'a mut dyn Transport,
    local_id: u32,
    remote_id: u32,
}

impl<'a> SyncStream<'a> {
    pub fn new(transport: &'a mut dyn Transport, local_id: u32, remote_id: u32) -> Self {
        Self {
            transport,
            local_id,
            remote_id,
        }
    }

    /// Send one SYNC message (8-byte id/length header + optional payload)
    /// as a single A_WRTE and wait for its A_OKAY ack.
    pub fn send_msg(&mut self, id: u32, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        let mut hdr = [0u8; 8];
        LittleEndian::write_u32(&mut hdr[0..4], id);
        LittleEndian::write_u32(&mut hdr[4..8], payload.len() as u32);
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(payload);
        send_wrte(self.transport, self.local_id, self.remote_id, &buf)?;
        Ok(())
    }

    /// Read exactly one SYNC message. A_OKAY acks for our own WRTEs are
    /// consumed transparently; foreign WRTEs are ACKed and parsed.
    pub fn recv_msg(&mut self) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
        loop {
            let (hdr, payload) = self.transport.recv_message()?;
            match hdr.command {
                A_OKAY => continue,
                A_WRTE => {
                    let ack = AdbMessageHeader::new(A_OKAY, self.local_id, hdr.arg0, &[]);
                    self.transport.send_message(&ack, &[])?;
                    if payload.len() < 8 {
                        return Err("SYNC message shorter than 8-byte header".into());
                    }
                    let id = LittleEndian::read_u32(&payload[0..4]);
                    let len = LittleEndian::read_u32(&payload[4..8]) as usize;
                    if len > payload.len() - 8 {
                        return Err(format!(
                            "SYNC {:#x} truncated: want {} bytes, got {}",
                            id,
                            len,
                            payload.len() - 8
                        )
                        .into());
                    }
                    return Ok((id, payload[8..8 + len].to_vec()));
                }
                A_CLSE => {
                    let ack = AdbMessageHeader::new(A_CLSE, self.local_id, hdr.arg0, &[]);
                    let _ = self.transport.send_message(&ack, &[]);
                    return Err("SYNC connection closed by device".into());
                }
                _ => continue,
            }
        }
    }

    /// Push one local file to the device (AOSP V1: SEND path,mode → DATA* →
    /// DONE mtime → read exactly one terminal OKAY/FAIL). Returns bytes sent.
    pub fn push_file(
        &mut self,
        local: &Path,
        remote: &str,
        mode: u32,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        use std::io::Read;

        let meta = std::fs::symlink_metadata(local)
            .map_err(|e| format!("cannot stat '{}': {e}", local.display()))?;

        let mut payload = Vec::new();
        build_sync_send_req(remote, mode, &mut payload)
            .map_err(|e| format!("build SEND req: {e}"))?;
        self.send_msg_from(&payload)?;

        let total = meta.len();
        if meta.is_symlink() {
            #[cfg(unix)]
            {
                let target = std::fs::read_link(local)?;
                let t = target.to_string_lossy().into_owned();
                let mut buf = Vec::new();
                build_sync_data_chunk(t.as_bytes(), &mut buf)?;
                self.send_msg_from(&buf)?;
            }
        } else {
            let mut f = std::fs::File::open(local)
                .map_err(|e| format!("cannot open '{}': {e}", local.display()))?;
            let mut chunk = vec![0u8; adb_protocol::constants::SYNC_DATA_MAX];
            loop {
                let n = f.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                let mut buf = Vec::with_capacity(8 + n);
                build_sync_data_chunk(&chunk[..n], &mut buf)?;
                self.send_msg_from(&buf)?;
            }
        }

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| saturating_mtime_u32(d.as_secs() as i64))
            .unwrap_or(0xFFFF_FFFF);
        let mut buf = Vec::new();
        build_sync_done(mtime, &mut buf)?;
        self.send_msg_from(&buf)?;

        let (id, msg) = self.recv_msg()?;
        match id {
            SYNC_OKAY => {}
            SYNC_FAIL => {
                return Err(format!(
                    "device rejected push of {remote}: {}",
                    String::from_utf8_lossy(&msg)
                )
                .into());
            }
            other => return Err(format!("unexpected SYNC reply after DONE: {other:#x}").into()),
        }
        let _ = total;
        Ok(total)
    }

    /// Internal: send a pre-built SYNC byte buffer (8-byte header + payload
    /// already serialized) as one WRTE, acked.
    fn send_msg_from(&mut self, buf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        send_wrte(self.transport, self.local_id, self.remote_id, buf)?;
        Ok(())
    }

    /// Push an in-memory buffer to the device (used by `install`). Wire
    /// order identical to `push_file`: SEND → DATA* → DONE → one OKAY/FAIL.
    pub fn push_bytes(
        &mut self,
        remote: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        build_sync_send_req(remote, mode, &mut buf)?;
        self.send_msg_from(&buf)?;

        const MAX_CHUNK: usize = 64 * 1024;
        for chunk in data.chunks(MAX_CHUNK) {
            let mut buf = Vec::with_capacity(8 + chunk.len());
            build_sync_data_chunk(chunk, &mut buf)?;
            self.send_msg_from(&buf)?;
        }

        let mut buf = Vec::new();
        build_sync_done(0xFFFF_FFFF, &mut buf)?;
        self.send_msg_from(&buf)?;

        let (id, msg) = self.recv_msg()?;
        match id {
            SYNC_OKAY => Ok(()),
            SYNC_FAIL => Err(format!(
                "device rejected push of {remote}: {}",
                String::from_utf8_lossy(&msg)
            )
            .into()),
            other => Err(format!("unexpected SYNC reply after DONE: {other:#x}").into()),
        }
    }

    /// Pull one remote file to a local path (AOSP V1 sync_recv_v1: send
    /// RECV path → read DATA* until DONE, writing through; FAIL aborts).
    pub fn pull_file(
        &mut self,
        remote: &str,
        local: &Path,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        use std::io::Write;

        let mut payload = Vec::new();
        build_sync_recv_req(remote, &mut payload)?;
        self.send_msg_from(&payload)?;

        // AOSP unlinks any existing target first.
        let _ = std::fs::remove_file(local);
        let mut out = std::fs::File::create(local)
            .map_err(|e| format!("cannot create '{}': {e}", local.display()))?;

        let mut copied: u64 = 0;
        loop {
            let (id, data) = self.recv_msg()?;
            match id {
                SYNC_DATA => {
                    out.write_all(&data)?;
                    copied += data.len() as u64;
                }
                // V1 DONE carries mtime in the length field; recv_msg returns
                // it as an empty payload. AOSP pull applies it only with -a
                // (copy_attrs); not implemented yet, so we ignore it.
                SYNC_DONE => break,
                SYNC_FAIL => {
                    let _ = std::fs::remove_file(local);
                    return Err(format!(
                        "pull {remote} failed: {}",
                        String::from_utf8_lossy(&data)
                    )
                    .into());
                }
                SYNC_OKAY => {
                    // Legacy AOSP quirk: pre-DONE OKAY must not terminate.
                    return Err(format!("unexpected SYNC OKAY during recv of {remote}").into());
                }
                other => {
                    let _ = std::fs::remove_file(local);
                    return Err(format!("unexpected SYNC id {other:#x} during recv").into());
                }
            }
        };
        out.flush()?;
        Ok(copied)
    }

    /// Close the sync stream politely (AOSP ~SyncConnection: QUIT, drain
    /// until the device answers, then CLSE both ways).
    pub fn quit(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        let mut hdr = [0u8; 8];
        LittleEndian::write_u32(&mut hdr[0..4], SYNC_QUIT);
        LittleEndian::write_u32(&mut hdr[4..8], 0);
        buf.extend_from_slice(&hdr);
        // QUIT: no reply is expected (AOSP just closes); send best-effort.
        let wrte = AdbMessageHeader::new(A_WRTE, self.local_id, self.remote_id, &buf);
        let _ = self.transport.send_message(&wrte, &buf);
        let clse = AdbMessageHeader::new(A_CLSE, self.local_id, self.remote_id, &[]);
        let _ = self.transport.send_message(&clse, &[]);
        Ok(())
    }
}

/// Ensure ADB server daemon is running on 127.0.0.1:5037.
/// If not running, autostarts it by spawning `adb-rs serve` in the background.
pub fn ensure_server_running() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running_at(ADB_SERVER_PORT)
}

pub fn ensure_server_running_at(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpStream;
    use std::process::{Command, Stdio};

    let addr = format!("127.0.0.1:{port}");
    if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(200)).is_ok() {
        return Ok(());
    }

    eprintln!("* daemon not running; starting it now at tcp:{port} *");
    let exe = std::env::current_exe().unwrap_or_else(|_| "adb-rs".into());
    let mut child = Command::new(&exe)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn ADB server daemon: {e}"))?;

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(3);
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(100)).is_ok() {
            eprintln!("* daemon started successfully *");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if let Ok(Some(status)) = child.try_wait() {
        return Err(format!("ADB server daemon exited immediately with status: {status}").into());
    }

    Err(format!("Timeout waiting for ADB server daemon to start at {addr}").into())
}

/// Kill the running ADB server on 127.0.0.1:5037.
pub fn kill_server() -> Result<(), Box<dyn std::error::Error>> {
    kill_server_at(ADB_SERVER_PORT)
}

pub fn kill_server_at(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let mut transport = match AdbServerTransport::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(t) => t,
        Err(_) => {
            // Server not running
            return Ok(());
        }
    };

    transport.send_host_request("host:kill")?;
    transport.read_status()?;

    // Wait for process termination
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(3);
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(100)).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Ok(())
}

/// Connect to ADB server (port 5037), switch transport if needed, and execute a host command.
fn host_command(
    serial: Option<&str>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = resolve_target_addr(serial, ADB_SERVER_PORT);
    let mut server = match AdbServerTransport::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(s) => s,
        Err(_) => {
            ensure_server_running()?;
            AdbServerTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to ADB server at {addr}: {e}"))?
        }
    };

    if !request.starts_with("host:forward")
        && !request.starts_with("host:reverse")
        && !request.starts_with("host:devices")
    {
        server.switch_transport(serial)?;
    }

    // Execute the host command
    let result = server.execute_host_command(request)
        .map_err(|e| format!("ADB host command failed: {e}"))?;
    Ok(result)
}

/// Connect to adbd, handshake, run shell, return captured output.
#[allow(dead_code)]
fn shell_over_adbd(cmd: &str, addr: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let transport = TcpTransport::connect_timeout(addr, Duration::from_secs(3))
        .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
    let (info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), default_auth())?;
    let captured = run_shell(&mut transport, &info.banner, cmd, true)?;
    Ok(captured.unwrap_or_default())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = resolve_target_addr(cli.serial.as_deref(), ADBD_PORT);

    match &cli.command {
        Commands::Devices => {
            println!("List of devices attached (adb-rs pure rust transport)");
            match host_command(cli.serial.as_deref(), "host:devices-l") {
                Ok(resp) => {
                    if !resp.is_empty() {
                        print!("{resp}");
                    }
                }
                Err(e) => {
                    let direct_addr = resolve_target_addr(cli.serial.as_deref(), ADBD_PORT);
                    if let Ok(transport) = open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(2)) {
                        if let Ok((device_info, _)) = connect_and_handshake_with_tls_upgrade(
                            transport,
                            &host_cnxn_payload(),
                            default_auth(),
                        ) {
                            println!("{}\tdevice ({})", direct_addr, device_info.banner.trim());
                            return Ok(());
                        }
                    }
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Shell { command } => {
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let (info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            let cmd_str = command.join(" ");
            let dest = shell_service_string(&info.banner, &cmd_str)?;

            let (_lid, remote_id) = open_service(&mut transport, &dest, 1)?;
            stream_shell_v2(&mut transport, _lid, remote_id, false)?;
        }
        Commands::ExecOut { command } | Commands::ExecIn { command } => {
            let exec_in = matches!(cli.command, Commands::ExecIn { .. });
            if command.is_empty() {
                eprintln!("usage: adb-rs {} command [ARGS...]", if exec_in { "exec-in" } else { "exec-out" });
                std::process::exit(1);
            }
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            // AOSP exec-in/exec-out open the raw `exec:` service — no shell-v2
            // framing, no PTY, and no banner feature gate (commandline.cpp:1802).
            let dest = adb_protocol::exec_service_string(command);
            let (local_id, remote_id) = open_service(&mut transport, &dest, 1)?;
            if exec_in {
                let stdin = std::io::stdin();
                let mut lock = stdin.lock();
                stream_raw_from(&mut transport, local_id, remote_id, &mut lock)?;
            } else {
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                stream_raw_to(&mut transport, local_id, remote_id, &mut lock)?;
            }
        }
        Commands::Push { local, remote } => {
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), default_auth())?;

            let local_path = Path::new(local);
            let meta = std::fs::symlink_metadata(local_path)
                .map_err(|e| format!("cannot stat '{local}': {e}"))?;
            if meta.is_dir() {
                return Err("push of directories is not implemented (single files only)".into());
            }

            let (local_id, remote_id) = open_service(&mut transport, "sync:", 1)?;
            let mut sync = SyncStream::new(&mut transport, local_id, remote_id);
            // AOSP sends the local st_mode verbatim (file type bits included).
            let mode = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    meta.mode()
                }
                #[cfg(not(unix))]
                {
                    0o100644
                }
            };
            let bytes = sync.push_file(local_path, remote, mode)?;
            sync.quit()?;
            println!("{local} -> {remote} ({} bytes)", bytes);
        }
        Commands::Pull { remote, local } => {
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), default_auth())?;

            // AOSP: if <dest> is an existing directory, pull into it using
            // the remote basename.
            let local_path = {
                let p = Path::new(local);
                if p.is_dir() {
                    let base = remote.rsplit('/').next().filter(|s| !s.is_empty());
                    match base {
                        Some(b) => p.join(b),
                        None => p.to_path_buf(),
                    }
                } else {
                    p.to_path_buf()
                }
            };

            let (local_id, remote_id) = open_service(&mut transport, "sync:", 1)?;
            let mut sync = SyncStream::new(&mut transport, local_id, remote_id);
            let bytes = sync.pull_file(remote, &local_path)?;
            sync.quit()?;
            println!("{remote} -> {} ({} bytes)", local_path.display(), bytes);
        }
        Commands::Reboot { target } => {
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), default_auth())?;

            let target_str = target.as_deref().unwrap_or("");
            let dest = format!("reboot:{}", target_str);
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, dest.as_bytes());
            transport.send_message(&open_hdr, dest.as_bytes())?;
            println!("[adb-rs] Reboot request sent to {}", addr);
        }

        // ==================== Command Group 2 ====================

        Commands::Forward { list, remove, remove_all, no_rebind, local, remote } => {
            let request = if *list {
                "host:forward:list".to_string()
            } else if let Some(rm) = remove {
                format!("host:forward:killforward:{rm}")
            } else if *remove_all {
                "host:forward:killforward-all".to_string()
            } else if let (Some(loc), Some(rem)) = (local, remote) {
                if *no_rebind {
                    format!("host:forward:norebind:{loc};{rem}")
                } else {
                    format!("host:forward:{loc};{rem}")
                }
            } else {
                eprintln!("error: specify --list, --remove, --remove-all, or LOCAL REMOTE");
                std::process::exit(1);
            };

            match host_command(cli.serial.as_deref(), &request) {
                Ok(resp) => {
                    if !resp.is_empty() {
                        println!("{resp}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Reverse { list, remove, remove_all, no_rebind, remote, local } => {
            let request = if *list {
                "host:reverse:list".to_string()
            } else if let Some(rm) = remove {
                format!("host:reverse:killreverse:{rm}")
            } else if *remove_all {
                "host:reverse:killreverse-all".to_string()
            } else if let (Some(rem), Some(loc)) = (remote, local) {
                if *no_rebind {
                    format!("host:reverse:norebind:{rem};{loc}")
                } else {
                    format!("host:reverse:{rem};{loc}")
                }
            } else {
                eprintln!("error: specify --list, --remove, --remove-all, or REMOTE LOCAL");
                std::process::exit(1);
            };

            match host_command(cli.serial.as_deref(), &request) {
                Ok(resp) => {
                    if !resp.is_empty() {
                        println!("{resp}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Install { apk } => {
            let apk_path = Path::new(apk);
            if !apk_path.exists() {
                eprintln!("Error: APK not found: {apk}");
                std::process::exit(1);
            }

            // Read APK file
            let apk_data = std::fs::read(apk_path)
                .map_err(|e| format!("Cannot read {apk}: {e}"))?;
            let file_name = apk_path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("package.apk");
            let remote_apk = format!("/data/local/tmp/{file_name}");

            // Connect to adbd
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), default_auth())?;

            // Open sync: service
            let (local_id, remote_id) = open_service(&mut transport, "sync:", 1)?;

            // AOSP wire order (daemon/file_sync_service.cpp handle_send_file):
            // SEND → DATA* → DONE, and only ONE terminal OKAY/FAIL after
            // DONE. Waiting for OKAY after SEND would block forever.
            println!("[adb-rs] Pushing {file_name} ({} bytes) to {remote_apk} ...", apk_data.len());
            let mut sync = SyncStream::new(&mut transport, local_id, remote_id);
            sync.push_bytes(&remote_apk, &apk_data, 0o100644)?;

            println!("[adb-rs] Push complete. Installing {remote_apk} ...");

            // Run pm install via shell
            let install_cmd = format!("pm install -r \"{remote_apk}\"");
            let result = run_shell(&mut transport, &info.banner, &install_cmd, true)?;
            let output = result.unwrap_or_default();
            let output_str = String::from_utf8_lossy(&output).trim().to_string();

            if output_str.contains("Success") || output_str.contains("Success\n") {
                println!("[adb-rs] Install succeeded: {output_str}");
            } else if output_str.is_empty() {
                println!("[adb-rs] Install completed (no output)");
            } else {
                eprintln!("[adb-rs] Install output: {output_str}");
            }

            // Clean up temp APK
            let _ = run_shell(&mut transport, &info.banner, &format!("rm -f \"{remote_apk}\""), false);
        }

        Commands::Uninstall { package } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            let cmd = format!("pm uninstall {package}");
            let result = run_shell(&mut transport, &info.banner, &cmd, true)?;
            let output = result.unwrap_or_default();
            let output_str = String::from_utf8_lossy(&output).trim().to_string();

            if output_str.contains("Success") {
                println!("Success\n[adb-rs] Uninstalled {package}");
            } else if output_str.is_empty() {
                println!("[adb-rs] Uninstall completed (no output)");
            } else {
                println!("{output_str}");
            }
        }

        Commands::Logcat { args } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            let logcat_cmd = if args.is_empty() {
                "logcat".to_string()
            } else {
                format!("logcat {}", args.join(" "))
            };
            let dest = shell_service_string(&info.banner, &logcat_cmd)?;
            let (local_id, remote_id) = open_service(&mut transport, &dest, 1)?;
            stream_shell_v2(&mut transport, local_id, remote_id, false)?;
        }

        Commands::Bugreport { output } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            let dest = shell_service_string(&info.banner, "bugreport")?;
            println!("[adb-rs] Capturing bugreport from {addr} ...");
            let (local_id, remote_id) = open_service(&mut transport, &dest, 1)?;
            let captured = stream_shell_v2(&mut transport, local_id, remote_id, true)?;
            let data = captured.unwrap_or_default();

            let out_path = output.as_deref().unwrap_or("bugreport.zip");
            std::fs::write(out_path, &data)
                .map_err(|e| format!("Failed to write bugreport to {out_path}: {e}"))?;
            println!("[adb-rs] Bugreport saved to {out_path} ({} bytes)", data.len());
        }

        Commands::Jdwp => {
            match host_command(cli.serial.as_deref(), "host:jdwp") {
                Ok(resp) => {
                    let trimmed = resp.trim();
                    if trimmed.is_empty() {
                        println!("[adb-rs] No JDWP processes found");
                    } else {
                        println!("[adb-rs] JDWP PIDs:");
                        for line in trimmed.lines() {
                            println!("  {line}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Serve => {
            println!("[adb-rs] Starting ADB server on 127.0.0.1:5037 ...");
            server::run_server();
        }

        Commands::StartServer => {
            let addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            if std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(200)).is_ok() {
                println!("* daemon already running *");
            } else {
                ensure_server_running()?;
            }
        }

        Commands::KillServer => {
            kill_server()?;
        }

        Commands::Pair { addr, code: _ } => {
            let target_addr = if addr.contains(':') { addr.clone() } else { format!("{addr}:5555") };
            eprintln!("Cannot pair with {target_addr}: AOSP pairing requires TLS 1.3 exporter + BoringSSL Curve25519 SPAKE2 and certificate persistence; this build refuses plaintext and the former custom SPAP protocol.");
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::constants::{A_AUTH_RSAKEY, A_AUTH_SIGNATURE, A_AUTH_TOKEN};

    /// Script a fake adbd `sync:` conversation per daemon semantics:
    /// replies CNXN to the client handshake, OKAY to A_OPEN("sync:"),
    /// then runs `script` against decoded sync messages.
    /// Returns the join handle plus a shared buffer of observed sync ids.
    struct FakeSyncDaemon {
        listener: std::net::TcpListener,
    }

    impl FakeSyncDaemon {
        fn bind() -> Self {
            Self {
                listener: std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            }
        }

        fn addr(&self) -> std::net::SocketAddr {
            self.listener.local_addr().unwrap()
        }

        /// Accept one client, run the handshake + sync: open, and then
        /// invoke `on_sync` with the message stream reader/writer.
        fn serve<F>(self, f: F) -> std::thread::JoinHandle<Vec<u32>>
        where
            F: FnOnce(&mut dyn FnMut() -> (u32, Vec<u8>), &mut dyn FnMut(u32, &[u8])) -> Vec<u32>
                + Send
                + 'static,
        {
            use std::io::{Read, Write};
            std::thread::spawn(move || {
                let (sock, _) = self.listener.accept().unwrap();
                let mut sock = sock;
                let mut buf = [0u8; 24];

                // client CNXN → server CNXN
                sock.read_exact(&mut buf).unwrap();
                let h = AdbMessageHeader::decode(&buf).unwrap();
                assert_eq!(h.command, A_CNXN);
                let mut p = vec![0u8; h.data_length as usize];
                if !p.is_empty() {
                    sock.read_exact(&mut p).unwrap();
                }
                let banner = b"device::ro.product.name=fake".to_vec();
                let resp = AdbMessageHeader::new(A_CNXN, 0x01000001, 1024 * 1024, &banner);
                let mut hdrb = [0u8; 24];
                resp.encode(&mut hdrb);
                sock.write_all(&hdrb).unwrap();
                sock.write_all(&banner).unwrap();
                sock.flush().unwrap();

                // client A_OPEN("sync:") → OKAY(remote_id=7, local_id=client)
                sock.read_exact(&mut buf).unwrap();
                let open = AdbMessageHeader::decode(&buf).unwrap();
                assert_eq!(open.command, A_OPEN);
                let mut svc = vec![0u8; open.data_length as usize];
                sock.read_exact(&mut svc).unwrap();
                assert_eq!(&svc, b"sync:");
                let okay = AdbMessageHeader::new(A_OKAY, 7, open.arg0, &[]);
                okay.encode(&mut hdrb);
                sock.write_all(&hdrb).unwrap();
                sock.flush().unwrap();

                // sync message pump (daemon side: reads SYNC requests from
                // A_WRTE, writes A_OKAY acks and SYNC responses in A_WRTE).
                let client_id = open.arg0;
                let mut dsock = sock.try_clone().unwrap();
                let mut rsock = sock.try_clone().unwrap();
                let mut asock = sock.try_clone().unwrap();
                let mut wsock = sock;
                let mut reader = move || -> (u32, Vec<u8>) {
                    let mut hb = [0u8; 24];
                    rsock.read_exact(&mut hb).unwrap();
                    let h = AdbMessageHeader::decode(&hb).unwrap();
                    assert_eq!(h.command, A_WRTE);
                    let mut pay = vec![0u8; h.data_length as usize];
                    rsock.read_exact(&mut pay).unwrap();
                    // ack every client WRTE (AOSP always acks)
                    let ack = AdbMessageHeader::new(A_OKAY, 7, client_id, &[]);
                    let mut ab = [0u8; 24];
                    ack.encode(&mut ab);
                    asock.write_all(&ab).unwrap();
                    asock.flush().unwrap();
                    (
                        byteorder::LittleEndian::read_u32(&pay[0..4]),
                        pay[8..].to_vec(),
                    )
                };
                let mut writer = move |id: u32, payload: &[u8]| {
                    let mut msg = Vec::with_capacity(8 + payload.len());
                    let mut hb = [0u8; 8];
                    byteorder::LittleEndian::write_u32(&mut hb[0..4], id);
                    byteorder::LittleEndian::write_u32(&mut hb[4..8], payload.len() as u32);
                    msg.extend_from_slice(&hb);
                    msg.extend_from_slice(payload);
                    let wr = AdbMessageHeader::new(A_WRTE, 7, client_id, &msg);
                    let mut wb = [0u8; 24];
                    wr.encode(&mut wb);
                    wsock.write_all(&wb).unwrap();
                    wsock.write_all(&msg).unwrap();
                    wsock.flush().unwrap();
                };
                let out = f(&mut reader, &mut writer);
                // AOSP adbd does not tear the socket down right after the
                // last response: it keeps draining client WRTEs (which are
                // acks for our DATA/DONE frames) until the client closes.
                // Without this, the client's final ack hits a closed socket.
                // A read timeout guarantees termination when the client is
                // still alive (transport drops only at test end).
                let _ = dsock.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
                let mut drain = [0u8; 24];
                loop {
                    match dsock.read_exact(&mut drain) {
                        Ok(()) => match AdbMessageHeader::decode(&drain) {
                            Ok(h) => {
                                let mut p = vec![0u8; h.data_length as usize];
                                if h.data_length > 0 && dsock.read_exact(&mut p).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        },
                        Err(_) => break,
                    }
                }
                out
            })
        }
    }

    use byteorder::ByteOrder as _;

    /// Connect a client transport + sync stream to the fake daemon.
    fn client_to_sync_daemon(
        addr: std::net::SocketAddr,
    ) -> (
        Box<dyn Transport>,
        u32,
        u32,
    ) {
        let transport = TcpTransport::connect_timeout(
            &format!("127.0.0.1:{}", addr.port()),
            Duration::from_secs(3),
        )
        .unwrap();
        let auth = AdbAuth::generate("sync-test@localhost").unwrap();
        let (_info, mut transport) =
            connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), &auth).unwrap();
        let (lid, rid) = open_service(&mut transport, "sync:", 1).unwrap();
        (transport, lid, rid)
    }

    /// Handshake a client transport against a raw fake-adbd socket that has
    /// already answered CNXN and OKAYed an A_OPEN for `expect_dest`. Returns
    /// the client transport plus (local_id, remote_id) for the open stream.
    /// The daemon side is scripted by the caller thread via `sock`.
    fn fake_exec_daemon_accept(
        listener: &std::net::TcpListener,
        expect_dest: &[u8],
    ) -> std::net::TcpStream {
        use std::io::{Read as _, Write as _};
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 24];
        // client CNXN → CNXN reply
        sock.read_exact(&mut buf).unwrap();
        let h = AdbMessageHeader::decode(&buf).unwrap();
        assert_eq!(h.command, A_CNXN);
        let mut p = vec![0u8; h.data_length as usize];
        if !p.is_empty() {
            sock.read_exact(&mut p).unwrap();
        }
        let banner = b"device::ro.product.name=fake".to_vec();
        let resp = AdbMessageHeader::new(A_CNXN, 0x01000001, 1024 * 1024, &banner);
        let mut hb = [0u8; 24];
        resp.encode(&mut hb);
        sock.write_all(&hb).unwrap();
        sock.write_all(&banner).unwrap();
        // client A_OPEN(dest) → OKAY
        sock.read_exact(&mut buf).unwrap();
        let open = AdbMessageHeader::decode(&buf).unwrap();
        assert_eq!(open.command, A_OPEN);
        let mut svc = vec![0u8; open.data_length as usize];
        sock.read_exact(&mut svc).unwrap();
        assert_eq!(svc, expect_dest, "fake-adbd got wrong service string");
        let okay = AdbMessageHeader::new(A_OKAY, 7, open.arg0, &[]);
        okay.encode(&mut hb);
        sock.write_all(&hb).unwrap();
        sock.flush().unwrap();
        sock
    }

    /// exec-out wire contract: the client opens `exec:` + raw program +
    /// escape_arg'ed args, streams RAW WRTE payloads to the sink byte-exact
    /// (no shell-v2 parsing even when bytes happen to look like v2 packets),
    /// acks every WRTE, and stops at CLSE.
    #[test]
    fn test_exec_out_streams_raw_bytes_byte_exact() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // The exact service string AOSP would build for: adb exec-out screencap -p
        let expect = b"exec:screencap '-p'".to_vec();
        // Binary-ish payload containing CRLF and shell-v2 lookalike bytes:
        // a v2 demuxer would corrupt these — stream_raw_to must not touch them.
        let png: Vec<u8> = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0x00, 0x2d];
        let png_expected = png.clone();

        let daemon = std::thread::spawn(move || {
            let mut sock = fake_exec_daemon_accept(&listener, &expect);
            let mut hb = [0u8; 24];
            // WRTE raw chunk 1
            let wr = AdbMessageHeader::new(A_WRTE, 7, 1, &png[..5]);
            wr.encode(&mut hb);
            sock.write_all(&hb).unwrap();
            sock.write_all(&png[..5]).unwrap();
            // daemon expects the client's OKAY ack
            sock.read_exact(&mut hb).unwrap();
            let ack = AdbMessageHeader::decode(&hb).unwrap();
            assert_eq!(ack.command, A_OKAY);
            // WRTE raw chunk 2
            let wr = AdbMessageHeader::new(A_WRTE, 7, 1, &png[5..]);
            wr.encode(&mut hb);
            sock.write_all(&hb).unwrap();
            sock.write_all(&png[5..]).unwrap();
            let mut drain = [0u8; 24];
            let _ = sock.read_exact(&mut drain); // ack (best effort)
            // CLSE ends the stream
            let clse = AdbMessageHeader::new(A_CLSE, 7, 1, &[]);
            clse.encode(&mut hb);
            sock.write_all(&hb).unwrap();
            sock.flush().unwrap();
        });

        let transport =
            TcpTransport::connect_timeout(&format!("127.0.0.1:{}", addr.port()), Duration::from_secs(3))
                .unwrap();
        let auth = AdbAuth::generate("exec-test@localhost").unwrap();
        let (_info, mut transport) =
            connect_and_handshake_with_tls_upgrade(transport, b"host::", &auth).unwrap();
        let args: Vec<String> = ["screencap", "-p"].iter().map(|s| s.to_string()).collect();
        let dest = adb_protocol::exec_service_string(&args);
        let (lid, rid) = open_service(&mut transport, &dest, 1).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let total = stream_raw_to(&mut transport, lid, rid, &mut sink).unwrap();
        assert_eq!(total as usize, png_expected.len());
        assert_eq!(sink, png_expected, "exec-out must be byte-exact raw");
        daemon.join().unwrap();
    }

    /// exec-in wire contract: chunks (cap MAX_PAYLOAD_V2) sent as WRTE each
    /// awaiting OKAY before the next, then a final A_CLSE signals stdin EOF.
    #[test]
    fn test_exec_in_feeds_stdin_and_closes() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expect = b"exec:cat 'a b'".to_vec();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();

        let daemon = std::thread::spawn(move || {
            let mut sock = fake_exec_daemon_accept(&listener, &expect);
            let mut received = Vec::new();
            let mut hb = [0u8; 24];
            loop {
                match sock.read_exact(&mut hb) {
                    Ok(()) => {}
                    Err(_) => break,
                }
                let h = match AdbMessageHeader::decode(&hb) {
                    Ok(h) => h,
                    Err(_) => break,
                };
                if h.command == A_CLSE {
                    break; // stdin EOF from the client
                }
                assert_eq!(h.command, A_WRTE);
                let mut pay = vec![0u8; h.data_length as usize];
                sock.read_exact(&mut pay).unwrap();
                received.extend_from_slice(&pay);
                let mut bufout = [0u8; 24];
                let ack = AdbMessageHeader::new(A_OKAY, 7, h.arg0, &[]);
                ack.encode(&mut bufout);
                sock.write_all(&bufout).unwrap();
                sock.flush().unwrap();
            }
            received
        });

        let transport =
            TcpTransport::connect_timeout(&format!("127.0.0.1:{}", addr.port()), Duration::from_secs(3))
                .unwrap();
        let auth = AdbAuth::generate("exec-test@localhost").unwrap();
        let (_info, mut transport) =
            connect_and_handshake_with_tls_upgrade(transport, b"host::", &auth).unwrap();
        let args: Vec<String> = ["cat", "a b"].iter().map(|s| s.to_string()).collect();
        let dest = adb_protocol::exec_service_string(&args);
        let (lid, rid) = open_service(&mut transport, &dest, 1).unwrap();
        let mut src = std::io::Cursor::new(data.clone());
        stream_raw_from(&mut transport, lid, rid, &mut src).unwrap();
        let received = daemon.join().unwrap();
        assert_eq!(received, data, "exec-in must deliver stdin byte-exact");
    }

    /// AOSP daemon: SEND is NOT acknowledged. OKAY comes exactly once, after
    /// DONE. A client that waits for OKAY after SEND blocks forever. This
    /// test encodes that wire contract and drives SyncStream::push_bytes.
    #[test]
    fn test_sync_push_daemon_faithful_okay_only_after_done() {
        let daemon = FakeSyncDaemon::bind();
        let daddr = daemon.addr();
        let handle = daemon.serve(|read, write| {
            let mut seen = Vec::new();
            // 1. SEND
            let (id, payload) = read();
            seen.push(id);
            assert_eq!(id, SYNC_SEND_L);
            let req = String::from_utf8_lossy(&payload).to_string();
            assert!(req.starts_with("/data/local/tmp/x.bin,0o100644") || req.starts_with("/data/local/tmp/x.bin,33188"), "got {req}");
            // ... NO OKAY here. Daemon opens file silently.

            // 2. DATA*
            loop {
                let (id, payload) = read();
                seen.push(id);
                if id == SYNC_DONE_L {
                    assert!(payload.is_empty());
                    break;
                }
                assert_eq!(id, SYNC_DATA_L);
                assert_eq!(&payload, b"PUSHED!");
            }

            // 3. OKAY after DONE
            write(0x59414B4F /* OKAY */, &[]);
            seen
        });

        let (mut transport, lid, rid) = client_to_sync_daemon(daddr);
        let mut sync = SyncStream::new(&mut transport, lid, rid);
        sync.push_bytes("/data/local/tmp/x.bin", b"PUSHED!", 0o100644)
            .unwrap();
        drop(sync);
        let seen = handle.join().unwrap();
        assert_eq!(
            seen,
            vec![SYNC_SEND_L, SYNC_DATA_L, SYNC_DONE_L],
            "push must be SEND → DATA → DONE with no interleaved waits"
        );
    }

    const SYNC_SEND_L: u32 = 0x444E4553; // "SEND"
    const SYNC_DATA_L: u32 = 0x41544144; // "DATA"
    const SYNC_DONE_L: u32 = 0x454E4F44; // "DONE"

    /// pull_file must drain DATA chunks until DONE and write exactly the
    /// concatenated bytes; FAIL must abort without leaving a partial file
    /// when the open fails mid-transfer.
    #[test]
    fn test_sync_pull_writes_all_data_until_done() {
        let daemon = FakeSyncDaemon::bind();
        let daddr = daemon.addr();
        let handle = daemon.serve(|read, write| {
            let mut seen = Vec::new();
            let (id, payload) = read();
            seen.push(id);
            assert_eq!(id, 0x56434552u32 /* RECV */);
            assert_eq!(payload, b"/remote/file.bin");
            // reply DATA chunks with mtime=123456 DONE terminator
            write(SYNC_DATA_L, b"AAAA");
            write(SYNC_DATA_L, b"BBBB");
            write(SYNC_DONE_L, &[]); // daemon sets length=0 for DONE on recv
            seen
        });

        let out = std::env::temp_dir().join(format!("pull-test-{}", std::process::id()));
        let (mut transport, lid, rid) = client_to_sync_daemon(daddr);
        {
            let mut sync = SyncStream::new(&mut transport, lid, rid);
            let n = sync.pull_file("/remote/file.bin", &out).unwrap();
            assert_eq!(n, 8);
        }
        assert_eq!(std::fs::read(&out).unwrap(), b"AAAABBBB");
        let _ = std::fs::remove_file(&out);
        assert_eq!(handle.join().unwrap(), vec![0x56434552u32]);
    }

    /// FAIL from the device during pull: the partial local file must be
    /// removed and the error surfaced.
    #[test]
    fn test_sync_pull_fail_removes_partial_file() {
        let daemon = FakeSyncDaemon::bind();
        let daddr = daemon.addr();
        let handle = daemon.serve(|read, write| {
            let (id, _) = read();
            assert_eq!(id, 0x56434552u32);
            write(SYNC_DATA_L, b"PARTIAL");
            write(0x4C494146u32 /* FAIL */, b"open failed");
            vec![id]
        });

        let out = std::env::temp_dir().join(format!("pull-fail-{}", std::process::id()));
        let (mut transport, lid, rid) = client_to_sync_daemon(daddr);
        {
            let mut sync = SyncStream::new(&mut transport, lid, rid);
            let err = sync.pull_file("/remote/x", &out).unwrap_err().to_string();
            assert!(err.contains("pull /remote/x failed"), "got {err}");
        }
        assert!(!out.exists(), "partial file must be cleaned up on FAIL");
        let _ = handle.join();
    }

    /// Fake-adbd end-to-end AUTH conversation over a real TCP transport:
    /// server sends A_AUTH TOKEN → client answers SIGNATURE → server accepts
    /// → CNXN. Verifies the AOSP client auth loop in
    /// `connect_and_handshake_with_tls_upgrade` (adb.cpp:457-474 semantics).
    #[test]
    fn test_handshake_auth_token_signature_loop() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Pre-generate the "user" key so both sides can reference it.
        let auth = AdbAuth::generate("fake-adbd-test@localhost").unwrap();
        let server_key = auth.clone();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 24];

            // 1. Read client CNXN
            sock.read_exact(&mut buf).unwrap();
            let cnxn_hdr = AdbMessageHeader::decode(&buf).unwrap();
            assert_eq!(cnxn_hdr.command, A_CNXN);
            let mut cnxn_payload = vec![0u8; cnxn_hdr.data_length as usize];
            if !cnxn_payload.is_empty() {
                sock.read_exact(&mut cnxn_payload).unwrap();
            }

            // 2. Send A_AUTH TOKEN (20 bytes)
            let token = b"fake_adbd_token_20!".to_vec();
            let auth_hdr = AdbMessageHeader::new_auth(A_AUTH_TOKEN, &token);
            let mut out = [0u8; 24];
            auth_hdr.encode(&mut out);
            sock.write_all(&out).unwrap();
            sock.write_all(&token).unwrap();
            sock.flush().unwrap();

            // 3. Read client SIGNATURE — must verify against the user key
            sock.read_exact(&mut buf).unwrap();
            let sig_hdr = AdbMessageHeader::decode(&buf).unwrap();
            assert_eq!(sig_hdr.command, A_AUTH);
            assert_eq!(sig_hdr.arg0, A_AUTH_SIGNATURE);
            let mut sig = vec![0u8; sig_hdr.data_length as usize];
            sock.read_exact(&mut sig).unwrap();
            assert!(adb_protocol::auth::verify_token_signature(
                server_key.public_key(),
                &token,
                &sig
            )
            .unwrap());

            // 4. Accept: send CNXN banner
            let banner = b"device product::model fake-adbd".to_vec();
            let ok_hdr = AdbMessageHeader::new(A_CNXN, 0x01000001, 256 * 1024, &banner);
            ok_hdr.encode(&mut out);
            sock.write_all(&out).unwrap();
            sock.write_all(&banner).unwrap();
            sock.flush().unwrap();
        });

        let transport = TcpTransport::connect_timeout(
            &format!("127.0.0.1:{}", addr.port()),
            Duration::from_secs(3),
        )
        .unwrap();
        let (info, _t) =
            connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), &auth)
                .unwrap();
        assert!(info.banner.contains("fake-adbd"));
        server.join().unwrap();
    }

    /// Fake adbd that never accepts: the client must exhaust its keys, send
    /// RSAPUBLICKEY, and keep waiting (no crash, no busy loop).
    #[test]
    fn test_handshake_auth_pubkey_fallback_then_wait() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let auth = AdbAuth::generate("unauth-test@localhost").unwrap();
        let server_key = auth.clone();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 24];
            sock.read_exact(&mut buf).unwrap();
            let cnxn_hdr = AdbMessageHeader::decode(&buf).unwrap();
            let mut p = vec![0u8; cnxn_hdr.data_length as usize];
            if !p.is_empty() {
                sock.read_exact(&mut p).unwrap();
            }

            let token = b"unauth_token_20byte!".to_vec();
            let mut out = [0u8; 24];

            // TOKEN #1 → expect SIGNATURE
            AdbMessageHeader::new_auth(A_AUTH_TOKEN, &token).encode(&mut out);
            sock.write_all(&out).unwrap();
            sock.write_all(&token).unwrap();
            sock.flush().unwrap();
            sock.read_exact(&mut buf).unwrap();
            let h = AdbMessageHeader::decode(&buf).unwrap();
            assert_eq!(h.command, A_AUTH);
            assert_eq!(h.arg0, A_AUTH_SIGNATURE);
            let mut sig = vec![0u8; h.data_length as usize];
            sock.read_exact(&mut sig).unwrap();
            assert!(adb_protocol::auth::verify_token_signature(
                server_key.public_key(),
                &token,
                &sig
            )
            .unwrap());

            // TOKEN #2 (re-request; AOSP adbd re-sends TOKEN after a failed
            // signature) → keys exhausted → expect RSAPUBLICKEY
            AdbMessageHeader::new_auth(A_AUTH_TOKEN, &token).encode(&mut out);
            sock.write_all(&out).unwrap();
            sock.write_all(&token).unwrap();
            sock.flush().unwrap();
            sock.read_exact(&mut buf).unwrap();
            let h2 = AdbMessageHeader::decode(&buf).unwrap();
            assert_eq!(h2.command, A_AUTH);
            assert_eq!(h2.arg0, A_AUTH_RSAKEY);
            let mut pubkey = vec![0u8; h2.data_length as usize];
            sock.read_exact(&mut pubkey).unwrap();
            // Must parse as the user key's public key string.
            let s = String::from_utf8(pubkey.clone()).unwrap();
            let (parsed, _) =
                adb_protocol::auth::parse_adb_public_key_string(&s).unwrap();
            assert_eq!(parsed, *server_key.public_key());

            // AOSP: after RSAPUBLICKEY the client waits for the framework;
            // the server ends the conversation by closing.
        });

        let transport = TcpTransport::connect_timeout(
            &format!("127.0.0.1:{}", addr.port()),
            Duration::from_secs(3),
        )
        .unwrap();
        // The client will block waiting for CNXN after sending RSAPUBLICKEY;
        // when the fake server closes, recv fails — that failure is the
        // expected outcome (NOT a panic).
        let result =
            connect_and_handshake_with_tls_upgrade(transport, &host_cnxn_payload(), &auth);
        assert!(result.is_err(), "server closed without CNXN; client must error");
        server.join().unwrap();
    }

    #[test]
    fn test_kill_server_when_not_running() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        assert!(kill_server_at(port).is_ok());
    }

    #[test]
    fn test_server_autostart_and_kill() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            server::run_server_with_listener(listener);
        });

        let addr = format!("127.0.0.1:{port}");
        assert!(std::net::TcpStream::connect(&addr).is_ok());

        assert!(kill_server_at(port).is_ok());

        handle.join().unwrap();

        assert!(std::net::TcpStream::connect(&addr).is_err());
    }
}
