use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbAuth, AdbMessageHeader, AdbServerTransport, AuthType, ShellV2Packet, TcpTransport,
    Transport, TransportError,
    A_AUTH, ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_STLS, A_WRTE, MAX_PAYLOAD_V2,
    build_sync_send_req, build_sync_data_chunk, build_sync_done, SyncMessageHeader,
    SYNC_FAIL, SYNC_OKAY,
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

/// Read a sync response (expects OKAY or FAIL in SyncMessageHeader format).
fn recv_sync_response(transport: &mut dyn Transport, local_id: u32, _remote_id: u32) -> Result<(), String> {
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(m) => m,
            Err(e) => return Err(format!("recv sync response error: {e}")),
        };
        match hdr.command {
            A_OKAY => {
                // This is ack for our WRTE, keep reading
            }
            A_WRTE => {
                // Ack the WRTE
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);

                // Parse sync header
                if payload.len() < 8 {
                    return Err("Sync response too short".to_string());
                }
                let sync_hdr = match SyncMessageHeader::decode(&payload) {
                    Ok(h) => h,
                    Err(e) => return Err(format!("Bad sync header: {e}")),
                };
                match sync_hdr.id {
                    SYNC_OKAY => return Ok(()),
                    SYNC_FAIL => {
                        let msg = String::from_utf8_lossy(&payload[8..]).to_string();
                        return Err(format!("Sync FAIL: {}", msg));
                    }
                    other => {
                        return Err(format!("Unexpected sync response id {:#x}", other));
                    }
                }
            }
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                return Err("Sync connection closed".to_string());
            }
            _ => {}
        }
    }
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

/// Open shell connection and stream output to stdout.
fn run_shell(
    transport: &mut dyn Transport,
    cmd: &str,
    capture: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let dest = format!("shell,v2,raw:{cmd}");
    let (local_id, remote_id) = open_service(transport, &dest, 1)?;
    stream_shell_v2(transport, local_id, remote_id, capture)
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
    let (_info, mut transport) =
        connect_and_handshake_with_tls_upgrade(transport, b"host::features=shell_v2,cmd", default_auth())?;
    let captured = run_shell(&mut transport, cmd, true)?;
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
                            b"host::features=shell_v2,cmd",
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
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            )?;

            let cmd_str = command.join(" ");
            let dest = if cmd_str.is_empty() {
                "shell,v2,raw:".to_string()
            } else {
                format!("shell,v2,raw:{}", cmd_str)
            };

            let (_lid, remote_id) = open_service(&mut transport, &dest, 1)?;
            stream_shell_v2(&mut transport, _lid, remote_id, false)?;
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
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            let sync_dest = b"sync:";
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, sync_dest);
            transport.send_message(&open_hdr, sync_dest)?;
            println!("[adb-rs] Connected sync transport to {} for push '{}' -> '{}'", addr, local, remote);
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
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            let sync_dest = b"sync:";
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, sync_dest);
            transport.send_message(&open_hdr, sync_dest)?;
            println!("[adb-rs] Connected sync transport to {} for pull '{}' -> '{}'", addr, remote, local);
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
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

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
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            // Open sync: service
            let (local_id, remote_id) = open_service(&mut transport, "sync:", 1)?;

            // Build SEND request
            let mut send_buf = Vec::new();
            build_sync_send_req(&remote_apk, 0o644, &mut send_buf)
                .map_err(|e| format!("Build SEND req failed: {e}"))?;
            println!("[adb-rs] Pushing {file_name} ({} bytes) to {remote_apk} ...", apk_data.len());

            // Send SEND request
            send_wrte(&mut transport, local_id, remote_id, &send_buf)?;

            // Expect SYNC_OKAY
            recv_sync_response(&mut transport, local_id, remote_id)?;

            // Send DATA chunks (max 64KB each)
            const MAX_CHUNK: usize = 64 * 1024;
            for chunk in apk_data.chunks(MAX_CHUNK) {
                let mut data_buf = Vec::new();
                build_sync_data_chunk(chunk, &mut data_buf)
                    .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
                send_wrte(&mut transport, local_id, remote_id, &data_buf)?;
            }

            // Send DONE
            let mut done_buf = Vec::new();
            build_sync_done(0xFFFF_FFFF, &mut done_buf) // use max mtime
                .map_err(|e| format!("Build DONE failed: {e}"))?;
            send_wrte(&mut transport, local_id, remote_id, &done_buf)?;

            // Expect SYNC_OKAY or SYNC_FAIL
            recv_sync_response(&mut transport, local_id, remote_id)?;

            // Close sync connection
            let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
            transport.send_message(&clse_hdr, &[])?;
            // Wait for CLSE ack
            let _ = transport.recv_message();

            println!("[adb-rs] Push complete. Installing {remote_apk} ...");

            // Run pm install via shell
            let install_cmd = format!("pm install -r \"{remote_apk}\"");
            let result = run_shell(&mut transport, &install_cmd, true)?;
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
            let _ = run_shell(&mut transport, &format!("rm -f \"{remote_apk}\""), false);
        }

        Commands::Uninstall { package } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            )?;

            let cmd = format!("pm uninstall {package}");
            let result = run_shell(&mut transport, &cmd, true)?;
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
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            )?;

            let logcat_cmd = if args.is_empty() {
                "logcat".to_string()
            } else {
                format!("logcat {}", args.join(" "))
            };
            let dest = format!("shell,v2,raw:{logcat_cmd}");
            let (local_id, remote_id) = open_service(&mut transport, &dest, 1)?;
            stream_shell_v2(&mut transport, local_id, remote_id, false)?;
        }

        Commands::Bugreport { output } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            )?;

            let dest = "shell,v2,raw:bugreport".to_string();
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
            connect_and_handshake_with_tls_upgrade(transport, b"host::features=shell_v2,cmd", &auth)
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
            connect_and_handshake_with_tls_upgrade(transport, b"host::", &auth);
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
