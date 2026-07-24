use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbAuth, AdbMessageHeader, AdbServerTransport, ShellV2Packet, TcpTransport, Transport,
    TransportError,
    ADB_VERSION, A_AUTH, A_AUTH_TOKEN,
    A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_STLS, A_WRTE, MAX_PAYLOAD_V2,
    build_sync_send_req, build_sync_data_chunk, build_sync_done, SyncMessageHeader,
    SYNC_FAIL, SYNC_OKAY,
};

mod server;
mod client;

use client::{protocol, shell, exec_out, server_cmds, host_command};
use client::server_cmds::{ensure_server_running, ensure_server_running_at, kill_server, kill_server_at};

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
    /// Run remote shell command and return raw stdout (no ShellV2 framing).
    /// Uses the 'exec:' service which provides raw Unix stdout without
    /// ShellV2 packet headers or stderr multiplexing.
    #[command(name = "exec-out")]
    ExecOut {
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
    /// Restart adbd as root
    Root,
    /// Restart adbd as non-root
    Unroot,
    /// Restart adbd listening on TCP on the specified port
    Tcpip {
        port: u16,
    },
    /// Restart adbd listening on USB
    Usb,
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
    /// Get device state: offline, device, recovery, etc.
    #[command(name = "get-state")]
    GetState,
    /// Get the device serial number
    #[command(name = "get-serialno")]
    GetSerialno,
    /// Get the device path (e.g., usb:12345)
    #[command(name = "get-devpath")]
    GetDevpath,
    /// Start the ADB server (listens on 127.0.0.1:5037)
    Serve,
    /// Start the ADB server daemon
    #[command(name = "start-server")]
    StartServer,
    /// Kill the running ADB server daemon
    #[command(name = "kill-server")]
    KillServer,
    /// Internal: fork-server mode (started by the adb client)
    #[command(name = "fork-server", hide = true)]
    ForkServer {
        #[arg(long = "reply-fd")]
        reply_fd: i32,
    },
    /// Connect to a device via TCP/IP
    Connect {
        /// Device address (host:port)
        host: String,
        /// Optional port (defaults to 5555)
        port: Option<u16>,
    },
    /// Disconnect from one or all TCP devices
    Disconnect {
        /// Optional target device address to disconnect (disconnects all if omitted)
        target: Option<String>,
    },
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
    if is_tcp_spec {
        let addr = resolve_target_addr(serial, ADBD_PORT);
        let t = TcpTransport::connect_timeout(&addr, timeout)?;
        return Ok(Box::new(t));
    }

    // 1. Explicit USB request — bypass ADB server, connect directly.
    //    This is the `-d` / `--usb` path and requires full CNXN/AUTH.
    if use_usb {
        #[cfg(feature = "usb")]
        {
            let mut dev = if let Some(s) = serial {
                adb_protocol::UsbfsAdbDevice::open_by_serial(s)
            } else {
                adb_protocol::UsbfsAdbDevice::open_first()
            }
            .map_err(|e| format!("Failed to open ADB USB device: {e}"))?;
            // AOSP adbd waits for the user/framework after AUTH_RSAKEY.
            // Do not abort while the authorization dialog is still visible.
            dev.set_timeout(Duration::from_secs(30 * 60));
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
        if let Ok(mut dev) = usb_res {
            dev.set_timeout(Duration::from_secs(30 * 60));
            let adapter = adb_protocol::UsbTransportAdapter::new(dev);
            return Ok(Box::new(adapter));
        }
    }

    // 2. Prefer a running ADB server daemon (port 5037) when available.
    //    The server holds a persistent USB transport between commands,
    //    avoiding repeated AUTH and USB endpoint-stall (EPROTO) on
    //    the second consecutive connection.  AOSP adb works this way.
    //
    //    NOTE: this must come AFTER the USB paths because server
    //    transport cannot perform CNXN/AUTH — the server already
    //    handled that. Commands that need raw ADB wire (shell,
    //    push, pull) do their own CNXN and must go via direct USB.
    //    Server transport is only useful for `host:devices` etc.
    //    For now, skip server for non-devices commands to avoid
    //    CNXN-over-server incompatibility.
    //{
    //    let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
    //    if let Ok(mut t) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
    //        if t.switch_transport(serial).is_ok() {
    //            return Ok(Box::new(t));
    //        }
    //    }
    //}

    let addr = resolve_target_addr(serial, ADBD_PORT);
    let t = TcpTransport::connect_timeout(&addr, timeout)
        .map_err(|_| format!("Connection failed to {addr} (Connection refused). Specify target device with `-s <IP:PORT>` or start ADB server."))?;
    Ok(Box::new(t))
}

/// Information about the device received in the CNXN response banner.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub banner: String,
}

/// Get or create the persistent ADB host identity.
pub fn default_auth() -> &'static AdbAuth {
    static AUTH: OnceLock<AdbAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        load_or_create_auth().expect("Failed to load or create persistent ADB auth key")
    })
}

fn adb_key_dirs() -> Vec<PathBuf> {
    // Priority order for ADB key directories.
    // 1. $HOME/.android  — standard ADB location, same as system ADB.
    //    When run via `su -c HOME=...`, this picks up the system ADB's key,
    //    giving the same device fingerprint and reusing any prior authorization.
    // 2. /sdcard/.android — fallback writable from both normal UID and root.
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs = Vec::with_capacity(2);
    if !home.is_empty() {
        dirs.push(PathBuf::from(&home).join(".android"));
    }
    dirs.push(PathBuf::from("/sdcard/.android"));
    dirs
}

fn load_or_create_auth() -> Result<AdbAuth, Box<dyn std::error::Error>> {
    let dirs = adb_key_dirs();

    // Try to load an existing key from each candidate directory.
    for dir in &dirs {
        let private_path = dir.join("adbkey");
        let public_path = dir.join("adbkey.pub");

        if private_path.is_file() {
            let pem = std::fs::read_to_string(&private_path)?;
            let private_key = adb_protocol::auth::load_private_key_from_pem(&pem)?;
            let mut label = "adb-rs@localhost".to_string();
            let auth = AdbAuth::new(private_key, &label);

            if public_path.is_file() {
                let public_text = std::fs::read_to_string(&public_path)?;
                if let Ok((public_key, public_label)) =
                    adb_protocol::auth::parse_adb_public_key_string(&public_text)
                {
                    if public_key == *auth.public_key() {
                        label = if public_label.is_empty() {
                            label
                        } else {
                            public_label
                        };
                    }
                }
            }

            let auth = AdbAuth::new(auth.private_key().clone(), &label);
            if !public_path.is_file()
                || std::fs::read(&public_path)? != auth.build_rsakey_payload()?
            {
                write_auth_public_key(&auth, &public_path)?;
            }
            return Ok(auth);
        }
    }

    // No existing key found — generate a new one.
    let auth = AdbAuth::generate("adb-rs@localhost")?;
    let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())?;

    // Save to the first writable directory.
    for dir in &dirs {
        if std::fs::create_dir_all(dir).is_ok() {
            let private_path = dir.join("adbkey");
            let public_path = dir.join("adbkey.pub");
            if write_private_key(&private_path, pem.as_bytes()).is_ok()
                && write_auth_public_key(&auth, &public_path).is_ok()
            {
                break;
            }
        }
    }

    Ok(auth)
}

fn write_private_key(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_auth_public_key(auth: &AdbAuth, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = auth.build_rsakey_payload()?;
    write_private_key(path, &bytes)
}

/// Append the host public key to /data/misc/adb/adb_keys so that future
/// SIGNATURE-based ADB connections succeed without a re-authorization dialog.
/// HyperOS does not always persist USB keys via AdbDebuggingManager, so
/// we write the key ourselves with root.
#[cfg(target_os = "android")]
pub(crate) fn persist_adb_pubkey(auth: &AdbAuth) -> Result<(), Box<dyn std::error::Error>> {
    let payload = auth.build_rsakey_payload()?;
    // Strip trailing null byte for the plain-text key file
    let key_line = if payload.ends_with(&[0]) {
        std::str::from_utf8(&payload[..payload.len() - 1])?
    } else {
        std::str::from_utf8(&payload)?
    };
    if key_line.is_empty() {
        return Ok(());
    }

    let key_path = "/data/misc/adb/adb_keys";
    // Check whether the key is already present
    let already_present = std::fs::read_to_string(key_path)
        .map(|content| content.lines().any(|l| l.trim() == key_line))
        .unwrap_or(false);
    if already_present {
        return Ok(());
    }

    // Append: use root if not already root, otherwise write directly
    use std::io::{Read, Write};
    let can_write = std::fs::OpenOptions::new().append(true).open(key_path).is_ok();
    if can_write {
        let mut f = std::fs::OpenOptions::new().append(true).open(key_path)?;
        writeln!(f, "{}", key_line)?;
    } else {
        let status = std::process::Command::new("su")
            .arg("-c")
            .arg(format!("printf '%s\\n' '{}' >> {}", key_line, key_path))
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => return Err(format!("su exited with {s}").into()),
            Err(e) => return Err(format!("failed to run su: {e}").into()),
        }
    }
    Ok(())
}

/// Connect to adbd, perform CNXN handshake with A_STLS TLS upgrade support.
///
/// If the device responds with A_STLS, the transport is upgraded to TLS
/// using the auth key, and the CNXN handshake is retried over the encrypted channel.
#[cfg(feature = "tls")]
pub fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    use adb_protocol::tls;
    use adb_protocol::AdbTlsTransport;

    let mut transport: Box<dyn Transport> = Box::new(transport);

    // Send initial CNXN
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    // Read response. Legacy USB adbd may require RSA AUTH before CNXN/STLS.
    let (mut resp_hdr, mut payload) = transport.recv_message()?;
    let mut sent_signature = false;
    let mut sent_public_key = false;
    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0).into());
        }
        if payload.len() != 20 {
            return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
        }

        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&payload)?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()?
        } else {
            return Err("adbd rejected the ADB RSA key after signature and public-key exchange".into());
        };
        transport.send_message(&auth_hdr, &auth_payload)?;
        (resp_hdr, payload) = transport.recv_message()?;
    }

    if resp_hdr.command == A_CNXN {
        // Normal path — no TLS required
        let banner = String::from_utf8_lossy(&payload).to_string();

        // Persist the public key so future SIGNATURE verifications succeed
        // without requiring another authorization dialog.
        #[cfg(target_os = "android")]
        if sent_public_key {
            persist_adb_pubkey(auth)?;
        }

        return Ok((DeviceInfo { banner }, transport));
    }

    if resp_hdr.command == A_STLS {
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
        let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
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

    Err(format!(
        "Unexpected handshake response: cmd={:#x}",
        resp_hdr.command
    )
    .into())
}

/// Non-TLS fallback — A_STLS will return an error if the device requires TLS.
#[cfg(not(feature = "tls"))]
fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
    transport: T,
    cnxn_payload: &[u8],
    auth: &AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let mut transport: Box<dyn Transport> = Box::new(transport);
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    let (mut resp_hdr, mut payload) = transport.recv_message()?;
    let mut sent_signature = false;
    let mut sent_public_key = false;
    while resp_hdr.command == A_AUTH {
        if resp_hdr.arg0 != A_AUTH_TOKEN {
            return Err(format!("Unsupported AUTH request type: {}", resp_hdr.arg0).into());
        }
        if payload.len() != 20 {
            return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
        }

        let (auth_hdr, auth_payload) = if !sent_signature {
            sent_signature = true;
            auth.make_signature_message(&payload)?
        } else if !sent_public_key {
            sent_public_key = true;
            auth.make_rsakey_message()?
        } else {
            return Err("adbd rejected the ADB RSA key after signature and public-key exchange".into());
        };
        transport.send_message(&auth_hdr, &auth_payload)?;
        (resp_hdr, payload) = transport.recv_message()?;
    }

    if resp_hdr.command == A_CNXN {
        let banner = String::from_utf8_lossy(&payload).to_string();

        // Persist the public key so future SIGNATURE verifications succeed
        // without requiring another authorization dialog.
        #[cfg(target_os = "android")]
        if sent_public_key {
            persist_adb_pubkey(auth)?;
        }

        return Ok((DeviceInfo { banner }, transport));
    }

    if resp_hdr.command == A_STLS {
        return Err("Device requires TLS (A_STLS) but the `tls` feature is not enabled. \
                    Rebuild with --features tls"
            .into());
    }

    Err(format!(
        "Unexpected handshake response: cmd={:#x}",
        resp_hdr.command
    )
    .into())
}

/// Connect to ADB server (port 5037), switch transport if needed, and execute a host command.

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

    if !request.starts_with("host:connect")
        && !request.starts_with("host:disconnect")
        && !request.starts_with("host:forward")
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
            let cmd_str = command.join(" ");
            let shell_service = if cmd_str.is_empty() {
                "shell,v2,raw:".to_string()
            } else {
                format!("shell,v2,raw:{}", cmd_str)
            };

            // Priority 1: ADB server (port 5037) — borrow the system ADB's
            // already-authenticated transport.
            //
            // Server protocol after host:transport:<serial>:
            //   Client sends shell service as hex-length prefixed string
            //   (NOT raw A_OPEN — the server creates A_OPEN internally).
            //   Server responds OKAY, then enters raw ADB forwarding mode.
            //   Client then reads WRTE/CLSE from the device via server.
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                if server.switch_transport(cli.serial.as_deref()).is_ok() {
                    // Send shell service via host service protocol
                    server.send_host_request(&shell_service)?;
                    server.read_status()?; // OKAY -> server created A_OPEN, device OK'd
                    // Now in raw forwarding mode — stream shell output
                    shell::stream_shell_v2_server(&mut server, false)?;
                    return Ok(());
                }
            }

            // Priority 2: direct USB/TCP transport — full CNXN/AUTH handshake.
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) = match connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            ) {
                Ok(result) => result,
                Err(e) if e.to_string().contains("0x45534c43") => {
                    std::thread::sleep(Duration::from_secs(15));
                    let retry_transport = open_adb_transport(
                        cli.serial.as_deref(),
                        cli.d,
                        Duration::from_secs(3),
                    )?;
                    connect_and_handshake_with_tls_upgrade(
                        retry_transport,
                        b"host::features=shell_v2,cmd",
                        default_auth(),
                    )?
                }
                Err(e) => return Err(e),
            };

            let (_lid, remote_id) = protocol::open_service(&mut transport, &shell_service, 1)?;
            shell::stream_shell_v2(&mut transport, _lid, remote_id, false)?;
        }
        Commands::ExecOut { command } => {
            let cmd_str = command.join(" ");

            // Priority 1: ADB server (port 5037) — same pattern as shell.
            let exec_service = format!("exec:{cmd_str}");
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                if server.switch_transport(cli.serial.as_deref()).is_ok() {
                    // Send exec service via host service protocol
                    server.send_host_request(&exec_service)?;
                    server.read_status()?; // OKAY -> server created A_OPEN, device OK'd
                    // Raw forwarding mode — exec: outputs raw bytes, no ShellV2 framing
                    exec_out::stream_raw_server(&mut server, false)?;
                    return Ok(());
                }
            }

            // Priority 2: direct USB/TCP transport — full CNXN/AUTH handshake.
            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) = match connect_and_handshake_with_tls_upgrade(
                transport,
                b"host::features=shell_v2,cmd",
                default_auth(),
            ) {
                Ok(result) => result,
                Err(e) if e.to_string().contains("0x45534c43") => {
                    std::thread::sleep(Duration::from_secs(15));
                    let retry_transport = open_adb_transport(
                        cli.serial.as_deref(),
                        cli.d,
                        Duration::from_secs(3),
                    )?;
                    connect_and_handshake_with_tls_upgrade(
                        retry_transport,
                        b"host::features=shell_v2,cmd",
                        default_auth(),
                    )?
                }
                Err(e) => return Err(e),
            };

            exec_out::run_exec_out(&mut transport, &cmd_str)?;
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
            let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;

            // Build SEND request
            let mut send_buf = Vec::new();
            build_sync_send_req(&remote_apk, 0o644, &mut send_buf)
                .map_err(|e| format!("Build SEND req failed: {e}"))?;
            println!("[adb-rs] Pushing {file_name} ({} bytes) to {remote_apk} ...", apk_data.len());

            // Send SEND request
            protocol::send_wrte(&mut transport, local_id, remote_id, &send_buf)?;

            // Expect SYNC_OKAY
            protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

            // Send DATA chunks (max 64KB each)
            const MAX_CHUNK: usize = 64 * 1024;
            for chunk in apk_data.chunks(MAX_CHUNK) {
                let mut data_buf = Vec::new();
                build_sync_data_chunk(chunk, &mut data_buf)
                    .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
                protocol::send_wrte(&mut transport, local_id, remote_id, &data_buf)?;
            }

            // Send DONE
            let mut done_buf = Vec::new();
            build_sync_done(0xFFFF_FFFF, &mut done_buf) // use max mtime
                .map_err(|e| format!("Build DONE failed: {e}"))?;
            protocol::send_wrte(&mut transport, local_id, remote_id, &done_buf)?;

            // Expect SYNC_OKAY or SYNC_FAIL
            protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

            // Close sync connection
            let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
            transport.send_message(&clse_hdr, &[])?;
            // Wait for CLSE ack
            let _ = transport.recv_message();

            println!("[adb-rs] Push complete. Installing {remote_apk} ...");

            // Run pm install via shell
            let install_cmd = format!("pm install -r \"{remote_apk}\"");
            let result = shell::run_shell(&mut transport, &install_cmd, true)?;
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
            let _ = shell::run_shell(&mut transport, &format!("rm -f \"{remote_apk}\""), false);
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
            let result = shell::run_shell(&mut transport, &cmd, true)?;
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
            let (local_id, remote_id) = protocol::open_service(&mut transport, &dest, 1)?;
            shell::stream_shell_v2(&mut transport, local_id, remote_id, false)?;
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
            let (local_id, remote_id) = protocol::open_service(&mut transport, &dest, 1)?;
            let captured = shell::stream_shell_v2(&mut transport, local_id, remote_id, true)?;
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

        Commands::GetState => {
            match host_command(cli.serial.as_deref(), "host:get-state") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::GetSerialno => {
            match host_command(cli.serial.as_deref(), "host:get-serialno") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::GetDevpath => {
            match host_command(cli.serial.as_deref(), "host:get-devpath") {
                Ok(resp) => println!("{}", resp.trim()),
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

        Commands::ForkServer { reply_fd } => {
            server::run_server_fork(Some(*reply_fd));
        }

        Commands::Connect { host, port } => {
            let port = port.unwrap_or(5555);
            let request = format!("host:connect:{}:{}", host, port);

            match host_command(cli.serial.as_deref(), &request) {
                Ok(resp) => {
                    let trimmed = resp.trim();
                    if !trimmed.is_empty() {
                        println!("{trimmed}");
                    } else {
                        println!("connected to {}:{}", host, port);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Disconnect { target } => {
            let request = match target {
                Some(t) => format!("host:disconnect:{}", t),
                None => "host:disconnect".to_string(),
            };

            match host_command(cli.serial.as_deref(), &request) {
                Ok(resp) => {
                    let trimmed = resp.trim();
                    if !trimmed.is_empty() {
                        println!("{trimmed}");
                    } else {
                        match target {
                            Some(t) => println!("disconnected {}", t),
                            None => println!("disconnected everything"),
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Pair { addr, code } => {
            let target_addr = if addr.contains(':') { addr.clone() } else { format!("{addr}:5555") };
            let pair_code = match code {
                Some(c) => c.clone(),
                None => {
                    eprint!("Enter 6-digit pairing code: ");
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            let mut client = adb_protocol::PairingClient::new(&pair_code)
                .map_err(|e| format!("Invalid pairing code: {e}"))?;

            println!("Connecting to pairing service at {target_addr}...");
            let tcp_stream = std::net::TcpStream::connect_timeout(
                &target_addr.parse().map_err(|e| format!("Invalid target address {target_addr}: {e}"))?,
                Duration::from_secs(5),
            ).map_err(|e| format!("Failed to connect to {target_addr}: {e}"))?;

            #[cfg(feature = "tls")]
            let peer_info = {
                println!("Establishing TLS 1.3 transport to {target_addr}...");
                let rsa_key = adb_protocol::auth::generate_rsa_key()?;
                let pem = adb_protocol::auth::export_private_key_to_pem(&rsa_key)?;
                let (cert_der, key_der) = adb_protocol::tls::generate_self_signed_cert(&pem)?;
                let tls_config = adb_protocol::tls::create_tls_config(cert_der, key_der)?;
                let (mut tls_stream, exported) = adb_protocol::tls::perform_tls_handshake_with_pairing_export(tcp_stream, tls_config, "localhost")?;

                println!("Executing SPAKE2+ key exchange and certificate pairing...");
                let peer_info = client.execute_pairing_with_exported_keys(&mut tls_stream, Some(&exported))
                    .map_err(|e| format!("Pairing failed with {target_addr}: {e}"))?;

                let home_dir = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
                let android_dir = home_dir.join(".android");
                let keystore = adb_protocol::pairing::save_adb_keystore(&rsa_key, "adb-rs", &android_dir)?;
                println!("Saved paired keystore to {}", keystore.public_key_path.display());
                peer_info
            };

            #[cfg(not(feature = "tls"))]
            {
                let _ = tcp_stream;
                return Err("TLS support is required for wireless pairing; rebuild with `--features tls`".into());
            }

            #[cfg(feature = "tls")]
            {
                let (serial, dev_name) = peer_info.parse_device_info();
                println!("Successfully paired to {target_addr} [device={}, serial={}]", dev_name, serial);
            }
        }

        Commands::Root => {
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("root:")?;
            server.read_status()?;
            let mut buf = [0u8; 8192];
            loop {
                let n = match server.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                std::io::stdout().write_all(&buf[..n])?;
            }
            std::io::stdout().flush()?;
        }

        Commands::Unroot => {
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("unroot:")?;
            server.read_status()?;
            let mut buf = [0u8; 8192];
            loop {
                let n = match server.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                std::io::stdout().write_all(&buf[..n])?;
            }
            std::io::stdout().flush()?;
        }

        Commands::Tcpip { port } => {
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            let service = format!("tcpip:{}", port);
            server.send_host_request(&service)?;
            server.read_status()?;
            let mut buf = [0u8; 8192];
            loop {
                let n = match server.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                std::io::stdout().write_all(&buf[..n])?;
            }
            std::io::stdout().flush()?;
        }

        Commands::Usb => {
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("usb:")?;
            server.read_status()?;
            let mut buf = [0u8; 8192];
            loop {
                let n = match server.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                std::io::stdout().write_all(&buf[..n])?;
            }
            std::io::stdout().flush()?;
        }

        _ => todo!("command not yet implemented"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            server::run_server_with_listener(listener, None);
        });

        let addr = format!("127.0.0.1:{port}");
        assert!(std::net::TcpStream::connect(&addr).is_ok());

        assert!(kill_server_at(port).is_ok());

        handle.join().unwrap();

        assert!(std::net::TcpStream::connect(&addr).is_err());
    }
}
