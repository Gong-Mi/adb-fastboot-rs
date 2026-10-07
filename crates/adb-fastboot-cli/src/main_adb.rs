#![allow(dead_code, unused_variables)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbAuth, AdbMessageHeader, AdbServerTransport, TcpTransport, Transport,
    ADB_VERSION, A_AUTH, A_AUTH_TOKEN,
    A_CLSE, A_CNXN, A_OPEN, A_STLS, MAX_PAYLOAD_V2,
    build_sync_send_req, build_sync_data_chunk, build_sync_done,
    host_cnxn_payload,
};

mod server;
mod client;

use client::{adb_wifi, console, detach, file_sync, protocol, shell, exec_out};
use client::server_cmds::{ensure_server_running, kill_server};
use client::host_command::host_command;
use client::transport::resolve_target_addr;

pub const ADBD_PORT: u16 = 5555;
pub const ADB_SERVER_PORT: u16 = 5037;

/// Parse `tcp:host:port` or `tcp:port` from the `-L` argument. Returns port only.
fn parse_server_addr(addr: &str) -> Option<u16> {
    let rest = addr.strip_prefix("tcp:").unwrap_or(addr);
    if let Some((_host, port_str)) = rest.rsplit_once(':') {
        port_str.parse().ok()
    } else {
        rest.parse().ok()
    }
}

/// Resolve the ADB server port from CLI `-P`, CLI `-L`, env vars, or default 5037.
fn resolve_server_port(port_flag: Option<u16>, listen_flag: Option<&str>) -> u16 {
    if let Some(p) = port_flag {
        return p;
    }
    if let Some(l) = listen_flag {
        if let Some(p) = parse_server_addr(l) {
            return p;
        }
    }
    if let Ok(spec) = std::env::var("ADB_SERVER_SOCKET") {
        if let Some(p) = parse_server_addr(&spec) {
            return p;
        }
    }
    if let Ok(port_str) = std::env::var("ANDROID_ADB_SERVER_PORT") {
        if let Ok(p) = port_str.parse::<u16>() {
            return p;
        }
    }
    ADB_SERVER_PORT
}

/// Map `adb reconnect [device|offline]` to the AOSP host-service request.
fn reconnect_service(target: Option<&str>) -> Result<&'static str, String> {
    match target {
        None => Ok("host:reconnect"),
        Some("device") => Ok("reconnect"),
        Some("offline") => Ok("host:reconnect-offline"),
        Some(other) => Err(format!("unknown reconnect target '{other}'. Use 'device' or 'offline'.")),
    }
}

/// The only compression selection safe on the current V1 SYNC transfer path.
///
/// AOSP selects SEND_V2/RECV_V2 codecs only after checking adbd's advertised
/// `sendrecv_v2*` features. This client does not retain those negotiated
/// features after connecting, so requesting a codec must fail instead of being
/// silently downgraded to an uncompressed V1 transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncCompressionOption {
    None,
}

fn sync_compression_option(
    algorithm: Option<&str>,
    no_compress: bool,
) -> Result<SyncCompressionOption, String> {
    if no_compress && algorithm.is_some() {
        return Err("-z and -Z cannot be used together".to_string());
    }

    match algorithm {
        None | Some("none") => Ok(SyncCompressionOption::None),
        Some("any" | "brotli" | "lz4" | "zstd") => Err(
            "compression requires sendrecv_v2 feature negotiation, which is unavailable in this client"
                .to_string(),
        ),
        Some(other) => Err(format!("unexpected compression type '{other}'")),
    }
}

#[derive(Parser)]
#[command(name = "adb-rs", author, version, about = "Rust ADB Command-Line Interface")]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub serial: Option<String>,

    /// Direct connection to USB device
    #[arg(short = 'd', global = true)]
    pub d: bool,

    /// Transport address (-L tcp:localhost:5037)
    #[arg(short = 'L', long = "listen", global = true)]
    pub transport: Option<String>,

    /// Server port (-P 5037)
    #[arg(short = 'P', global = true)]
    pub port: Option<u16>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum MdnsCommands {
    /// Check mDNS availability
    Check,
    /// List all discovered services
    Services,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List connected devices
    Devices {
        /// Show detailed device info (long output)
        #[arg(short = 'l', long)]
        long: bool,
    },
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
    /// Run remote command feeding local stdin to its raw stdin
    /// (AOSP `adb exec-in`)
    ExecIn {
        command: Vec<String>,
    },
    /// Push local file to device
    Push {
        local: String,
        remote: String,
        /// Synchronize file timestamps (sync push only if newer)
        #[arg(long)]
        sync: bool,
        /// Compression algorithm (`none` is supported; codecs require unavailable device feature negotiation)
        #[arg(short = 'z')]
        algorithm: Option<String>,
        /// Disable compression
        #[arg(short = 'Z')]
        no_compress: bool,
    },
    /// Pull remote file from device
    Pull {
        remote: String,
        local: String,
        /// Preserve file timestamp and mode
        #[arg(short = 'a')]
        preserve: bool,
        /// Compression algorithm (`none` is supported; codecs require unavailable device feature negotiation)
        #[arg(short = 'z')]
        algorithm: Option<String>,
        /// Disable compression
        #[arg(short = 'Z')]
        no_compress: bool,
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
    /// Install one APK or APEX; APEX requires streamed mode and device apex support
    Install {
        /// Require streamed install; fail if the device lacks the cmd feature
        #[arg(long, conflicts_with = "no_streaming")]
        streaming: bool,
        /// Force legacy sync-push install even when streamed install is supported
        #[arg(long, conflicts_with = "streaming")]
        no_streaming: bool,
        /// Incremental (IncFS) install: requires a v4-signed file (with
        /// .idsig) for APKs, or pass to allow missing signatures explicitly
        #[arg(long, conflicts_with_all = ["streaming", "no_streaming", "no_incremental"])]
        incremental: bool,
        /// Never use incremental install (AOSP `--no-incremental`)
        #[arg(long)]
        no_incremental: bool,
        /// Block until the incremental server finishes streaming (AOSP `--wait`)
        #[arg(long)]
        wait: bool,
        apk: String,
    },
    /// Push multiple APKs to device and install them
    #[command(name = "install-multiple")]
    InstallMultiple {
        #[arg(required = true)]
        apks: Vec<String>,
        /// Incremental (IncFS) install of the whole set (AOSP
        /// install_multiple_app, adb_install.cpp:680-717)
        #[arg(long, conflicts_with = "no_incremental")]
        incremental: bool,
        /// Never use incremental install (AOSP `--no-incremental`)
        #[arg(long)]
        no_incremental: bool,
        /// Block until the incremental server finishes streaming (AOSP `--wait`)
        #[arg(long)]
        wait: bool,
    },
    /// Atomic batch install of multiple APKs using pm install-create/write/commit
    #[command(name = "install-multi-package")]
    InstallMultiPackage {
        #[arg(required = true)]
        apks: Vec<String>,
        /// Seconds to wait for staged APEX sessions to become ready before
        /// commit; forwarded verbatim to `install-commit` on success
        /// (adb_install.cpp:930-941).
        #[arg(long, value_name = "SECONDS")]
        staged_ready_timeout: Option<String>,
    },
    /// Sync a local directory to the device, pushing changed/new files
    Sync {
        /// Local directory to sync (default: current directory)
        directory: Option<String>,
        /// Remote destination path (default: /sdcard/)
        #[arg(default_value = "/sdcard/")]
        remote: String,
    },
    /// Wait for device to reach a given state
    /// Format: [TRANSPORT-]STATE where TRANSPORT is usb|local|any (default any)
    /// and STATE is device|recovery|rescue|sideload|bootloader|disconnect
    #[command(name = "wait-for", trailing_var_arg = true)]
    WaitFor {
        /// Full spec string, e.g. "device", "usb-device", "local-recovery"
        spec: Vec<String>,
    },
    /// Wait for device state 'device'
    #[command(name = "wait-for-device")]
    WaitForDevice,
    /// Wait for device state 'recovery'
    #[command(name = "wait-for-recovery")]
    WaitForRecovery,
    /// Wait for device state 'bootloader'
    #[command(name = "wait-for-bootloader")]
    WaitForBootloader,
    /// Wait for device state 'disconnect'
    #[command(name = "wait-for-disconnect")]
    WaitForDisconnect,
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
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Restart adbd listening on USB
    Usb,
    /// Show log output from device
    Logcat {
        #[arg(default_value = "logcat", trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Generate a bugreport and save to file
    Bugreport {
        path: Option<String>,
    },
    /// List JDWP PIDs (uses ADB server on port 5037)
    Jdwp,
    /// mDNS service operations
    #[command(name = "mdns", subcommand)]
    Mdns(MdnsCommands),
    /// Emulator console commands
    #[command(name = "emu")]
    Emu {
        args: Vec<String>,
    },
    /// Print version information
    #[command(name = "version")]
    Version,
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
    /// Start the ADB server daemon (AOSP compatibility)
    #[command(name = "server")]
    Server {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Start the ADB server daemon
    #[command(name = "start-server")]
    StartServer,
    /// Kill the running ADB server daemon
    #[command(name = "kill-server")]
    KillServer,
    /// Internal: fork-server mode (started by the adb client)
    #[command(name = "fork-server", hide = true)]
    ForkServer {
        /// Mode argument — AOSP passes "server" here (ignored)
        mode: Option<String>,

        #[arg(long = "reply-fd")]
        reply_fd: i32,
    },
    /// Internal: incremental streaming server (spawned by adb install with
    /// inherited fds; AOSP commandline.cpp:2213-2238)
    #[command(name = "inc-server", hide = true)]
    IncServer {
        /// Connection fd to the device (>= 3)
        connection_fd: i32,
        /// Output fd; non-protocol device output is forwarded here (>= 3)
        output_fd: i32,
        /// Signed files to serve; argument position is the file id
        files: Vec<String>,
    },
    /// Internal: A_WRTE ↔ plain-byte channel bridge for incremental installs
    /// (spawned by adb install; see client/incremental/pump.rs)
    #[command(name = "inc-pump", hide = true)]
    IncPump {
        /// Transport socket fd (>= 3); speaks raw A_WRTE frames to adbd
        transport_fd: i32,
        /// Channel fd (>= 3) carrying the plain pm byte stream
        channel_fd: i32,
        /// Local id of the open abb_exec service
        local_id: u32,
        /// Remote id of the open abb_exec service
        remote_id: u32,
    },
    /// Connect to a device via TCP/IP
    Connect {
        /// Device address (host:port)
        target: String,
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
    /// Reconnect device (optionally: device, offline)
    Reconnect {
        /// Target: "device" or "offline" (empty for default reconnect)
        target: Option<String>,
    },
    /// Attach to device (server-side)
    Attach,
    /// Detach from device to allow use by other processes
    Detach,
    /// Disable dm-verity on device
    #[command(name = "disable-verity")]
    DisableVerity,
    /// Enable dm-verity on device
    #[command(name = "enable-verity")]
    EnableVerity,
    /// Generate ADB RSA key pair
    Keygen {
        /// Output file path for the private key (adbkey)
        file: String,
    },
    /// Print public key corresponding to private key file
    Pubkey {
        /// Input private key file path
        file: String,
    },
    /// Remount partitions read-write
    Remount {
        /// Reboot after remount
        #[arg(short = 'R')]
        reboot: bool,
    },
    /// Sideload an OTA package
    Sideload {
        /// Path to the OTA package zip file
        ota_package: String,
    },
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
    //    let server_addr = server_addr.to_string();
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
///
/// AOSP semantics (adb_auth_init/load_userkey): `$HOME/.android/adbkey`,
/// generated on first use and reused afterwards. Falls back to an ephemeral
/// key only if the persistent store cannot be created/read. On Android,
/// AOSP_HOST_ADB_KEY_DIRS-style fallbacks are handled by adb_protocol's
/// key loader; HyperOS persistence is handled by `persist_adb_pubkey`.
pub fn default_auth() -> &'static AdbAuth {
    static AUTH: OnceLock<AdbAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        AdbAuth::load_persistent()
            .unwrap_or_else(|_| AdbAuth::generate("adb-rs@localhost").expect("Failed to generate ADB auth key"))
    })
}

fn adb_key_dirs() -> Vec<PathBuf> {
    // Kept for callers/tests that inspect ADB key directory candidates.
    // The active loader is adb_protocol's AdbAuth::load_persistent()
    // ($HOME/.android/adbkey); this list documents the Android fallbacks.
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs = Vec::with_capacity(2);
    if !home.is_empty() {
        dirs.push(PathBuf::from(&home).join(".android"));
    }
    dirs.push(PathBuf::from("/sdcard/.android"));
    dirs
}

#[allow(dead_code)]
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
    use std::io::Write;
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
    let mut transport: Box<dyn Transport> = Box::new(transport);

    // AOSP client semantics (adb.cpp handle_packet → A_AUTH/TOKEN, auth.cpp
    // send_auth_response): answer each A_AUTH TOKEN with a SIGNATURE from the
    // next key; when keys are exhausted send RSAPUBLICKEY once and wait.
    let mut responder = adb_protocol::AuthResponder::single(auth.clone());

    // Send initial CNXN
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    loop {
        let (resp_hdr, payload) = transport.recv_message()?;

        match resp_hdr.command {
            A_CNXN => {
                // Normal path — no TLS required
                let banner = String::from_utf8_lossy(&payload).to_string();

                // Persist the public key so future SIGNATURE verifications
                // succeed without requiring another authorization dialog
                // (HyperOS does not always persist via AdbDebuggingManager).
                #[cfg(target_os = "android")]
                if responder.pubkey_sent() {
                    persist_adb_pubkey(auth)?;
                }

                return Ok((DeviceInfo { banner }, transport));
            }
            A_AUTH if resp_hdr.arg0 == A_AUTH_TOKEN => {
                if payload.len() != 20 {
                    return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
                }
                if let Some((hdr, auth_payload)) = responder.respond_to_token(&payload)? {
                    transport.send_message(&hdr, &auth_payload)?;
                }
                continue;
            }
            A_STLS => break, // TLS upgrade path below
            _ => {
                return Err(format!(
                    "Unexpected handshake response: cmd={:#x}",
                    resp_hdr.command
                )
                .into());
            }
        }
    }

    // A_STLS received — upgrade to TLS and re-send CNXN.
    {
        use adb_protocol::tls;
        use adb_protocol::AdbTlsTransport;

        let rsa_pem = match adb_protocol::auth::export_private_key_to_pem(auth.private_key()) {
            Ok(pem) => pem,
            Err(e) => return Err(format!("Failed to export RSA key: {e}").into()),
        };
        let (cert_der, key_der) = match tls::generate_self_signed_cert(&rsa_pem) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[adb-auth] TLS cert generation failed (falling back to non-TLS): {e}");
                return Ok((DeviceInfo { banner: String::new() }, transport));
            }
        };
        let config = match tls::create_tls_config(cert_der, key_der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[adb-auth] TLS config creation failed (falling back to non-TLS): {e}");
                return Ok((DeviceInfo { banner: String::new() }, transport));
            }
        };

        let tls_transport = match AdbTlsTransport::new(transport, config, "adb") {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[adb-auth] TLS upgrade failed: {e}");
                return Err(format!("TLS upgrade failed: {e}").into());
            }
        };

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
        Ok((DeviceInfo { banner }, tls_box))
    }
}

/// Non-TLS fallback — A_STLS will return an error if the device requires TLS.
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
        if resp_hdr.command == A_AUTH && resp_hdr.arg0 == A_AUTH_TOKEN {
            if payload.len() != 20 {
                return Err(format!("Invalid ADB AUTH token length: {}", payload.len()).into());
            }
            if let Some((hdr, auth_payload)) = responder.respond_to_token(&payload)? {
                transport.send_message(&hdr, &auth_payload)?;
            }
            continue;
        }
        if resp_hdr.command != A_CNXN {
            return Err(format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into());
        }

        let banner = String::from_utf8_lossy(&payload).to_string();

        // Persist the public key so future SIGNATURE verifications succeed
        // without requiring another authorization dialog.
        #[cfg(target_os = "android")]
        if responder.pubkey_sent() {
            persist_adb_pubkey(auth)?;
        }

        return Ok((DeviceInfo { banner }, transport));
    }
}

/// AOSP install_app_incremental (adb_install.cpp:299-357) over an already
/// connected transport. Returns `Err(None)` for a silent failure (the caller
/// falls back to the regular install) and `Err(Some(message))` for a hard
/// failure (the caller prints `adb: <message>` and exits).
fn run_incremental_attempt(
    transport: &mut dyn Transport,
    files: &[&Path],
    silent: bool,
    wait: bool,
) -> Result<(), Option<String>> {
    if silent && !client::incremental::should_use_incremental_by_default(files) {
        return Err(None);
    }
    println!("Performing Incremental Install");
    let started = std::time::Instant::now();
    let executor = std::env::current_exe()
        .map_err(|error| Some(format!("Cannot resolve the adb executable path: {error}")))?;
    match client::incremental::install(transport, files, &[], silent, &executor.to_string_lossy()) {
        Ok(processes) => {
            println!(
                "Install command complete in {} ms",
                started.elapsed().as_millis()
            );
            if wait {
                client::incremental::wait_for_incremental_server(processes.server);
            }
            Ok(())
        }
        Err(_) if silent => Err(None),
        Err(error) => Err(Some(error)),
    }
}

/// Open a fresh connection to the device. AOSP's fallback installs run their
/// own `send_command` (each opens a new connection via `adb_connect`); mirror
/// that for the incremental fallback path so a consumed connection is left
/// behind.
fn fresh_transport(
    addr: &str,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let transport = TcpTransport::connect_timeout(addr, Duration::from_secs(3))
        .map_err(|error| format!("Cannot connect to adbd at {addr}: {error}"))?;
    let cnxn_payload = host_cnxn_payload();
    connect_and_handshake_with_tls_upgrade(transport, &cnxn_payload, default_auth())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = resolve_target_addr(cli.serial.as_deref(), ADBD_PORT);
    let server_port = resolve_server_port(cli.port, cli.transport.as_deref());
    let server_addr = format!("127.0.0.1:{server_port}");
    let host_cmd = |req: &str| -> Result<String, Box<dyn std::error::Error>> {
        client::host_command::host_command_at(server_port, cli.serial.as_deref(), req)
    };

    match &cli.command {
        Commands::Devices { long } => {
            if *long {
                println!("List of devices attached (adb-rs pure rust transport)");
                match host_cmd("host:devices-l") {
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
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("List of devices attached (adb-rs pure rust transport)");
                match host_cmd("host:devices") {
                    Ok(resp) => {
                        if !resp.is_empty() {
                            print!("{resp}");
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
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
            let server_addr = &server_addr;
            if let Ok(mut server) = AdbServerTransport::connect_timeout(server_addr, Duration::from_millis(300)) {
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
                &host_cnxn_payload(),
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
                        &host_cnxn_payload(),
                        default_auth(),
                    )?
                }
                Err(e) => return Err(e),
            };

            let (_lid, remote_id) = protocol::open_service(&mut transport, &shell_service, 1)?;
            shell::stream_shell_v2(&mut transport, _lid, remote_id, false)?;
        }
        Commands::ExecOut { command } | Commands::ExecIn { command } => {
            // AOSP commandline.cpp:1802: exec-in/exec-out open the raw `exec:`
            // service — no shell-v2 framing, no PTY. ADB escape rules apply
            // to the command arguments (exec_service_string).
            let exec_in = matches!(cli.command, Commands::ExecIn { .. });
            let exec_service = if exec_in {
                adb_protocol::exec_service_string(command)
            } else {
                format!("exec:{}", command.join(" "))
            };

            // Priority 1: ADB server (port 5037) — same pattern as shell.
            let server_addr = &server_addr;
            if let Ok(mut server) = AdbServerTransport::connect_timeout(server_addr, Duration::from_millis(300)) {
                if server.switch_transport(cli.serial.as_deref()).is_ok() {
                    // Send exec service via host service protocol
                    server.send_host_request(&exec_service)?;
                    server.read_status()?; // OKAY -> server created A_OPEN, device OK'd
                    // Raw forwarding mode — exec: outputs raw bytes, no ShellV2 framing
                    if exec_in {
                        exec_out::stream_raw_from_server(&mut server)?;
                    } else {
                        exec_out::stream_raw_server(&mut server, false)?;
                    }
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
                &host_cnxn_payload(),
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
                        &host_cnxn_payload(),
                        default_auth(),
                    )?
                }
                Err(e) => return Err(e),
            };

            if exec_in {
                exec_out::run_exec_in(&mut transport, &exec_service)?;
            } else {
                exec_out::run_exec_out_service(&mut transport, &exec_service)?;
            }
        }
        Commands::Push { local, remote, sync, algorithm, no_compress } => {
            let serial = cli.serial.as_deref();
            if *sync {
                return Err("--sync is not implemented for push".into());
            }
            let _compression = sync_compression_option(algorithm.as_deref(), *no_compress)?;
            match file_sync::push(serial, local, remote) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error: push failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Pull { remote, local, preserve, algorithm, no_compress } => {
            let serial = cli.serial.as_deref();
            let _compression = sync_compression_option(algorithm.as_deref(), *no_compress)?;
            match file_sync::pull(serial, remote, local, *preserve) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error: pull failed: {e}");
                    std::process::exit(1);
                }
            }
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

            match host_cmd(&request) {
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

            match host_cmd(&request) {
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

        Commands::Install {
            apk,
            streaming,
            no_streaming,
            incremental,
            no_incremental,
            wait,
        } => {
            let apk_path = Path::new(apk);
            if !apk_path.exists() {
                return Err(format!("APK not found: {apk}").into());
            }
            let extension = apk_path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default();
            let is_apex = extension.eq_ignore_ascii_case("apex");
            if !extension.eq_ignore_ascii_case("apk") && !is_apex {
                return Err(format!("filename doesn't end .apk or .apex: {apk}").into());
            }
            if is_apex && *no_streaming {
                return Err("APEX packages are only compatible with Streamed Install".into());
            }
            if is_apex && *incremental {
                return Err("--incremental does not support .apex files".into());
            }

            // APEX is a streamed-only package, not an unsigned incremental
            // companion. An explicit regular mode also bypasses the automatic
            // incremental settings probe in calculate_install_mode.
            let mode_from_args = if *streaming || is_apex {
                Some(client::adb_install::InstallMode::Streamed)
            } else if *no_streaming {
                Some(client::adb_install::InstallMode::Push)
            } else {
                None
            };
            let incremental_request = if *incremental {
                client::adb_install::CmdlineIncremental::Enable
            } else if *no_incremental {
                client::adb_install::CmdlineIncremental::Disable
            } else {
                client::adb_install::CmdlineIncremental::None
            };
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|error| format!("Cannot connect to adbd at {addr}: {error}"))?;
            let cnxn_payload = host_cnxn_payload();
            let (device_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &cnxn_payload,
                default_auth(),
            )?;

            if is_apex
                && !client::adb_install::CommandTransport::apex_supported(&device_info.banner)
            {
                return Err(".apex is not supported on the target device".into());
            }

            // AOSP calculate_install_mode (adb_install.cpp:353-415): pick the
            // primary mode and optional fallback; the incremental-by-default
            // path consults the abb_exec, env and device-setting gates.
            let best_mode = client::adb_install::select_install_mode(
                &device_info.banner,
                client::adb_install::InstallModeRequest::Auto,
            )?;
            let env_value = std::env::var("ADB_INSTALL_DEFAULT_INCREMENTAL").ok();
            let (primary, fallback) = match client::adb_install::calculate_install_mode(
                mode_from_args,
                incremental_request,
                client::adb_install::abb_exec_supported(&device_info.banner),
                env_value,
                best_mode,
                || match client::adb_install::probe_incremental_default_disabled(&mut transport) {
                    Ok(value) => value,
                    Err(message) => {
                        eprintln!(
                            "adb: retrieving the default device installation mode failed: {message}"
                        );
                        None
                    }
                },
            ) {
                Ok(plan) => plan,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };
            if (primary == client::adb_install::InstallMode::Streamed
                || fallback.unwrap_or(client::adb_install::InstallMode::Push)
                    == client::adb_install::InstallMode::Streamed)
                && best_mode == client::adb_install::InstallMode::Push
            {
                eprintln!("Attempting to use streaming install on unsupported device");
                std::process::exit(1);
            }

            let mut mode = primary;
            if mode == client::adb_install::InstallMode::Incremental {
                let silent = fallback.is_some();
                let files: [&Path; 1] = [apk_path];
                match run_incremental_attempt(&mut transport, &files, silent, *wait) {
                    Ok(()) => return Ok(()),
                    Err(None) => {
                        // AOSP's fallback install opens its own connection
                        // (`send_command` → `adb_connect`); mirror that so
                        // the consumed incremental connection is left behind.
                        mode = fallback.expect("silent attempts carry a fallback");
                        let (_, fresh) = fresh_transport(&addr)?;
                        transport = fresh;
                    }
                    Err(Some(message)) => {
                        eprintln!("adb: {message}");
                        std::process::exit(1);
                    }
                }
            }

            let options = client::adb_install::InstallOptions {
                reinstall: true,
                ..Default::default()
            };

            match mode {
                client::adb_install::InstallMode::Streamed => {
                    println!("Performing Streamed Install");
                    let cmd_transport = client::adb_install::CommandTransport::from_banner(&device_info.banner);
                    let output = client::adb_install::install_apk_streamed(
                        &mut transport,
                        apk_path,
                        &options,
                        cmd_transport,
                        &device_info.banner,
                    )?;
                    println!("[adb-rs] Streamed install succeeded: {}", output.trim());
                }
                client::adb_install::InstallMode::Push => {
                    println!("Performing Push Install");
                    let mut printer = client::line_printer::LinePrinter::new();
                    client::adb_install::install_apk(
                        &mut transport,
                        apk_path,
                        &options,
                        &mut printer,
                    )?;
                    println!("[adb-rs] Push install succeeded");
                }
                client::adb_install::InstallMode::Incremental => {
                    eprintln!("invalid install mode");
                    std::process::exit(1);
                }
            }
        }

        Commands::InstallMultiple { apks, incremental, no_incremental, wait } => {
            let apk_paths: Vec<&Path> = apks.iter().map(|apk| Path::new(apk)).collect();
            let missing: Vec<&str> = apks
                .iter()
                .filter(|apk| !Path::new(apk).exists())
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                return Err(format!("APK(s) not found: {}", missing.join(", ")).into());
            }

            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|error| format!("Cannot connect to adbd at {addr}: {error}"))?;
            let cnxn_payload = host_cnxn_payload();
            let (device_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, &cnxn_payload, default_auth())?;

            // AOSP install_multiple_app (adb_install.cpp:680-717): same
            // mode resolution as `install` (no mode flags on this command).
            let incremental_request = if *incremental {
                client::adb_install::CmdlineIncremental::Enable
            } else if *no_incremental {
                client::adb_install::CmdlineIncremental::Disable
            } else {
                client::adb_install::CmdlineIncremental::None
            };
            let best_mode = client::adb_install::select_install_mode(
                &device_info.banner,
                client::adb_install::InstallModeRequest::Auto,
            )?;
            let env_value = std::env::var("ADB_INSTALL_DEFAULT_INCREMENTAL").ok();
            let (primary, fallback) = match client::adb_install::calculate_install_mode(
                None,
                incremental_request,
                client::adb_install::abb_exec_supported(&device_info.banner),
                env_value,
                best_mode,
                || match client::adb_install::probe_incremental_default_disabled(&mut transport) {
                    Ok(value) => value,
                    Err(message) => {
                        eprintln!(
                            "adb: retrieving the default device installation mode failed: {message}"
                        );
                        None
                    }
                },
            ) {
                Ok(plan) => plan,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };

            let mut mode = primary;
            if mode == client::adb_install::InstallMode::Incremental {
                let silent = fallback.is_some();
                match run_incremental_attempt(&mut transport, &apk_paths, silent, *wait) {
                    Ok(()) => return Ok(()),
                    Err(None) => {
                        mode = fallback.expect("silent attempts carry a fallback");
                        let (_, fresh) = fresh_transport(&addr)?;
                        transport = fresh;
                    }
                    Err(Some(message)) => {
                        eprintln!("adb: {message}");
                        std::process::exit(1);
                    }
                }
            }

            let mut printer = client::line_printer::LinePrinter::new();
            let options = client::adb_install::InstallOptions {
                streaming: Some(mode == client::adb_install::InstallMode::Streamed),
                reinstall: true,
                ..Default::default()
            };
            client::adb_install::install_multiple(
                &mut transport,
                &apk_paths,
                &options,
                &mut printer,
                &device_info.banner,
            )?;
            println!("[adb-rs] Install-multiple succeeded");
        }

        Commands::InstallMultiPackage { apks, staged_ready_timeout } => {
            if apks.is_empty() {
                return Err("No APK files specified".into());
            }

            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|error| format!("Cannot connect to adbd at {addr}: {error}"))?;
            let cnxn_payload = host_cnxn_payload();
            let (device_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &cnxn_payload,
                default_auth(),
            )?;
            client::adb_install::install_multi_package(
                &mut transport,
                &apks,
                &device_info.banner,
                &client::adb_install::InstallOptions::default(),
                staged_ready_timeout.as_deref(),
            )?;
            println!("[adb-rs] Atomic multi-package install succeeded");
        }

        Commands::Uninstall { package } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
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
                &host_cnxn_payload(),
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

        Commands::Bugreport { path } => {
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) = connect_and_handshake_with_tls_upgrade(
                transport,
                &host_cnxn_payload(),
                default_auth(),
            )?;

            let dest = "shell,v2,raw:bugreport".to_string();
            println!("[adb-rs] Capturing bugreport from {addr} ...");
            let (local_id, remote_id) = protocol::open_service(&mut transport, &dest, 1)?;
            let captured = shell::stream_shell_v2(&mut transport, local_id, remote_id, true)?;
            let data = captured.unwrap_or_default();

            let out_path = path.as_deref().unwrap_or("bugreport.zip");
            std::fs::write(out_path, &data)
                .map_err(|e| format!("Failed to write bugreport to {out_path}: {e}"))?;
            println!("[adb-rs] Bugreport saved to {out_path} ({} bytes)", data.len());
        }

        Commands::Jdwp => {
            match host_cmd("host:jdwp") {
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

        Commands::Mdns(MdnsCommands::Check) => {
            // AOSP commandline.cpp:1965-1968: adb_query_command("host:mdns:check").
            match host_cmd("host:mdns:check") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Mdns(MdnsCommands::Services) => {
            // AOSP commandline.cpp:1969-1972.
            println!("List of discovered mdns services");
            match host_cmd("host:mdns:services") {
                Ok(resp) => print!("{}", resp),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Emu { args } => {
            // AOSP console.cpp adb_send_emulator_command: connect directly
            // to the emulator's console port on loopback (NOT a host service
            // — "host:emu:" does not exist in the ADB protocol).
            if args.is_empty() {
                eprintln!("error: no emulator command specified");
                std::process::exit(1);
            }
            console::adb_send_emulator_command(args, cli.serial.as_deref())?;
        }

        Commands::Version => {
            println!("Android Debug Bridge version {}", env!("CARGO_PKG_VERSION"));
            println!("Revision deadbeef1234-android");
        }

        Commands::GetState => {
            match host_cmd("host:get-state") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::GetSerialno => {
            match host_cmd("host:get-serialno") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::GetDevpath => {
            match host_cmd("host:get-devpath") {
                Ok(resp) => println!("{}", resp.trim()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Serve => {
            println!("[adb-rs] Starting ADB server on {server_addr} ...");
            server::run_server();
        }

        Commands::Server { args } => {
            let nodaemon = args.iter().any(|a| a == "nodaemon");
            if nodaemon {
                let default_spec = format!("tcp:127.0.0.1:{server_port}");
                let spec = cli.transport.as_deref().unwrap_or(&default_spec);
                server::run_server_fork(None, spec);
            } else {
                client::server_cmds::ensure_server_running_spec(cli.transport.as_deref(), server_port)?;
            }
        }

        Commands::StartServer => {
            client::server_cmds::ensure_server_running_spec(cli.transport.as_deref(), server_port)?;
        }

        Commands::KillServer => {
            let _ = client::server_cmds::kill_server_at(server_port);
        }

        Commands::ForkServer { mode: _, reply_fd } => {
            let default_spec = format!("tcp:127.0.0.1:{server_port}");
            let spec = cli.transport.as_deref().unwrap_or(&default_spec);
            server::run_server_fork(Some(*reply_fd), spec);
        }

        Commands::IncServer { connection_fd, output_fd, files } => {
            // AOSP commandline.cpp:2221-2237. `adb_register_socket` is a
            // no-op on unix (sysdeps.h:514).
            let connection_fd = *connection_fd;
            if !server::sysdeps_unix::is_valid_os_fd(connection_fd) {
                eprintln!("Invalid connection_fd number given: {connection_fd}");
                std::process::exit(1);
            }
            server::sysdeps_unix::close_on_exec(connection_fd);

            let output_fd = *output_fd;
            if !server::sysdeps_unix::is_valid_os_fd(output_fd) {
                eprintln!("Invalid output_fd number given: {output_fd}");
                std::process::exit(1);
            }
            server::sysdeps_unix::close_on_exec(output_fd);

            // AOSP returns the bool straight as an exit code, which inverts
            // it; keep the sane mapping instead (nobody checks it).
            let succeeded = client::incremental::serve(connection_fd, output_fd, files);
            std::process::exit(if succeeded { 0 } else { 1 });
        }

        Commands::IncPump { transport_fd, channel_fd, local_id, remote_id } => {
            let transport_fd = *transport_fd;
            if !server::sysdeps_unix::is_valid_os_fd(transport_fd) {
                eprintln!("Invalid transport_fd number given: {transport_fd}");
                std::process::exit(1);
            }
            server::sysdeps_unix::close_on_exec(transport_fd);

            let channel_fd = *channel_fd;
            if !server::sysdeps_unix::is_valid_os_fd(channel_fd) {
                eprintln!("Invalid channel_fd number given: {channel_fd}");
                std::process::exit(1);
            }
            server::sysdeps_unix::close_on_exec(channel_fd);

            match client::incremental::run_pump(transport_fd, channel_fd, *local_id, *remote_id) {
                Ok(()) => std::process::exit(0),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Connect { target } => {
            let request = format!("host:connect:{target}");
            match host_cmd(&request) {
                Ok(resp) => {
                    let trimmed = resp.trim();
                    if !trimmed.is_empty() {
                        println!("{trimmed}");
                    } else {
                        println!("connected to {target}");
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Disconnect { target } => {
            let request = match target {
                Some(t) => format!("host:disconnect:{}", t),
                None => "host:disconnect".to_string(),
            };

            match host_cmd(&request) {
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

            // Extract host and port from target_addr
            let (host, port) = match target_addr.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(5555)),
                None => (target_addr.clone(), 5555),
            };

            let device = adb_wifi::pair_device(&host, port, &pair_code, Duration::from_secs(5))
                .map_err(|e| format!("Pairing failed: {e}"))?;

            println!(
                "Paired to {} [serial={}, device={}]",
                device.addr(),
                device.serial.as_deref().unwrap_or("unknown"),
                device.device_name.as_deref().unwrap_or("unknown"),
            );
        }

        Commands::Root => {
            let server_addr = server_addr.to_string();
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
            let server_addr = server_addr.to_string();
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

        Commands::Tcpip { args } => {
            if args.is_empty() {
                eprintln!("adb: tcpip requires an argument");
                std::process::exit(1);
            }
            let port: u16 = match args[0].parse() {
                Ok(p) if p > 0 => p,
                _ => {
                    eprintln!("adb: tcpip: invalid port: {}", args[0]);
                    std::process::exit(1);
                }
            };
            let server_addr = server_addr.to_string();
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
            let server_addr = server_addr.to_string();
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

        Commands::Reconnect { target } => {
            let server_addr = server_addr.to_string();
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            let request = reconnect_service(target.as_deref())?;
            if target.as_deref() == Some("device") {
                server.switch_transport(cli.serial.as_deref())
                    .map_err(|e| format!("Failed to switch transport: {e}"))?;
            }
            server.send_host_request(request)?;
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

        Commands::Attach => {
            let server_addr = server_addr.to_string();
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("attach:")?;
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
        }

        Commands::Detach => {
            let serial = cli.serial.as_deref().unwrap_or("");
            match detach::detach_device(serial, None) {
                Ok(_) => println!("disconnected {}", serial),
                Err(e) => eprintln!("Error: {e}"),
            }
        }

        #[allow(unreachable_patterns)]
        Commands::DisableVerity => {
            let server_addr = server_addr.to_string();
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("disable-verity:")?;
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

        Commands::EnableVerity => {
            let server_addr = server_addr.to_string();
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            server.send_host_request("enable-verity:")?;
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

        Commands::Keygen { file } => {
            crate::client::auth::adb_auth_keygen(file)?;
        }

        Commands::Pubkey { file } => {
            let pubkey = crate::client::auth::adb_auth_pubkey(file)?;
            println!("{pubkey}");
        }

        Commands::Remount { reboot } => {
            let server_addr = server_addr.to_string();
            let mut server = match AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: ADB server not running. Start it with `adb-rs start-server`.");
                    std::process::exit(1);
                }
            };
            server.switch_transport(cli.serial.as_deref())
                .map_err(|e| format!("Failed to switch transport: {e}"))?;
            let service = if *reboot {
                "remount,-R".to_string()
            } else {
                "remount:".to_string()
            };
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

        Commands::Sideload { ota_package } => {
            let ota_path = Path::new(ota_package);
            if !ota_path.exists() {
                eprintln!("Error: OTA package not found: {ota_package}");
                std::process::exit(1);
            }
            let ota_data = std::fs::read(ota_path)
                .map_err(|e| format!("Cannot read {ota_package}: {e}"))?;
            let file_name = ota_path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("ota.zip");

            let transport = match open_adb_transport(cli.serial.as_deref(), cli.d, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            let (local_id, remote_id) = protocol::open_service(&mut transport, "sideload:", 1)?;

            // Send sideload header: filename length (4 bytes LE) + filename + data length (8 bytes LE) + data
            let name_bytes = file_name.as_bytes();
            let payload_len = 4 + name_bytes.len() + 8 + ota_data.len();
            println!("[adb-rs] Sideloading {file_name} ({} bytes) ...", ota_data.len());

            let mut send_buf = Vec::with_capacity(payload_len);
            // filename length (u32 LE)
            send_buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            // filename bytes
            send_buf.extend_from_slice(name_bytes);
            // data length (u64 LE)
            send_buf.extend_from_slice(&(ota_data.len() as u64).to_le_bytes());
            // data
            send_buf.extend_from_slice(&ota_data);

            protocol::send_wrte(&mut transport, local_id, remote_id, &send_buf)?;

            // Read response
            let (_hdr, payload) = transport.recv_message()?;
            let response = String::from_utf8_lossy(&payload);
            println!("{response}");

            // Close
            let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
            transport.send_message(&clse_hdr, &[])?;
            let _ = transport.recv_message();
        }

        Commands::Sync { directory, remote } => {
            let local_dir = directory.as_deref().unwrap_or(".");
            let local_path = Path::new(local_dir);
            if !local_path.is_dir() {
                eprintln!("Error: '{}' is not a directory", local_path.display());
                std::process::exit(1);
            }

            // Connect to adbd
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            let remote_base = remote.trim_end_matches('/');

            // Recursively walk local directory and push each file
            fn walk_and_push(
                transport: &mut dyn Transport,
                dir: &Path,
                base: &Path,
                remote_base: &str,
            ) -> Result<(), Box<dyn std::error::Error>> {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        walk_and_push(transport, &path, base, remote_base)?;
                    } else if path.is_file() {
                        let relative = path
                            .strip_prefix(base)
                            .unwrap_or(&path);
                        let relative_str = relative
                            .to_str()
                            .ok_or("Non-UTF-8 path")?;
                        let remote_path = format!("{remote_base}/{relative_str}");
                        let file_data = std::fs::read(&path)
                            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
                        let (local_id, remote_id) = protocol::open_service(transport, "sync:", 1)?;

                        let mut send_buf = Vec::new();
                        build_sync_send_req(&remote_path, 0o644, &mut send_buf)
                            .map_err(|e| format!("Build SEND req failed: {e}"))?;
                        println!("[adb-rs] Syncing {} -> {} ({} bytes)",
                            relative_str, remote_path, file_data.len());

                        // SEND gets an ADB A_OKAY transport ACK, not a SYNC result.
                        protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;

                        const MAX_CHUNK: usize = 64 * 1024;
                        for chunk in file_data.chunks(MAX_CHUNK) {
                            let mut data_buf = Vec::new();
                            build_sync_data_chunk(chunk, &mut data_buf)
                                .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
                            protocol::send_wrte(transport, local_id, remote_id, &data_buf)?;
                        }

                        let mut done_buf = Vec::new();
                        build_sync_done(0xFFFF_FFFF, &mut done_buf)
                            .map_err(|e| format!("Build DONE failed: {e}"))?;
                        protocol::send_wrte(transport, local_id, remote_id, &done_buf)?;
                        protocol::recv_sync_response(transport, local_id, remote_id)?;

                        let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                        transport.send_message(&clse_hdr, &[])?;
                        let _ = transport.recv_message();
                    }
                }
                Ok(())
            }

            let local_canon = local_path.canonicalize()
                .map_err(|e| format!("Cannot resolve path '{}': {e}", local_path.display()))?;
            match walk_and_push(&mut transport, &local_canon, &local_canon, remote_base) {
                Ok(()) => println!("[adb-rs] Sync complete: '{}' -> '{}'", local_path.display(), remote_base),
                Err(e) => {
                    eprintln!("[adb-rs] Sync error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::WaitForDevice => {
            let max_attempts = 60;
            let mut attempts = 0;
            loop {
                let result = host_cmd("host:get-state");
                if let Ok(resp) = &result {
                    if resp.trim() == "device" {
                        return Ok(());
                    }
                }
                attempts += 1;
                if attempts >= max_attempts {
                    eprintln!("error: timeout waiting for device");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::WaitForRecovery => {
            let max_attempts = 60;
            let mut attempts = 0;
            loop {
                let result = host_cmd("host:get-state");
                if let Ok(resp) = &result {
                    if resp.trim() == "recovery" {
                        return Ok(());
                    }
                }
                attempts += 1;
                if attempts >= max_attempts {
                    eprintln!("error: timeout waiting for recovery");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::WaitForBootloader => {
            let max_attempts = 60;
            let mut attempts = 0;
            loop {
                let result = host_cmd("host:get-state");
                if let Ok(resp) = &result {
                    if resp.trim() == "bootloader" {
                        return Ok(());
                    }
                }
                attempts += 1;
                if attempts >= max_attempts {
                    eprintln!("error: timeout waiting for bootloader");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::WaitForDisconnect => {
            let max_attempts = 60;
            let mut attempts = 0;
            loop {
                let result = host_cmd("host:get-state");
                if result.is_err() {
                    return Ok(());
                }
                attempts += 1;
                if attempts >= max_attempts {
                    eprintln!("error: timeout waiting for disconnect");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::WaitFor { spec } => {
            let spec_str = spec.join(" ");
            let spec_str = spec_str.trim();

            // Parse [TRANSPORT-]STATE
            let (transport_prefix, state) = if let Some(idx) = spec_str.rfind('-') {
                let prefix = &spec_str[..idx];
                let st = &spec_str[idx + 1..];
                (Some(prefix.to_string()), st.to_string())
            } else {
                (None, spec_str.to_string())
            };

            let valid_states = ["device", "recovery", "rescue", "sideload", "bootloader", "disconnect"];
            if !valid_states.contains(&state.as_str()) {
                eprintln!("Error: unknown state '{}'. Valid states: device, recovery, rescue, sideload, bootloader, disconnect", state);
                std::process::exit(1);
            }

            if let Some(ref t) = transport_prefix {
                let valid_prefixes = ["usb", "local", "any"];
                if !valid_prefixes.contains(&t.as_str()) {
                    eprintln!("Error: unknown transport '{}'. Valid transports: usb, local, any", t);
                    std::process::exit(1);
                }
            }

            let max_attempts = 60; // ~60 seconds
            let mut attempts = 0;

            println!("[adb-rs] Waiting for device state '{spec_str}' ...");

            loop {
                let result = host_cmd("host:get-state");
                let current_state = match &result {
                    Ok(resp) => resp.trim().to_string(),
                    Err(_) if state == "disconnect" => "disconnect".to_string(),
                    Err(e) => {
                        if attempts >= max_attempts {
                            eprintln!("Error: timeout waiting for device state '{spec_str}': {e}");
                            std::process::exit(1);
                        }
                        format!("error: {e}")
                    }
                };

                if current_state == state {
                    println!("[adb-rs] Device reached state '{state}'");
                    return Ok(());
                }

                if state == "disconnect" && current_state == "disconnect" {
                    println!("[adb-rs] Device disconnected");
                    return Ok(());
                }

                attempts += 1;
                if attempts >= max_attempts {
                    eprintln!("Error: timeout waiting for device state '{state}'. Last state: {current_state}");
                    std::process::exit(1);
                }

                // Show progress
                if attempts % 10 == 0 {
                    println!("[adb-rs] Still waiting for '{state}' (current: {current_state}, attempt {attempts}/{max_attempts}) ...");
                }

                std::thread::sleep(Duration::from_secs(1));
            }
        }

        #[allow(unreachable_patterns)]
        _ => todo!("command not yet implemented"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::server_cmds::kill_server_at;

    #[test]
    fn sync_compression_accepts_explicit_no_compression() {
        assert_eq!(sync_compression_option(Some("none"), false).unwrap(), SyncCompressionOption::None);
        assert_eq!(sync_compression_option(None, true).unwrap(), SyncCompressionOption::None);
    }

    #[test]
    fn sync_compression_rejects_enabled_codec_without_feature_negotiation() {
        let error = sync_compression_option(Some("zstd"), false).unwrap_err();
        assert!(error.contains("sendrecv_v2 feature negotiation"));
        assert!(error.contains("unavailable"));
    }

    #[test]
    fn sync_compression_rejects_unknown_algorithm() {
        assert_eq!(
            sync_compression_option(Some("snappy"), false).unwrap_err(),
            "unexpected compression type 'snappy'"
        );
    }

    #[test]
    fn reconnect_offline_uses_aosp_host_service() {
        assert_eq!(reconnect_service(Some("offline")).unwrap(), "host:reconnect-offline");
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
            server::run_server_with_listener(listener, None);
        });

        let addr = format!("127.0.0.1:{port}");
        assert!(std::net::TcpStream::connect(&addr).is_ok());

        assert!(kill_server_at(port).is_ok());

        handle.join().unwrap();

        assert!(std::net::TcpStream::connect(&addr).is_err());
    }

    #[test]
    fn test_cli_keygen_and_pubkey_subcommands() {
        use clap::Parser;
        let keygen_args = Cli::try_parse_from(["adb-rs", "keygen", "my_key"]).unwrap();
        match keygen_args.command {
            Commands::Keygen { file } => assert_eq!(file, "my_key"),
            _ => panic!("expected Keygen"),
        }

        let pubkey_args = Cli::try_parse_from(["adb-rs", "pubkey", "my_key"]).unwrap();
        match pubkey_args.command {
            Commands::Pubkey { file } => assert_eq!(file, "my_key"),
            _ => panic!("expected Pubkey"),
        }
    }
}
