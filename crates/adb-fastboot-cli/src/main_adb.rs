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
    let rest = addr.strip_prefix("tcp:")?;
    if let Some((_host, port_str)) = rest.rsplit_once(':') {
        port_str.parse().ok()
    } else {
        rest.parse().ok()
    }
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
    /// Push a single APK to device and install it
    Install {
        apk: String,
    },
    /// Push multiple APKs to device and install them
    #[command(name = "install-multiple")]
    InstallMultiple {
        #[arg(required = true)]
        apks: Vec<String>,
    },
    /// Atomic batch install of multiple APKs using pm install-create/write/commit
    #[command(name = "install-multi-package")]
    InstallMultiPackage {
        #[arg(required = true)]
        apks: Vec<String>,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = resolve_target_addr(cli.serial.as_deref(), ADBD_PORT);

    match &cli.command {
        Commands::Devices { long } => {
            if *long {
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
                                println!("{}\\tdevice ({})", direct_addr, device_info.banner.trim());
                                return Ok(());
                            }
                        }
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("List of devices attached (adb-rs pure rust transport)");
                match host_command(cli.serial.as_deref(), "host:devices") {
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
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
            if let Ok(mut server) = AdbServerTransport::connect_timeout(&server_addr, Duration::from_millis(300)) {
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

        Commands::InstallMultiple { apks } => {
            if apks.is_empty() {
                eprintln!("Error: no APK files specified");
                std::process::exit(1);
            }

            // Validate all APKs exist
            let apk_paths: Vec<&Path> = apks.iter().map(|a| Path::new(a)).collect();
            let mut missing = Vec::new();
            for (i, p) in apk_paths.iter().enumerate() {
                if !p.exists() {
                    missing.push(apks[i].clone());
                }
            }
            if !missing.is_empty() {
                eprintln!("Error: APK(s) not found: {}", missing.join(", "));
                std::process::exit(1);
            }

            // Connect to adbd
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            // Push each APK via sync protocol
            let staging = "/data/local/tmp";
            let mut remote_paths = Vec::new();
            for apk_path in &apk_paths {
                let apk_data = std::fs::read(apk_path)
                    .map_err(|e| format!("Cannot read {}: {e}", apk_path.display()))?;
                let file_name = apk_path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("package.apk");
                let remote_apk = format!("{staging}/{file_name}");

                let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;

                let mut send_buf = Vec::new();
                build_sync_send_req(&remote_apk, 0o644, &mut send_buf)
                    .map_err(|e| format!("Build SEND req failed: {e}"))?;
                println!("[adb-rs] Pushing {file_name} ({} bytes) to {remote_apk} ...", apk_data.len());

                protocol::send_wrte(&mut transport, local_id, remote_id, &send_buf)?;
                protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

                const MAX_CHUNK: usize = 64 * 1024;
                for chunk in apk_data.chunks(MAX_CHUNK) {
                    let mut data_buf = Vec::new();
                    build_sync_data_chunk(chunk, &mut data_buf)
                        .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
                    protocol::send_wrte(&mut transport, local_id, remote_id, &data_buf)?;
                }

                let mut done_buf = Vec::new();
                build_sync_done(0xFFFF_FFFF, &mut done_buf)
                    .map_err(|e| format!("Build DONE failed: {e}"))?;
                protocol::send_wrte(&mut transport, local_id, remote_id, &done_buf)?;
                protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

                let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                transport.send_message(&clse_hdr, &[])?;
                let _ = transport.recv_message();

                remote_paths.push(remote_apk);
            }

            // Run pm install with all remote paths
            let paths_str: Vec<&str> = remote_paths.iter().map(|s| s.as_str()).collect();
            let quoted: Vec<String> = paths_str.iter().map(|p| format!("\"{p}\"")).collect();
            let install_cmd = format!("pm install -r {}", quoted.join(" "));
            println!("[adb-rs] Installing {} APKs ...", apks.len());
            let result = shell::run_shell(&mut transport, &install_cmd, true)?;
            let output = result.unwrap_or_default();
            let output_str = String::from_utf8_lossy(&output).trim().to_string();

            if output_str.contains("Success") || output_str.contains("Success\n") {
                println!("[adb-rs] Install-multiple succeeded: {output_str}");
            } else if output_str.is_empty() {
                println!("[adb-rs] Install-multiple completed (no output)");
            } else {
                eprintln!("[adb-rs] Install-multiple output: {output_str}");
            }

            // Clean up temp APKs
            for rp in &remote_paths {
                let _ = shell::run_shell(&mut transport, &format!("rm -f \"{rp}\""), false);
            }
        }

        Commands::InstallMultiPackage { apks } => {
            if apks.is_empty() {
                eprintln!("Error: no APK files specified");
                std::process::exit(1);
            }

            // Validate all APKs exist
            let apk_paths: Vec<&Path> = apks.iter().map(|a| Path::new(a)).collect();
            let mut missing = Vec::new();
            for (i, p) in apk_paths.iter().enumerate() {
                if !p.exists() {
                    missing.push(apks[i].clone());
                }
            }
            if !missing.is_empty() {
                eprintln!("Error: APK(s) not found: {}", missing.join(", "));
                std::process::exit(1);
            }

            // Connect to adbd
            let transport = TcpTransport::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("Cannot connect to adbd at {addr}: {e}"))?;
            let (_info, mut transport) =
                connect_and_handshake_with_tls_upgrade(transport, b"host::", default_auth())?;

            // Push each APK via sync protocol
            let staging = "/data/local/tmp";
            let mut remote_paths = Vec::new();
            for apk_path in &apk_paths {
                let apk_data = std::fs::read(apk_path)
                    .map_err(|e| format!("Cannot read {}: {e}", apk_path.display()))?;
                let file_name = apk_path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("package.apk");
                let remote_apk = format!("{staging}/{file_name}");

                let (local_id, remote_id) = protocol::open_service(&mut transport, "sync:", 1)?;

                let mut send_buf = Vec::new();
                build_sync_send_req(&remote_apk, 0o644, &mut send_buf)
                    .map_err(|e| format!("Build SEND req failed: {e}"))?;
                println!("[adb-rs] Pushing {file_name} ({} bytes) ...", apk_data.len());

                protocol::send_wrte(&mut transport, local_id, remote_id, &send_buf)?;
                protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

                const MAX_CHUNK: usize = 64 * 1024;
                for chunk in apk_data.chunks(MAX_CHUNK) {
                    let mut data_buf = Vec::new();
                    build_sync_data_chunk(chunk, &mut data_buf)
                        .map_err(|e| format!("Build DATA chunk failed: {e}"))?;
                    protocol::send_wrte(&mut transport, local_id, remote_id, &data_buf)?;
                }

                let mut done_buf = Vec::new();
                build_sync_done(0xFFFF_FFFF, &mut done_buf)
                    .map_err(|e| format!("Build DONE failed: {e}"))?;
                protocol::send_wrte(&mut transport, local_id, remote_id, &done_buf)?;
                protocol::recv_sync_response(&mut transport, local_id, remote_id)?;

                let clse_hdr = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                transport.send_message(&clse_hdr, &[])?;
                let _ = transport.recv_message();

                remote_paths.push(remote_apk);
            }

            // Use pm install-create / install-write / install-commit
            println!("[adb-rs] Running pm install-create ...");
            let create_result = shell::run_shell(&mut transport, "pm install-create", true)?;
            let create_output = create_result.unwrap_or_default();
            let create_str = String::from_utf8_lossy(&create_output).trim().to_string();
            println!("[adb-rs] install-create output: {create_str}");

            // Extract session ID from output (format: "Success: created install session [1234567890]")
            let session_id = create_str
                .split('[')
                .nth(1)
                .and_then(|s| s.split(']').next())
                .unwrap_or("")
                .to_string();

            if session_id.is_empty() {
                eprintln!("[adb-rs] Failed to create install session. Output: {create_str}");
                // Still try to install individually
                for rp in &remote_paths {
                    let cmd = format!("pm install -r \"{rp}\"");
                    let _ = shell::run_shell(&mut transport, &cmd, false);
                }
            } else {
                // Write each APK to the session
                for rp in &remote_paths {
                    let name = Path::new(rp)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("split.apk");
                    let size = match std::fs::metadata(rp) {
                        Ok(m) => m.len(),
                        Err(_) => 0,
                    };
                    let _write_cmd = format!("pm install-write -S {size} {session_id} \"{name}\" < \"{rp}\"");
                    println!("[adb-rs] Writing {name} ({} bytes) to session {session_id} ...", size);
                    // Use shell exec (cat file | pm install-write ...)
                    let write_cmd_shell = format!("cat \"{rp}\" | pm install-write -S {size} {session_id} \"{name}\"");
                    let write_result = shell::run_shell(&mut transport, &write_cmd_shell, true)?;
                    let write_output = write_result.unwrap_or_default();
                    let write_str = String::from_utf8_lossy(&write_output).trim().to_string();
                    println!("[adb-rs] install-write output: {write_str}");
                }

                // Commit the session
                let commit_cmd = format!("pm install-commit {session_id}");
                println!("[adb-rs] Committing session {session_id} ...");
                let commit_result = shell::run_shell(&mut transport, &commit_cmd, true)?;
                let commit_output = commit_result.unwrap_or_default();
                let commit_str = String::from_utf8_lossy(&commit_output).trim().to_string();

                if commit_str.contains("Success") {
                    println!("[adb-rs] Install-multi-package succeeded: {commit_str}");
                } else if commit_str.is_empty() {
                    println!("[adb-rs] Install-multi-package completed (no output)");
                } else {
                    eprintln!("[adb-rs] Install-multi-package output: {commit_str}");
                }
            }

            // Clean up temp APKs
            for rp in &remote_paths {
                let _ = shell::run_shell(&mut transport, &format!("rm -f \"{rp}\""), false);
            }
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

        Commands::Mdns(MdnsCommands::Check) => {
            // AOSP commandline.cpp:1965-1968: adb_query_command("host:mdns:check").
            match host_command(cli.serial.as_deref(), "host:mdns:check") {
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
            match host_command(cli.serial.as_deref(), "host:mdns:services") {
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

        Commands::ForkServer { mode: _, reply_fd } => {
            let addr = cli.transport.as_deref().unwrap_or("tcp:127.0.0.1:5037");
            let port = parse_server_addr(addr).unwrap_or(ADB_SERVER_PORT);
            server::run_server_fork(Some(*reply_fd), port);
        }

        Commands::Connect { target } => {
            // Parse target as host:port
            let (host, port) = if let Some(idx) = target.rfind(':') {
                let h = &target[..idx];
                let p: u16 = target[idx+1..].parse().unwrap_or(5555);
                (h.to_string(), p)
            } else {
                (target.clone(), 5555)
            };
            let request = format!("host:connect:{}:{}", host, port);

            match host_command(cli.serial.as_deref(), &request) {
                Ok(_resp) => {
                    println!("connected to {}:{}", host, port);
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

        Commands::Reconnect { target } => {
            let server_addr = format!("127.0.0.1:{ADB_SERVER_PORT}");
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
            let path = Path::new(file);
            if path.exists() {
                eprintln!("Error: '{}' already exists", file);
                std::process::exit(1);
            }
            let private_path = if file.ends_with(".pub") {
                // User specified the public key file — derive private
                let priv_path = file.strip_suffix(".pub").unwrap_or(file);
                PathBuf::from(priv_path)
            } else {
                path.to_path_buf()
            };
            let public_path = {
                let mut p = private_path.clone();
                p.set_extension("pub");
                p
            };

            let auth = AdbAuth::generate("adb-rs@localhost")?;
            let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())?;
            write_private_key(&private_path, pem.as_bytes())?;
            let pub_bytes = auth.build_rsakey_payload()?;
            write_private_key(&public_path, &pub_bytes)?;
            println!("[adb-rs] Generated ADB key pair:");
            println!("       Private: {}", private_path.display());
            println!("       Public:  {}", public_path.display());
        }

        Commands::Remount { reboot } => {
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

                        protocol::send_wrte(transport, local_id, remote_id, &send_buf)?;
                        protocol::recv_sync_response(transport, local_id, remote_id)?;

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
                let result = host_command(cli.serial.as_deref(), "host:get-state");
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
}
