use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbAuth, AdbMessageHeader, AdbServerTransport, ShellV2Packet, TcpTransport, Transport,
    TransportError,
    ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_STLS, A_WRTE, MAX_PAYLOAD_V2,
    build_sync_send_req, build_sync_data_chunk, build_sync_done, SyncMessageHeader,
    SYNC_FAIL, SYNC_OKAY,
};

mod server;

const ADBD_PORT: u16 = 5555;
const ADB_SERVER_PORT: u16 = 5037;

#[derive(Parser)]
#[command(name = "adb-rs", author, version, about = "Rust ADB Command-Line Interface")]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
}

fn resolve_target_addr(serial: Option<&str>, default_port: u16) -> String {
    match serial {
        Some(s) if s.contains(':') => s.to_string(),
        Some(s) => format!("{}:{}", s, default_port),
        None => format!("127.0.0.1:{}", default_port),
    }
}

/// Information about the device received in the CNXN response banner.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub banner: String,
}

/// Get or create a default ADB auth key (singleton).
fn default_auth() -> &'static AdbAuth {
    static AUTH: OnceLock<AdbAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        AdbAuth::generate("adb-rs@localhost").expect("Failed to generate ADB auth key")
    })
}

/// Connect to adbd, perform CNXN handshake with A_STLS TLS upgrade support.
///
/// If the device responds with A_STLS, the transport is upgraded to TLS
/// using the auth key, and the CNXN handshake is retried over the encrypted channel.
#[cfg(feature = "tls")]
fn connect_and_handshake_with_tls_upgrade<T: Transport + 'static>(
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

    // Read response
    let (resp_hdr, payload) = transport.recv_message()?;

    if resp_hdr.command == A_CNXN {
        // Normal path — no TLS required
        let banner = String::from_utf8_lossy(&payload).to_string();
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
    _auth: &AdbAuth,
) -> Result<(DeviceInfo, Box<dyn Transport>), Box<dyn std::error::Error>> {
    let mut transport: Box<dyn Transport> = Box::new(transport);
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);

    transport.send_message(&cnxn_hdr, cnxn_payload)?;

    let (resp_hdr, payload) = transport.recv_message()?;
    if resp_hdr.command == A_STLS {
        return Err("Device requires TLS (A_STLS) but the `tls` feature is not enabled. \
                    Rebuild with --features tls"
            .into());
    }
    if resp_hdr.command != A_CNXN {
        return Err(format!("Unexpected handshake response: cmd={:#x}", resp_hdr.command).into());
    }

    let banner = String::from_utf8_lossy(&payload).to_string();
    Ok((DeviceInfo { banner }, transport))
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

/// Connect to ADB server (port 5037), switch transport, and execute a host command.
fn host_command(
    serial: Option<&str>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = resolve_target_addr(serial, ADB_SERVER_PORT);
    let mut server = AdbServerTransport::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("Cannot connect to ADB server at {addr}: {e}"))?;

    // Switch transport to target device
    server.switch_transport(serial)?;

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
            match TcpTransport::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(transport) => {
                    match connect_and_handshake_with_tls_upgrade(
                        transport,
                        b"host::features=shell_v2,cmd",
                        default_auth(),
                    ) {
                        Ok((device_info, _transport)) => {
                            println!("{}\tdevice ({})", addr, device_info.banner.trim());
                        }
                        Err(e) => {
                            eprintln!("Error during handshake with {}: {}", addr, e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Shell { command } => {
            let transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
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
            let transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
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
            let transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
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
            let transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
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
                format!("host:forward:remove:{rm}")
            } else if *remove_all {
                "host:forward:remove-all".to_string()
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
                format!("host:reverse:remove:{rm}")
            } else if *remove_all {
                "host:reverse:remove-all".to_string()
            } else if let (Some(rem), Some(loc)) = (remote, local) {
                if *no_rebind {
                    format!("host:reverse:norebind:{rem}:{loc}")
                } else {
                    format!("host:reverse:{rem}:{loc}")
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
    }

    Ok(())
}
