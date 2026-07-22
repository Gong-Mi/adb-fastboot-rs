use std::io::Write;
use std::time::Duration;
use clap::{Parser, Subcommand};
use adb_protocol::{
    AdbMessageHeader, ShellV2Packet, TcpTransport, Transport, TransportError,
    ADB_VERSION, A_AUTH, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_WRTE, MAX_PAYLOAD_V2,
};

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
}

fn resolve_target_addr(serial: Option<&str>, default_port: u16) -> String {
    match serial {
        Some(s) if s.contains(':') => s.to_string(),
        Some(s) => format!("{}:{}", s, default_port),
        None => format!("127.0.0.1:{}", default_port),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = resolve_target_addr(cli.serial.as_deref(), 5555);

    match cli.command {
        Commands::Devices => {
            println!("List of devices attached (adb-rs pure rust transport)");
            match TcpTransport::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(mut transport) => {
                    let cnxn_payload = b"host::features=shell_v2,cmd";
                    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
                    if let Err(e) = transport.send_message(&cnxn_hdr, cnxn_payload) {
                        eprintln!("Error sending ADB handshake to {}: {}", addr, e);
                        std::process::exit(1);
                    }
                    match transport.recv_message() {
                        Ok((resp_hdr, payload)) if resp_hdr.command == A_CNXN => {
                            let sys_info = String::from_utf8_lossy(&payload);
                            println!("{}\tdevice ({})", addr, sys_info.trim());
                        }
                        Ok((resp_hdr, _)) => {
                            println!("{}\tdevice (cmd={:#x})", addr, resp_hdr.command);
                        }
                        Err(e) => {
                            eprintln!("Error receiving handshake response from {}: {}", addr, e);
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
            let mut transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            // Handshake A_CNXN
            let cnxn_payload = b"host::features=shell_v2,cmd";
            let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
            transport.send_message(&cnxn_hdr, cnxn_payload)?;

            let (resp_hdr, _) = transport.recv_message()?;
            if resp_hdr.command != A_CNXN && resp_hdr.command != A_AUTH {
                eprintln!("Error: Unexpected handshake response (cmd {:#x})", resp_hdr.command);
                std::process::exit(1);
            }

            // Send A_OPEN frame
            let cmd_str = command.join(" ");
            let open_dest = if cmd_str.is_empty() {
                "shell,v2,raw:".to_string()
            } else {
                format!("shell,v2,raw:{}", cmd_str)
            };
            let local_id = 1u32;
            let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, open_dest.as_bytes());
            transport.send_message(&open_hdr, open_dest.as_bytes())?;

            // Read response stream loop
            let mut remote_id = 0u32;
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
                                            std::io::stdout().write_all(data)?;
                                            std::io::stdout().flush()?;
                                        }
                                        ShellV2Packet::Stderr(data) => {
                                            std::io::stderr().write_all(data)?;
                                            std::io::stderr().flush()?;
                                        }
                                        ShellV2Packet::ExitCode(code) => {
                                            if code != 0 {
                                                std::process::exit(code as i32);
                                            }
                                            return Ok(());
                                        }
                                        _ => {}
                                    }
                                    rest = &rest[consumed..];
                                }
                                Err(_) => {
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
        }
        Commands::Push { local, remote } => {
            let mut transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cnxn_payload = b"host::";
            let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
            transport.send_message(&cnxn_hdr, cnxn_payload)?;
            let _ = transport.recv_message()?;

            let sync_dest = b"sync:";
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, sync_dest);
            transport.send_message(&open_hdr, sync_dest)?;
            println!("[adb-rs] Connected sync transport to {} for push '{}' -> '{}'", addr, local, remote);
        }
        Commands::Pull { remote, local } => {
            let mut transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cnxn_payload = b"host::";
            let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
            transport.send_message(&cnxn_hdr, cnxn_payload)?;
            let _ = transport.recv_message()?;

            let sync_dest = b"sync:";
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, sync_dest);
            transport.send_message(&open_hdr, sync_dest)?;
            println!("[adb-rs] Connected sync transport to {} for pull '{}' -> '{}'", addr, remote, local);
        }
        Commands::Reboot { target } => {
            let mut transport: TcpTransport = match TcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cnxn_payload = b"host::";
            let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
            transport.send_message(&cnxn_hdr, cnxn_payload)?;
            let _ = transport.recv_message()?;

            let target_str = target.as_deref().unwrap_or("");
            let dest = format!("reboot:{}", target_str);
            let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, dest.as_bytes());
            transport.send_message(&open_hdr, dest.as_bytes())?;
            println!("[adb-rs] Reboot request sent to {}", addr);
        }
    }

    Ok(())
}
