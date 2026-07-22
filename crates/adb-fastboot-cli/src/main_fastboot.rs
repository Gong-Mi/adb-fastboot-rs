use std::time::Duration;
use clap::{Parser, Subcommand};
use fastboot_protocol::{FastbootTcpTransport, FastbootTransport};

#[derive(Parser)]
#[command(name = "fastboot-rs", author, version, about = "Rust Fastboot Command-Line Interface")]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List connected fastboot devices
    Devices,
    /// Get variable value from bootloader
    Getvar {
        variable: String,
    },
    /// Flash partition with image
    Flash {
        partition: String,
        file: String,
    },
    /// Erase partition
    Erase {
        partition: String,
    },
    /// Reboot device
    Reboot {
        target: Option<String>,
    },
    /// Send OEM command
    Oem {
        command: Vec<String>,
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
    let addr = resolve_target_addr(cli.serial.as_deref(), 5554);

    match cli.command {
        Commands::Devices => {
            println!("List of fastboot devices (fastboot-rs pure rust protocol)");
            match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(mut transport) => {
                    if let Ok(_) = transport.send_cmd("getvar:version") {
                        if let Ok(resp) = transport.recv_response() {
                            println!("{}\tfastboot ({:?})", addr, resp);
                        } else {
                            println!("{}\tfastboot", addr);
                        }
                    } else {
                        println!("{}\tfastboot", addr);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Getvar { variable } => {
            let mut transport: FastbootTcpTransport = match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("getvar:{}", variable);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Response: {:?}", resp);
        }
        Commands::Flash { partition, file } => {
            let mut transport: FastbootTcpTransport = match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] Connected to fastboot target {}", addr);
            let cmd = format!("flash:{}", partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Flash response for file '{}': {:?}", file, resp);
        }
        Commands::Erase { partition } => {
            let mut transport: FastbootTcpTransport = match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("erase:{}", partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Erase response: {:?}", resp);
        }
        Commands::Reboot { target } => {
            let mut transport: FastbootTcpTransport = match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let target_str = target.as_deref().unwrap_or("");
            let cmd = if target_str.is_empty() {
                "reboot".to_string()
            } else {
                format!("reboot-{}", target_str)
            };
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Reboot response: {:?}", resp);
        }
        Commands::Oem { command } => {
            let mut transport: FastbootTcpTransport = match FastbootTcpTransport::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("oem {}", command.join(" "));
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] OEM response: {:?}", resp);
        }
    }

    Ok(())
}
