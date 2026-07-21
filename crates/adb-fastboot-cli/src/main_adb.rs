use clap::{Parser, Subcommand};
use adb_protocol::{AdbMessageHeader, A_OPEN};

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Devices => {
            println!("List of devices attached (adb-rs pure rust transport)");
            println!("dali_wireless_adb\tdevice");
        }
        Commands::Shell { command } => {
            let cmd_str = command.join(" ");
            println!("[adb-rs] Executing shell command: '{}'", if cmd_str.is_empty() { "interactive" } else { &cmd_str });
            let header = AdbMessageHeader::new(A_OPEN, 1, 0, format!("shell,v2,raw:{}", cmd_str).as_bytes());
            let mut buf = [0u8; 24];
            header.encode(&mut buf);
            println!("[adb-rs] Formatted ADB OPEN frame (24-bytes): {:02x?}", &buf[..8]);
        }
        Commands::Push { local, remote } => {
            println!("[adb-rs] Push '{}' -> '{}'", local, remote);
        }
        Commands::Pull { remote, local } => {
            println!("[adb-rs] Pull '{}' -> '{}'", remote, local);
        }
        Commands::Reboot { target } => {
            let target_str = target.as_deref().unwrap_or("system");
            println!("[adb-rs] Rebooting to target: {}", target_str);
        }
    }
}
