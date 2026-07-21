use clap::{Parser, Subcommand};
use fastboot_protocol::FastbootResponse;

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Devices => {
            println!("List of fastboot devices (fastboot-rs pure rust protocol)");
            println!("dali_fastboot\tfastboot");
        }
        Commands::Getvar { variable } => {
            println!("[fastboot-rs] getvar:{}", variable);
            let dummy_resp = b"OKAY0.1";
            if let Ok(resp) = FastbootResponse::parse(dummy_resp) {
                println!("[fastboot-rs] Response: {:?}", resp);
            }
        }
        Commands::Flash { partition, file } => {
            println!("[fastboot-rs] Flashing partition '{}' with '{}'", partition, file);
        }
        Commands::Erase { partition } => {
            println!("[fastboot-rs] Erasing partition '{}'", partition);
        }
        Commands::Reboot { target } => {
            let target_str = target.as_deref().unwrap_or("system");
            println!("[fastboot-rs] Rebooting to target: {}", target_str);
        }
        Commands::Oem { command } => {
            println!("[fastboot-rs] OEM command: {}", command.join(" "));
        }
    }
}
