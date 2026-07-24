use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use clap::Parser;
use aidl_rs::{generate_rust, parse_aidl};

#[derive(Parser, Debug)]
#[command(name = "aidl-rs", author, version, about = "Android AIDL compiler to Rust bindings")]
struct Args {
    /// Input AIDL file path
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output Rust file path (prints to stdout if omitted)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let content = fs::read_to_string(&args.input)?;

    let parsed = parse_aidl(&content)
        .map_err(|e| format!("Failed to parse AIDL file '{:?}': {}", args.input, e))?;

    let generated = generate_rust(&parsed);

    if let Some(output_path) = args.output {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&output_path, generated)?;
    } else {
        io::stdout().write_all(generated.as_bytes())?;
    }

    Ok(())
}
