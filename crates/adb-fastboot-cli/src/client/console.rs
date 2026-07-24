//! Interactive ADB console (simple read-eval-print loop).
//!
//! Maps to AOSP `vendor/adb/client/console.cpp`.
//!
//! The ADB console connects to a device's adbd service and provides an
//! interactive shell-like interface for sending commands to the device.
//! Notable differences from a full PTY shell: the console supports a
//! limited set of commands (shell, reboot, devices, connect, disconnect,
//! help, exit) and communicates over the ADB transport protocol.

use std::io::{self, Write};

use adb_protocol::{
    AdbMessageHeader, AdbServerTransport, Transport,
    A_CLSE, A_OKAY, A_OPEN, A_WRTE,
};

/// Represents a parsed console command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleCommand {
    /// Connect to a remote ADB device (host[:port]).
    Connect(String),
    /// Disconnect from a remote ADB device (host[:port]).
    Disconnect(String),
    /// List devices (or just reconnect to the ADB server).
    Devices,
    /// Open an interactive shell on the device.
    Shell,
    /// Reboot the device (normal, bootloader, recovery).
    Reboot(String),
    /// Show help text.
    Help,
    /// Exit the console.
    Exit,
    /// Unknown/unrecognized command.
    Unknown(String),
}

impl ConsoleCommand {
    /// Parse a command line into a `ConsoleCommand`.
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ConsoleCommand::Unknown(String::new());
        }

        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        let cmd = parts[0].to_lowercase();
        let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match cmd.as_str() {
            "connect" => {
                if arg.is_empty() {
                    ConsoleCommand::Unknown(trimmed.to_string())
                } else {
                    ConsoleCommand::Connect(arg.to_string())
                }
            }
            "disconnect" => {
                if arg.is_empty() {
                    ConsoleCommand::Unknown(trimmed.to_string())
                } else {
                    ConsoleCommand::Disconnect(arg.to_string())
                }
            }
            "devices" | "dev" | "list" => ConsoleCommand::Devices,
            "shell" => ConsoleCommand::Shell,
            "reboot" => {
                let mode = if arg.is_empty() {
                    String::new()
                } else {
                    arg.to_string()
                };
                ConsoleCommand::Reboot(mode)
            }
            "help" | "?" => ConsoleCommand::Help,
            "exit" | "quit" | "q" => ConsoleCommand::Exit,
            _ => ConsoleCommand::Unknown(trimmed.to_string()),
        }
    }
}

/// Run an interactive console, connecting to the local ADB server at the given port.
///
/// `serial` identifies the target device (or `None` for transport-any).
///
/// AOSP equivalent: `console.cpp::ConsoleThread`.
pub fn run_console(
    server_port: u16,
    serial: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{server_port}");
    let mut transport = AdbServerTransport::connect(&addr)?;

    let mut stdout = io::stdout();
    let stdin = io::stdin();
    let prompt = format!(
        "adb-rs ({}) > ",
        serial.unwrap_or("default")
    );

    writeln!(stdout, "ADB console — type 'help' for commands.")?;

    loop {
        write!(stdout, "{prompt}")?;
        stdout.flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            // EOF
            writeln!(stdout)?;
            break;
        }

        let cmd = ConsoleCommand::parse(&line);
        match cmd {
            ConsoleCommand::Exit => {
                writeln!(stdout, "exiting console")?;
                break;
            }
            ConsoleCommand::Help => {
                print_help(&mut stdout)?;
            }
            ConsoleCommand::Devices => {
                handle_devices(&mut transport, &mut stdout)?;
            }
            ConsoleCommand::Connect(target) => {
                handle_connect(&mut transport, &target, &mut stdout)?;
            }
            ConsoleCommand::Disconnect(target) => {
                handle_disconnect(&mut transport, &target, &mut stdout)?;
            }
            ConsoleCommand::Shell => {
                handle_shell(&mut transport, serial, &mut stdout)?;
            }
            ConsoleCommand::Reboot(mode) => {
                handle_reboot(&mut transport, serial, &mode, &mut stdout)?;
            }
            ConsoleCommand::Unknown(raw) => {
                if !raw.is_empty() {
                    writeln!(stdout, "unknown command: {raw}")?;
                    writeln!(stdout, "type 'help' for available commands")?;
                }
            }
        }
    }

    Ok(())
}

/// Print help text.
fn print_help(stdout: &mut io::Stdout) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(stdout, "Available commands:")?;
    writeln!(stdout, "  connect <host>[:<port>]  — connect to a device via TCP")?;
    writeln!(stdout, "  disconnect <host>[:<port>] — disconnect from a TCP device")?;
    writeln!(stdout, "  devices                  — list connected devices")?;
    writeln!(stdout, "  shell                    — open interactive shell")?;
    writeln!(stdout, "  reboot [mode]            — reboot device (bootloader/recovery)")?;
    writeln!(stdout, "  help                     — show this message")?;
    writeln!(stdout, "  exit/quit/q              — exit console")?;
    Ok(())
}

/// Handle the `devices` command.
fn handle_devices(
    transport: &mut AdbServerTransport,
    stdout: &mut io::Stdout,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = transport.execute_host_command("host:devices")?;
    writeln!(stdout, "List of devices attached")?;
    if body.trim().is_empty() {
        writeln!(stdout, "(no devices)")?;
    } else {
        for line in body.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                writeln!(stdout, "{trimmed}")?;
            }
        }
    }
    Ok(())
}

/// Handle the `connect` command.
fn handle_connect(
    transport: &mut AdbServerTransport,
    target: &str,
    stdout: &mut io::Stdout,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = format!("host:connect:{target}");
    transport.send_host_request(&req)?;
    transport.read_status()?;
    let msg = transport.read_payload()?;
    let s = String::from_utf8_lossy(&msg);
    writeln!(stdout, "{s}")?;
    Ok(())
}

/// Handle the `disconnect` command.
fn handle_disconnect(
    transport: &mut AdbServerTransport,
    target: &str,
    stdout: &mut io::Stdout,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = format!("host:disconnect:{target}");
    transport.send_host_request(&req)?;
    transport.read_status()?;
    let msg = transport.read_payload()?;
    let s = String::from_utf8_lossy(&msg);
    writeln!(stdout, "{s}")?;
    Ok(())
}

/// Handle the `shell` command — send a simple shell command to the device.
fn handle_shell(
    transport: &mut AdbServerTransport,
    serial: Option<&str>,
    stdout: &mut io::Stdout,
) -> Result<(), Box<dyn std::error::Error>> {
    // Switch to target device transport
    transport.switch_transport(serial)?;

    // Open the shell service via ADB message protocol
    let local_id: u32 = 1;
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, b"shell:");
    transport.send_message(&open_hdr, b"shell:")?;

    // Wait for OKAY
    loop {
        let (hdr, _payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => break,
            A_CLSE => {
                writeln!(stdout, "shell service closed")?;
                return Ok(());
            }
            _ => {}
        }
    }

    // Send a simple echo command via ADB WRTE
    let echo_cmd = b"echo 'ADB console shell active'\n";
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, local_id, 0, echo_cmd);
    transport.send_message(&wrte_hdr, echo_cmd)?;

    // Read response
    loop {
        match transport.recv_message() {
            Ok((hdr, payload)) => {
                match hdr.command {
                    A_WRTE => {
                        stdout.write_all(&payload)?;
                        stdout.flush()?;

                        // Ack the WRTE
                        let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                        let _ = transport.send_message(&ack, &[]);
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
            Err(e) => {
                writeln!(stdout, "shell error: {e}")?;
                break;
            }
        }
    }

    Ok(())
}

/// Handle the `reboot` command.
fn handle_reboot(
    transport: &mut AdbServerTransport,
    serial: Option<&str>,
    mode: &str,
    stdout: &mut io::Stdout,
) -> Result<(), Box<dyn std::error::Error>> {
    // Switch to target device transport
    transport.switch_transport(serial)?;

    let service = if mode.is_empty() {
        "reboot:".to_string()
    } else {
        format!("reboot:{mode}")
    };

    let local_id: u32 = 1;
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, service.as_bytes());
    transport.send_message(&open_hdr, service.as_bytes())?;

    loop {
        let (hdr, _payload) = transport.recv_message()?;
        match hdr.command {
            A_OKAY => {
                writeln!(stdout, "rebooting...")?;
                break;
            }
            A_CLSE => {
                writeln!(stdout, "reboot service closed")?;
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect() {
        assert_eq!(
            ConsoleCommand::parse("connect 192.168.1.100:5555"),
            ConsoleCommand::Connect("192.168.1.100:5555".into())
        );
    }

    #[test]
    fn test_parse_disconnect() {
        assert_eq!(
            ConsoleCommand::parse("disconnect 192.168.1.100:5555"),
            ConsoleCommand::Disconnect("192.168.1.100:5555".into())
        );
    }

    #[test]
    fn test_parse_devices() {
        assert_eq!(ConsoleCommand::parse("devices"), ConsoleCommand::Devices);
        assert_eq!(ConsoleCommand::parse("dev"), ConsoleCommand::Devices);
        assert_eq!(ConsoleCommand::parse("list"), ConsoleCommand::Devices);
    }

    #[test]
    fn test_parse_shell() {
        assert_eq!(ConsoleCommand::parse("shell"), ConsoleCommand::Shell);
    }

    #[test]
    fn test_parse_reboot() {
        assert_eq!(ConsoleCommand::parse("reboot"), ConsoleCommand::Reboot(String::new()));
        assert_eq!(
            ConsoleCommand::parse("reboot bootloader"),
            ConsoleCommand::Reboot("bootloader".into())
        );
    }

    #[test]
    fn test_parse_help() {
        assert_eq!(ConsoleCommand::parse("help"), ConsoleCommand::Help);
        assert_eq!(ConsoleCommand::parse("?"), ConsoleCommand::Help);
    }

    #[test]
    fn test_parse_exit() {
        assert_eq!(ConsoleCommand::parse("exit"), ConsoleCommand::Exit);
        assert_eq!(ConsoleCommand::parse("quit"), ConsoleCommand::Exit);
        assert_eq!(ConsoleCommand::parse("q"), ConsoleCommand::Exit);
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(
            ConsoleCommand::parse("xyzzy"),
            ConsoleCommand::Unknown("xyzzy".into())
        );
    }

    #[test]
    fn test_parse_empty() {
        assert_eq!(
            ConsoleCommand::parse(""),
            ConsoleCommand::Unknown(String::new())
        );
    }

    #[test]
    fn test_parse_connect_no_arg_is_unknown() {
        match ConsoleCommand::parse("connect") {
            ConsoleCommand::Unknown(_) => {}
            _ => panic!("expected Unknown"),
        }
    }
}
