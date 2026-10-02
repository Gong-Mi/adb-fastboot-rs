//! Incremental ADB installation (adb install --incremental).
//!
//! AOSP sources: `client/adb_install.cpp`, `client/incremental.cpp`,
//! `client/incremental_utils.cpp`, and `client/incremental_server.cpp`.
//!
//! Handles:
//! - Incremental APK installation using the Incremental File System (IncFS)
//! - Splits APK into chunks and streams them on-demand
//! - Reduces install time for large APKs by allowing apps to start before
//!   the full APK is transferred
//!
//! Current status: AOSP Incremental File System installation is not implemented.
//! This module refuses explicit incremental requests instead of pretending that
//! `pm install --incremental` plus a `/proc/fs/incfs` probe implements AOSP's
//! signature/database/inc-server/`abb_exec` protocol.

use std::path::Path;

use adb_protocol::Transport;

use super::adb_install::{InstallOptions, install_apk, install_multiple};
use super::line_printer::LinePrinter;

/// Advisory kernel-state probe only: a visible `/proc/fs/incfs` entry does not
/// establish that AOSP incremental installation is usable. AOSP additionally
/// requires the `abb_exec` path, v4 signature validation, a database and the
/// incremental server; this helper must not be used to select an install mode.
pub fn incfs_mountpoint_visible(transport: &mut dyn Transport) -> Result<bool, Box<dyn std::error::Error>> {
    use super::protocol::open_service;
    use adb_protocol::AdbMessageHeader;
    use adb_protocol::A_CLSE;
    use adb_protocol::A_OKAY;
    use adb_protocol::A_WRTE;

    // Check if /proc/fs/incfs exists on the device
    let dest = "shell,v2,raw:ls /proc/fs/incfs 2>/dev/null".to_string();
    let (local_id, _remote_id) = match open_service(transport, &dest, 1) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let mut output = Vec::new();
    loop {
        let (hdr, payload) = match transport.recv_message() {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match hdr.command {
            A_CLSE => {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                break;
            }
            A_WRTE => {
                let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
                let _ = transport.send_message(&ack, &[]);
                output.extend_from_slice(&payload);
            }
            _ => {}
        }
    }

    let stdout = String::from_utf8_lossy(&output);
    Ok(stdout.contains("incfs") || stdout.contains("incremental"))
}

/// Install options for incremental installation.
#[derive(Debug, Clone)]
pub struct IncrementalOptions {
    /// Base install options.
    pub install_opts: InstallOptions,
    /// Enable incremental install (IncFS).
    pub incremental: bool,
    /// Timeout in seconds for the incremental installation.
    pub timeout_secs: u64,
}

impl Default for IncrementalOptions {
    fn default() -> Self {
        Self {
            install_opts: InstallOptions::default(),
            incremental: false,
            timeout_secs: 300,
        }
    }
}

/// Install an APK incrementally if IncFS is available.
///
/// Falls back to regular install if IncFS is not supported.
pub fn install_apk_incremental(
    transport: &mut dyn Transport,
    local_apk: &Path,
    options: &IncrementalOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    if options.incremental {
        return Err("Incremental ADB install is not implemented: refusing to substitute `pm install --incremental` for AOSP's signature/database/inc-server pipeline".into());
    }
    install_apk(transport, local_apk, &options.install_opts, printer)
}

/// Install multiple APKs incrementally.
pub fn install_multiple_incremental(
    transport: &mut dyn Transport,
    apks: &[&Path],
    options: &IncrementalOptions,
    printer: &mut LinePrinter,
) -> Result<(), Box<dyn std::error::Error>> {
    if options.incremental {
        return Err("Incremental ADB multi-package install is not implemented: refusing to install packages individually or pass a superficial `--incremental` flag".into());
    }
    install_multiple(transport, apks, &options.install_opts, printer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::{AdbMessageHeader, TransportError};
    use std::io::{Read, Write};

    #[derive(Default)]
    struct NoWireTransport {
        sent_messages: usize,
    }

    impl Read for NoWireTransport {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for NoWireTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Transport for NoWireTransport {
        fn send_message(
            &mut self,
            _header: &AdbMessageHeader,
            _payload: &[u8],
        ) -> Result<(), TransportError> {
            self.sent_messages += 1;
            Ok(())
        }

        fn recv_message(&mut self) -> Result<(AdbMessageHeader, Vec<u8>), TransportError> {
            Err(TransportError::Protocol("unexpected wire read".to_string()))
        }
    }

    #[test]
    fn explicit_incremental_request_is_rejected_before_opening_a_service() {
        let mut transport = NoWireTransport::default();
        let options = IncrementalOptions { incremental: true, ..Default::default() };
        let mut printer = LinePrinter::new();
        let error = install_apk_incremental(
            &mut transport,
            Path::new("not-read.apk"),
            &options,
            &mut printer,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not implemented"));
        assert_eq!(transport.sent_messages, 0);
    }

    #[test]
    fn explicit_incremental_multi_request_is_rejected_before_opening_a_service() {
        let mut transport = NoWireTransport::default();
        let options = IncrementalOptions { incremental: true, ..Default::default() };
        let mut printer = LinePrinter::new();
        let paths = [Path::new("one.apk"), Path::new("two.apk")];
        let error = install_multiple_incremental(
            &mut transport,
            &paths,
            &options,
            &mut printer,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not implemented"));
        assert_eq!(transport.sent_messages, 0);
    }
}
