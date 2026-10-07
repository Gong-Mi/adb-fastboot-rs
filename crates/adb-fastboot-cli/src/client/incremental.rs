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

mod incremental_utils;

pub use incremental_utils::{
    encode_signature, read_id_sig_headers, read_signature, requires_v4_signature,
    validate_signature, verity_tree_blocks_for_file, verity_tree_size_for_file,
};

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
    device_banner: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if options.incremental {
        return Err("Incremental ADB multi-package install is not implemented: refusing to install packages individually or pass a superficial `--incremental` flag".into());
    }
    install_multiple(transport, apks, &options.install_opts, printer, device_banner)
}

/// AOSP `should_use_incremental_by_default` (incremental.cpp:295-315):
/// every file must exist, and v4-signature-requiring files (.apk/.sdm) must
/// carry a valid `.idsig` whose tree size matches the file size.
pub fn should_use_incremental_by_default(files: &[&Path]) -> bool {
    for file in files {
        let metadata = match std::fs::metadata(file) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        let path_string = file.to_string_lossy();
        if requires_v4_signature(&path_string) {
            let Ok(signature) = read_signature(&idsig_path_for(file)) else {
                return false;
            };
            if validate_signature(&signature.signature, signature.tree_size, metadata.len() as i64)
                .is_err()
            {
                return false;
            }
        }
    }
    true
}

/// AOSP signature path convention (incremental.cpp:129): `<file>` + ".idsig".
fn idsig_path_for(file: &Path) -> std::path::PathBuf {
    let mut path = file.as_os_str().to_os_string();
    path.push(incremental_utils::IDSIG_EXTENSION);
    std::path::PathBuf::from(path)
}

/// AOSP `ISDatabaseEntry` hierarchy (incremental.cpp:60-110): one entry per
/// input file, carrying its IncrementalServer file id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsDatabaseEntry {
    /// `ISSignedDatabaseEntry` — v4-signed, later streamed by inc-server.
    Signed {
        filename: String,
        size: u64,
        file_id: i32,
        /// Base64-encoded signature (with embedded length prefixes).
        signature: String,
        /// Local path, needed by inc-server args (incremental.cpp:455-457).
        path: std::path::PathBuf,
    },
    /// `ISUnsignedDatabaseEntry` — sent over the connection stdin before
    /// any signed streaming (incremental.cpp:96-110).
    Unsigned {
        filename: String,
        size: u64,
        file_id: i32,
    },
}

impl IsDatabaseEntry {
    pub fn is_v4_signed(&self) -> bool {
        matches!(self, IsDatabaseEntry::Signed { .. })
    }

    pub fn file_id(&self) -> i32 {
        match self {
            IsDatabaseEntry::Signed { file_id, .. } | IsDatabaseEntry::Unsigned { file_id, .. } => *file_id,
        }
    }

    /// AOSP `serialize()` (incremental.cpp:85-92):
    /// signed → `filename:size:file_id:signature:protocolVersion`,
    /// unsigned → `filename:size:file_id`. kProtocolVersion = 1
    /// (incremental.cpp:94).
    pub fn serialize(&self) -> String {
        const PROTOCOL_VERSION: i32 = 1;
        match self {
            IsDatabaseEntry::Signed {
                filename,
                size,
                file_id,
                signature,
                ..
            } => format!("{filename}:{size}:{file_id}:{signature}:{PROTOCOL_VERSION}"),
            IsDatabaseEntry::Unsigned {
                filename,
                size,
                file_id,
            } => format!("{filename}:{size}:{file_id}"),
        }
    }
}

/// AOSP `CheckPolicy` (incremental.cpp:44-49).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckPolicy {
    Normal,
    /// Allows missing signatures for files that would normally require a v4
    /// signature (stderr warning instead of failure).
    AllowMissingSignatures,
}

/// AOSP `build_database` (incremental.cpp:181-267): read `.idsig` for every
/// file, validate v4 signatures per check policy, then assign file ids —
/// signed files first (ids match list indexes so inc-server args line up),
/// unsigned files after, both in input order.
pub fn build_database(
    files: &[&Path],
    check_policy: CheckPolicy,
) -> Result<Vec<IsDatabaseEntry>, String> {
    let mut signatures_by_file: Vec<(std::path::PathBuf, Vec<u8>, i32)> = Vec::new();
    for file in files {
        let signature = read_signature(&idsig_path_for(file))?;
        if requires_v4_signature(&file.to_string_lossy()) && signature.signature.is_empty() {
            let message = format!("V4 signature missing for '{}'", file.display());
            if check_policy == CheckPolicy::AllowMissingSignatures {
                eprintln!("{message}.");
            } else {
                return Err(message);
            }
        }
        signatures_by_file.push((file.to_path_buf(), signature.signature, signature.tree_size));
    }

    let mut database = Vec::with_capacity(files.len());
    let mut file_id: i32 = 0;

    // Signed files first: file ids must equal list indexes (incremental.cpp:232-237).
    for (file, signature, tree_size) in &signatures_by_file {
        if signature.is_empty() {
            continue;
        }
        let size = std::fs::metadata(file)
            .map_err(|error| format!("Failed to open input file '{}': {}", file.display(), error))?
            .len();
        validate_signature(signature, *tree_size, size as i64)?;
        database.push(IsDatabaseEntry::Signed {
            filename: file
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("Invalid filename: {}", file.display()))?
                .to_string(),
            size,
            file_id: {
                let id = file_id;
                file_id += 1;
                id
            },
            signature: encode_signature(signature),
            path: file.clone(),
        });
    }

    // Unsigned files after, in input order (incremental.cpp:244-266).
    for (file, signature, _) in &signatures_by_file {
        if !signature.is_empty() {
            continue;
        }
        let size = std::fs::metadata(file)
            .map_err(|error| format!("Failed to open input file '{}': {}", file.display(), error))?
            .len();
        database.push(IsDatabaseEntry::Unsigned {
            filename: file
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("Invalid filename: {}", file.display()))?
                .to_string(),
            size,
            file_id: {
                let id = file_id;
                file_id += 1;
                id
            },
        });
    }

    Ok(database)
}

/// AOSP `connect_and_send_database` (incremental.cpp:269-293): the service
/// string is `abb_exec:package\0install-incremental\0<passthrough...>\0<entries...>`
/// — NUL-joined raw args over the device `abb_exec` service.
pub fn incremental_service_string(
    database: &[IsDatabaseEntry],
    passthrough_args: &[String],
) -> String {
    let mut args: Vec<String> = vec!["package".to_string(), "install-incremental".to_string()];
    args.extend(passthrough_args.iter().cloned());
    args.extend(database.iter().map(|entry| entry.serialize()));
    let mut service = String::from("abb_exec:");
    service.push_str(&args.join("\0"));
    service
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
            "device::features=cmd,shell_v2",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not implemented"));
        assert_eq!(transport.sent_messages, 0);
    }

    fn write_idsig(path: &Path, file_size: i64) {
        // Minimal valid .idsig v2 header whose treeSize matches `file_size`:
        // version=2, hashingInfo=[4]abcd, signingInfo=[3]xyz,
        // treeSize=verity_tree_size_for_file(file_size).
        let mut input = Vec::new();
        input.extend_from_slice(&2i32.to_le_bytes());
        input.extend_from_slice(&4i32.to_le_bytes());
        input.extend_from_slice(b"abcd");
        input.extend_from_slice(&3i32.to_le_bytes());
        input.extend_from_slice(b"xyz");
        input.extend_from_slice(&(verity_tree_size_for_file(file_size) as i32).to_le_bytes());
        std::fs::write(path, input).unwrap();
    }

    #[test]
    fn should_use_incremental_requires_valid_idsig_for_apks() {
        use incremental_utils::verity_tree_size_for_file;
        let root = std::env::temp_dir().join(format!("incr-default-{}", std::process::id()));

        // Missing file → false.
        assert!(!should_use_incremental_by_default(&[&root.join("gone.apk")]));

        // .apk without .idsig → signature empty → validate passes?? No:
        // read_signature returns empty for ENOENT and validate_signature
        // passes only when tree size expectation is 0 — a real APK is bigger.
        let apk = root.join("app.apk");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&apk, vec![0u8; 8192]).unwrap();
        assert!(!should_use_incremental_by_default(&[apk.as_path()]));

        // With a matching .idsig → true.
        write_idsig(&root.join("app.apk.idsig"), 8192);
        assert!(should_use_incremental_by_default(&[apk.as_path()]));

        // Wrong tree size → false.
        let mut bad = Vec::new();
        bad.extend_from_slice(&2i32.to_le_bytes());
        bad.extend_from_slice(&0i32.to_le_bytes());
        bad.extend_from_slice(&0i32.to_le_bytes());
        bad.extend_from_slice(&999i32.to_le_bytes());
        std::fs::write(root.join("app.apk.idsig"), bad).unwrap();
        assert!(!should_use_incremental_by_default(&[apk.as_path()]));

        // Non-apk file without idsig → still true (no v4 requirement).
        let txt = root.join("notes.txt");
        std::fs::write(&txt, b"hello").unwrap();
        assert!(should_use_incremental_by_default(&[txt.as_path()]));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn build_database_assigns_signed_ids_first_then_unsigned() {
        let root = std::env::temp_dir().join(format!("incr-db-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        // Signed APK (8192 bytes = 2 blocks, needs tree size 4096).
        let apk = root.join("app.apk");
        std::fs::write(&apk, vec![0u8; 8192]).unwrap();
        write_idsig(&root.join("app.apk.idsig"), 8192);

        // Unsigned non-apk file (no v4 requirement, no idsig).
        let txt = root.join("notes.txt");
        std::fs::write(&txt, b"hello").unwrap();

        let database = build_database(
            &[apk.as_path(), txt.as_path()],
            CheckPolicy::Normal,
        )
        .unwrap();

        assert_eq!(database.len(), 2);
        // Signed first, file_id 0 = its list index; carries base64 signature + path.
        match &database[0] {
            IsDatabaseEntry::Signed {
                filename,
                size,
                file_id,
                signature,
                path,
            } => {
                assert_eq!(filename, "app.apk");
                assert_eq!(*size, 8192);
                assert_eq!(*file_id, 0);
                assert_eq!(path, &apk);
                assert!(!signature.is_empty());
            }
            other => panic!("expected signed entry first, got {other:?}"),
        }
        // Unsigned after, id 1; serialization omits signature/version.
        match &database[1] {
            IsDatabaseEntry::Unsigned {
                filename,
                size,
                file_id,
            } => {
                assert_eq!(filename, "notes.txt");
                assert_eq!(*size, 5);
                assert_eq!(*file_id, 1);
            }
            other => panic!("expected unsigned entry second, got {other:?}"),
        }

        assert_eq!(
            database[0].serialize(),
            format!("app.apk:8192:0:{}:1", database[0].serialize().split(':').nth(3).unwrap())
        );
        assert_eq!(database[1].serialize(), "notes.txt:5:1");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn build_database_rejects_missing_v4_signature_under_normal_policy() {
        let root = std::env::temp_dir().join(format!("incr-db-miss-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let apk = root.join("bare.apk");
        std::fs::write(&apk, vec![0u8; 8192]).unwrap();

        let error = build_database(&[apk.as_path()], CheckPolicy::Normal).unwrap_err();
        assert!(error.contains("V4 signature missing"), "{error}");

        // AllowMissingSignatures warns but proceeds — the file lands unsigned.
        let database = build_database(&[apk.as_path()], CheckPolicy::AllowMissingSignatures).unwrap();
        assert_eq!(database.len(), 1);
        assert!(matches!(database[0], IsDatabaseEntry::Unsigned { .. }));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incremental_service_string_is_abb_exec_with_nul_joined_entries() {
        let entries = vec![
            IsDatabaseEntry::Signed {
                filename: "a.apk".into(),
                size: 4096,
                file_id: 0,
                signature: "QUJD".into(),
                path: std::path::PathBuf::from("/tmp/a.apk"),
            },
            IsDatabaseEntry::Unsigned {
                filename: "b.txt".into(),
                size: 3,
                file_id: 1,
            },
        ];

        let service = incremental_service_string(&entries, &["-r".to_string()]);
        assert_eq!(
            service,
            "abb_exec:package\0install-incremental\0-r\0a.apk:4096:0:QUJD:1\0b.txt:3:1"
        );
    }
}
