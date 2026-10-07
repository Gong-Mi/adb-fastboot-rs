//! Production CLI regressions against a strict plaintext TCP adbd peer.
//! AOSP packages/modules/adb @ 9084198a: adb_install.cpp streamed APEX
//! extension/feature gates, --apex, -S and raw payload contract. No USB,
//! system ADB server, real device or user adbkey is used.
use adb_protocol::{A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_WRTE};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const REMOTE_ID: u32 = 73;
const ALL_FEATURES: &str = "device::features=cmd,abb_exec,apex";

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// Independent daemon-side framing: do not reuse the client's codec or
// service-string builder as the expected wire oracle.
struct FakeAdbd(TcpStream);
impl FakeAdbd {
    fn recv(&mut self) -> io::Result<(u32, u32, u32, Vec<u8>)> {
        let mut header = [0u8; 24];
        self.0.read_exact(&mut header)?;
        let command = word(&header);
        assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
        let length = word(&header[12..]) as usize;
        assert!(length <= 1024 * 1024, "bounded ADB payload");
        let mut payload = vec![0; length];
        self.0.read_exact(&mut payload)?;
        let checksum = payload
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        assert!(word(&header[16..]) == 0 || word(&header[16..]) == checksum);
        Ok((command, word(&header[4..]), word(&header[8..]), payload))
    }

    fn send(&mut self, command: u32, arg0: u32, arg1: u32, payload: &[u8]) {
        let checksum = payload
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
        for field in [
            command,
            arg0,
            arg1,
            payload.len() as u32,
            checksum,
            command ^ u32::MAX,
        ] {
            self.0.write_all(&field.to_le_bytes()).unwrap();
        }
        self.0.write_all(payload).unwrap();
    }

    fn expect(&mut self, command: u32, local_id: u32) -> Vec<u8> {
        let (got, arg0, arg1, payload) = self.recv().unwrap();
        assert_eq!(got, command);
        assert_eq!((arg0, arg1), (local_id, REMOTE_ID), "negotiated stream IDs");
        payload
    }

    fn expect_eof(&mut self) {
        match self.recv() {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            other => panic!("CLI must close without any further OPEN or payload: {other:?}"),
        }
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Same already-public BoringSSL CRL test identity as adb_sync_cli.rs.
// Seed a private disposable HOME: avoid RSA prime-generation timing and never
// inspect/copy the user's key. The vendored fixture is not a live credential.
fn seed_public_test_identity(home: &Path) {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let source = include_str!("../../../vendor/boringssl/crypto/x509/x509_test.cc");
    let (_, note) = source
        .split_once("// kCRLTestRoot is a test root certificate. It has private key:")
        .expect("vendored public BoringSSL test identity");
    let begin = concat!("-----BEGIN ", "RSA PRIVATE KEY-----");
    let end = concat!("-----END ", "RSA PRIVATE KEY-----");
    let mut pem = String::new();
    for line in note.lines().filter_map(|line| line.strip_prefix("//     ")) {
        if line == begin || !pem.is_empty() {
            pem.push_str(line);
            pem.push('\n');
        }
        if line == end {
            break;
        }
    }
    assert!(pem.starts_with(begin) && pem.contains(end));
    let directory = home.join(".android");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("adbkey"))
        .unwrap();
    file.write_all(pem.as_bytes()).unwrap();
}

#[derive(Clone, Copy)]
enum Wire {
    AbbExec,
    ExecCmd,
}

enum Expectation {
    Install {
        wire: Wire,
        is_apex: bool,
        response: &'static str,
    },
    Reject {
        message: &'static str,
        connects: bool,
    },
}

fn run_cli(extension: &str, flags: &[&str], banner: &str, expected: Expectation) {
    use std::os::unix::fs::DirBuilderExt;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = Fixture(std::env::temp_dir().join(format!(
        "adb-apex-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::DirBuilder::new().mode(0o700).create(&root.0).unwrap();
    seed_public_test_identity(&root.0);
    let package = root.0.join(format!("package with spaces.{extension}"));
    // More than two stream chunks, including NULs and non-text bytes: no
    // shell quoting, SYNC framing, database encoding or truncation is legal.
    let bytes: Vec<u8> = (0..2 * 64 * 1024 + 17)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&package, &bytes).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let peer_done = done.clone();
    let banner = banner.as_bytes().to_vec();
    let (service, response) = match &expected {
        Expectation::Install {
            wire,
            is_apex,
            response,
        } => {
            let service = match wire {
                Wire::AbbExec => format!(
                    "abb_exec:package\0install\0-r\0-S\0{}{}",
                    bytes.len(),
                    if *is_apex { "\0--apex" } else { "" }
                ),
                Wire::ExecCmd => format!(
                    "exec:cmd package install -r -S {}{}",
                    bytes.len(),
                    if *is_apex { " --apex" } else { "" }
                ),
            };
            (Some(service.into_bytes()), response.as_bytes().to_vec())
        }
        Expectation::Reject { .. } => (None, Vec::new()),
    };
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(12);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if peer_done.load(Ordering::Acquire) {
                        return false;
                    }
                    assert!(Instant::now() < deadline, "CLI never completed");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        socket.set_nodelay(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut peer = FakeAdbd(socket);
        let (command, version, max_payload, host_banner) = peer.recv().unwrap();
        assert_eq!(command, A_CNXN);
        assert_eq!(version, 0x0100_0001);
        assert!(max_payload >= 64 * 1024);
        assert!(host_banner.starts_with(b"host::"));
        peer.send(A_CNXN, 0x0100_0001, 1024 * 1024, &banner);
        if let Some(service) = service {
            let (command, local_id, remote_id, opened) = peer.recv().unwrap();
            assert_eq!(command, A_OPEN);
            assert_eq!(remote_id, 0);
            assert_eq!(
                opened, service,
                "exact service, size, --apex; no incremental probe"
            );
            peer.send(A_OKAY, REMOTE_ID, local_id, &[]);
            let mut received = Vec::new();
            while received.len() < bytes.len() {
                let payload = peer.expect(A_WRTE, local_id);
                assert!(!payload.is_empty());
                received.extend_from_slice(&payload);
                assert!(received.len() <= bytes.len(), "no extra bytes");
                assert_eq!(
                    received,
                    bytes[..received.len()],
                    "raw original package payload"
                );
                peer.send(A_OKAY, REMOTE_ID, local_id, &[]);
            }
            assert_eq!(received, bytes);
            peer.send(A_WRTE, REMOTE_ID, local_id, &response);
            assert!(peer.expect(A_OKAY, local_id).is_empty());
            peer.send(A_CLSE, REMOTE_ID, local_id, &[]);
            assert!(peer.expect(A_CLSE, local_id).is_empty());
        }
        // Rejected inputs send no OPEN at all; successful/failed installs
        // cannot open a fallback, repeat install or send extra payload.
        peer.expect_eof();
        while !peer_done.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "CLI did not exit");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "no second connection/fallback"
        );
        true
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
        .arg("-s")
        .arg(address.to_string())
        .arg("install")
        .args(flags)
        .arg(&package)
        .env("HOME", &root.0)
        .env_remove("ADB_VENDOR_KEYS")
        // Force the riskiest default: APEX must still skip the settings probe
        // and incremental path. Each child has its own environment.
        .env("ADB_INSTALL_DEFAULT_INCREMENTAL", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut timed_out = false;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    done.store(true, Ordering::Release);
    let output = child.wait_with_output().unwrap();
    let peer_result = peer.join();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out,
        "CLI timed out: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        peer_result.is_ok(),
        "strict peer failed: rc={:?}, stdout={stdout}, stderr={stderr}",
        output.status.code()
    );
    let connected = peer_result.unwrap();
    match expected {
        Expectation::Install { response, .. } => {
            let success = response.starts_with("Success");
            assert_eq!(
                output.status.code(),
                Some(if success { 0 } else { 1 }),
                "{stderr}"
            );
            assert!(connected, "real CLI must reach adbd");
            assert!(stdout.contains("Performing Streamed Install"), "{stdout}");
            assert!(
                !stdout.contains("Incremental") && !stdout.contains("Push Install"),
                "{stdout}"
            );
            if success {
                assert!(
                    stdout.contains("Streamed install succeeded: Success"),
                    "{stdout}"
                );
            } else {
                assert!(stderr.contains(response.trim()), "{stderr}");
                assert!(!stdout.contains("succeeded"), "{stdout}");
            }
        }
        Expectation::Reject { message, connects } => {
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr.contains(message), "expected {message:?}: {stderr}");
            assert_eq!(
                connected, connects,
                "preflight/feature gate connection boundary"
            );
            assert!(
                !stdout.contains("succeeded") && !stdout.contains("Performing"),
                "{stdout}"
            );
        }
    }
}

#[test]
fn apex_explicit_streaming_uses_abb_exec_and_original_payload() {
    run_cli(
        "apex",
        &["--streaming"],
        ALL_FEATURES,
        Expectation::Install {
            wire: Wire::AbbExec,
            is_apex: true,
            response: "Success\n",
        },
    );
}

#[test]
fn apex_default_forces_streamed_despite_incremental_default() {
    run_cli(
        "apex",
        &[],
        ALL_FEATURES,
        Expectation::Install {
            wire: Wire::AbbExec,
            is_apex: true,
            response: "Success\n",
        },
    );
}

#[test]
fn apex_uppercase_extension_and_no_incremental_are_accepted() {
    run_cli(
        "APEX",
        &["--no-incremental"],
        ALL_FEATURES,
        Expectation::Install {
            wire: Wire::AbbExec,
            is_apex: true,
            response: "Success\n",
        },
    );
}

#[test]
fn apex_without_abb_exec_uses_exec_cmd_streaming() {
    run_cli(
        "apex",
        &[],
        "device::features=cmd,apex",
        Expectation::Install {
            wire: Wire::ExecCmd,
            is_apex: true,
            response: "Success\n",
        },
    );
}

#[test]
fn apex_device_failure_is_not_reported_as_success_or_retried() {
    run_cli(
        "apex",
        &["--streaming"],
        ALL_FEATURES,
        Expectation::Install {
            wire: Wire::AbbExec,
            is_apex: true,
            response: "Failure [INSTALL_FAILED_INVALID_APK]\n",
        },
    );
}

#[test]
fn apex_missing_feature_is_rejected_before_any_open() {
    run_cli(
        "apex",
        &[],
        "device::features=cmd,abb_exec",
        Expectation::Reject {
            message: ".apex is not supported on the target device",
            connects: true,
        },
    );
}

#[test]
fn apex_without_cmd_cannot_silently_use_push_or_incremental() {
    run_cli(
        "apex",
        &[],
        "device::features=abb_exec,apex",
        Expectation::Reject {
            message: "Attempting to use streaming install on unsupported device",
            connects: true,
        },
    );
}

#[test]
fn apex_explicit_push_is_rejected_before_any_open() {
    run_cli(
        "apex",
        &["--no-streaming"],
        ALL_FEATURES,
        Expectation::Reject {
            message: "APEX packages are only compatible with Streamed Install",
            connects: false,
        },
    );
}

#[test]
fn apex_explicit_incremental_is_rejected_not_silently_streamed() {
    run_cli(
        "apex",
        &["--incremental"],
        ALL_FEATURES,
        Expectation::Reject {
            message: "--incremental does not support .apex files",
            connects: false,
        },
    );
}

#[test]
fn incorrect_extension_is_rejected_before_any_open() {
    run_cli(
        "zip",
        &[],
        ALL_FEATURES,
        Expectation::Reject {
            message: "filename doesn't end .apk or .apex:",
            connects: false,
        },
    );
}

#[test]
fn apk_streaming_regression_has_no_apex_argument() {
    run_cli(
        "apk",
        &["--streaming"],
        ALL_FEATURES,
        Expectation::Install {
            wire: Wire::AbbExec,
            is_apex: false,
            response: "Success\n",
        },
    );
}
