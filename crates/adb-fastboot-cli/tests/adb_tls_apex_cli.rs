//! Real executable CLI: plaintext STLS exchange -> mutually authenticated
//! TLS1.3 -> encrypted CNXN -> APEX OPEN/WRTE/status/CLSE. Independent fake
//! adbd framing and persisted-host SPKI authorization; no real device/server.
#[cfg(feature = "tls")]
#[path = "support/adb_tls.rs"]
#[allow(dead_code)]
mod support;

#[cfg(feature = "tls")]
mod encrypted {
    use super::support::*;
    use adb_protocol::{A_CLSE, A_OKAY, A_WRTE};
    use std::sync::atomic::{AtomicBool, Ordering};

    const REMOTE_ID: u32 = 73;
    const ALL_FEATURES: &[u8] = b"device::features=cmd,abb_exec,apex\0";

    #[derive(Clone, Copy)]
    enum Outcome {
        Success { abb_exec: bool },
        Failure,
        MissingApex,
        WrongHost,
    }

    fn expect_stream_frame(stream: &mut impl Read, command: u32, local_id: u32) -> Vec<u8> {
        let (got, local, remote, payload) = recv_frame(stream).unwrap();
        assert_eq!(got, command, "encrypted stream frame, not extra OPEN/CNXN");
        assert_eq!((local, remote), (local_id, REMOTE_ID));
        payload
    }

    fn expect_eof(stream: &mut impl Read) {
        match recv_frame(stream) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            other => panic!("must close, no extra OPEN/CNXN/WRTE; timeout is not EOF: {other:?}"),
        }
    }

    fn run_apex(tag: &str, flags: &[&str], banner: &[u8], outcome: Outcome) {
        let home = match outcome {
            Outcome::WrongHost => Home::with_pem(tag, &server_identity().2),
            _ => Home::new(tag),
        };
        // Read only this disposable HOME. The daemon's authorized identity
        // never follows an adversarial HOME to an unauthorized replacement key.
        let authorized_pem = match outcome {
            Outcome::WrongHost => HOST_PEM.to_string(),
            _ => std::fs::read_to_string(home.0.join(".android/adbkey")).unwrap(),
        };
        let authorized_spki = public_spki(&authorized_pem);
        let observed_spki = authorized_spki.clone();
        let config = server_config_for(false, authorized_spki);
        let package = home.0.join("package with spaces.apex");
        // Three WRTE chunks, NUL and non-text bytes, including a short tail.
        let bytes: Vec<u8> = (0..2 * 64 * 1024 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&package, &bytes).unwrap();
        let package_len = bytes.len();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let peer_done = done.clone();
        let banner = banner.to_vec();
        let peer = thread::spawn(move || {
            let socket = accept_stls(listener.try_clone().unwrap());
            // Independent rustls server handshake, not production ADB's helper.
            let mut stream =
                rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
            if matches!(outcome, Outcome::WrongHost) {
                let error = loop {
                    match stream.conn.complete_io(&mut stream.sock) {
                        Err(error) => break error,
                        Ok(_) => assert!(stream.conn.is_handshaking(), "wrong host completed TLS"),
                    }
                };
                assert!(
                    error.to_string().contains("ApplicationVerificationFailure"),
                    "{error}"
                );
                eprintln!("TLS+APEX wrong-host: handshake rejected with {error}; no CNXN/OPEN");
            } else {
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock).unwrap();
                }
                assert_eq!(
                    stream.conn.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
                let actual_certs = stream.conn.peer_certificates().unwrap();
                assert_eq!(actual_certs.len(), 1);
                assert_eq!(
                    certificate_spki(actual_certs[0].as_ref()).unwrap(),
                    observed_spki,
                    "actual cert SPKI equals the persisted authorized host key"
                );
                // Device sends encrypted CNXN immediately. No second host CNXN.
                send_stream_frame(&mut stream, A_CNXN, 0x0100_0001, 1024 * 1024, &banner);
                if !matches!(outcome, Outcome::MissingApex) {
                    let (command, local, remote, service) = recv_frame(&mut stream).unwrap();
                    assert_eq!(
                        command, A_OPEN,
                        "first encrypted host packet is APEX OPEN, never CNXN/probe"
                    );
                    assert_eq!(remote, 0);
                    assert_ne!(local, 0);
                    let expected_service =
                        if matches!(outcome, Outcome::Success { abb_exec: false }) {
                            format!("exec:cmd package install -r -S {} --apex", bytes.len())
                        } else {
                            format!("abb_exec:package\0install\0-r\0-S\0{}\0--apex", bytes.len())
                        };
                    assert_eq!(
                        service,
                        expected_service.as_bytes(),
                        "exact APEX transport/size/args"
                    );
                    send_stream_frame(&mut stream, A_OKAY, REMOTE_ID, local, &[]);
                    let mut received = Vec::new();
                    let mut wrtes = 0;
                    while received.len() < bytes.len() {
                        let payload = expect_stream_frame(&mut stream, A_WRTE, local);
                        assert!(!payload.is_empty());
                        received.extend_from_slice(&payload);
                        assert!(received.len() <= bytes.len(), "no extra package bytes");
                        assert_eq!(received, bytes[..received.len()], "original raw APEX bytes");
                        wrtes += 1;
                        send_stream_frame(&mut stream, A_OKAY, REMOTE_ID, local, &[]);
                    }
                    assert_eq!(received, bytes);
                    assert!(wrtes >= 3, "must exercise multiple encrypted WRTE chunks");
                    let response: &[u8] = if matches!(outcome, Outcome::Failure) {
                        b"Failure [INSTALL_FAILED_INVALID_APK]\n"
                    } else {
                        b"Success\n"
                    };
                    // Split the daemon status across encrypted WRTE packets.
                    for part in [&response[..3], &response[3..]] {
                        send_stream_frame(&mut stream, A_WRTE, REMOTE_ID, local, part);
                        assert!(expect_stream_frame(&mut stream, A_OKAY, local).is_empty());
                    }
                    send_stream_frame(&mut stream, A_CLSE, REMOTE_ID, local, &[]);
                    assert!(expect_stream_frame(&mut stream, A_CLSE, local).is_empty());
                    eprintln!("TLS+APEX: service={expected_service:?}, bytes={}, WRTE={wrtes}, remote_id={REMOTE_ID}; status={response:?}", bytes.len());
                }
                // Feature rejection emits zero OPEN; completed/failed installs
                // cannot retry, fall back to plaintext, or open a second service.
                expect_eof(&mut stream);
            }
            let deadline = Instant::now() + TIMEOUT;
            while !peer_done.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "CLI did not exit");
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "no second connection or plaintext fallback"
            );
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
            .args(["-s", &addr.to_string(), "install"])
            .args(flags)
            .arg(&package)
            .env("HOME", &home.0)
            .env_remove("ADB_VENDOR_KEYS")
            .env("ADB_INSTALL_DEFAULT_INCREMENTAL", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + TIMEOUT;
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
        assert!(!timed_out, "CLI timeout: {output:?}");
        assert!(peer_result.is_ok(), "peer contract failed: {output:?}");
        match outcome {
            Outcome::Success { .. } => {
                assert_eq!(output.status.code(), Some(0), "{stderr}");
                assert!(stdout.contains("Performing Streamed Install"), "{stdout}");
                assert!(
                    stdout.contains("Streamed install succeeded: Success"),
                    "{stdout}"
                );
            }
            Outcome::Failure => {
                assert_eq!(output.status.code(), Some(1));
                assert!(
                    stderr.contains("Failure [INSTALL_FAILED_INVALID_APK]"),
                    "{stderr}"
                );
                assert!(!stdout.contains("succeeded"), "{stdout}");
            }
            Outcome::MissingApex => {
                assert_eq!(output.status.code(), Some(1));
                assert!(
                    stderr.contains(".apex is not supported on the target device"),
                    "{stderr}"
                );
                assert!(!stdout.contains("Performing"), "{stdout}");
            }
            Outcome::WrongHost => {
                assert_eq!(output.status.code(), Some(1));
                assert!(stderr.contains("TLS upgrade failed"), "{stderr}");
                assert!(!stdout.contains("Performing"), "{stdout}");
            }
        }
        assert!(
            !stdout.contains("Incremental") && !stdout.contains("Push Install"),
            "{stdout}"
        );
        eprintln!(
            "{tag}: CLI rc={:?}, package_bytes={package_len}, stdout={stdout:?}, stderr={stderr:?}",
            output.status.code()
        );
    }

    #[test]
    fn apex_tls_abb_exec_streaming_success_original_payload() {
        run_apex(
            "apex-tls-streaming",
            &["--streaming"],
            ALL_FEATURES,
            Outcome::Success { abb_exec: true },
        );
    }

    #[test]
    fn apex_tls_default_is_streamed_without_incremental_probe_or_second_open() {
        run_apex(
            "apex-tls-default",
            &[],
            ALL_FEATURES,
            Outcome::Success { abb_exec: true },
        );
    }

    #[test]
    fn apex_tls_without_abb_exec_uses_exec_cmd() {
        run_apex(
            "apex-tls-exec",
            &[],
            b"device::features=cmd,apex\0",
            Outcome::Success { abb_exec: false },
        );
    }

    #[test]
    fn apex_tls_device_failure_returns_one_without_retry_or_second_open() {
        run_apex(
            "apex-tls-failure",
            &["--streaming"],
            ALL_FEATURES,
            Outcome::Failure,
        );
    }

    #[test]
    fn apex_tls_missing_apex_feature_sends_no_open() {
        run_apex(
            "apex-tls-feature",
            &[],
            b"device::features=cmd,abb_exec\0",
            Outcome::MissingApex,
        );
    }

    #[test]
    fn apex_tls_wrong_persisted_host_identity_is_rejected_before_open() {
        run_apex("apex-tls-wrong-host", &[], ALL_FEATURES, Outcome::WrongHost);
    }
}

// A no-default run reporting zero TLS tests is not evidence of rejecting STLS.
// This explicit CLI case is discovered only in the non-TLS configuration.
#[cfg(not(feature = "tls"))]
mod disabled {
    use adb_protocol::{A_CNXN, A_STLS, A_STLS_VERSION};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    struct DisposableHome(PathBuf);
    impl Drop for DisposableHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cli_without_tls_explicitly_rejects_stls_without_open_or_client_hello() {
        let home = DisposableHome(
            std::env::temp_dir().join(format!("adb-stls-disabled-{}", std::process::id())),
        );
        std::fs::create_dir_all(home.0.join(".android")).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.0.join(".android/adbkey"))
            .unwrap();
        file.write_all(include_str!("fixtures/public-rsa2048-host.pem").as_bytes())
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "CLI never connected");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = [0; 24];
            socket.read_exact(&mut header).unwrap();
            let word = |index| u32::from_le_bytes(header[index..index + 4].try_into().unwrap());
            assert_eq!(word(0), A_CNXN);
            assert_eq!(word(20), A_CNXN ^ u32::MAX);
            let size = word(12) as usize;
            assert!(size <= 1024 * 1024);
            let mut banner = vec![0; size];
            socket.read_exact(&mut banner).unwrap();
            assert!(banner.starts_with(b"host::"));
            for field in [A_STLS, A_STLS_VERSION, 0, 0, 0, A_STLS ^ u32::MAX] {
                socket.write_all(&field.to_le_bytes()).unwrap();
            }
            socket.flush().unwrap();
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => {
                    panic!("no OPEN/STLS reply/ClientHello; timeout is not closure: {other:?}")
                }
            }
        });
        // Seed an independent disposable HOME; never read the user's key.
        let mut child = Command::new(env!("CARGO_BIN_EXE_adb-rs"))
            .args(["-s", &addr.to_string(), "reboot", "tls-disabled-fixture"])
            .env("HOME", &home.0)
            .env_remove("ADB_VENDOR_KEYS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                panic!("non-TLS CLI did not reject STLS");
            }
            thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        peer.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Device requires TLS (A_STLS) but the `tls` feature is not enabled"),
            "{stderr}"
        );
        assert!(stderr.contains("Rebuild with --features tls"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Reboot request sent"));
        eprintln!(
            "explicit non-TLS STLS rejection: CLI rc={:?}, stderr={stderr:?}",
            output.status.code()
        );
    }
}
