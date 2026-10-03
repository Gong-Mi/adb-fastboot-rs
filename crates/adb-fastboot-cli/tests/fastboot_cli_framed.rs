//! Executable-CLI regressions against a strict AOSP FB01 TCP peer.
//! No USB/device access: every command is sent to an ephemeral loopback listener.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Peer(TcpStream);

impl Peer {
    fn accept(listener: TcpListener) -> Self {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI never connected");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut handshake = [0; 4];
        stream.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        stream.write_all(b"FB01").unwrap();
        Self(stream)
    }

    fn expect(&mut self, expected: &[u8]) {
        let mut header = [0; 8];
        self.0.read_exact(&mut header).unwrap();
        let length = u64::from_be_bytes(header);
        assert_eq!(length, expected.len() as u64, "wrong command/payload frame length");
        let mut payload = vec![0; length as usize];
        self.0.read_exact(&mut payload).unwrap();
        assert_eq!(payload, expected, "wrong command order or bytes");
    }

    fn send_fragmented(&mut self, messages: &[&[u8]]) {
        for message in messages {
            let mut wire = (message.len() as u64).to_be_bytes().to_vec();
            wire.extend_from_slice(message);
            // Split both the eight-byte frame header and response prefix/body.
            for fragment in wire.chunks(2) {
                self.0.write_all(fragment).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn expect_closed(&mut self) {
        assert_eq!(self.0.read(&mut [0; 1]).unwrap(), 0, "unexpected command after FAIL");
    }

    fn send(&mut self, messages: &[&[u8]]) {
        let mut wire = Vec::new();
        for message in messages {
            wire.extend_from_slice(&(message.len() as u64).to_be_bytes());
            wire.extend_from_slice(message);
        }
        // Deliberately coalesce frames: read-ahead must not discard the next status.
        self.0.write_all(&wire).unwrap();
    }
}

fn run_cli(args: &[&str], script: impl FnOnce(Peer) + Send + 'static) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let peer = thread::spawn(move || script(Peer::accept(listener)));
    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &address])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            let _ = peer.join();
            panic!("CLI timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    peer.join().unwrap();
    output
}

#[test]
fn getvar_all_preserves_info_tokens_and_rejects_real_fail() {
    let output = run_cli(&["getvar", "all"], |mut peer| {
        peer.expect(b"getvar:all");
        peer.send(&[
            b"INFOdiagnostic contains OKAY/FAIL/DATA text",
            b"TEXTmore OKAY/FAIL/DATA text",
            b"FAILterminal rejection",
        ]);
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "FAIL must exit nonzero: {output:?}");
    assert!(stderr.contains("terminal rejection"), "{output:?}");
    assert!(stdout.contains("diagnostic contains OKAY/FAIL/DATA text"), "{output:?}");
    assert!(stdout.contains("more OKAY/FAIL/DATA text"), "{output:?}");
    assert!(!stdout.contains("Finished."), "failure must not print success: {output:?}");
}

#[test]
fn fragmented_info_text_and_terminal_bodies_are_not_scanned_for_tokens() {
    let output = run_cli(&["getvar", "version"], |mut peer| {
        peer.expect(b"getvar:version");
        peer.send_fragmented(&[
            b"INFOOKAY FAIL DATA are diagnostic text",
            b"TEXTDATA FAIL OKAY are still text",
            b"OKAYversion with FAIL/DATA/OKAY inside",
        ]);
    });
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "OKAY FAIL DATA are diagnostic text",
        "DATA FAIL OKAY are still text",
        "version with FAIL/DATA/OKAY inside",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}: {output:?}");
    }
}

#[test]
fn ordinary_terminal_failures_exit_nonzero() {
    // Cover the shared log helper, direct trait calls, and reboot's disconnect path.
    for (args, command) in [
        (vec!["getvar", "version"], "getvar:version"),
        (vec!["getvar", "all"], "getvar:all"),
        (vec!["set-active", "b"], "set_active:b"),
        (vec!["erase", "boot"], "erase:boot"),
        (vec!["oem", "diagnose"], "oem diagnose"),
        (vec!["create-logical-partition", "scratch", "1024"], "create-logical-partition:scratch:1024"),
        (vec!["delete-logical-partition", "scratch"], "delete-logical-partition:scratch"),
        (vec!["resize-logical-partition", "scratch", "2048"], "resize-logical-partition:scratch:2048"),
        (vec!["reboot"], "reboot"),
    ] {
        let output = run_cli(&args, move |mut peer| {
            peer.expect(command.as_bytes());
            peer.send(&[b"INFOdiagnostic text", b"FAILterminal rejection"]);
            peer.expect_closed();
        });
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("terminal rejection"), "{output:?}");
    }
}

struct Files(std::path::PathBuf);

impl Files {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("fastboot-framed-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generic_flash_helper_uses_frame_parser_and_rejects_flash_fail() {
    let files = Files::new("flash");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"INFOFAIL DATA OKAY are not a status", b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send_fragmented(&[b"TEXTDATA OKAY FAIL before DATA", b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"INFOdownload OKAY FAIL DATA text", b"OKAYdownloaded"]);
        peer.expect(b"flash:boot");
        peer.send(&[b"INFOflashing OKAY FAIL DATA text", b"FAILflash rejected"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("max-download-size: 4096"), "generic getvar bypassed parser: {output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("flash rejected"), "{output:?}");
}

#[test]
fn generic_boot_and_flash_raw_helpers_do_not_bypass_the_frame_parser() {
    let files = Files::new("boot-raw");
    let image = files.path("boot.img");
    let payload = fastboot_protocol::BootImageBuilder::new()
        .kernel(b"dummy kernel".to_vec())
        .build();
    std::fs::write(&image, &payload).unwrap();
    for (args, final_command) in [
        (vec!["boot", image.as_str()], "boot"),
        (vec!["flash:raw", "boot", image.as_str()], "flash:boot"),
    ] {
        let payload = payload.clone();
        let output = run_cli(&args, move |mut peer| {
            peer.expect(b"getvar:max-download-size");
            peer.send(&[b"INFOOKAY FAIL DATA are text", b"OKAY0x10000"]);
            peer.expect(format!("download:{:08x}", payload.len()).as_bytes());
            peer.send(&[b"TEXTOKAY FAIL DATA before download", format!("DATA{:08x}", payload.len()).as_bytes()]);
            peer.expect(&payload);
            peer.send(&[b"INFOOKAY FAIL DATA after download", b"OKAYdownloaded"]);
            peer.expect(final_command.as_bytes());
            peer.send(&[b"INFOOKAY FAIL DATA before failure", b"FAILboot image rejected"]);
            peer.expect_closed();
        });
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("boot image rejected"), "{output:?}");
    }
}

#[test]
fn post_download_fail_stops_the_generic_helper_before_flash() {
    let files = Files::new("post-download");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"INFOOKAY FAIL DATA before failure", b"FAILpayload rejected"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("payload rejected"), "{output:?}");
}

#[test]
fn generic_download_failure_stops_before_payload_or_flash() {
    let files = Files::new("download-fail");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:max-download-size");
        // An unsupported optional query still permits the existing fallback.
        peer.send(&[b"INFOOKAY is only text", b"FAILunknown variable"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"INFOOKAY is only text", b"FAILdownload rejected"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("download rejected"), "{output:?}");
}

#[test]
fn get_staged_preserves_fragmented_payload_and_post_data_fail() {
    let files = Files::new("staged");
    let destination = files.path("staged.bin");
    let output = run_cli(&["get-staged", &destination], |mut peer| {
        peer.expect(b"get_staged");
        peer.send(&[b"INFOOKAY FAIL DATA before payload", b"DATA0000000c"]);
        // DATA is opaque, including status-looking bytes, and may span TCP frames.
        peer.send_fragmented(&[b"OKAYF", b"AILDATA"]);
        peer.send(&[b"TEXTOKAY FAIL DATA after payload", b"FAILupload rejected"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"OKAYFAILDATA");
    assert!(String::from_utf8_lossy(&output.stderr).contains("upload rejected"), "{output:?}");
}

#[test]
fn fetch_consumes_each_post_data_status_before_the_next_command() {
    let files = Files::new("fetch");
    let destination = files.path("fetch.bin");
    let output = run_cli(&["fetch", "boot", &destination], |mut peer| {
        peer.expect(b"getvar:max-fetch-size");
        peer.send(&[b"INFOOKAY FAIL DATA query", b"OKAY0x3"]);
        peer.expect(b"getvar:partition-size:boot");
        peer.send(&[b"OKAY0x6"]);
        peer.expect(b"fetch:boot:0x00000000:0x00000003");
        peer.send(&[b"TEXTOKAY FAIL DATA first", b"DATA00000003", b"abc", b"INFOOKAY FAIL DATA end", b"OKAYfirst"]);
        peer.expect(b"fetch:boot:0x00000003:0x00000003");
        peer.send_fragmented(&[b"DATA00000003", b"d", b"ef", b"TEXTOKAY FAIL DATA end", b"OKAYsecond"]);
    });
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");
    assert!(String::from_utf8_lossy(&output.stdout).contains("second"), "{output:?}");
}

#[test]
fn offset_only_fetch_propagates_post_data_fail() {
    let files = Files::new("fetch-fail");
    let destination = files.path("fetch.bin");
    let output = run_cli(&["fetch", "boot", &destination, "--offset", "0"], |mut peer| {
        peer.expect(b"getvar:max-fetch-size");
        peer.send(&[b"OKAY0x3"]);
        peer.expect(b"fetch:boot:0x00000000");
        peer.send(&[b"DATA00000003", b"abc", b"FAILfetch rejected"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"abc");
    assert!(String::from_utf8_lossy(&output.stderr).contains("fetch rejected"), "{output:?}");
}
