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
    run_cli_serial("{addr}", args, script)
}

/// `serial` may contain `{addr}`; AOSP accepts both a bare `HOST:PORT` and the
/// `tcp:HOST:PORT` network-serial form.
fn run_cli_serial(serial: &str, args: &[&str], script: impl FnOnce(Peer) + Send + 'static) -> Output {
    run_cli_with(Some(serial), None, args, script)
}

/// `serial = None` means: no `-s` at all (device selection from storage/USB).
/// `home` overrides `$HOME` so `.fastboot/devices` is isolated per test.
fn run_cli_with(
    serial: Option<&str>,
    home: Option<&str>,
    args: &[&str],
    script: impl FnOnce(Peer) + Send + 'static,
) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let serial = serial.map(|s| s.replace("{addr}", &address));
    let peer = thread::spawn(move || script(Peer::accept(listener)));
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"));
    if let Some(serial) = serial.as_deref() {
        command.args(["-s", serial]);
    }
    if let Some(home) = home {
        command.env("HOME", home);
    }
    let mut child = command
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
        // AOSP resolves has-slot before touching the download path.
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
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
    // `fastboot boot` addresses no partition (no slot probe); `flash:raw` goes
    // through AOSP's do_for_partitions() and therefore probes has-slot first.
    for (args, final_command, slot_aware) in [
        (vec!["boot", image.as_str()], "boot", false),
        (vec!["flash:raw", "boot", image.as_str()], "flash:boot", true),
    ] {
        let payload = payload.clone();
        let output = run_cli(&args, move |mut peer| {
            if slot_aware {
                peer.expect(b"getvar:has-slot:boot");
                peer.send(&[b"OKAYno"]);
            }
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
        // AOSP resolves has-slot before touching the download path.
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
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
        // AOSP resolves has-slot before touching the download path.
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
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
        // Device without slots: resolution keeps the plain partition name.
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
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
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
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

// --- A/B slot resolution (AOSP `do_for_partition`) -------------------------
// A real bootloader has no unsuffixed slot partition: `flash boot` must ask
// has-slot + current-slot and target `boot_a`. Sending `flash:boot` fails on
// device with "partition 'boot' not found".

#[test]
fn flash_resolves_current_slot_before_upload() {
    let files = Files::new("flash-slot");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflash done"]);
    });
    assert!(output.status.success(), "slot-suffixed flash must succeed: {output:?}");
}

#[test]
fn flash_keeps_plain_name_when_device_has_no_slots() {
    let files = Files::new("flash-noslot");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYno"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot");
        peer.send(&[b"OKAYflash done"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn explicit_slot_skips_current_slot_query() {
    let files = Files::new("flash-explicit-slot");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["--slot", "b", "flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_b");
        peer.send(&[b"OKAYflash done"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn erase_resolves_current_slot() {
    let output = run_cli(&["erase", "boot"], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"erase:boot_a");
        peer.send(&[b"OKAYerased"]);
    });
    assert!(output.status.success(), "erase must target boot_a: {output:?}");
}

#[test]
fn erase_fail_exits_nonzero_after_slot_resolution() {
    let output = run_cli(&["erase", "boot"], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"erase:boot_a");
        peer.send(&[b"INFOdiagnostic text", b"FAILterminal rejection"]);
        peer.expect_closed();
    });
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("terminal rejection"), "{output:?}");
}

#[test]
fn tcp_network_serial_form_reaches_the_peer() {
    // AOSP ParseNetworkSerial: `-s tcp:HOST:PORT`. The prefix must be consumed
    // by the CLI, not handed to the resolver.
    let output = run_cli_serial("tcp:{addr}", &["getvar", "version"], |mut peer| {
        peer.expect(b"getvar:version");
        peer.send(&[b"OKAY0.4"]);
    });
    assert!(output.status.success(), "tcp: serial must connect: {output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("0.4"), "{output:?}");
}

#[test]
fn malformed_tcp_serial_fails_before_connecting() {
    // No listening peer: a malformed network serial must be rejected by parsing.
    let output = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", "tcp:127.0.0.1", "getvar", "version"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid network address"), "{output:?}");
}

#[test]
fn fetch_resolves_current_slot_before_sizing() {
    // AOSP resolves the partition (has-slot + current-slot) before asking for
    // max-fetch-size / partition-size. `partition-size:boot` FAILs on a real
    // bootloader and used to abort the whole fetch.
    let files = Files::new("fetch-slot");
    let destination = files.path("fetch.bin");
    let output = run_cli(&["fetch", "boot", &destination], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:max-fetch-size");
        peer.send(&[b"OKAY0x2"]);
        peer.expect(b"getvar:partition-size:boot_a");
        peer.send(&[b"OKAY0x4"]);
        peer.expect(b"fetch:boot_a:0x00000000:0x00000002");
        peer.send(&[b"DATA00000002", b"ab", b"OKAY"]);
        peer.expect(b"fetch:boot_a:0x00000002:0x00000002");
        peer.send(&[b"DATA00000002", b"cd", b"OKAY"]);
    });
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"abcd");
}

#[test]
fn flash_probes_is_logical_and_partition_size_before_download() {
    // AOSP flash_buf -> copy_avb_footer asks is-logical + partition-size before
    // any download, and warns (but still flashes) when the partition is
    // smaller than the image.
    let files = Files::new("flash-avb");
    let image = files.path("image.bin");
    std::fs::write(&image, vec![0x41u8; 1024]).unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:is-logical:boot_a");
        peer.send(&[b"OKAYno"]);
        peer.expect(b"getvar:partition-size:boot_a");
        peer.send(&[b"OKAY0x200"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000400");
        peer.send(&[b"DATA00000400"]);
        peer.expect(&vec![0x41u8; 1024]);
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skip copying boot_a image avb footer"),
        "AOSP warns when the partition is smaller than the image: {output:?}"
    );
}

#[test]
fn flash_skips_avb_probe_for_tiny_images() {
    // AOSP copy_avb_footer returns early when the image cannot hold a 64-byte
    // AVB footer, so no is-logical/partition-size queries are sent.
    let files = Files::new("flash-tiny");
    let image = files.path("image.bin");
    std::fs::write(&image, b"HELLO").unwrap();
    let output = run_cli(&["flash", "boot", &image], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x1000"]);
        peer.expect(b"download:00000005");
        peer.send(&[b"DATA00000005"]);
        peer.expect(b"HELLO");
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn standalone_set_active_flag_is_a_command() {
    // AOSP: `fastboot --set-active=b` (no subcommand) still sets the slot:
    // supports_AB() gate (getvar:slot-count) then set_active:<slot>.
    let output = run_cli(&["--set-active=b"], |mut peer| {
        peer.expect(b"getvar:slot-count");
        peer.send(&[b"OKAY2"]);
        peer.expect(b"set_active:b");
        peer.send(&[b"OKAY"]);
    });
    assert!(output.status.success(), "standalone --set-active must work: {output:?}");
}

/// Like `run_cli_with`, but pre-seeds `$HOME/.fastboot/devices` with the peer
/// address before the CLI starts (that is the AOSP selection path under test).
fn run_cli_stored(home: &str, args: &[&str], script: impl FnOnce(Peer) + Send + 'static) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let storage = std::path::Path::new(home).join(".fastboot");
    std::fs::create_dir_all(&storage).unwrap();
    std::fs::write(storage.join("devices"), format!("tcp:{address}\n")).unwrap();
    let peer = thread::spawn(move || script(Peer::accept(listener)));
    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .env("HOME", home)
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
fn command_without_serial_uses_the_stored_network_device() {
    // AOSP `open_device()` with no `-s`: USB first, then the last reachable
    // network device recorded by `fastboot connect`.
    let files = Files::new("stored-device");
    let home = files.path("home");
    let output = run_cli_stored(&home, &["getvar", "version"], |mut peer| {
        peer.expect(b"getvar:version");
        peer.send(&[b"OKAY0.4"]);
    });
    assert!(output.status.success(), "stored device must be used: {output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("0.4"), "{output:?}");
}

#[test]
fn flash_relocates_avb_footer_to_the_end_of_the_partition() {
    // AOSP copy_avb_footer: partition 0x800 > image 0x400 with an "AVBf" footer
    // at image_size-64 -> payload becomes image ++ zeros ++ footer, size 0x800.
    let files = Files::new("avb-relocate");
    let image = files.path("boot.img");
    let mut data = vec![0x5Au8; 1024];
    data[960..964].copy_from_slice(b"AVBf");
    data[964..1024].copy_from_slice(&[0xA5u8; 60]);
    std::fs::write(&image, &data).unwrap();

    let mut expected = vec![0u8; 2048];
    expected[..1024].copy_from_slice(&data);
    expected[1984..2048].copy_from_slice(&data[960..1024]);

    let output = run_cli(&["flash", "boot", &image], move |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:is-logical:boot_a");
        peer.send(&[b"OKAYno"]);
        peer.expect(b"getvar:partition-size:boot_a");
        peer.send(&[b"OKAY0x800"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x10000"]);
        peer.expect(b"download:00000800");
        peer.send(&[b"DATA00000800"]);
        peer.expect(&expected);
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "relocated flash must succeed: {output:?}");
}

#[test]
fn flash_keeps_image_when_no_avb_footer_is_present() {
    let files = Files::new("avb-nofooter");
    let image = files.path("boot.img");
    let data = vec![0x5Au8; 1024];          // no "AVBf" magic
    std::fs::write(&image, &data).unwrap();
    let output = run_cli(&["flash", "boot", &image], move |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:is-logical:boot_a");
        peer.send(&[b"OKAYno"]);
        peer.expect(b"getvar:partition-size:boot_a");
        peer.send(&[b"OKAY0x800"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x10000"]);
        peer.expect(b"download:00000400");   // unchanged size
        peer.send(&[b"DATA00000400"]);
        peer.expect(&data);
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn flash_raw_uses_aosp_bootimage_defaults() {
    // AOSP mkbootimg defaults: page 2048, header v0 -> 2048 (header) + 4096
    // (kernel page) = 6144 bytes for a 4096-byte kernel, no ramdisk.
    let files = Files::new("raw-defaults");
    let kernel = files.path("kernel.bin");
    std::fs::write(&kernel, vec![0x4Bu8; 4096]).unwrap();
    let output = run_cli(&["flash:raw", "boot", &kernel], |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x10000"]);
        peer.expect(b"download:00001800");
        peer.send(&[b"DATA00001800"]);
        // Read the framed payload (8-byte big-endian length + bytes).
        let mut header = [0u8; 8];
        peer.0.read_exact(&mut header).unwrap();
        assert_eq!(u64::from_be_bytes(header), 6144, "payload frame length");
        let mut payload = vec![0u8; 6144];
        peer.0.read_exact(&mut payload).unwrap();
        assert_eq!(&payload[..8], b"ANDROID!", "built boot image must carry BOOT_MAGIC");
        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn flash_raw_header_page_matches_aosp_mkbootimg_bytes() {
    // Byte-exact oracle: AOSP `fastboot` 35.0.2 driven against the same fake
    // device (4096-byte 0x4B kernel, no ramdisk) sends 6144 bytes with
    // sha256 bb846a1b212333e0edfc0ab645a24ac5e5443ce96e0ef6b3a4c1f9f7bd3a2037.
    // Fields come from mkbootimg() writing `g_boot_img_hdr`
    // (fastboot.cpp:2223-2228) plus `g_base_addr` 0x10000000
    // (bootimg_utils.cpp:111-121).
    const KERNEL_BYTE: u8 = 0x4B;
    let files = Files::new("raw-oracle");
    let kernel = files.path("kernel.bin");
    std::fs::write(&kernel, vec![KERNEL_BYTE; 4096]).unwrap();

    let output = run_cli(&["flash:raw", "boot", &kernel], move |mut peer| {
        peer.expect(b"getvar:has-slot:boot");
        peer.send(&[b"OKAYyes"]);
        peer.expect(b"getvar:current-slot");
        peer.send(&[b"OKAYa"]);
        peer.expect(b"getvar:max-download-size");
        peer.send(&[b"OKAY0x10000"]);
        peer.expect(b"download:00001800");
        peer.send(&[b"DATA00001800"]);

        let mut frame = [0u8; 8];
        peer.0.read_exact(&mut frame).unwrap();
        let mut payload = vec![0u8; u64::from_be_bytes(frame) as usize];
        peer.0.read_exact(&mut payload).unwrap();
        assert_eq!(payload.len(), 6144, "payload length");

        let word = |off: usize| u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
        // boot_img_hdr_v0 scalars, offsets per bootimg.h.
        assert_eq!(word(8), 4096, "kernel_size");
        assert_eq!(word(12), 0x1000_8000, "kernel_addr = 0x8000 + base");
        assert_eq!(word(16), 0, "ramdisk_size");
        assert_eq!(word(20), 0x1100_0000, "ramdisk_addr = 0x01000000 + base");
        assert_eq!(word(24), 0, "second_size");
        assert_eq!(word(28), 0x10F0_0000, "second_addr = 0x00f00000 + base");
        assert_eq!(word(32), 0x1000_0100, "tags_addr = 0x00000100 + base");
        assert_eq!(word(36), 2048, "page_size");
        assert_eq!(word(40), 0, "header_version");
        assert_eq!(word(44), 0, "os_version");
        assert_eq!(&payload[48..64], &[0u8; 16], "name");
        assert_eq!(&payload[64..576], &[0u8; 512], "cmdline");
        assert_eq!(&payload[576..608], &[0u8; 32], "id is never re-signed");
        assert_eq!(&payload[608..1632], &[0u8; 1024], "extra_cmdline");
        assert_eq!(word(1632), 0, "recovery_dtbo_size (v1 field, zero for v0)");
        assert_eq!(word(1648), 0, "dtb_size");
        // mkbootimg() does `*hdr = src` over a whole boot_img_hdr_v2, so the
        // v2 dtb_addr default survives past the 1632-byte v0 header.
        assert_eq!(word(1652), 0x0110_0000, "v2 tail dtb_addr default");

        // Whole-image equality: those fields, zeros elsewhere in the page,
        // then the kernel occupying one padded page.
        let mut expected = vec![0u8; 2048];
        expected[..8].copy_from_slice(b"ANDROID!");
        for (off, value) in [
            (8usize, 4096u32),
            (12, 0x1000_8000),
            (20, 0x1100_0000),
            (28, 0x10F0_0000),
            (32, 0x1000_0100),
            (36, 2048),
            (1652, 0x0110_0000),
        ] {
            expected[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        expected.extend(std::iter::repeat(KERNEL_BYTE).take(4096));
        assert_eq!(payload, expected, "boot image must match AOSP mkbootimg");

        peer.send(&[b"OKAYdownloaded"]);
        peer.expect(b"flash:boot_a");
        peer.send(&[b"OKAYflashed"]);
    });
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn flash_raw_rejects_kernels_shorter_than_a_v3_header() {
    // AOSP LoadBootableImage: `size < sizeof(boot_img_hdr_v3)` -> "too short"
    // before any device command is sent.
    let files = Files::new("raw-short");
    let kernel = files.path("kernel.bin");
    std::fs::write(&kernel, vec![0x4Bu8; 512]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", "127.0.0.1:1", "flash:raw", "boot", &kernel])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("too short"),
        "{output:?}"
    );
}
