//! Host write-transaction gates through the real fastboot-rs executable and FB01.
//! This models protocol order and forbidden follow-up commands, not physical flashing.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Script {
    limit: usize,
    negotiation: Option<Vec<u8>>,
    post: Vec<Vec<u8>>,
    terminal: Vec<Vec<u8>>,
    fail_download: usize,
    queries: Vec<(String, Vec<u8>)>,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            limit: 65536,
            negotiation: None,
            post: vec![b"OKAYdownloaded".to_vec()],
            terminal: vec![b"OKAYwritten".to_vec()],
            fail_download: 1,
            queries: Vec::new(),
        }
    }
}
#[derive(Default)]
struct Transcript {
    connected: bool,
    commands: Vec<String>,
    payloads: Vec<Vec<u8>>,
}
impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcript")
            .field("connected", &self.connected)
            .field("commands", &self.commands)
            .field(
                "payload_sizes",
                &self.payloads.iter().map(Vec::len).collect::<Vec<_>>(),
            )
            .finish()
    }
}
fn read_packet(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0; 8];
    match stream.read(&mut header[..1]) {
        Ok(0) => return None,
        Ok(1) => stream.read_exact(&mut header[1..]).unwrap(),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
        result => panic!("peer stalled/invalid read: {result:?}"),
    }
    let len = u64::from_be_bytes(header) as usize;
    assert!(len > 0 && len <= 1024 * 1024, "invalid frame length {len}");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).unwrap();
    Some(bytes)
}
fn send(stream: &mut TcpStream, messages: &[Vec<u8>]) {
    let mut wire = Vec::new();
    for message in messages {
        wire.extend_from_slice(&(message.len() as u64).to_be_bytes());
        wire.extend_from_slice(message);
    }
    // Coalesced statuses deliberately test that DATA cannot hide a later FAIL.
    if let Err(error) = stream.write_all(&wire) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "{error}"
        );
    }
}
fn run(args: &[&str], script: Script) -> (Output, Transcript) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let stop = finished.clone();
    let peer = thread::spawn(move || {
        let mut transcript = Transcript::default();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::Acquire) {
                        return transcript;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        transcript.connected = true;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let mut handshake = [0; 4];
        stream.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        stream.write_all(b"FB01").unwrap();
        let mut download = 0;
        while let Some(packet) = read_packet(&mut stream) {
            let command = String::from_utf8(packet).expect("command must be ASCII");
            transcript.commands.push(command.clone());
            if let Some(variable) = command.strip_prefix("getvar:") {
                let response = script
                    .queries
                    .iter()
                    .find(|(name, _)| name == variable)
                    .map(|(_, response)| response.clone())
                    .unwrap_or_else(|| match variable {
                        "max-download-size" => format!("OKAY0x{:x}", script.limit).into_bytes(),
                        "current-slot" => b"OKAYa".to_vec(),
                        "has-slot:boot" => b"OKAYyes".to_vec(),
                        name if name.starts_with("has-slot:") => b"OKAYno".to_vec(),
                        _ => b"OKAYtest".to_vec(),
                    });
                send(&mut stream, &[response]);
            } else if let Some(size) = command.strip_prefix("download:") {
                download += 1;
                assert_eq!(size.len(), 8);
                let size = usize::from_str_radix(size, 16).unwrap();
                assert!(size > 0 && size <= script.limit);
                if let Some(response) = &script.negotiation {
                    send(&mut stream, &[response.clone()]);
                    continue;
                }
                send(&mut stream, &[format!("DATA{size:08x}").into_bytes()]);
                let mut payload = Vec::new();
                while payload.len() < size {
                    match read_packet(&mut stream) {
                        Some(bytes) => payload.extend(bytes),
                        // A broken host can send the next download while an old FAIL
                        // is queued, then close before its payload. Retain that forbidden
                        // command so the test fails on the production ordering invariant.
                        None => return transcript,
                    }
                }
                assert_eq!(payload.len(), size, "DATA byte count must be exact");
                transcript.payloads.push(payload);
                if download == script.fail_download {
                    send(&mut stream, &script.post);
                } else {
                    send(&mut stream, &[b"OKAYdownloaded".to_vec()]);
                }
            } else if command.starts_with("flash:") || command == "boot" || command == "signature" {
                assert!(!transcript.payloads.is_empty(), "write without any payload");
                send(&mut stream, &script.terminal);
                if command == "boot" {
                    break;
                } // boot disconnects after its status
            } else {
                panic!("forbidden/unmodelled command: {command}");
            }
        }
        transcript
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &address])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            finished.store(true, Ordering::Release);
            let output = child.wait_with_output().unwrap();
            let _ = peer.join();
            panic!("CLI timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    finished.store(true, Ordering::Release);
    (output, peer.join().unwrap())
}
struct Files(std::path::PathBuf);
impl Files {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "fastboot-transaction-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }
    fn zip(&self, name: &str, entries: &[(&str, &[u8])]) -> String {
        let path = self.0.join(name);
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        for (name, bytes) in entries {
            zip.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
        path.to_str().unwrap().to_owned()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn assert_failed(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "must not fabricate success: {output:?}"
    );
}
fn downloads(transcript: &Transcript) -> usize {
    transcript
        .commands
        .iter()
        .filter(|c| c.starts_with("download:"))
        .count()
}
fn writes(transcript: &Transcript) -> Vec<&str> {
    transcript
        .commands
        .iter()
        .filter(|c| !c.starts_with("getvar:") && !c.starts_with("download:"))
        .map(String::as_str)
        .collect()
}
fn post_data_case(name: &str, split: bool) {
    let files = Files::new(name);
    let payload = if name == "boot" || name == "flash-raw" {
        fastboot_protocol::BootImageBuilder::new()
            .kernel(b"kernel".to_vec())
            .build()
    } else if split {
        vec![0x53; 12288]
    } else {
        b"HELLO".to_vec()
    };
    let image = files.write("image.img", &payload);
    let update = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", &payload),
            ("system.img", b"SYSTEM"),
        ],
    );
    let args = match name {
        "boot" => vec!["boot", image.as_str()],
        "flash-raw" => vec!["flash:raw", "boot", image.as_str()],
        "wipe-super" => vec!["wipe-super", image.as_str()],
        "stage" => vec!["stage", image.as_str()],
        name if name.starts_with("update") => vec!["update", update.as_str()],
        _ => vec!["flash", "boot", image.as_str()],
    };
    let (output, transcript) = run(
        &args,
        Script {
            limit: if split { 8500 } else { 65536 },
            post: vec![
                b"INFOOKAY FAIL DATA are diagnostic text".to_vec(),
                b"DATA00000001".to_vec(),
                b"FAILlate rejection".to_vec(),
            ],
            ..Script::default()
        },
    );
    assert!(transcript.connected);
    assert_eq!(
        downloads(&transcript),
        1,
        "must stop before next chunk/partition: {transcript:?}"
    );
    assert_eq!(transcript.payloads.len(), 1);
    if !split {
        assert_eq!(transcript.payloads[0], payload);
    }
    assert!(
        writes(&transcript).is_empty(),
        "non-OKAY download must not trigger flash/boot: {transcript:?}"
    );
    assert_failed(&output);
}
#[test]
fn flash_stream_post_data_stops_before_flash() {
    post_data_case("flash-stream", false);
}
#[test]
fn flash_split_post_data_stops_before_flash() {
    post_data_case("flash-split", true);
}
#[test]
fn wipe_super_post_data_stops_before_flash() {
    post_data_case("wipe-super", false);
}
#[test]
fn boot_post_data_stops_before_boot() {
    post_data_case("boot", false);
}
#[test]
fn flash_raw_post_data_stops_before_flash() {
    post_data_case("flash-raw", false);
}
#[test]
fn stage_post_data_cannot_report_success() {
    post_data_case("stage", false);
}
#[test]
fn update_stream_post_data_stops_before_flash() {
    post_data_case("update-stream", false);
}
#[test]
fn update_split_post_data_stops_before_flash() {
    post_data_case("update-split", true);
}

fn final_data_case(name: &str) {
    let files = Files::new(name);
    let boot_payload = fastboot_protocol::BootImageBuilder::new()
        .kernel(b"kernel".to_vec())
        .build();
    let image = files.write("boot.img", &boot_payload);
    let update = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let args = match name {
        "boot-final" => vec!["boot", image.as_str()],
        "raw-final" => vec!["flash:raw", "boot", image.as_str()],
        _ => vec!["update", update.as_str()],
    };
    let (output, transcript) = run(
        &args,
        Script {
            terminal: vec![
                b"DATA00000001".to_vec(),
                b"FAILlate write rejection".to_vec(),
            ],
            ..Script::default()
        },
    );
    assert_eq!(
        downloads(&transcript),
        1,
        "final status must stop next partition: {transcript:?}"
    );
    assert_eq!(writes(&transcript).len(), 1, "{transcript:?}");
    assert_failed(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("所有分区已刷写完成"));
}
#[test]
fn boot_final_data_cannot_report_success() {
    final_data_case("boot-final");
}
#[test]
fn raw_flash_final_data_cannot_report_success() {
    final_data_case("raw-final");
}
#[test]
fn update_final_data_stops_before_next_partition() {
    final_data_case("update-final");
}

fn rejected_option(option: &str) {
    let (output, transcript) = run(&["getvar", "version", option], Script::default());
    assert!(
        !transcript.connected,
        "unsupported option must reject before any I/O: {option}: {transcript:?}"
    );
    assert_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(option.split('=').next().unwrap()) && stderr.contains("not supported"),
        "explicit unsupported diagnostic required: {output:?}"
    );
}
#[test]
fn set_active_global_is_rejected_before_io() {
    rejected_option("--set-active=b");
}
#[test]
fn skip_secondary_is_rejected_before_io() {
    rejected_option("--skip-secondary");
}
#[test]
fn force_is_rejected_before_io() {
    rejected_option("--force");
}
#[test]
fn skip_reboot_is_rejected_before_io() {
    rejected_option("--skip-reboot");
}
#[test]
fn unbuffered_is_rejected_before_io() {
    rejected_option("--unbuffered");
}

#[test]
fn update_preflight_missing_system_stops_before_any_download() {
    let files = Files::new("missing-system");
    let zip = files.zip(
        "update.zip",
        &[("android-info.txt", b""), ("boot.img", b"BOOT")],
    );
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert_failed(&output);
    assert_eq!(
        downloads(&transcript),
        0,
        "late missing image must not leave boot flashed: {transcript:?}"
    );
    assert!(writes(&transcript).is_empty());
}
#[test]
fn update_preflight_empty_system_stops_before_any_download() {
    let files = Files::new("empty-system");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b""),
        ],
    );
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert_failed(&output);
    assert_eq!(downloads(&transcript), 0, "{transcript:?}");
}
#[test]
fn update_preflight_partition_exists_requires_its_image() {
    let files = Files::new("required-vendor");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b"require partition-exists=vendor\n"),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert_failed(&output);
    assert_eq!(
        downloads(&transcript),
        0,
        "partition-exists must promote vendor.img to required: {transcript:?}"
    );
}
#[test]
fn update_preflight_query_data_must_not_continue() {
    let files = Files::new("query-data");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b"require version-bootloader=test\n"),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            queries: vec![("version-bootloader".into(), b"DATA00000001".to_vec())],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(
        downloads(&transcript),
        0,
        "mandatory DATA query must not continue: {transcript:?}"
    );
}
#[test]
fn update_preflight_inverse_query_fail_is_not_a_match() {
    let files = Files::new("inverse-query");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b"require inverse product=wrong\n"),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            queries: vec![("product".into(), b"FAILunknown variable".to_vec())],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(
        downloads(&transcript),
        0,
        "query failure cannot satisfy an inverse requirement: {transcript:?}"
    );
}
#[test]
fn update_preflight_has_slot_controls_suffix_and_all_queries_precede_download() {
    let files = Files::new("has-slot");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(writes(&transcript), ["flash:boot_a", "flash:system"]);
    assert_eq!(transcript.payloads, [b"BOOT".to_vec(), b"SYSTEM".to_vec()]);
    let first_download = transcript
        .commands
        .iter()
        .position(|c| c.starts_with("download:"))
        .unwrap();
    for required in [
        "getvar:has-slot:boot",
        "getvar:has-slot:system",
        "getvar:current-slot",
    ] {
        let query = transcript
            .commands
            .iter()
            .position(|c| c == required)
            .expect("required plan query missing");
        assert!(
            query < first_download,
            "plan must freeze before any download: {transcript:?}"
        );
    }
}
#[test]
fn update_preflight_has_slot_failure_stops_before_any_download() {
    let files = Files::new("slot-fail");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            queries: vec![("has-slot:system".into(), b"FAILquery rejected".to_vec())],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(
        downloads(&transcript),
        0,
        "must validate later partition before boot flash: {transcript:?}"
    );
}
#[test]
fn update_preflight_current_slot_failure_is_not_unsuffixed_fallback() {
    let files = Files::new("current-slot-fail");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            queries: vec![("current-slot".into(), b"FAILquery rejected".to_vec())],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(downloads(&transcript), 0, "{transcript:?}");
}
#[test]
fn update_preflight_explicit_slot_is_consumed() {
    let files = Files::new("explicit-slot");
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(&["--slot=b", "update", &zip], Script::default());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(writes(&transcript), ["flash:boot_b", "flash:system"]);
}

#[test]
fn unsupported_multi_slot_options_reject_before_io() {
    for value in ["all", "other"] {
        let files = Files::new(&format!("multi-slot-{value}"));
        let zip = files.zip(
            "update.zip",
            &[
                ("android-info.txt", b""),
                ("boot.img", b"BOOT"),
                ("system.img", b"SYSTEM"),
            ],
        );
        let option = format!("--slot={value}");
        let (output, transcript) = run(&[&option, "update", &zip], Script::default());
        assert!(
            !transcript.connected,
            "unsupported multi-slot plan must reject before I/O: {transcript:?}"
        );
        assert_failed(&output);
    }
}
#[test]
fn unconsumed_slot_and_vbmeta_options_reject_before_io() {
    for option in ["--slot=b", "--disable-verity", "--disable-verification"] {
        let (output, transcript) = run(&["getvar", "version", option], Script::default());
        assert!(!transcript.connected, "unconsumed {option}: {transcript:?}");
        assert_failed(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not supported"),
            "{output:?}"
        );
    }
}

#[test]
fn negotiation_requires_matching_data_and_forbids_payload_on_error() {
    let files = Files::new("negotiation");
    let image = files.write("image.img", b"HELLO");
    for response in [
        b"DATA00000004".as_slice(),
        b"OKAYnot DATA",
        b"FAILnot accepted",
    ] {
        let (output, transcript) = run(
            &["flash", "boot", &image],
            Script {
                negotiation: Some(response.to_vec()),
                ..Script::default()
            },
        );
        assert_failed(&output);
        assert_eq!(downloads(&transcript), 1);
        assert!(
            transcript.payloads.is_empty() && writes(&transcript).is_empty(),
            "{transcript:?}"
        );
    }
}
#[test]
fn post_download_fail_and_unknown_status_stop_without_flash() {
    let files = Files::new("post-status");
    let image = files.write("image.img", b"HELLO");
    for status in [b"FAILpayload rejected".as_slice(), b"BOGUSunexpected"] {
        let (output, transcript) = run(
            &["flash", "boot", &image],
            Script {
                post: vec![b"INFOOKAY is only text".to_vec(), status.to_vec()],
                ..Script::default()
            },
        );
        assert_failed(&output);
        assert_eq!(transcript.payloads, [b"HELLO".to_vec()]);
        assert!(writes(&transcript).is_empty(), "{transcript:?}");
    }
}
#[test]
fn update_second_split_download_fail_preserves_prior_write_but_stops_plan() {
    let files = Files::new("second-split");
    let image = vec![0x53; 12288];
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", &image),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            limit: 8500,
            fail_download: 2,
            post: vec![
                b"TEXTOKAY is not success".to_vec(),
                b"FAILsecond chunk rejected".to_vec(),
            ],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(downloads(&transcript), 2, "{transcript:?}");
    assert_eq!(transcript.payloads.len(), 2);
    assert_eq!(
        writes(&transcript),
        ["flash:boot_a"],
        "earlier write is not rolled back, but no failed chunk/next partition: {transcript:?}"
    );
}
#[test]
fn update_split_final_data_stops_before_next_chunk_or_partition() {
    let files = Files::new("split-final");
    let image = vec![0x53; 12288];
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", &image),
            ("system.img", b"SYSTEM"),
        ],
    );
    let (output, transcript) = run(
        &["update", &zip],
        Script {
            limit: 8500,
            terminal: vec![b"DATA00000001".to_vec(), b"FAILlate write failure".to_vec()],
            ..Script::default()
        },
    );
    assert_failed(&output);
    assert_eq!(downloads(&transcript), 1, "{transcript:?}");
    assert_eq!(writes(&transcript), ["flash:boot_a"]);
}
#[test]
fn update_corrupt_later_image_is_rejected_before_any_download() {
    let files = Files::new("bad-crc");
    let original = b"UNIQUE_SYSTEM_PAYLOAD";
    let zip = files.zip(
        "update.zip",
        &[
            ("android-info.txt", b""),
            ("boot.img", b"BOOT"),
            ("system.img", original),
        ],
    );
    let mut bytes = std::fs::read(&zip).unwrap();
    let offset = bytes
        .windows(original.len())
        .position(|window| window == original)
        .unwrap();
    bytes[offset] ^= 1; // retain the ZIP's old CRC to induce a real extraction error
    std::fs::write(&zip, bytes).unwrap();
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert_failed(&output);
    assert_eq!(downloads(&transcript), 0, "{transcript:?}");
}
#[test]
fn valid_download_command_families_complete_and_do_not_auto_reboot() {
    let files = Files::new("positive");
    let boot = fastboot_protocol::BootImageBuilder::new()
        .kernel(b"kernel".to_vec())
        .build();
    let image = files.write("boot.img", &boot);
    let signature = files.write("signature.bin", &[0x25; 256]);
    for (args, payload, terminal) in [
        (
            vec!["flash", "boot", image.as_str()],
            boot.clone(),
            Some("flash:boot"),
        ),
        (
            vec!["wipe-super", image.as_str()],
            boot.clone(),
            Some("flash:super"),
        ),
        (
            vec!["flash:raw", "boot", image.as_str()],
            boot.clone(),
            Some("flash:boot"),
        ),
        (vec!["boot", image.as_str()], boot.clone(), Some("boot")),
        (vec!["stage", image.as_str()], boot.clone(), None),
        (
            vec!["signature", signature.as_str()],
            vec![0x25; 256],
            Some("signature"),
        ),
    ] {
        let (output, transcript) = run(&args, Script::default());
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(transcript.payloads, [payload]);
        assert_eq!(
            writes(&transcript),
            terminal.into_iter().collect::<Vec<_>>(),
            "{transcript:?}"
        );
    }
}
#[test]
fn supported_vbmeta_options_reach_flash_payload() {
    let files = Files::new("vbmeta");
    let mut payload = vec![0; 256];
    payload[..4].copy_from_slice(b"AVB0");
    let image = files.write("vbmeta.img", &payload);
    let (output, transcript) = run(
        &[
            "--disable-verity",
            "--disable-verification",
            "flash",
            "vbmeta",
            &image,
        ],
        Script::default(),
    );
    assert!(output.status.success(), "{output:?}");
    payload[123] = 3;
    assert_eq!(transcript.payloads, [payload]);
    assert_eq!(writes(&transcript), ["flash:vbmeta"]);
}
#[test]
fn update_aosp_require_reject_board_alternatives_and_product_guard() {
    let files = Files::new("aosp-requirements");
    let zip = files.zip("update.zip", &[("android-info.txt", b"require board=wrong|te*\nreject version-bootloader=wrong\nrequire-for-product:other version-baseband=wrong\n"), ("boot.img", b"BOOT"), ("system.img", b"SYSTEM")]);
    let (output, transcript) = run(&["update", &zip], Script::default());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(writes(&transcript), ["flash:boot_a", "flash:system"]);
    assert!(!transcript.commands.iter().any(|c| c == "getvar:board"));
}

#[test]
fn update_preflight_sparse_and_split_errors_are_found_before_any_download() {
    for case in ["malformed-sparse", "impossible-split"] {
        let files = Files::new(case);
        let mut image = vec![0; 128];
        if case == "malformed-sparse" {
            image[..4].copy_from_slice(&0xed26ff3au32.to_le_bytes());
        }
        let zip = files.zip(
            "update.zip",
            &[
                ("android-info.txt", b""),
                ("boot.img", b"BOOT"),
                ("system.img", &image),
            ],
        );
        let (output, transcript) = run(
            &["update", &zip],
            Script {
                limit: 64,
                ..Script::default()
            },
        );
        assert_failed(&output);
        assert_eq!(
            downloads(&transcript),
            0,
            "later image planning error must precede boot flash: {transcript:?}"
        );
    }
}

#[test]
fn signature_post_data_already_fails_closed() {
    let files = Files::new("signature");
    let signature = files.write("signature.bin", &[0x25; 256]);
    let (output, transcript) = run(
        &["signature", &signature],
        Script {
            post: vec![b"DATA00000001".to_vec()],
            ..Script::default()
        },
    );
    assert_eq!(transcript.payloads, vec![vec![0x25; 256]]);
    assert!(writes(&transcript).is_empty());
    assert_failed(&output);
}
