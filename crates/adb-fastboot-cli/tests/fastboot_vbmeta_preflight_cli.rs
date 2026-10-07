//! AVB conversion preflight through the real fastboot-rs executable and strict FB01 peer.
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
fn writes(transcript: &Transcript) -> Vec<&str> {
    transcript
        .commands
        .iter()
        .filter(|c| !c.starts_with("getvar:") && !c.starts_with("download:"))
        .map(String::as_str)
        .collect()
}
// Independent serialization of Android 17.0.0_r1 packed structures, not offsets
// imported from the implementation under test. libavb at ba2dec4b035b0a3b61c5f8f8a74d86bcd450b1ee:
// avb_vbmeta_image.h (256-byte header); avb_footer.h (64-byte footer).
// Fastboot core 545d2487e38192a2ce25040897ced877cf6b4f53 rewrites flags at 123 + offset.
fn standalone() -> Vec<u8> {
    let mut header = b"AVB0".to_vec();
    header.extend(1u32.to_be_bytes()); // required major
    header.extend(0u32.to_be_bytes()); // required minor
    header.extend(0u64.to_be_bytes()); // authentication block size
    header.extend(0u64.to_be_bytes()); // auxiliary block size
    header.extend(0u32.to_be_bytes()); // algorithm NONE
    for _ in 0..11 {
        // hash, signature, public key, metadata, descriptors, rollback
        header.extend(0u64.to_be_bytes());
    }
    header.extend(0xa4bc_de80u32.to_be_bytes()); // flags (preserve unrelated bits)
    header.extend(7u32.to_be_bytes()); // rollback index location
    let mut release = [0; 48];
    release[..13].copy_from_slice(b"avbtool 1.3.0");
    header.extend(release);
    header.extend([0; 80]);
    assert_eq!(header.len(), 256);
    header
}
fn footer_image() -> Vec<u8> {
    let mut image = vec![0x57; 192]; // 128-byte original image + padding to vbmeta
    image.extend(standalone());
    image.extend([0; 96]); // partition padding; not part of vbmeta_size
    let mut footer = b"AVBf".to_vec();
    footer.extend(1u32.to_be_bytes()); // major at 4
    footer.extend(0u32.to_be_bytes()); // minor at 8
    footer.extend(128u64.to_be_bytes()); // original_image_size at 12 (NOT vbmeta_offset)
    footer.extend(192u64.to_be_bytes()); // vbmeta_offset at 20
    footer.extend(256u64.to_be_bytes()); // vbmeta_size at 28
    footer.extend([0; 28]);
    assert_eq!(footer.len(), 64);
    image.extend(footer);
    image
}
fn bad_vectors() -> Vec<(&'static str, Vec<u8>)> {
    let mut vectors = Vec::new();
    let mut legacy = vec![0; 320];
    legacy[..4].copy_from_slice(b"AVB0");
    legacy[256..260].copy_from_slice(b"AVBf");
    legacy[264..272].copy_from_slice(&u64::MAX.to_be_bytes());
    vectors.push(("legacy-minor-original-overflow", legacy));
    for (name, field, value) in [
        ("offset-max", 20, u64::MAX),
        ("offset-near-max", 20, u64::MAX - 3),
        ("offset-past-image", 20, 4096),
        ("offset-in-footer", 20, 544),
        ("size-max", 28, u64::MAX),
        ("size-short", 28, 255),
        ("size-past-footer", 28, 4096),
        ("original-overlaps-vbmeta", 12, 193),
    ] {
        let mut image = footer_image();
        let start = image.len() - 64;
        image[start + field..start + field + 8].copy_from_slice(&value.to_be_bytes());
        vectors.push((name, image));
    }
    let mut image = footer_image();
    let start = image.len() - 64;
    image[start + 4..start + 8].copy_from_slice(&2u32.to_be_bytes());
    vectors.push(("unsupported-footer-major", image));
    let mut image = footer_image();
    image[192..196].copy_from_slice(b"BAD!");
    vectors.push(("footer-points-to-non-header", image));
    vectors.push(("truncated-header", standalone()[..124].to_vec()));
    for (name, offset, value) in [
        ("auth-size-max", 12, u64::MAX),
        ("aux-size-max", 20, u64::MAX),
        ("auth-block-truncated", 12, 64),
        ("aux-block-truncated", 20, 64),
        ("auth-size-unaligned", 12, 1),
        ("hash-range-max", 32, u64::MAX),
        ("signature-range-max", 48, u64::MAX),
        ("public-key-range-max", 64, u64::MAX),
        ("public-key-metadata-range-max", 80, u64::MAX),
        ("descriptor-range-max", 96, u64::MAX),
    ] {
        let mut image = standalone();
        image[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        vectors.push((name, image));
    }
    vectors
}
fn update_zip(files: &Files, name: &str, vbmeta: &[u8]) -> String {
    files.zip(
        name,
        &[
            ("android-info.txt", b"require product=test\n"),
            ("boot.img", b"independent boot payload"),
            ("system.img", b"independent system payload"),
            ("vbmeta.img", vbmeta),
        ],
    )
}
fn assert_no_write(output: &Output, transcript: &Transcript) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Check forbidden effects FIRST, so the old late panic cannot hide earlier writes.
    assert!(
        transcript.commands.iter().all(|c| c.starts_with("getvar:")),
        "a malformed later image must fail before ANY download/flash: {transcript:?}; {stderr}"
    );
    assert!(
        transcript.payloads.is_empty(),
        "payload sent: {transcript:?}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "controlled error, not panic/success: {output:?}"
    );
    assert!(
        stderr.to_lowercase().contains("vbmeta") || stderr.contains("AVB"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}
#[test]
fn update_bad_vbmeta_preflights_before_boot_or_system_download() {
    let files = Files::new("vbmeta-bad-update");
    for (name, bytes) in bad_vectors() {
        let path = update_zip(&files, &format!("{name}.zip"), &bytes);
        let (output, transcript) = run(&["--disable-verity", "update", &path], Script::default());
        assert_no_write(&output, &transcript);
    }
}
#[test]
fn flash_bad_vbmeta_errors_without_download_or_panic() {
    let files = Files::new("vbmeta-bad-flash");
    for (name, bytes) in bad_vectors() {
        let path = files.write(&format!("{name}.img"), &bytes);
        let (output, transcript) = run(
            &["--disable-verification", "flash", "vbmeta", &path],
            Script::default(),
        );
        assert_no_write(&output, &transcript);
    }
}
#[test]
fn update_independent_standalone_and_footer_vectors_preserve_all_other_bytes() {
    let files = Files::new("vbmeta-valid-update");
    for (name, bytes, flags) in [
        ("standalone", standalone(), 123),
        ("footer", footer_image(), 315),
    ] {
        for (suffix, options, bits) in [
            ("verity", vec!["--disable-verity"], 1),
            ("verification", vec!["--disable-verification"], 2),
            (
                "both",
                vec!["--disable-verity", "--disable-verification"],
                3,
            ),
        ] {
            let path = update_zip(&files, &format!("{name}-{suffix}.zip"), &bytes);
            let mut args = options;
            args.extend(["update", &path]);
            let (output, transcript) = run(&args, Script::default());
            assert!(output.status.success(), "{output:?}; {transcript:?}");
            let mut expected = bytes.clone();
            expected[flags] |= bits;
            assert_eq!(
                transcript.payloads,
                vec![
                    b"independent boot payload".to_vec(),
                    b"independent system payload".to_vec(),
                    expected
                ]
            );
            assert_eq!(
                writes(&transcript),
                ["flash:boot_a", "flash:system", "flash:vbmeta"]
            );
        }
    }
}
#[test]
fn flash_split_path_rejects_corrupt_vbmeta_before_download() {
    let files = Files::new("vbmeta-bad-split");
    let mut bytes = standalone();
    bytes[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
    bytes.resize(65537, 0); // exceeds the peer's 65536-byte maximum
    let path = files.write("bad-large-vbmeta.img", &bytes);
    let (output, transcript) = run(
        &["--disable-verity", "flash", "vbmeta", &path],
        Script::default(),
    );
    assert_no_write(&output, &transcript);
}

#[test]
fn update_accepts_block_ranges_at_the_boundary_and_footer_version_compatibility() {
    let files = Files::new("vbmeta-valid-ranges");
    let mut bytes = standalone();
    bytes[12..20].copy_from_slice(&64u64.to_be_bytes());
    bytes[20..28].copy_from_slice(&64u64.to_be_bytes());
    // Nonempty auth/aux blocks with each relative range ending exactly at 64.
    for field in [32, 48, 64, 80, 96] {
        bytes[field..field + 8].copy_from_slice(&48u64.to_be_bytes());
        bytes[field + 8..field + 16].copy_from_slice(&16u64.to_be_bytes());
    }
    bytes.extend([0x35; 64]);
    bytes.extend([0x79; 64]);
    let path = update_zip(&files, "valid-ranges.zip", &bytes);
    let (output, transcript) = run(
        &[
            "--disable-verity",
            "--disable-verification",
            "update",
            &path,
        ],
        Script::default(),
    );
    assert!(output.status.success(), "{output:?}; {transcript:?}");
    bytes[123] |= 3;
    assert_eq!(transcript.payloads.last(), Some(&bytes));
    // Match avb_footer_validate_and_byteswap: reject major > 1, not a
    // future minor or legacy major 0. Do not silently narrow valid input.
    for major in [0u32, 1] {
        let mut bytes = footer_image();
        let start = bytes.len() - 64;
        bytes[start + 4..start + 8].copy_from_slice(&major.to_be_bytes());
        bytes[start + 8..start + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        let path = update_zip(&files, &format!("footer-version-{major}.zip"), &bytes);
        let (output, transcript) = run(&["--disable-verity", "update", &path], Script::default());
        assert!(output.status.success(), "{output:?}; {transcript:?}");
        bytes[315] |= 1;
        assert_eq!(transcript.payloads.last(), Some(&bytes));
    }
}

#[test]
fn update_preserves_unrecognized_data_and_no_flag_behavior() {
    let files = Files::new("vbmeta-noop");
    // Existing Rust behavior: no AVB magic (including short data) stays byte-exact.
    for (name, bytes, flags) in [
        ("no-magic", vec![0x85; 256], vec!["--disable-verity"]),
        (
            "short-no-magic",
            b"legacy payload".to_vec(),
            vec!["--disable-verification"],
        ),
        ("recognized-but-no-flags", bad_vectors().remove(0).1, vec![]),
    ] {
        let path = update_zip(&files, &format!("{name}.zip"), &bytes);
        let mut args = flags;
        args.extend(["update", &path]);
        let (output, transcript) = run(&args, Script::default());
        assert!(output.status.success(), "{output:?}; {transcript:?}");
        assert_eq!(transcript.payloads.last(), Some(&bytes));
    }
    // Do not expand the existing partition-selection gate to boot or chained vbmeta.
    let bad = bad_vectors().remove(0).1;
    let path = files.zip(
        "unselected-transform.zip",
        &[
            ("android-info.txt", b"require product=test\n"),
            ("boot.img", &bad),
            ("system.img", b"system"),
            ("vbmeta_system.img", &bad),
        ],
    );
    let (output, transcript) = run(&["--disable-verity", "update", &path], Script::default());
    assert!(output.status.success(), "{output:?}; {transcript:?}");
    assert_eq!(
        transcript.payloads,
        vec![bad.clone(), b"system".to_vec(), bad]
    );
}
