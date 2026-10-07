//! Independent raw ZIP fixtures + the production CLI over an FB01 peer.
//! No ZipWriter: duplicate names must remain two real central-directory records.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn u16le(out: &mut Vec<u8>, n: u16) {
    out.extend(n.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, n: u32) {
    out.extend(n.to_le_bytes());
}
fn u64le(out: &mut Vec<u8>, n: u64) {
    out.extend(n.to_le_bytes());
}
#[derive(Clone)]
struct Entry {
    name: Vec<u8>,
    data: Vec<u8>,
    extra: Vec<u8>,
    flags: u16,
    method: u16,
    packed: Vec<u8>,
}
impl Entry {
    fn new(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            extra: vec![],
            flags: 0,
            method: 0,
            packed: data.to_vec(),
        }
    }
    fn deflated(mut self, descriptor: bool) -> Self {
        // RFC 1951 stored DEFLATE block, constructed without a compression crate.
        self.method = 8;
        self.packed = vec![1]; // final block, BTYPE=00, zero padding
        let length = self.data.len() as u16;
        u16le(&mut self.packed, length);
        u16le(&mut self.packed, !length);
        self.packed.extend(&self.data);
        if descriptor {
            self.flags |= 1 << 3;
        }
        self
    }
}
fn entries() -> Vec<Entry> {
    vec![
        Entry::new("android-info.txt", b"require product=test\n"),
        Entry::new("boot.img", b"BOOT"),
        Entry::new("system.img", b"FIRST"),
    ]
}
struct Fixture {
    bytes: Vec<u8>,
    cd: usize,
    eocd: usize,
    zip64: Option<usize>,
    headers: Vec<usize>,
}
fn zip(entries: &[Entry], zip64: bool, prefix: &[u8], comment: &[u8]) -> Fixture {
    let mut bytes = prefix.to_vec();
    let mut offsets = Vec::new();
    for entry in entries {
        offsets.push((bytes.len() - prefix.len()) as u64);
        u32le(&mut bytes, 0x04034b50);
        u16le(&mut bytes, 20);
        u16le(&mut bytes, entry.flags);
        u16le(&mut bytes, entry.method);
        u16le(&mut bytes, 0);
        u16le(&mut bytes, 0x21);
        let descriptor = entry.flags & (1 << 3) != 0;
        u32le(&mut bytes, if descriptor { 0 } else { crc32(&entry.data) });
        u32le(
            &mut bytes,
            if descriptor {
                0
            } else {
                entry.packed.len() as u32
            },
        );
        u32le(
            &mut bytes,
            if descriptor {
                0
            } else {
                entry.data.len() as u32
            },
        );
        u16le(&mut bytes, entry.name.len() as u16);
        u16le(&mut bytes, entry.extra.len() as u16);
        bytes.extend(&entry.name);
        bytes.extend(&entry.extra);
        bytes.extend(&entry.packed);
        if descriptor {
            u32le(&mut bytes, 0x08074b50);
            u32le(&mut bytes, crc32(&entry.data));
            u32le(&mut bytes, entry.packed.len() as u32);
            u32le(&mut bytes, entry.data.len() as u32);
        }
    }
    let cd = bytes.len();
    let mut headers = Vec::new();
    for (entry, offset) in entries.iter().zip(offsets) {
        headers.push(bytes.len());
        let mut extra = Vec::new();
        if zip64 {
            u16le(&mut extra, 1);
            u16le(&mut extra, 24);
            u64le(&mut extra, entry.data.len() as u64);
            u64le(&mut extra, entry.packed.len() as u64);
            u64le(&mut extra, offset);
        }
        extra.extend(&entry.extra);
        u32le(&mut bytes, 0x02014b50);
        u16le(&mut bytes, if zip64 { 45 } else { 20 });
        u16le(&mut bytes, if zip64 { 45 } else { 20 });
        u16le(&mut bytes, entry.flags);
        u16le(&mut bytes, entry.method);
        u16le(&mut bytes, 0);
        u16le(&mut bytes, 0x21);
        u32le(&mut bytes, crc32(&entry.data));
        let size = if zip64 {
            u32::MAX
        } else {
            entry.data.len() as u32
        };
        u32le(
            &mut bytes,
            if zip64 {
                u32::MAX
            } else {
                entry.packed.len() as u32
            },
        );
        u32le(&mut bytes, size);
        u16le(&mut bytes, entry.name.len() as u16);
        u16le(&mut bytes, extra.len() as u16);
        u16le(&mut bytes, 0);
        u16le(&mut bytes, 0);
        u16le(&mut bytes, 0);
        u32le(&mut bytes, 0);
        u32le(&mut bytes, if zip64 { u32::MAX } else { offset as u32 });
        bytes.extend(&entry.name);
        bytes.extend(&extra);
    }
    let cd_size = (bytes.len() - cd) as u64;
    let cd_offset = (cd - prefix.len()) as u64;
    let zip64_start = if zip64 {
        let start = bytes.len();
        u32le(&mut bytes, 0x06064b50);
        u64le(&mut bytes, 44);
        u16le(&mut bytes, 45);
        u16le(&mut bytes, 45);
        u32le(&mut bytes, 0);
        u32le(&mut bytes, 0);
        u64le(&mut bytes, entries.len() as u64);
        u64le(&mut bytes, entries.len() as u64);
        u64le(&mut bytes, cd_size);
        u64le(&mut bytes, cd_offset);
        u32le(&mut bytes, 0x07064b50);
        u32le(&mut bytes, 0);
        u64le(&mut bytes, (start - prefix.len()) as u64);
        u32le(&mut bytes, 1);
        Some(start)
    } else {
        None
    };
    let eocd = bytes.len();
    u32le(&mut bytes, 0x06054b50);
    u16le(&mut bytes, 0);
    u16le(&mut bytes, 0);
    let count = if zip64 {
        u16::MAX
    } else {
        entries.len() as u16
    };
    u16le(&mut bytes, count);
    u16le(&mut bytes, count);
    u32le(&mut bytes, if zip64 { u32::MAX } else { cd_size as u32 });
    u32le(&mut bytes, if zip64 { u32::MAX } else { cd_offset as u32 });
    u16le(&mut bytes, comment.len() as u16);
    bytes.extend(comment);
    Fixture {
        bytes,
        cd,
        eocd,
        zip64: zip64_start,
        headers,
    }
}
fn frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0; 8];
    match stream.read(&mut length[..1]) {
        Ok(0) => return None,
        Ok(1) => stream.read_exact(&mut length[1..]).unwrap(),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
        other => panic!("invalid frame: {other:?}"),
    }
    let length = u64::from_be_bytes(length) as usize;
    assert!(length > 0 && length < 65536);
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).unwrap();
    Some(packet)
}
fn send(stream: &mut TcpStream, data: &[u8]) {
    stream
        .write_all(&(data.len() as u64).to_be_bytes())
        .unwrap();
    stream.write_all(data).unwrap();
}
#[derive(Debug, Default)]
struct Transcript {
    commands: Vec<String>,
    payloads: Vec<Vec<u8>>,
}
fn run(name: &str, fixture: Fixture) -> (Output, Transcript) {
    let path = std::env::temp_dir().join(format!("zip-identity-{name}-{}.zip", std::process::id()));
    std::fs::write(&path, fixture.bytes).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI never connected");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let mut handshake = [0; 4];
        stream.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        stream.write_all(b"FB01").unwrap();
        let mut transcript = Transcript::default();
        while let Some(packet) = frame(&mut stream) {
            let command = String::from_utf8(packet).unwrap();
            transcript.commands.push(command.clone());
            if let Some(size) = command.strip_prefix("download:") {
                let size = usize::from_str_radix(size, 16).unwrap();
                send(&mut stream, format!("DATA{size:08x}").as_bytes());
                let mut data = vec![];
                while data.len() < size {
                    data.extend(frame(&mut stream).expect("missing payload"));
                }
                assert_eq!(data.len(), size);
                transcript.payloads.push(data);
                send(&mut stream, b"OKAY");
            } else if command.starts_with("flash:") {
                send(&mut stream, b"OKAY");
            } else if command == "getvar:max-download-size" {
                send(&mut stream, b"OKAY0x10000");
            } else if command.starts_with("getvar:has-slot:") {
                send(&mut stream, b"OKAYno");
            } else if command.starts_with("getvar:") {
                send(&mut stream, b"OKAYtest");
            } else {
                panic!("unexpected command: {command}");
            }
        }
        transcript
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &address, "update", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("CLI timed out");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    let transcript = peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
    (output, transcript)
}
fn reject(name: &str, fixture: Fixture, diagnostic: &str) {
    let (output, transcript) = run(name, fixture);
    assert!(
        !output.status.success(),
        "{name}: ZIP accepted, status={} transcript={transcript:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(diagnostic), "{name}: {stderr}");
    assert!(
        transcript.payloads.is_empty(),
        "{name}: sent payload: {transcript:?}"
    );
    assert!(
        transcript.commands.iter().all(|c| c.starts_with("getvar:")),
        "{name}: target write I/O before identity gate: {transcript:?}"
    );
}
#[test]
fn duplicate_system_entries_rejected_before_any_download() {
    let mut entries = entries();
    entries.push(Entry::new("system.img", b"SECOND"));
    for zip64 in [false, true] {
        reject(
            if zip64 {
                "duplicate-zip64"
            } else {
                "duplicate"
            },
            zip(&entries, zip64, b"", b""),
            "duplicate effective update ZIP entry",
        );
    }
}
#[test]
fn distinct_raw_names_with_same_unicode_effective_identity_are_rejected() {
    let mut entries = entries();
    let mut alias = Entry::new("alias.img", b"SECOND");
    let mut data = vec![1];
    u32le(&mut data, crc32(&alias.name));
    data.extend(b"system.img");
    u16le(&mut alias.extra, 0x7075);
    u16le(&mut alias.extra, data.len() as u16);
    alias.extra.extend(data);
    entries.push(alias);
    reject(
        "unicode-alias",
        zip(&entries, false, b"", b""),
        "duplicate effective update ZIP entry",
    );
}
#[test]
fn cross_encoding_identity_and_non_image_duplicates_are_rejected() {
    let mut encoded = entries();
    let mut cp437 = Entry::new("placeholder", b"one");
    cp437.name = b"\x82.bin".to_vec();
    let mut utf8 = Entry::new("é.bin", b"two");
    utf8.flags = 1 << 11;
    encoded.extend([cp437, utf8]);
    reject(
        "cross-encoding",
        zip(&encoded, false, b"", b""),
        "duplicate effective update ZIP entry",
    );
    for name in ["android-info.txt", "boot.img", "unselected.txt"] {
        let mut duplicate = entries();
        duplicate.extend([Entry::new(name, b"one"), Entry::new(name, b"two")]);
        reject(
            &format!("duplicate-{name}"),
            zip(&duplicate, false, b"", b""),
            "duplicate effective update ZIP entry",
        );
    }
}
#[test]
fn valid_zip64_extensible_sector_and_maximum_comment_are_accepted() {
    let mut f = zip(
        &entries(),
        true,
        b"MZ prefix",
        &vec![b'x'; u16::MAX as usize],
    );
    let start = f.zip64.unwrap();
    let sector = [0x99, 0, 3, 0, 0, 0, 1, 2, 3];
    f.bytes.splice(start + 56..start + 56, sector);
    f.bytes[start + 4..start + 12].copy_from_slice(&(44u64 + sector.len() as u64).to_le_bytes());
    let (output, transcript) = run("zip64-extensible", f);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(transcript.payloads, [b"BOOT".to_vec(), b"FIRST".to_vec()]);
}
#[test]
fn valid_deflate_and_data_descriptor_still_use_library_decompression() {
    for zip64 in [false, true] {
        for descriptor in [false, true] {
            let es = entries()
                .into_iter()
                .map(|e| e.deflated(descriptor))
                .collect::<Vec<_>>();
            let (output, transcript) = run(
                &format!("deflate-{zip64}-{descriptor}"),
                zip(&es, zip64, b"MZ prefix", b""),
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(transcript.payloads, [b"BOOT".to_vec(), b"FIRST".to_vec()]);
        }
    }
}
#[test]
fn valid_standard_zip64_and_self_extracting_prefix_preserve_payloads() {
    for zip64 in [false, true] {
        for prefix in [b"".as_slice(), b"MZ self-extracting prefix".as_slice()] {
            let name = format!("valid-{zip64}-{}", prefix.len());
            let (output, transcript) =
                run(&name, zip(&entries(), zip64, prefix, b"archive comment"));
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(transcript.payloads, [b"BOOT".to_vec(), b"FIRST".to_vec()]);
            assert_eq!(
                transcript
                    .commands
                    .iter()
                    .filter(|c| c.starts_with("flash:"))
                    .collect::<Vec<_>>(),
                ["flash:boot", "flash:system"]
            );
        }
    }
}
#[test]
fn corrupt_cd_boundaries_counts_and_extra_fields_fail_closed() {
    for case in [
        "size-short",
        "size-long",
        "count-low",
        "disk-count",
        "offset",
        "entry-overrun",
        "bad-extra",
        "trailing",
        "zip64-size",
        "zip64-count",
        "zip64-locator",
        "zip64-contradiction",
        "zip64-record-size",
        "zip64-extension-tlv",
        "count-high",
        "local-name",
        "invalid-utf8",
    ] {
        let is64 = case.starts_with("zip64");
        let mut f = zip(&entries(), is64, b"", b"");
        match case {
            "size-short" => {
                let size = (f.eocd - f.cd - 1) as u32;
                f.bytes[f.eocd + 12..f.eocd + 16].copy_from_slice(&size.to_le_bytes());
            }
            "size-long" => {
                let size = (f.eocd - f.cd + 1) as u32;
                f.bytes[f.eocd + 12..f.eocd + 16].copy_from_slice(&size.to_le_bytes());
            }
            "count-low" => {
                f.bytes[f.eocd + 8..f.eocd + 12].copy_from_slice(&[2, 0, 2, 0]);
            }
            "disk-count" => {
                f.bytes[f.eocd + 10..f.eocd + 12].copy_from_slice(&4u16.to_le_bytes());
            }
            "offset" => {
                f.bytes[f.eocd + 16..f.eocd + 20]
                    .copy_from_slice(&((f.cd - 1) as u32).to_le_bytes());
            }
            "entry-overrun" => {
                let h = f.headers[2];
                f.bytes[h + 32..h + 34].copy_from_slice(&u16::MAX.to_le_bytes());
            }
            "bad-extra" => {
                let h = f.headers[2];
                f.bytes[h + 30..h + 32].copy_from_slice(&1u16.to_le_bytes());
            }
            "trailing" => f.bytes.push(0),
            "zip64-size" => {
                let h = f.zip64.unwrap();
                f.bytes[h + 40..h + 48].copy_from_slice(&1u64.to_le_bytes());
            }
            "zip64-count" => {
                let h = f.zip64.unwrap();
                f.bytes[h + 24..h + 40].copy_from_slice(&[0; 16]);
            }
            "zip64-locator" => {
                f.bytes[f.eocd - 12..f.eocd - 4].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            "zip64-contradiction" => {
                f.bytes[f.eocd + 10..f.eocd + 12].copy_from_slice(&2u16.to_le_bytes());
            }
            "zip64-record-size" => {
                let h = f.zip64.unwrap();
                f.bytes[h + 4..h + 12].copy_from_slice(&45u64.to_le_bytes());
            }
            "zip64-extension-tlv" => {
                let h = f.zip64.unwrap();
                // APPNOTE extensible-sector TLV claims three bytes, contains one.
                f.bytes.splice(h + 56..h + 56, [0x99, 0, 3, 0, 0, 0, 1]);
                f.bytes[h + 4..h + 12].copy_from_slice(&51u64.to_le_bytes());
            }
            "count-high" => {
                f.bytes[f.eocd + 8..f.eocd + 12].copy_from_slice(&[4, 0, 4, 0]);
            }
            "local-name" => {
                let h = f.headers[2];
                let local =
                    u32::from_le_bytes(f.bytes[h + 42..h + 46].try_into().unwrap()) as usize;
                f.bytes[local + 30] = b'X';
            }
            "invalid-utf8" => {
                let h = f.headers[2];
                let local =
                    u32::from_le_bytes(f.bytes[h + 42..h + 46].try_into().unwrap()) as usize;
                f.bytes[h + 8..h + 10].copy_from_slice(&(1u16 << 11).to_le_bytes());
                f.bytes[local + 6..local + 8].copy_from_slice(&(1u16 << 11).to_le_bytes());
                f.bytes[h + 46] = 0xff;
                f.bytes[local + 30] = 0xff;
            }
            _ => unreachable!(),
        }
        reject(case, f, "update ZIP identity");
    }
}
