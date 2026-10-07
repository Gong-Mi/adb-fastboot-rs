//! Executable CLI tests, not helper-only tests. The peer models repeated sparse
//! flashes onto one partition; every flash starts at offset zero and skips holes.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("fastboot-sparse-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_packet(socket: &mut TcpStream, max: usize) -> Vec<u8> {
    let mut header = [0; 8];
    socket.read_exact(&mut header).unwrap();
    let len = u64::from_be_bytes(header);
    assert!(len > 0 && len <= max as u64, "invalid TCP packet length {len}");
    let mut bytes = vec![0; len as usize];
    socket.read_exact(&mut bytes).unwrap();
    bytes
}

fn write_packet(socket: &mut TcpStream, bytes: &[u8]) {
    socket.write_all(&(bytes.len() as u64).to_be_bytes()).unwrap();
    socket.write_all(bytes).unwrap();
}

// Deliberately independent of SparseFile::from_bytes/to_raw, including literals.
fn flash_sparse(bytes: &[u8], partition: &mut [u8]) -> u32 {
    let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    assert_eq!(u32_at(0), 0xed26ff3a);
    assert_eq!(u16_at(4), 1);
    let block_size = u32_at(12) as usize;
    let span = u32_at(16);
    assert!(span as usize * block_size <= partition.len());
    let mut wire_offset = u16_at(8) as usize;
    let chunk_header_size = u16_at(10) as usize;
    let mut offset = 0; // reset on EVERY flash, never append downloaded payloads
    for _ in 0..u32_at(20) {
        let kind = u16_at(wire_offset);
        let length = u32_at(wire_offset + 4) as usize * block_size;
        let wire_size = u32_at(wire_offset + 8) as usize;
        let payload = &bytes[wire_offset + chunk_header_size..wire_offset + wire_size];
        assert!(offset + length <= partition.len());
        match kind {
            0xcac1 => {
                assert_eq!(payload.len(), length);
                partition[offset..offset + length].copy_from_slice(payload);
            }
            0xcac2 => {
                assert_eq!(payload.len(), 4);
                for (index, byte) in partition[offset..offset + length].iter_mut().enumerate() {
                    *byte = payload[index % 4];
                }
            }
            0xcac3 => assert!(payload.is_empty()), // skip, do NOT zero existing bytes
            0xcac4 => {
                assert_eq!(length, 0);
                assert_eq!(payload.len(), 4);
            }
            _ => panic!("unexpected chunk type {kind:#x}"),
        }
        offset += length;
        wire_offset += wire_size;
    }
    assert_eq!(wire_offset, bytes.len());
    assert_eq!(offset, span as usize * block_size);
    span
}

fn run_split_flash(name: &str, image: &[u8], expected: &[u8], initial: u8, max_download: usize) {
    assert!(image.len() > max_download, "fixture must trigger automatic CLI split");
    let scratch = Scratch::new(name);
    let image_path = scratch.0.join("system.img");
    std::fs::write(&image_path, image).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let partition_len = expected.len();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("CLI did not connect: {error}"),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut handshake = [0; 4];
        socket.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        socket.write_all(b"FB01").unwrap();
        assert_eq!(read_packet(&mut socket, 64), b"getvar:max-download-size");
        write_packet(&mut socket, format!("OKAY0x{max_download:x}").as_bytes());

        let mut partition = vec![initial; partition_len];
        let mut spans = Vec::new();
        let mut downloads = Vec::new();
        loop {
            // Order is download -> DATA -> exactly N bytes -> OKAY -> flash -> OKAY.
            let mut header = [0; 8];
            match socket.read(&mut header[..1]) {
                Ok(0) => break,
                Ok(1) => socket.read_exact(&mut header[1..]).unwrap(),
                result => panic!("CLI stalled or invalid read: {result:?}"),
            }
            let command_len = u64::from_be_bytes(header) as usize;
            assert_eq!(command_len, 17);
            let mut command = vec![0; command_len];
            socket.read_exact(&mut command).unwrap();
            let command = String::from_utf8(command).unwrap();
            let hex = command.strip_prefix("download:").expect("only downloads are allowed here");
            assert_eq!(hex.len(), 8);
            let download_len = usize::from_str_radix(hex, 16).unwrap();
            assert!(download_len > 0 && download_len <= max_download);
            write_packet(&mut socket, format!("DATA{download_len:08x}").as_bytes());
            let mut payload = Vec::new();
            while payload.len() < download_len {
                payload.extend(read_packet(&mut socket, download_len - payload.len()));
            }
            assert_eq!(payload.len(), download_len);
            write_packet(&mut socket, b"OKAY");
            // This peer has only a system partition. Never accept erase/reboot/other slots.
            assert_eq!(read_packet(&mut socket, 64), b"flash:system");
            spans.push(flash_sparse(&payload, &mut partition));
            downloads.push(payload);
            write_packet(&mut socket, b"OKAY");
        }
        (partition, spans, downloads)
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &addr.to_string(), "flash", "system"])
        .arg(&image_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("fastboot-rs did not terminate within 15 seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let result = peer.join().expect("strict sparse peer failed");
    assert!(output.status.success(), "CLI failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(result.2.len() >= 2, "must exercise multiple flashes");
    let mismatch = result.0.iter().zip(expected).position(|(actual, expected)| actual != expected);
    assert_eq!(mismatch, None, "final partition first differs at {mismatch:?}");
    assert!(result.1.iter().all(|&span| span as usize * 4096 == expected.len()));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Split into"));
}

#[test]
fn executable_automatically_splits_raw_and_reconstructs_one_partition() {
    let raw: Vec<u8> = (1..=3).flat_map(|value| vec![value; 4096]).collect();
    run_split_flash("raw", &raw, &raw, 0, 8500);
}

#[test]
fn executable_resplits_mixed_sparse_without_overwriting_holes_or_prior_flashes() {
    let mut file = fastboot_protocol::SparseFile::new(4096);
    file.add_chunk(fastboot_protocol::SparseChunk::dont_care(1).unwrap());
    let raw: Vec<u8> = (1..=3).flat_map(|value| vec![value; 4096]).collect();
    file.add_chunk(fastboot_protocol::SparseChunk::raw(raw.clone(), 4096).unwrap());
    file.add_chunk(fastboot_protocol::SparseChunk::fill(0x12345678, 2).unwrap());
    file.add_chunk(fastboot_protocol::SparseChunk::dont_care(1).unwrap());
    file.add_chunk(fastboot_protocol::SparseChunk::raw(vec![0x44; 4096], 4096).unwrap());
    file.add_chunk(fastboot_protocol::SparseChunk::dont_care(1).unwrap());
    let mut expected = vec![0xa5; 4096];
    expected.extend(raw);
    expected.extend((0..2048).flat_map(|_| [0x78, 0x56, 0x34, 0x12]));
    expected.extend(vec![0xa5; 4096]);
    expected.extend(vec![0x44; 4096]);
    expected.extend(vec![0xa5; 4096]);
    run_split_flash("mixed", &file.encode(), &expected, 0xa5, 8500);
}
