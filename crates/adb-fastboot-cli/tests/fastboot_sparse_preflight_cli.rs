//! Real update CLI safety regression. Fixtures and FB01 peer are independent of
//! SparseFile and its encoder: AOSP libsparse sparse_read.cpp (Android 17,
//! 545d2487e38192a2ce25040897ced877cf6b4f53) requires the logical block sum
//! to equal total_blks, and CRC32 contributes no output blocks.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sparse(block_size: u32, total_blocks: u32, chunks: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend(0xed26ff3au32.to_le_bytes());
    for value in [1u16, 0, 28, 12] {
        wire.extend(value.to_le_bytes());
    }
    for value in [block_size, total_blocks, chunks.len() as u32, 0] {
        wire.extend(value.to_le_bytes());
    }
    for &(kind, blocks, payload) in chunks {
        wire.extend(kind.to_le_bytes());
        wire.extend(0u16.to_le_bytes());
        wire.extend(blocks.to_le_bytes());
        wire.extend((12 + payload.len() as u32).to_le_bytes());
        wire.extend(payload);
    }
    wire
}

fn packet(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0; 8];
    match socket.read(&mut header[..1]) {
        Ok(0) => return None,
        Ok(1) => socket.read_exact(&mut header[1..]).unwrap(),
        result => panic!("peer stalled or failed: {result:?}"),
    }
    let length = u64::from_be_bytes(header);
    assert!(length > 0 && length <= 65536, "invalid FB01 frame {length}");
    let mut bytes = vec![0; length as usize];
    socket.read_exact(&mut bytes).unwrap();
    Some(bytes)
}

fn respond(socket: &mut TcpStream, bytes: &[u8]) {
    socket
        .write_all(&(bytes.len() as u64).to_be_bytes())
        .unwrap();
    socket.write_all(bytes).unwrap();
}

#[derive(Debug)]
struct Effects {
    commands: Vec<String>,
    downloads: usize,
    boot: Vec<u8>,
    system: Vec<u8>,
}

// Independent structural check, not a call to the production sparse parser.
// CRC blocks advance no output position. DONT_CARE seeks without writing.
fn valid_sparse(bytes: &[u8]) -> bool {
    let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let half = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    if bytes.len() < 28 || word(0) != 0xed26ff3a || half(4) != 1 {
        return false;
    }
    let block_size = word(12);
    if block_size == 0 || block_size % 4 != 0 {
        return false;
    }
    let mut offset = half(8) as usize;
    let chunk_header = half(10) as usize;
    if offset < 28 || chunk_header < 12 || offset > bytes.len() {
        return false;
    }
    let mut blocks = 0u64;
    for _ in 0..word(20) {
        if offset + chunk_header > bytes.len() {
            return false;
        }
        let count = word(offset + 4);
        let size = word(offset + 8) as usize;
        if size < chunk_header || offset + size > bytes.len() {
            return false;
        }
        let payload = size - chunk_header;
        match half(offset) {
            0xcac1 if count > 0 && payload as u64 == u64::from(count) * u64::from(block_size) => {
                blocks += u64::from(count);
            }
            0xcac2 if count > 0 && payload == 4 => blocks += u64::from(count),
            0xcac3 if count > 0 && payload == 0 => blocks += u64::from(count),
            0xcac4 if count == 0 && payload == 4 => {}
            _ => return false,
        }
        offset += size;
    }
    blocks == u64::from(word(16))
}

fn run_update(name: &str, system: &[u8]) -> (Output, Effects) {
    // Every image is smaller than the peer's limit. The regression must not
    // accidentally exercise split(), which already rejected a wrong span.
    assert!(system.len() < 65536);
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fastboot-sparse-preflight-{name}-{}",
        std::process::id()
    )));
    std::fs::create_dir_all(&scratch.0).unwrap();
    let zip_path = scratch.0.join("update.zip");
    let mut archive = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    for (entry, data) in [
        ("android-info.txt", &b""[..]),
        ("boot.img", &b"BOOT"[..]),
        ("system.img", system),
    ] {
        archive
            .start_file(
                entry,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(data).unwrap();
    }
    archive.finish().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let expected_system = system.to_vec();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
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
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut handshake = [0; 4];
        socket.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        socket.write_all(b"FB01").unwrap();
        let mut effects = Effects {
            commands: Vec::new(),
            downloads: 0,
            boot: b"untouched-boot".to_vec(),
            system: b"untouched-system".to_vec(),
        };
        let mut staged = None;
        while let Some(bytes) = packet(&mut socket) {
            let command = String::from_utf8(bytes).unwrap();
            effects.commands.push(command.clone());
            match command.as_str() {
                "getvar:version-bootloader" | "getvar:version-baseband" | "getvar:serialno" => {
                    respond(&mut socket, b"OKAYtest")
                }
                "getvar:max-download-size" => respond(&mut socket, b"OKAY0x10000"),
                "getvar:has-slot:boot" | "getvar:has-slot:system" => {
                    respond(&mut socket, b"OKAYno")
                }
                "flash:boot" => {
                    assert_eq!(staged.take().unwrap(), b"BOOT");
                    effects.boot = b"BOOT".to_vec();
                    respond(&mut socket, b"OKAY");
                }
                "flash:system" => {
                    let payload = staged.take().unwrap();
                    assert_eq!(payload, expected_system, "wrong downloaded image");
                    if valid_sparse(&payload) {
                        effects.system = payload;
                        respond(&mut socket, b"OKAY");
                    } else {
                        // Do not panic before recording the forbidden earlier
                        // boot write. Return a real device rejection and EOF.
                        respond(&mut socket, b"FAILinvalid sparse structure");
                    }
                }
                "reboot" => respond(&mut socket, b"OKAY"),
                command if command.starts_with("download:") => {
                    assert!(staged.is_none(), "unflashed payload");
                    let hex = command.strip_prefix("download:").unwrap();
                    assert_eq!(hex.len(), 8);
                    let size = usize::from_str_radix(hex, 16).unwrap();
                    assert!(size > 0 && size <= 65536);
                    effects.downloads += 1;
                    respond(&mut socket, format!("DATA{size:08x}").as_bytes());
                    let mut payload = Vec::new();
                    while payload.len() < size {
                        payload.extend(packet(&mut socket).expect("short download"));
                        assert!(payload.len() <= size, "oversized download");
                    }
                    staged = Some(payload);
                    respond(&mut socket, b"OKAY");
                }
                _ => panic!("unexpected wire command {command:?}"),
            }
        }
        effects
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &address, "update"])
        .arg(&zip_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            let _ = peer.join();
            panic!("CLI timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    (output, peer.join().unwrap())
}

fn rejects_before_any_write(name: &str, bytes: Vec<u8>) {
    assert!(
        !valid_sparse(&bytes),
        "negative fixture must be independently invalid"
    );
    let (output, effects) = run_update(name, &bytes);
    // Check effects before stderr: the old CLI also exits 1 after damaging boot.
    assert_eq!(
        effects.downloads, 0,
        "invalid later system.img must be rejected before ANY download/flash: {effects:?}"
    );
    assert_eq!(effects.boot, b"untouched-boot");
    assert_eq!(effects.system, b"untouched-system");
    assert!(
        effects
            .commands
            .iter()
            .all(|command| command.starts_with("getvar:")),
        "write/reboot after preflight failure: {effects:?}"
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Error"),
        "{output:?}"
    );
}

#[test]
fn wrong_sparse_span_is_rejected_before_the_first_update_download() {
    rejects_before_any_write("wrong-span", sparse(4096, 2, &[(0xcac3, 1, &[])]));
}
