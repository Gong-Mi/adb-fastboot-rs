//! ADB I/O primitives — hex-prefix protocol, robust read/write, orderly shutdown.
//!
//! Mirrors AOSP `vendor/adb/adb_io.cpp`.

use std::io::{Read, Write};

/// Maximum ADB payload size (256 KiB).
pub const MAX_PAYLOAD: usize = 256 * 1024;

/// Write a 4-character hex length prefix followed by the data (AOSP: `SendProtocolString`).
pub fn send_protocol_string(stream: &mut impl Write, s: &[u8]) -> std::io::Result<()> {
    let length = s.len();
    if length > MAX_PAYLOAD - 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload too large"));
    }
    let prefix = format!("{:04x}", length);
    stream.write_all(prefix.as_bytes())?;
    stream.write_all(s)
}

/// Read a 4-character hex length prefix, then read that many bytes (AOSP: `ReadProtocolString`).
pub fn read_protocol_string(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len_str = std::str::from_utf8(&len_buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 length"))?;
    let len = usize::from_str_radix(len_str, 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad hex length"))?;
    if len > MAX_PAYLOAD {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload too large"));
    }
    let mut data = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut data)?;
    }
    Ok(data)
}

/// Write "OKAY" (AOSP: `SendOkay`).
pub fn send_okay(stream: &mut impl Write) -> std::io::Result<()> {
    stream.write_all(b"OKAY")
}

/// Write "FAIL" + hex-prefixed reason string (AOSP: `SendFail`).
pub fn send_fail(stream: &mut impl Write, reason: &str) -> std::io::Result<()> {
    stream.write_all(b"FAIL")?;
    send_protocol_string(stream, reason.as_bytes())
}

/// Read exactly `len` bytes, with EAGAIN retry + EPIPE handling (AOSP: `ReadFdExactly`).
///
/// Rust's `read_exact` does partial-read looping but doesn't handle EAGAIN/yield.
pub fn read_exactly(stream: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match stream.read(&mut buf[offset..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read 0 bytes")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Write exactly `buf` bytes, with EAGAIN retry + EPIPE handling (AOSP: `WriteFdExactly`).
pub fn write_exactly(stream: &mut dyn Write, buf: &[u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match stream.write(&buf[offset..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Check for orderly/graceful shutdown from peer (AOSP: `ReadOrderlyShutdown`).
///
/// Reads up to 16 bytes from the stream. Returns:
/// - `Ok(true)` — peer performed orderly shutdown (read 0 bytes)
/// - `Ok(false)` — read returned an error (not EAGAIN)
/// - `Err(data)` — unexpectedly received data (protocol error)
pub fn read_orderly_shutdown(stream: &mut dyn Read) -> Result<bool, Vec<u8>> {
    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(0) => Ok(true),
        Ok(n) => Err(buf[..n].to_vec()),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // Nonblocking socket with nothing to read — treat as no data
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_send_protocol_string_roundtrip() {
        let input = b"shell:v2,raw:";
        let mut buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut buf);
            send_protocol_string(cursor.get_mut(), input).unwrap();
        }
        // Parse manually: first 4 bytes = hex length, rest = data
        let len_str = std::str::from_utf8(&buf[..4]).unwrap();
        let len = usize::from_str_radix(len_str, 16).unwrap();
        assert_eq!(len, input.len());
        assert_eq!(&buf[4..], input);
    }

    #[test]
    fn test_read_protocol_string_roundtrip() {
        let input = b"shell:v2,raw:";
        let mut buf = format!("{:04x}", input.len()).into_bytes();
        buf.extend_from_slice(input);
        let mut cursor = Cursor::new(buf);
        let result = read_protocol_string(&mut cursor).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_send_okay() {
        let mut buf = Vec::new();
        send_okay(&mut buf).unwrap();
        assert_eq!(buf, b"OKAY");
    }

    #[test]
    fn test_send_fail() {
        let mut buf = Vec::new();
        send_fail(&mut buf, "device not found").unwrap();
        assert_eq!(&buf[..4], b"FAIL");
        let len_str = std::str::from_utf8(&buf[4..8]).unwrap();
        let len = usize::from_str_radix(len_str, 16).unwrap();
        assert_eq!(&buf[8..8 + len], b"device not found");
    }

    #[test]
    fn test_read_exactly() {
        let data = b"hello world";
        let mut cursor = Cursor::new(data);
        let mut buf = vec![0u8; 5];
        read_exactly(&mut cursor, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_write_exactly() {
        let mut buf = Vec::new();
        write_exactly(&mut buf, b"hello").unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn test_read_orderly_shutdown() {
        // Empty stream → orderly shutdown
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(read_orderly_shutdown(&mut empty).unwrap());

        // Stream with data → Err
        let mut data = Cursor::new(b"unexpected");
        let result = read_orderly_shutdown(&mut data);
        assert!(result.is_err());
    }
}
