//! One owner per fresh TCP service connection: no fd/transport clones, no
//! blocking recv under a shared mutex. This thread alone reads AND writes ADB.
//! Legacy ACK mode only (we do not advertise delayed_ack). TLS is polled even
//! when the underlying fd is not readable, because rustls may buffer plaintext.
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use adb_protocol::{AdbMessageHeader, Transport, A_CLSE, A_OKAY, A_OPEN, A_WRTE, MAX_PAYLOAD_V2};

const TICK: Duration = Duration::from_millis(2);
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const INPUT_CHUNK: usize = 4096; // safe even for legacy 4-KiB peers
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

// Linux/Android reports RDHUP even when unread input remains. peek() alone
// cannot see EOF behind queued bytes while device ACK credit is exhausted.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_half_closed(client: &TcpStream) -> Result<bool, String> {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: client.as_raw_fd(),
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut fd, 1, 0) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(format!("client close poll: {error}"));
    }
    Ok(fd.revents & (libc::POLLRDHUP | libc::POLLHUP) != 0)
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_half_closed(_client: &TcpStream) -> Result<bool, String> {
    Ok(false)
}

fn temporary(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Validating, partial-read-preserving framing. Never retry recv_message after
/// WouldBlock: read_exact would lose a partially consumed header/payload.
#[derive(Default)]
struct Frames {
    bytes: Vec<u8>,
}
impl Frames {
    fn next(&mut self) -> Result<Option<(AdbMessageHeader, Vec<u8>)>, String> {
        if self.bytes.len() < 24 {
            return Ok(None);
        }
        let h = AdbMessageHeader::decode(&self.bytes[..24]).map_err(|e| e.to_string())?;
        if h.data_length > MAX_PAYLOAD_V2 {
            return Err("oversized ADB frame".into());
        }
        let end = 24 + h.data_length as usize;
        if self.bytes.len() < end {
            return Ok(None);
        }
        let payload = self.bytes[24..end].to_vec();
        h.verify_payload(&payload).map_err(|e| e.to_string())?;
        self.bytes.drain(..end);
        Ok(Some((h, payload)))
    }
    fn read(&mut self, transport: &mut dyn Transport) -> Result<bool, String> {
        // Drain completed frames before admitting another read. A flood of tiny
        // unrelated-ID packets must not grow this buffer beyond one max frame
        // plus one read chunk, nor conceal an oversize header.
        if self.bytes.len() >= 24 {
            let h = AdbMessageHeader::decode(&self.bytes[..24]).map_err(|e| e.to_string())?;
            if h.data_length > MAX_PAYLOAD_V2 {
                return Err("oversized ADB frame".into());
            }
            if self.bytes.len() >= 24 + h.data_length as usize {
                return Ok(false);
            }
        }
        let mut buf = [0; 8192];
        match transport.read(&mut buf) {
            Ok(0) => Err(if self.bytes.is_empty() {
                "device EOF"
            } else {
                "device EOF inside ADB frame"
            }
            .into()),
            Ok(n) => {
                self.bytes.extend_from_slice(&buf[..n]);
                Ok(true)
            }
            Err(e) if temporary(&e) => Ok(false),
            Err(e) => Err(format!("device read: {e}")),
        }
    }
}

struct Pending {
    bytes: Vec<u8>,
    offset: usize,
    until: Instant,
}
impl Pending {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            offset: 0,
            until: Instant::now() + PROGRESS_TIMEOUT,
        }
    }
    fn write(&mut self, io: &mut (impl Write + ?Sized)) -> Result<bool, String> {
        if Instant::now() >= self.until {
            return Err("bridge write timeout".into());
        }
        if self.offset == self.bytes.len() {
            return Ok(false);
        }
        match io.write(&self.bytes[self.offset..]) {
            Ok(0) => Err("zero-progress write".into()),
            Ok(n) => {
                self.offset += n;
                Ok(true)
            }
            Err(e) if temporary(&e) => Ok(false),
            Err(e) => Err(format!("write: {e}")),
        }
    }
    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Single serial writer queue. A frame's header+payload and TLS flush complete
/// before another frame starts. TLS write's accepted plaintext is never replayed.
#[derive(Default)]
struct Writer {
    frames: VecDeque<Pending>,
}
impl Writer {
    fn queue(&mut self, cmd: u32, local: u32, remote: u32, data: &[u8]) -> Result<(), String> {
        // One WRTE, its ACK and a close are enough for this single-stream owner.
        if self.frames.len() >= 8 {
            return Err("ADB writer queue overflow".into());
        }
        let h = AdbMessageHeader::new(cmd, local, remote, data);
        let mut header = [0; 24];
        h.encode(&mut header);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(data);
        self.frames.push_back(Pending::new(bytes));
        Ok(())
    }
    fn pump(&mut self, io: &mut dyn Transport) -> Result<bool, String> {
        let Some(frame) = self.frames.front_mut() else {
            return Ok(false);
        };
        if Instant::now() >= frame.until {
            return Err("ADB frame write/flush timeout".into());
        }
        let progress = frame.write(io)?;
        if frame.done() {
            match io.flush() {
                Ok(()) => {
                    self.frames.pop_front();
                    return Ok(true);
                }
                Err(e) if temporary(&e) => {}
                Err(e) => return Err(format!("frame flush: {e}")),
            }
        }
        Ok(progress)
    }
    fn empty(&self) -> bool {
        self.frames.is_empty()
    }
}

pub(crate) struct RemoteSocket {
    pub local_id: u32,
    pub remote_id: u32,
    transport: Box<dyn Transport>,
    reader: Frames,
    writer: Writer,
}
impl RemoteSocket {
    /// Ownership moves once: handshake caller -> OPEN owner -> bridge owner.
    pub(crate) fn open(mut transport: Box<dyn Transport>, service: &str) -> Result<Self, String> {
        // Shared USB transports intentionally fail before OPEN: enabling this
        // requires a cached-transport-wide dispatcher, not a second USB claim.
        transport.inner_tcp_mut().ok_or("duplex bridge requires exclusively owned TCP/TLS transport; USB dispatcher not implemented")?
            .set_nonblocking(true).map_err(|e| e.to_string())?;
        let local_id = loop {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                break id;
            }
        };
        let mut this = Self {
            local_id,
            remote_id: 0,
            transport,
            reader: Frames::default(),
            writer: Writer::default(),
        };
        let mut service = service.as_bytes().to_vec();
        service.push(0);
        this.writer.queue(A_OPEN, local_id, 0, &service)?;
        let until = Instant::now() + OPEN_TIMEOUT;
        loop {
            this.writer.pump(&mut *this.transport)?;
            while let Some((h, payload)) = this.reader.next()? {
                if h.arg1 != local_id {
                    continue;
                }
                match h.command {
                    A_OKAY if h.arg0 != 0 && payload.is_empty() => {
                        this.remote_id = h.arg0;
                        return Ok(this);
                    }
                    A_CLSE => {
                        return Err(format!(
                            "device rejected service (CLSE): {}",
                            String::from_utf8_lossy(&payload)
                        ))
                    }
                    _ => return Err("invalid OPEN response".into()),
                }
            }
            this.reader.read(&mut *this.transport)?;
            if Instant::now() >= until {
                return Err("device OPEN timeout".into());
            }
            std::thread::sleep(TICK);
        }
    }

    pub(crate) fn bridge(
        mut self,
        mut client: TcpStream,
        running: &AtomicBool,
    ) -> Result<(), String> {
        client.set_nonblocking(true).map_err(|e| e.to_string())?;
        let result = self.relay(&mut client, running);
        // No child relay thread to detach/join. Owner return closes the device
        // connection; shutdown wakes the smart-socket peer even on error.
        let _ = client.shutdown(Shutdown::Both);
        result
    }

    fn relay(&mut self, client: &mut TcpStream, running: &AtomicBool) -> Result<(), String> {
        let mut awaiting_ack: Option<Instant> = None;
        let mut output: Option<Pending> = None;
        let mut closing: Option<Instant> = None;
        let mut device_closed = false;
        let mut terminal_error: Option<String> = None;
        loop {
            let now = Instant::now();
            if !running.load(Ordering::Acquire) && closing.is_none() {
                self.writer
                    .queue(A_CLSE, self.local_id, self.remote_id, &[])?;
                closing = Some(now + CLOSE_TIMEOUT);
                terminal_error = Some("server bridge cancelled".into());
                output = None; // cancellation is not output-drain success
            }
            let mut progress = self.writer.pump(&mut *self.transport)?;

            // Dispatch every frame through one reader. OKAY never goes to the
            // output consumer, and WRTE never goes to a competing ACK waiter.
            for _ in 0..128 {
                let Some((h, payload)) = self.reader.next()? else {
                    break;
                };
                progress = true;
                if h.arg1 != self.local_id
                    || (h.arg0 != self.remote_id && !(h.command == A_CLSE && h.arg0 == 0))
                {
                    continue; // AOSP drops mismatched stream IDs; no data/credit leakage
                }
                match h.command {
                    A_OKAY if payload.is_empty() => {
                        awaiting_ack = None;
                    }
                    A_WRTE if closing.is_none() => {
                        if output.is_some() {
                            return Err("device WRTE before previous output ACK".into());
                        }
                        output = Some(Pending::new(payload));
                    }
                    A_CLSE if payload.is_empty() => {
                        if !device_closed && closing.is_none() {
                            self.writer
                                .queue(A_CLSE, self.local_id, self.remote_id, &[])?;
                        }
                        device_closed = true;
                        closing.get_or_insert(now + CLOSE_TIMEOUT);
                    }
                    A_WRTE if closing.is_some() => {} // close revokes new input/output
                    _ => return Err("invalid device stream frame".into()),
                }
            }
            if let Some(pending) = output.as_mut() {
                progress |= pending.write(client)?;
                if pending.done() {
                    output = None;
                    // ACK only after all accepted output reaches the local socket.
                    if !device_closed {
                        self.writer
                            .queue(A_OKAY, self.local_id, self.remote_id, &[])?;
                    }
                }
            }
            if closing.is_none() && awaiting_ack.is_none() && self.writer.empty() {
                let mut input = [0; INPUT_CHUNK];
                match client.read(&mut input) {
                    Ok(0) => {
                        self.writer
                            .queue(A_CLSE, self.local_id, self.remote_id, &[])?;
                        closing = Some(now + CLOSE_TIMEOUT);
                    }
                    Ok(n) => {
                        self.writer
                            .queue(A_WRTE, self.local_id, self.remote_id, &input[..n])?;
                        awaiting_ack = Some(now + PROGRESS_TIMEOUT);
                        progress = true;
                    }
                    Err(e) if temporary(&e) => {}
                    Err(e) => return Err(format!("client read: {e}")),
                }
            } else if closing.is_none() && read_half_closed(client)? {
                self.writer
                    .queue(A_CLSE, self.local_id, self.remote_id, &[])?;
                closing = Some(now + CLOSE_TIMEOUT);
            } else if closing.is_none() {
                // Detect client cancellation even while waiting for device ACK
                // without consuming or buffering more input past the credit limit.
                let mut byte = [0];
                match client.peek(&mut byte) {
                    Ok(0) => {
                        self.writer
                            .queue(A_CLSE, self.local_id, self.remote_id, &[])?;
                        closing = Some(now + CLOSE_TIMEOUT);
                    }
                    Ok(_) => {}
                    Err(e) if temporary(&e) => {}
                    Err(e) => return Err(format!("client peek: {e}")),
                }
            }
            if let Some(until) = closing {
                if output.is_none() && self.writer.empty() {
                    return match terminal_error {
                        Some(error) => Err(error),
                        None => Ok(()),
                    };
                }
                if now >= until {
                    return Err("close drain timeout".into());
                }
            } else if awaiting_ack.is_some_and(|until| now >= until) {
                return Err("device ACK timeout".into());
            }
            if !device_closed {
                match self.reader.read(&mut *self.transport) {
                    Ok(read) => progress |= read,
                    Err(error) => {
                        // Complete WRTE already accepted before EOF still drains
                        // to the local socket. Preserve the failure as the outcome;
                        // do not acknowledge data on a dead transport or call it
                        // a clean CLSE. Incomplete trailing frames are never emitted.
                        terminal_error = Some(error);
                        device_closed = true;
                        self.writer.frames.clear();
                        closing.get_or_insert(now + CLOSE_TIMEOUT);
                    }
                }
            }
            if !progress {
                std::thread::sleep(TICK);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::TcpTransport;
    use std::net::TcpListener;
    use std::sync::{mpsc, Arc};
    use std::thread;

    fn wire(cmd: &[u8; 4], a: u32, b: u32, p: &[u8]) -> Vec<u8> {
        let cmd = u32::from_le_bytes(*cmd);
        let mut out = Vec::new();
        for w in [cmd, a, b, p.len() as u32, 0, !cmd] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(p);
        out
    }
    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        a.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        (a, b)
    }
    fn owner(socket: TcpStream) -> RemoteSocket {
        socket.set_nonblocking(true).unwrap();
        RemoteSocket {
            local_id: 29,
            remote_id: 73,
            transport: Box::new(TcpTransport::from_stream(socket)),
            reader: Frames::default(),
            writer: Writer::default(),
        }
    }
    fn small_send_buffer(s: &TcpStream) {
        use std::os::fd::AsRawFd;
        let size = 4096i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const i32).cast(),
                    std::mem::size_of::<i32>() as _,
                )
            },
            0
        );
    }
    #[test]
    fn framing_preserves_every_byte_fragment_and_coalesced_tail() {
        let first = wire(b"WRTE", 73, 29, b"hello");
        let second = wire(b"OKAY", 73, 29, &[]);
        let mut r = Frames::default();
        for (i, b) in first.iter().enumerate() {
            r.bytes.push(*b);
            if i + 1 != first.len() {
                assert!(r.next().unwrap().is_none());
            }
        }
        r.bytes.extend_from_slice(&second);
        let (h, p) = r.next().unwrap().unwrap();
        assert_eq!(
            (h.command, h.arg0, h.arg1, p),
            (A_WRTE, 73, 29, b"hello".to_vec())
        );
        assert_eq!(r.next().unwrap().unwrap().0.command, A_OKAY);
        assert!(r.next().unwrap().is_none());
    }
    #[test]
    fn framing_rejects_bad_magic_oversize_and_bad_checksum() {
        for which in 0..3 {
            let mut bytes = wire(b"WRTE", 73, 29, b"x");
            if which == 0 {
                bytes[20] ^= 1;
            }
            if which == 1 {
                bytes[12..16].copy_from_slice(&(MAX_PAYLOAD_V2 + 1).to_le_bytes());
            }
            if which == 2 {
                bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
            }
            assert!(Frames { bytes }.next().is_err());
        }
    }
    struct PartialWriter {
        bytes: Vec<u8>,
        calls: usize,
        flushes: usize,
    }
    impl Read for PartialWriter {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }
    }
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls % 3 == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.bytes.push(bytes[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes % 2 == 1 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        }
    }
    impl Transport for PartialWriter {}
    #[test]
    fn serial_writer_preserves_frames_on_short_write_and_flush_wouldblock() {
        let mut q = Writer::default();
        q.queue(A_WRTE, 29, 73, b"abc").unwrap();
        q.queue(A_OKAY, 29, 73, &[]).unwrap();
        let mut io = PartialWriter {
            bytes: vec![],
            calls: 0,
            flushes: 0,
        };
        for _ in 0..200 {
            if q.empty() {
                break;
            }
            q.pump(&mut io).unwrap();
        }
        assert!(q.empty());
        let mut expected = wire(b"WRTE", 29, 73, b"abc");
        expected.extend_from_slice(&wire(b"OKAY", 29, 73, &[]));
        assert_eq!(io.bytes, expected);
    }
    #[test]
    fn writer_queue_is_bounded() {
        let mut q = Writer::default();
        for _ in 0..8 {
            q.queue(A_OKAY, 29, 73, &[]).unwrap();
        }
        assert!(q.queue(A_OKAY, 29, 73, &[]).is_err());
    }

    #[test]
    fn fakewire_eof_drains_accepted_output_before_owner_exit() {
        let (mut device, server_device) = pair();
        let (mut client, server_client) = pair();
        small_send_buffer(&server_client);
        let active = Arc::new(AtomicBool::new(true));
        let flag = active.clone();
        let handle = thread::spawn(move || owner(server_device).bridge(server_client, &flag));
        let data = vec![b'z'; 512 * 1024];
        device.write_all(&wire(b"WRTE", 73, 29, &data)).unwrap();
        device.shutdown(Shutdown::Write).unwrap();
        let mut output = Vec::new();
        client.read_to_end(&mut output).unwrap();
        assert_eq!(
            output.len(),
            data.len(),
            "EOF cannot discard a complete accepted WRTE"
        );
        assert_eq!(output, data);
        assert!(handle.join().unwrap().unwrap_err().contains("EOF"));
    }
    #[test]
    fn fakewire_cancel_silent_reader_joins_and_closes_both_peers() {
        let (mut device, server_device) = pair();
        let (mut client, server_client) = pair();
        let active = Arc::new(AtomicBool::new(true));
        let flag = active.clone();
        let (done, wait) = mpsc::channel();
        let handle = thread::spawn(move || {
            let r = owner(server_device).bridge(server_client, &flag);
            done.send(r).unwrap();
        });
        active.store(false, Ordering::Release);
        assert!(wait
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err()
            .contains("cancelled"));
        handle.join().unwrap();
        let mut packet = Vec::new();
        device.read_to_end(&mut packet).unwrap();
        assert_eq!(packet, wire(b"CLSE", 29, 73, &[]));
        let mut b = [0];
        assert_eq!(client.read(&mut b).unwrap(), 0);
    }

    #[test]
    fn fakewire_cancel_backpressured_output_joins_without_false_ack() {
        let (mut device, server_device) = pair();
        let (mut client, server_client) = pair();
        small_send_buffer(&server_client);
        let active = Arc::new(AtomicBool::new(true));
        let flag = active.clone();
        let (done, wait) = mpsc::channel();
        let handle = thread::spawn(move || {
            let r = owner(server_device).bridge(server_client, &flag);
            done.send(r).unwrap();
        });
        device
            .write_all(&wire(b"WRTE", 73, 29, &vec![b'z'; 512 * 1024]))
            .unwrap();
        client.set_nonblocking(true).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let mut byte = [0];
            if client.peek(&mut byte).unwrap_or(0) != 0 {
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(TICK);
        }
        active.store(false, Ordering::Release);
        assert!(wait
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err()
            .contains("cancelled"));
        handle.join().unwrap();
        let mut packet = Vec::new();
        device.read_to_end(&mut packet).unwrap();
        assert_eq!(
            packet,
            wire(b"CLSE", 29, 73, &[]),
            "no ACK for undrained output"
        );
        client.set_nonblocking(false).unwrap();
        let mut accepted = Vec::new();
        client.read_to_end(&mut accepted).unwrap();
        assert!(!accepted.is_empty());
        assert!(
            accepted.len() < 512 * 1024,
            "fixture actually backpressured the client"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fakewire_client_eof_with_unread_input_closes_while_ack_is_withheld() {
        let (mut device, server_device) = pair();
        let (mut client, server_client) = pair();
        let active = Arc::new(AtomicBool::new(true));
        let flag = active.clone();
        let (done, wait) = mpsc::channel();
        let handle = thread::spawn(move || {
            done.send(owner(server_device).bridge(server_client, &flag))
                .unwrap();
        });
        client.write_all(&vec![b'i'; 8192]).unwrap();
        let mut first = [0; 24 + INPUT_CHUNK];
        device.read_exact(&mut first).unwrap();
        assert_eq!(&first[..4], b"WRTE");
        client.shutdown(Shutdown::Write).unwrap();
        wait.recv_timeout(Duration::from_secs(2))
            .expect("buffered input must not conceal client EOF")
            .unwrap();
        handle.join().unwrap();
        let mut remaining = Vec::new();
        device.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, wire(b"CLSE", 29, 73, &[]));
        let mut out = Vec::new();
        client.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn write_deadline_does_not_reset_on_unrelated_activity() {
        let mut io = PartialWriter {
            bytes: vec![],
            calls: 0,
            flushes: 0,
        };
        let mut pending = Pending::new(vec![1]);
        pending.until = Instant::now() - Duration::from_millis(1);
        assert!(pending.write(&mut io).unwrap_err().contains("timeout"));
        assert!(io.bytes.is_empty());
        let mut q = Writer::default();
        q.queue(A_WRTE, 29, 73, b"x").unwrap();
        q.frames.front_mut().unwrap().until = Instant::now() - Duration::from_millis(1);
        assert!(q.pump(&mut io).unwrap_err().contains("timeout"));
    }
}
