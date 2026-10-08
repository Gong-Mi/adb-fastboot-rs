//! Exclusive asynchronous USB frame I/O. No shared reader or duplicated claim.
use super::urb::{Completion, TransferId, UsbfsUrbOwner};
use crate::{AdbMessageHeader, Transport, MAX_PAYLOAD_V2};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

/// Completion backend boundary, also used by device-free peers. Each backend
/// owns its transfer storage until completion or exclusive shutdown on Drop.
pub trait UrbIo: Send {
    fn packet_size(&self) -> usize;
    fn submit_read(&mut self, length: usize) -> io::Result<TransferId>;
    fn submit_write(&mut self, bytes: &[u8]) -> io::Result<TransferId>;
    fn poll(&mut self) -> io::Result<Option<Completion>>;
    fn cancel(&mut self, id: TransferId) -> io::Result<()>;
}
impl UrbIo for UsbfsUrbOwner {
    fn packet_size(&self) -> usize {
        self.packet_size()
    }
    fn submit_read(&mut self, n: usize) -> io::Result<TransferId> {
        self.submit_read(n)
    }
    fn submit_write(&mut self, b: &[u8]) -> io::Result<TransferId> {
        self.submit_write(b)
    }
    fn poll(&mut self) -> io::Result<Option<Completion>> {
        self.poll()
    }
    fn cancel(&mut self, id: TransferId) -> io::Result<()> {
        self.cancel(id)
    }
}

pub struct UrbFrameTransport<B: UrbIo> {
    backend: B,
    input: VecDeque<u8>,
    read_id: Option<TransferId>,
    write_id: Option<(TransferId, usize)>,
    frame: Vec<u8>,
    transfers: VecDeque<Vec<u8>>,
    failed: Option<String>,
    nonblocking: bool,
    deadline: Option<Instant>,
}
impl<B: UrbIo> UrbFrameTransport<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            input: VecDeque::new(),
            read_id: None,
            write_id: None,
            frame: Vec::new(),
            transfers: VecDeque::new(),
            failed: None,
            nonblocking: false,
            deadline: None,
        }
    }
    fn fail(&mut self, msg: impl ToString) -> io::Error {
        let msg = msg.to_string();
        self.failed = Some(msg.clone());
        io::Error::other(msg)
    }
    fn live(&self) -> io::Result<()> {
        match &self.failed {
            Some(e) => Err(io::Error::other(e.clone())),
            None => Ok(()),
        }
    }
    fn pump(&mut self) -> io::Result<()> {
        self.live()?;
        for _ in 0..16 {
            let c = match self.backend.poll() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(self.fail(e)),
            };
            if self.read_id == Some(c.id) {
                self.read_id = None;
                if c.data.len() != c.actual_length {
                    return Err(self.fail("invalid IN completion length"));
                }
                // Preserve bytes before publishing terminal status; never resubmit
                // an errored transfer or replay OUT data.
                self.input.extend(c.data);
                if c.status != 0 || c.cancellation_requested {
                    self.failed = Some(format!(
                        "USB IN completion status {} cancelled {}",
                        c.status, c.cancellation_requested
                    ));
                }
                // A successful zero IN is a USB ZLP, not byte-stream EOF.
            } else if self.write_id.map(|x| x.0) == Some(c.id) {
                let expected = self.write_id.take().unwrap().1;
                if c.status != 0 || c.cancellation_requested || c.actual_length != expected {
                    return Err(self.fail(format!(
                        "USB OUT completion status {} actual {} expected {} cancelled {}",
                        c.status, c.actual_length, expected, c.cancellation_requested
                    )));
                }
                self.transfers.pop_front();
            } else {
                return Err(self.fail("unknown dispatcher completion"));
            }
        }
        Ok(())
    }
    fn pause(&mut self) -> io::Result<()> {
        if self.nonblocking {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.deadline.is_some_and(|until| Instant::now() >= until) {
            return Err(self.fail("USB handshake deadline"));
        }
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
    fn prepare_frame(&mut self) -> io::Result<()> {
        if self.frame.is_empty() {
            return Ok(());
        }
        if self.frame.len() < 24 {
            return Err(self.fail("incomplete USB frame header"));
        }
        let h = AdbMessageHeader::decode(&self.frame[..24]).map_err(|e| self.fail(e))?;
        let n = h.data_length as usize;
        if h.data_length > MAX_PAYLOAD_V2 || self.frame.len() != 24 + n {
            return Err(self.fail("incomplete or oversized USB frame"));
        }
        h.verify_payload(&self.frame[24..])
            .map_err(|e| self.fail(e))?;
        let packet = self.backend.packet_size();
        if packet == 0 {
            return Err(self.fail("zero USB packet size"));
        }
        self.transfers.push_back(self.frame[..24].to_vec());
        if n != 0 {
            self.transfers.push_back(self.frame[24..].to_vec());
            if n % packet == 0 {
                self.transfers.push_back(Vec::new());
            }
        }
        self.frame.clear();
        Ok(())
    }
}
impl<B: UrbIo> Read for UrbFrameTransport<B> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        loop {
            if !self.input.is_empty() {
                let n = bytes.len().min(self.input.len());
                for b in &mut bytes[..n] {
                    *b = self.input.pop_front().unwrap();
                }
                return Ok(n);
            }
            self.live()?;
            if self.read_id.is_none() {
                let p = self.backend.packet_size();
                if p == 0 || p > 65536 {
                    return Err(self.fail("invalid USB packet size"));
                }
                self.read_id = Some(
                    self.backend
                        .submit_read(8192usize.div_ceil(p) * p)
                        .map_err(|e| self.fail(e))?,
                );
            }
            self.pump()?;
            if !self.input.is_empty() {
                continue;
            }
            self.live()?;
            self.pause()?;
        }
    }
}
impl<B: UrbIo> Write for UrbFrameTransport<B> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        self.live()?;
        if !self.transfers.is_empty() || self.write_id.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.frame.len().saturating_add(bytes.len()) > 24 + MAX_PAYLOAD_V2 as usize {
            return Err(self.fail("USB writer buffer overflow"));
        }
        self.frame.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.live()?;
        self.prepare_frame()?;
        loop {
            self.pump()?;
            self.live()?;
            if self.write_id.is_none() {
                let Some(bytes) = self.transfers.front() else {
                    return Ok(());
                };
                let len = bytes.len();
                let id = self.backend.submit_write(bytes).map_err(|e| self.fail(e))?;
                self.write_id = Some((id, len));
            }
            self.pump()?;
            if self.transfers.is_empty() {
                return Ok(());
            }
            self.pause()?;
        }
    }
}
impl<B: UrbIo> Transport for UrbFrameTransport<B> {
    fn enable_urb_dispatch(&mut self) -> io::Result<()> {
        self.live()?;
        self.nonblocking = true;
        Ok(())
    }
}
impl<B: UrbIo> Drop for UrbFrameTransport<B> {
    fn drop(&mut self) {
        if let Some(id) = self.read_id {
            let _ = self.backend.cancel(id);
        }
        if let Some((id, _)) = self.write_id {
            let _ = self.backend.cancel(id);
        }
        // Backend closes exclusive fd before releasing unreaped buffers. Kernel
        // DISCARD and close are not promised hard-real-time operations.
    }
}
