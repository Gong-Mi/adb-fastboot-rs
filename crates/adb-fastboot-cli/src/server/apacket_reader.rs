//! ADB packet framing reader — reassembles ADB wire packets from byte streams.
//!
//! Maps to AOSP `vendor/adb/apacket_reader.cpp` + `vendor/adb/types.cpp` (Block).
//!
//! Handles: header split, payload split, merged payload+next-header,
//! empty payloads, oversized payload rejection, corrupt magic.

use adb_protocol::constants::MAX_PAYLOAD_V2;
use adb_protocol::header::AdbMessageHeader;

/// Maximum allowed ADB payload size.
pub const MAX_PAYLOAD: u32 = MAX_PAYLOAD_V2;

// ---------------------------------------------------------------------------
// Block — position-tracked byte buffer (AOSP "Block" from types.h)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Block {
    buf: Vec<u8>,
    pos: usize,
}

impl Block {
    pub fn new(size: usize) -> Self {
        Self { buf: vec![0u8; size], pos: 0 }
    }
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self { buf: v, pos: 0 }
    }
    pub fn size(&self) -> usize { self.buf.len() }
    pub fn position(&self) -> usize { self.pos }
    pub fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }
    pub fn is_full(&self) -> bool { self.pos >= self.buf.len() }
    pub fn rewind(&mut self) { self.pos = 0; }
    pub fn data(&self) -> &[u8] { &self.buf }

    /// Copy bytes from src into self, advancing both cursors.
    pub fn fill_from(&mut self, src: &mut Block) {
        let n = self.remaining().min(src.remaining());
        if n == 0 { return; }
        self.buf[self.pos..self.pos + n].copy_from_slice(&src.buf[src.pos..src.pos + n]);
        self.pos += n;
        src.pos += n;
    }

    pub fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }

    pub fn clear(&mut self) {
        self.buf.fill(0);
        self.pos = 0;
    }

    pub fn resize(&mut self, new_size: usize) {
        self.buf.resize(new_size, 0);
        self.pos = self.pos.min(self.buf.len());
    }
}

impl From<Vec<u8>> for Block {
    fn from(v: Vec<u8>) -> Self { Self::from_vec(v) }
}

// ---------------------------------------------------------------------------
// AdbPacket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AdbPacket {
    pub header: AdbMessageHeader,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// APacketReader — stateless reassembly
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct APacketReader {
    header_: Block,
    packet_: Option<AdbMessageHeader>,
    payload_: Option<Block>,
    packets_: Vec<AdbPacket>,
}

impl APacketReader {
    pub fn new() -> Self {
        Self {
            header_: Block::new(AdbMessageHeader::SIZE),
            packet_: None,
            payload_: None,
            packets_: Vec::new(),
        }
    }

    /// Feed raw bytes. Returns packets that were completed during this call.
    pub fn add_bytes(&mut self, data: &[u8]) -> Vec<AdbPacket> {
        if data.is_empty() {
            return std::mem::take(&mut self.packets_);
        }
        self.process_block(&mut Block::from_vec(data.to_vec()));
        std::mem::take(&mut self.packets_)
    }

    fn process_block(&mut self, block: &mut Block) {
        if block.remaining() == 0 {
            return;
        }

        self.header_.fill_from(block);
        if !self.header_.is_full() {
            return;
        }

        // AOSP APacketReader assembles the raw amessage here and defers magic
        // validation to transport.cpp::check_header(). Keep framing separate
        // from transport-level validation for the same handoff.
        let header = Self::decode_framing_header(self.header_.data());

        if header.data_length > MAX_PAYLOAD {
            self.prepare_next();
            return;
        }

        if header.data_length == 0 {
            self.packets_.push(AdbPacket { header, payload: Vec::new() });
            self.prepare_next();
            self.process_block(block);
            return;
        }

        if block.remaining() == 0 && self.packet_.is_none() {
            self.packet_ = Some(header);
            return;
        }

        if self.packet_.is_none() {
            self.packet_ = Some(header);
            let plen = header.data_length as usize;
            if block.remaining() == plen {
                let payload = block.data()[block.position()..block.position() + plen].to_vec();
                block.advance(plen);
                self.packets_.push(AdbPacket { header, payload });
                self.prepare_next();
                self.process_block(block);
                return;
            } else {
                self.payload_ = Some(Block::new(plen));
            }
        }

        // packet_ is Some but payload_ hasn't been started yet
        if self.payload_.is_none() && block.remaining() > 0 {
            self.payload_ = Some(Block::new(self.packet_.as_ref().unwrap().data_length as usize));
        }

        if let Some(ref mut pb) = self.payload_ {
            pb.fill_from(block);
            if pb.is_full() {
                let hdr = self.packet_.take().unwrap();
                let pl = pb.data().to_vec();
                self.packets_.push(AdbPacket { header: hdr, payload: pl });
                self.payload_ = None;
                self.prepare_next();
                self.process_block(block);
            }
        }
    }

    fn prepare_next(&mut self) {
        // types.h::Block::rewind() retains the fixed header allocation and
        // resets only its cursor. This is required before recursive parsing of
        // residual bytes from a merged payload/header block.
        self.header_.rewind();
        self.packet_ = None;
        self.payload_ = None;
    }

    fn decode_framing_header(buf: &[u8]) -> AdbMessageHeader {
        debug_assert_eq!(buf.len(), AdbMessageHeader::SIZE);
        AdbMessageHeader {
            command: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            arg0: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            arg1: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            data_length: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            data_check: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            magic: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
        }
    }

    pub fn drain_packets(&mut self) -> Vec<AdbPacket> {
        std::mem::take(&mut self.packets_)
    }
}

impl Default for APacketReader {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Generic streaming reader wrapping any Read
// ---------------------------------------------------------------------------

use std::io::Read;

#[derive(Debug)]
pub struct APacketStreamReader<R: Read> {
    reader: R,
    buf: Vec<u8>,
    state: PacketReadState,
    pending_header: Option<AdbMessageHeader>,
    stream_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketReadState {
    NeedHeader,
    NeedPayload { remaining: usize },
}

impl<R: Read> APacketStreamReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::with_capacity(4096),
            state: PacketReadState::NeedHeader,
            pending_header: None,
            stream_offset: 0,
        }
    }

    pub fn fill(&mut self) -> Result<Option<(AdbMessageHeader, Vec<u8>)>, String> {
        let mut tmp = [0u8; 8192];
        loop {
            match self.state {
                PacketReadState::NeedHeader => {
                    if self.buf.len() < AdbMessageHeader::SIZE {
                        let n = self.reader.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
                        if n == 0 {
                            return if self.buf.is_empty() { Ok(None) }
                                   else { Err("EOF during header".into()) };
                        }
                        self.buf.extend_from_slice(&tmp[..n]);
                        self.stream_offset += n as u64;
                        continue;
                    }

                    let hdr_bytes = &self.buf[..AdbMessageHeader::SIZE];
                    let header = AdbMessageHeader::decode(hdr_bytes)
                        .map_err(|e| format!("bad header: {e}"))?;
                    let data_len = header.data_length as usize;
                    if data_len > MAX_PAYLOAD as usize {
                        return Err(format!("payload too large: {}", data_len));
                    }
                    if data_len == 0 {
                        self.buf.drain(..AdbMessageHeader::SIZE);
                        return Ok(Some((header, Vec::new())));
                    }
                    self.state = PacketReadState::NeedPayload { remaining: data_len + AdbMessageHeader::SIZE };
                    self.pending_header = Some(header);
                }

                PacketReadState::NeedPayload { remaining } => {
                    if self.buf.len() < remaining {
                        let need = remaining - self.buf.len();
                        let read_max = need.min(tmp.len());
                        let n = self.reader.read(&mut tmp[..read_max]).map_err(|e| format!("read: {e}"))?;
                        if n == 0 {
                            return Err("EOF during payload".into());
                        }
                        let chunk = tmp[..n].to_vec();
                        self.buf.extend_from_slice(&chunk);
                        self.stream_offset += n as u64;
                        continue;
                    }

                    let header = self.pending_header.take().unwrap();
                    let data_len = header.data_length as usize;
                    let payload = self.buf[AdbMessageHeader::SIZE..AdbMessageHeader::SIZE + data_len].to_vec();
                    self.buf.drain(..AdbMessageHeader::SIZE + data_len);
                    self.state = PacketReadState::NeedHeader;
                    return Ok(Some((header, payload)));
                }
            }
        }
    }

    pub fn stream_offset(&self) -> u64 { self.stream_offset }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adb_protocol::constants::*;

    fn encode(cmd: u32, payload: &[u8]) -> Vec<u8> {
        let h = AdbMessageHeader::new(cmd, 0, 0, payload);
        let mut buf = vec![0u8; 24 + payload.len()];
        let mut hb = [0u8; 24];
        h.encode(&mut hb);
        buf[..24].copy_from_slice(&hb);
        buf[24..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn test_empty() {
        assert!(APacketReader::new().add_bytes(b"").is_empty());
    }

    #[test]
    fn test_no_payload() {
        let r = encode(A_OKAY, b"");
        let p = APacketReader::new().add_bytes(&r);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].header.command, A_OKAY);
        assert!(p[0].payload.is_empty());
    }

    #[test]
    fn test_with_payload() {
        let r = encode(A_OKAY, b"hello");
        let p = APacketReader::new().add_bytes(&r);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].payload, b"hello");
    }

    #[test]
    fn test_header_split() {
        let full = encode(A_OKAY, b"12345");
        let (a, b) = full.split_at(12);
        let mut r = APacketReader::new();
        assert!(r.add_bytes(a).is_empty());
        let p = r.add_bytes(b);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].payload, b"12345");
    }

    #[test]
    fn test_payload_split() {
        let full = encode(A_OKAY, b"abcdefghij");
        let (h, rest) = full.split_at(24);
        let (p1, p2) = rest.split_at(5);
        let mut r = APacketReader::new();
        assert!(r.add_bytes(h).is_empty());
        assert!(r.add_bytes(p1).is_empty());
        let p = r.add_bytes(p2);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].payload, b"abcdefghij");
    }

    #[test]
    fn test_merged() {
        let p1 = encode(A_OKAY, b"hello");
        let p2 = encode(A_CLSE, b"world");
        let mut merged = p1;
        merged.extend_from_slice(&p2);
        let p = APacketReader::new().add_bytes(&merged);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].header.command, A_OKAY);
        assert_eq!(p[0].payload, b"hello");
        assert_eq!(p[1].header.command, A_CLSE);
        assert_eq!(p[1].payload, b"world");
    }

    #[test]
    fn test_oversized() {
        let big = vec![0u8; (MAX_PAYLOAD + 1) as usize];
        let r = encode(A_OKAY, &big);
        assert!(APacketReader::new().add_bytes(&r).is_empty());
    }

    #[test]
    fn test_preserves_invalid_magic_for_transport_validation() {
        // AOSP APacketReader only bounds-checks data_length before assembling
        // the apacket; transport.cpp::check_header() validates magic later.
        let mut raw = encode(A_OKAY, b"data");
        raw[20] ^= 0xff;

        let packets = APacketReader::new().add_bytes(&raw);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].header.magic, !A_OKAY ^ 0xff);
        assert_eq!(packets[0].payload, b"data");
    }

    #[test]
    fn test_5_no_payload() {
        let mut raw = Vec::new();
        for _ in 0..5 { raw.extend_from_slice(&encode(A_OKAY, b"")); }
        let p = APacketReader::new().add_bytes(&raw);
        assert_eq!(p.len(), 5);
    }

    #[test]
    fn test_chainsaw() {
        // apacket_reader.h requires arbitrary chopping/merging boundaries.
        // End the first block after one byte of the following header to exercise
        // recursive residual-header parsing after the first payload completes.
        let first = encode(A_OKAY, b"payload");
        let second = encode(A_CLSE, b"next");
        let split = first.len() + 1;
        let merged = [first, second].concat();
        let mut reader = APacketReader::new();

        assert_eq!(reader.add_bytes(&merged[..split]).len(), 1);
        let packets = reader.add_bytes(&merged[split..]);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].header.command, A_CLSE);
        assert_eq!(packets[0].payload, b"next");
    }

    #[test]
    fn test_block() {
        let mut src = Block::from_vec(vec![1u8, 2, 3, 4, 5]);
        let mut dst = Block::new(3);
        dst.fill_from(&mut src);
        assert_eq!(dst.data(), &[1, 2, 3]);
        assert_eq!(src.remaining(), 2);
        assert!(dst.is_full());
    }

    #[test]
    fn test_stream_reader_single() {
        use std::io::Cursor;
        let raw = encode(A_OKAY, b"hello");
        let mut sr = APacketStreamReader::new(Cursor::new(raw));
        let pkt = sr.fill().unwrap().unwrap();
        assert_eq!(pkt.0.command, A_OKAY);
        assert_eq!(pkt.1, b"hello");
        assert!(sr.fill().unwrap().is_none());
    }

    #[test]
    fn test_stream_reader_two_packets() {
        use std::io::Cursor;
        let raw = [encode(A_OKAY, b"abc"), encode(A_CLSE, b"def")].concat();
        let mut sr = APacketStreamReader::new(Cursor::new(raw));
        let p1 = sr.fill().unwrap().unwrap();
        assert_eq!(p1.1, b"abc");
        let p2 = sr.fill().unwrap().unwrap();
        assert_eq!(p2.1, b"def");
        assert!(sr.fill().unwrap().is_none());
    }

    #[test]
    fn test_legacy_checksum() {
        let h = AdbMessageHeader::new_v1_legacy(A_OKAY, 0, 0, b"hi");
        let mut buf = vec![0u8; 24 + 2];
        let mut hb = [0u8; 24];
        h.encode(&mut hb);
        buf[..24].copy_from_slice(&hb);
        buf[24..].copy_from_slice(b"hi");
        let p = APacketReader::new().add_bytes(&buf);
        // Legacy checksum is ignored by APacketReader (adbd 0x01000001+)
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].payload, b"hi");
    }
}
