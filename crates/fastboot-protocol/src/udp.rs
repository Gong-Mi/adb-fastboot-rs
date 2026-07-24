use std::io::{Read, Write, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use crate::transport::FastbootTransportError;

/// Fastboot UDP Header Length (4 bytes in AOSP standard: ID, Flags, Seq HI, Seq LO).
pub const UDP_HEADER_LEN: usize = 4;

/// Packet IDs matching AOSP system/core/fastboot/udp.cpp specification.
pub const UDP_ID_ERROR: u8 = 0x00;
pub const UDP_ID_QUERY: u8 = 0x01;
pub const UDP_ID_INIT: u8 = 0x02;
pub const UDP_ID_FASTBOOT: u8 = 0x03;

/// Packet Flags.
pub const UDP_FLAG_NONE: u8 = 0x00;
pub const UDP_FLAG_CONTINUATION: u8 = 0x01;

/// Default Fastboot UDP packet size limit (including 4-byte header).
pub const MIN_UDP_PACKET_SIZE: usize = 512;
pub const HOST_MAX_UDP_PACKET_SIZE: usize = 8192;
pub const DEFAULT_UDP_PACKET_SIZE: usize = MIN_UDP_PACKET_SIZE;
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_UDP_MAX_RETRIES: usize = 120;

/// Header structure for Fastboot UDP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub id: u8,
    pub flags: u8,
    pub seq: u16,
}

impl UdpHeader {
    pub fn new(id: u8, flags: u8, seq: u16) -> Self {
        Self { id, flags, seq }
    }

    /// Encode into 4-byte big-endian header: [id, flags, seq_hi, seq_lo]
    pub fn encode_4byte(&self) -> [u8; 4] {
        let seq_bytes = self.seq.to_be_bytes();
        [self.id, self.flags, seq_bytes[0], seq_bytes[1]]
    }

    /// Encode into 2-byte header: [flags, seq_lo]
    pub fn encode_2byte(&self) -> [u8; 2] {
        [self.flags, (self.seq & 0xff) as u8]
    }

    /// Decode header from byte slice. Supports both 4-byte and 2-byte framing.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FastbootTransportError> {
        if buf.len() >= 4 {
            let id = buf[0];
            let flags = buf[1];
            let seq = u16::from_be_bytes([buf[2], buf[3]]);
            Ok((Self { id, flags, seq }, 4))
        } else if buf.len() >= 2 {
            let flags = buf[0];
            let seq = buf[1] as u16;
            Ok((Self { id: UDP_ID_FASTBOOT, flags, seq }, 2))
        } else {
            Err(FastbootTransportError::Protocol(
                "UDP header too short".to_string(),
            ))
        }
    }
}

/// Fastboot UDP Transport implementation matching AOSP system/core/fastboot/udp.cpp specs.
pub struct FastbootUdpTransport {
    socket: UdpSocket,
    target_addr: SocketAddr,
    seq: u16,
    max_packet_size: usize,
    timeout: Duration,
    max_retries: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl FastbootUdpTransport {
    /// Create transport from pre-bound UdpSocket connected to target_addr.
    pub fn from_socket(socket: UdpSocket, target_addr: SocketAddr) -> Self {
        let _ = socket.set_read_timeout(Some(DEFAULT_UDP_TIMEOUT));
        let _ = socket.set_write_timeout(Some(DEFAULT_UDP_TIMEOUT));
        Self {
            socket,
            target_addr,
            seq: 0,
            max_packet_size: DEFAULT_UDP_PACKET_SIZE,
            timeout: DEFAULT_UDP_TIMEOUT,
            max_retries: DEFAULT_UDP_MAX_RETRIES,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Connect to a fastboot UDP target endpoint with default 3s timeout.
    pub fn connect<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<Self, FastbootTransportError> {
        Self::connect_timeout(addr, DEFAULT_UDP_TIMEOUT)
    }

    /// Connect to a fastboot UDP target endpoint with timeout.
    pub fn connect_timeout<A: ToSocketAddrs + std::fmt::Display>(
        addr: A,
        timeout: Duration,
    ) -> Result<Self, FastbootTransportError> {
        let addr_str = addr.to_string();
        let target_addr = addr
            .to_socket_addrs()
            .map_err(|e| FastbootTransportError::ConnectFailed {
                addr: addr_str.clone(),
                source: e,
            })?
            .next()
            .ok_or_else(|| FastbootTransportError::ConnectFailed {
                addr: addr_str.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No socket address resolved",
                ),
            })?;

        let bind_addr = if target_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr).map_err(|e| FastbootTransportError::ConnectFailed {
            addr: addr_str.clone(),
            source: e,
        })?;

        socket.connect(target_addr).map_err(|e| FastbootTransportError::ConnectFailed {
            addr: addr_str.clone(),
            source: e,
        })?;

        socket.set_read_timeout(Some(timeout)).ok();
        socket.set_write_timeout(Some(timeout)).ok();

        let mut transport = Self {
            socket,
            target_addr,
            seq: 0,
            max_packet_size: DEFAULT_UDP_PACKET_SIZE,
            timeout,
            max_retries: DEFAULT_UDP_MAX_RETRIES,
            read_buf: Vec::new(),
            read_pos: 0,
        };

        transport.perform_handshake()?;

        Ok(transport)
    }

    /// Set custom retransmission timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        self.socket.set_read_timeout(Some(timeout)).ok();
        self.socket.set_write_timeout(Some(timeout)).ok();
    }

    /// Set maximum retransmission attempts per packet.
    pub fn set_max_retries(&mut self, max_retries: usize) {
        self.max_retries = max_retries;
    }

    /// Get target socket address.
    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    /// Current sequence number.
    pub fn sequence_number(&self) -> u16 {
        self.seq
    }

    /// Max UDP payload packet size.
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    /// Send a logical packet, handling AOSP continuation packets and retransmissions.
    pub fn send_packet_with_ack(
        &mut self,
        id: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, FastbootTransportError> {
        let mut tx_id = id;
        let mut tx = payload;
        let mut tx_flags = flags;
        let mut result = Vec::new();
        let mut error_data = Vec::new();
        loop {
            let expected_seq = self.seq;
            let header = UdpHeader::new(tx_id, tx_flags, expected_seq).encode_4byte();
            let mut packet = Vec::with_capacity(UDP_HEADER_LEN + tx.len());
            packet.extend_from_slice(&header);
            packet.extend_from_slice(tx);
            let mut matched = None;
            let mut last_err = None;
            for _ in 0..=self.max_retries {
                self.socket.send(&packet).map_err(FastbootTransportError::Io)?;
                let mut recv_buf = vec![0u8; HOST_MAX_UDP_PACKET_SIZE];
                match self.socket.recv(&mut recv_buf) {
                    Ok(n) => {
                        let (resp, hlen) = UdpHeader::decode(&recv_buf[..n])?;
                        if resp.seq != expected_seq || (resp.id != tx_id && resp.id != UDP_ID_ERROR) { continue; }
                        matched = Some((resp, recv_buf[hlen..n].to_vec()));
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => last_err = Some(e),
                    Err(e) => return Err(FastbootTransportError::Io(e)),
                }
            }
            let (resp, data) = matched.ok_or_else(|| FastbootTransportError::Io(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP retransmission limit reached"))))?;
            self.seq = self.seq.wrapping_add(1);
            if resp.id == UDP_ID_ERROR {
                error_data.extend_from_slice(&data);
            } else {
                result.extend_from_slice(&data);
            }
            if resp.flags & UDP_FLAG_CONTINUATION == 0 {
                if !error_data.is_empty() {
                    return Err(FastbootTransportError::Protocol(format!("UDP Error response from target: {}", String::from_utf8_lossy(&error_data))));
                }
                return Ok(result);
            }
            tx_id = resp.id;
            tx = &[];
            tx_flags = UDP_FLAG_NONE;
        }
    }

    /// Perform AOSP Query + Init handshake if supported by target.
    fn perform_handshake(&mut self) -> Result<(), FastbootTransportError> {
        let query = self.send_packet_with_ack(UDP_ID_QUERY, UDP_FLAG_NONE, &[])?;
        if query.len() < 2 {
            return Err(FastbootTransportError::Protocol("invalid query response from target".into()));
        }
        self.seq = u16::from_be_bytes([query[0], query[1]]);
        let init = [0u8, 1, (HOST_MAX_UDP_PACKET_SIZE >> 8) as u8, HOST_MAX_UDP_PACKET_SIZE as u8];
        let response = self.send_packet_with_ack(UDP_ID_INIT, UDP_FLAG_NONE, &init)?;
        if response.len() < 4 {
            return Err(FastbootTransportError::Protocol("invalid initialization response from target".into()));
        }
        let version = u16::from_be_bytes([response[0], response[1]]);
        let remote = u16::from_be_bytes([response[2], response[3]]) as usize;
        if version < 1 {
            return Err(FastbootTransportError::Protocol(format!("target reported invalid protocol version {version}")));
        }
        if remote < MIN_UDP_PACKET_SIZE {
            return Err(FastbootTransportError::Protocol(format!("target reported invalid packet size {remote}")));
        }
        self.max_packet_size = HOST_MAX_UDP_PACKET_SIZE.min(remote);
        Ok(())
    }
}

impl Read for FastbootUdpTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.read_pos < self.read_buf.len() {
            let n = std::cmp::min(buf.len(), self.read_buf.len() - self.read_pos);
            buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Ok(n);
        }

        let payload = self
            .send_packet_with_ack(UDP_ID_FASTBOOT, UDP_FLAG_NONE, &[])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        if payload.len() > buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP target sent more fastboot data than requested buffer",
            ));
        }
        if payload.is_empty() {
            return Ok(0);
        }

        buf[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }
}

impl Write for FastbootUdpTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let max_payload = self.max_packet_size.saturating_sub(UDP_HEADER_LEN).max(1);

        let chunks: Vec<&[u8]> = if buf.is_empty() {
            vec![&[]]
        } else {
            buf.chunks(max_payload).collect()
        };

        let num_chunks = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let is_last = i == num_chunks - 1;
            let flags = if is_last {
                UDP_FLAG_NONE
            } else {
                UDP_FLAG_CONTINUATION
            };
            self.send_packet_with_ack(UDP_ID_FASTBOOT, flags, chunk)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_udp_header_encode_decode_4byte() {
        let header = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_CONTINUATION, 0x1234);
        let encoded = header.encode_4byte();
        assert_eq!(encoded, [UDP_ID_FASTBOOT, UDP_FLAG_CONTINUATION, 0x12, 0x34]);

        let (decoded, len) = UdpHeader::decode(&encoded).unwrap();
        assert_eq!(len, 4);
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_udp_header_decode_2byte() {
        let raw = [UDP_FLAG_NONE, 0x42];
        let (decoded, len) = UdpHeader::decode(&raw).unwrap();
        assert_eq!(len, 2);
        assert_eq!(decoded.id, UDP_ID_FASTBOOT);
        assert_eq!(decoded.flags, UDP_FLAG_NONE);
        assert_eq!(decoded.seq, 0x42);
    }

    #[test]
    fn test_sequence_number_wrapping() {
        let mut transport = FastbootUdpTransport {
            socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
            target_addr: "127.0.0.1:5554".parse().unwrap(),
            seq: u16::MAX,
            max_packet_size: 512,
            timeout: Duration::from_millis(100),
            max_retries: 1,
            read_buf: Vec::new(),
            read_pos: 0,
        };

        assert_eq!(transport.sequence_number(), u16::MAX);
        transport.seq = transport.seq.wrapping_add(1);
        assert_eq!(transport.sequence_number(), 0);
    }

    #[test]
    fn test_udp_transport_wire_sequence_mock_socket() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1024];

            // 1. Receive command packet ("getvar:version")
            let (n, client_addr) = server_socket.recv_from(&mut buf).unwrap();
            let (header, h_len) = UdpHeader::decode(&buf[..n]).unwrap();
            assert_eq!(header.id, UDP_ID_FASTBOOT);
            assert_eq!(&buf[h_len..n], b"getvar:version");

            // Send ACK packet back with matching sequence number
            let ack_header = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_NONE, header.seq);
            server_socket.send_to(&ack_header.encode_4byte(), client_addr).unwrap();

            // 2. Receive read prompt packet
            let (n2, _) = server_socket.recv_from(&mut buf).unwrap();
            let (header2, _) = UdpHeader::decode(&buf[..n2]).unwrap();

            // Send response packet ("OKAY0.4")
            let resp_header = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_NONE, header2.seq);
            let mut resp_pkt = resp_header.encode_4byte().to_vec();
            resp_pkt.extend_from_slice(b"OKAY0.4");
            server_socket.send_to(&resp_pkt, client_addr).unwrap();
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(server_addr).unwrap();

        let mut transport = FastbootUdpTransport::from_socket(client_socket, server_addr);
        transport.set_timeout(Duration::from_millis(500));

        // Perform fastboot command exchange over UDP
        transport.write_all(b"getvar:version").unwrap();

        let mut resp_buf = [0u8; 64];
        let n = transport.read(&mut resp_buf).unwrap();
        assert_eq!(&resp_buf[..n], b"OKAY0.4");

        handle.join().unwrap();
    }

    #[test]
    fn test_aosp_handshake_uses_query_sequence_and_payload_offsets() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_n, peer) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..4], &[UDP_ID_QUERY, UDP_FLAG_NONE, 0, 0]);
            let mut response = UdpHeader::new(UDP_ID_QUERY, UDP_FLAG_NONE, 0).encode_4byte().to_vec();
            response.extend_from_slice(&0x1234u16.to_be_bytes());
            server.send_to(&response, peer).unwrap();
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..4], &[UDP_ID_INIT, UDP_FLAG_NONE, 0x12, 0x34]);
            assert_eq!(&buf[4..n], &[0, 1, 0x20, 0x00]);
            let mut response = UdpHeader::new(UDP_ID_INIT, UDP_FLAG_NONE, 0x1234).encode_4byte().to_vec();
            response.extend_from_slice(&[0, 1, 0x02, 0x00]);
            server.send_to(&response, peer).unwrap();
        });
        let transport = FastbootUdpTransport::connect_timeout(addr, Duration::from_millis(100)).unwrap();
        assert_eq!(transport.sequence_number(), 0x1235);
        assert_eq!(transport.max_packet_size(), 512);
        handle.join().unwrap();
    }

    #[test]
    fn test_continuation_response_is_prompted_with_next_sequence() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let (h, _) = UdpHeader::decode(&buf[..n]).unwrap();
            assert_eq!(h.seq, 0);
            let mut response = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_CONTINUATION, 0).encode_4byte().to_vec();
            response.extend_from_slice(b"one");
            server.send_to(&response, peer).unwrap();
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], &[UDP_ID_FASTBOOT, UDP_FLAG_NONE, 0, 1]);
            let mut response = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_NONE, 1).encode_4byte().to_vec();
            response.extend_from_slice(b"two");
            server.send_to(&response, peer).unwrap();
        });
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(addr).unwrap();
        let mut transport = FastbootUdpTransport::from_socket(socket, addr);
        transport.set_timeout(Duration::from_millis(100));
        assert_eq!(transport.send_packet_with_ack(UDP_ID_FASTBOOT, UDP_FLAG_NONE, b"x").unwrap(), b"onetwo");
        handle.join().unwrap();
    }

    #[test]
    fn test_udp_transport_retransmission_on_timeout() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        server_socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let server_addr = server_socket.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1024];

            // Ignore 1st packet (simulating dropped packet)
            let (_n, _client_addr) = server_socket.recv_from(&mut buf).unwrap();

            // Receive 2nd packet (retransmission)
            let (n2, client_addr) = server_socket.recv_from(&mut buf).unwrap();
            let (header, _) = UdpHeader::decode(&buf[..n2]).unwrap();

            let ack_header = UdpHeader::new(UDP_ID_FASTBOOT, UDP_FLAG_NONE, header.seq);
            server_socket.send_to(&ack_header.encode_4byte(), client_addr).unwrap();
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(server_addr).unwrap();

        let mut transport = FastbootUdpTransport::from_socket(client_socket, server_addr);
        transport.set_timeout(Duration::from_millis(150));
        transport.set_max_retries(3);

        let res = transport.send_packet_with_ack(UDP_ID_FASTBOOT, UDP_FLAG_NONE, b"test");
        assert!(res.is_ok());

        handle.join().unwrap();
    }
}
