//! ADB SPA (Secure Pair Authentication) & Wireless Pairing (`adb pair`) implementation.
//!
//! Provides SPA packet framing, HKDF-SHA256 key derivation from 6-digit pairing codes,
//! AES-128-GCM encrypted payload framing, and `PairingClient` state machine.

use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

/// SPA Packet Magic bytes: "SPAP" (0x53504150)
pub const SPA_MAGIC: [u8; 4] = *b"SPAP";

/// Header size in bytes
pub const SPA_HEADER_SIZE: usize = 8;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PairingError {
    #[error("Invalid pairing code format: {0}")]
    InvalidPairingCode(String),

    #[error("Invalid SPA packet header: {0}")]
    InvalidHeader(String),

    #[error("Invalid SPA payload: {0}")]
    InvalidPayload(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Pairing rejected by peer: status code {0}")]
    PairingRejected(u8),

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for PairingError {
    fn from(err: std::io::Error) -> Self {
        PairingError::Io(err.to_string())
    }
}

/// Message types in SPA protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpaMessageType {
    Init = 1,
    Exchange = 2,
    Result = 3,
}

impl SpaMessageType {
    pub fn from_u8(val: u8) -> Result<Self, PairingError> {
        match val {
            1 => Ok(Self::Init),
            2 => Ok(Self::Exchange),
            3 => Ok(Self::Result),
            _ => Err(PairingError::InvalidHeader(format!("unknown message type {val}"))),
        }
    }
}

/// Result status codes returned in Result message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingResultStatus {
    Success = 0,
    FailedInvalidCode = 1,
    FailedProtocolError = 2,
    Unknown = 255,
}

impl PairingResultStatus {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Success,
            1 => Self::FailedInvalidCode,
            2 => Self::FailedProtocolError,
            _ => Self::Unknown,
        }
    }
}

/// Header for SPA packets (8 bytes total)
/// [Magic 4B][MsgType 1B][Flags 1B][PayloadLen 2B BE]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaHeader {
    pub magic: [u8; 4],
    pub msg_type: SpaMessageType,
    pub flags: u8,
    pub payload_len: u16,
}

impl SpaHeader {
    pub fn new(msg_type: SpaMessageType, flags: u8, payload_len: u16) -> Self {
        Self {
            magic: SPA_MAGIC,
            msg_type,
            flags,
            payload_len,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SPA_HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.msg_type as u8);
        buf.push(self.flags);
        buf.write_u16::<BigEndian>(self.payload_len).unwrap();
        buf
    }

    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, PairingError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != SPA_MAGIC {
            return Err(PairingError::InvalidHeader(format!(
                "invalid magic bytes {:?}, expected {:?}",
                magic, SPA_MAGIC
            )));
        }
        let msg_type_raw = reader.read_u8()?;
        let msg_type = SpaMessageType::from_u8(msg_type_raw)?;
        let flags = reader.read_u8()?;
        let payload_len = reader.read_u16::<BigEndian>()?;

        Ok(Self {
            magic,
            msg_type,
            flags,
            payload_len,
        })
    }
}

/// SPA Packet combining header and payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaPacket {
    pub header: SpaHeader,
    pub payload: Vec<u8>,
}

impl SpaPacket {
    pub fn new(msg_type: SpaMessageType, flags: u8, payload: Vec<u8>) -> Result<Self, PairingError> {
        if payload.len() > u16::MAX as usize {
            return Err(PairingError::InvalidPayload("payload size exceeds u16::MAX".into()));
        }
        let header = SpaHeader::new(msg_type, flags, payload.len() as u16);
        Ok(Self { header, payload })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PairingError> {
        writer.write_all(&self.header.encode())?;
        writer.write_all(&self.payload)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, PairingError> {
        let header = SpaHeader::decode(reader)?;
        let mut payload = vec![0u8; header.payload_len as usize];
        reader.read_exact(&mut payload)?;
        Ok(Self { header, payload })
    }
}

struct HkdfOutKey<const N: usize>([u8; N]);
impl<const N: usize> hkdf::KeyType for HkdfOutKey<N> {
    fn len(&self) -> usize {
        N
    }
}

/// Derive 16-byte key + 12-byte IV from 6-digit numeric pairing code and salt using HKDF-SHA256
pub fn derive_pairing_key(pairing_code: &str, salt: &[u8]) -> Result<([u8; 16], [u8; 12]), PairingError> {
    let pairing_code = pairing_code.trim();
    if pairing_code.len() != 6 || !pairing_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(PairingError::InvalidPairingCode(
            "pairing code must be exactly 6 numeric digits".into(),
        ));
    }

    let salt_obj = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt_obj.extract(pairing_code.as_bytes());

    let info: &[&[u8]] = &[b"adb spa hkdf key derivation"];
    let okm = prk
        .expand(info, HkdfOutKey::<28>([0u8; 28]))
        .map_err(|_| PairingError::CryptoError("HKDF expansion failed".into()))?;

    let mut key_out = [0u8; 28];
    okm.fill(&mut key_out)
        .map_err(|_| PairingError::CryptoError("HKDF fill failed".into()))?;

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&key_out[..16]);
    iv.copy_from_slice(&key_out[16..28]);

    Ok((key, iv))
}

/// Encrypt payload using AES-128-GCM.
/// Formats framed output as: `[12-byte Nonce][Ciphertext][16-byte Tag]`.
pub fn encrypt_payload(key: &[u8; 16], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
    let unbound = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| PairingError::CryptoError("failed to create AES-128-GCM unbound key".into()))?;
    let key_obj = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| PairingError::CryptoError("invalid GCM nonce".into()))?;

    let mut in_out = plaintext.to_vec();
    key_obj
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| PairingError::CryptoError("AES-128-GCM encryption failed".into()))?;

    let mut framed = Vec::with_capacity(12 + in_out.len());
    framed.extend_from_slice(nonce_bytes);
    framed.extend_from_slice(&in_out);
    Ok(framed)
}

/// Decrypt payload using AES-128-GCM from framed buffer: `[12-byte Nonce][Ciphertext][16-byte Tag]`.
pub fn decrypt_payload(key: &[u8; 16], framed: &[u8]) -> Result<Vec<u8>, PairingError> {
    if framed.len() < 12 + 16 {
        return Err(PairingError::InvalidPayload(
            "framed payload too short for AES-GCM (min 28 bytes)".into(),
        ));
    }

    let (nonce_bytes, ciphertext_and_tag) = framed.split_at(12);
    let unbound = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| PairingError::CryptoError("failed to create AES-128-GCM unbound key".into()))?;
    let key_obj = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| PairingError::CryptoError("invalid GCM nonce".into()))?;

    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext = key_obj
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| PairingError::CryptoError("AES-128-GCM decryption failed".into()))?;

    Ok(plaintext.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
    Unpaired,
    ExchangingSalt,
    Authenticating,
    Paired,
    Failed(String),
}

pub struct PairingClient {
    pairing_code: String,
    state: PairingState,
    client_salt: [u8; 16],
    derived_key: Option<[u8; 16]>,
    derived_iv: Option<[u8; 12]>,
}

impl PairingClient {
    pub fn new(pairing_code: &str) -> Result<Self, PairingError> {
        let code = pairing_code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(PairingError::InvalidPairingCode(
                "pairing code must be exactly 6 numeric digits".into(),
            ));
        }

        let rng = SystemRandom::new();
        let mut client_salt = [0u8; 16];
        rng.fill(&mut client_salt)
            .map_err(|_| PairingError::CryptoError("failed to generate random salt".into()))?;

        Ok(Self {
            pairing_code: code.to_string(),
            state: PairingState::Unpaired,
            client_salt,
            derived_key: None,
            derived_iv: None,
        })
    }

    /// Construct PairingClient with custom salt (useful for deterministic tests)
    pub fn with_salt(pairing_code: &str, salt: [u8; 16]) -> Result<Self, PairingError> {
        let code = pairing_code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(PairingError::InvalidPairingCode(
                "pairing code must be exactly 6 numeric digits".into(),
            ));
        }
        Ok(Self {
            pairing_code: code.to_string(),
            state: PairingState::Unpaired,
            client_salt: salt,
            derived_key: None,
            derived_iv: None,
        })
    }

    pub fn state(&self) -> &PairingState {
        &self.state
    }

    pub fn is_paired(&self) -> bool {
        self.state == PairingState::Paired
    }

    /// Step 1: Create initial `Init` packet to send to server.
    pub fn create_init_packet(&mut self) -> Result<SpaPacket, PairingError> {
        if self.state != PairingState::Unpaired {
            return Err(PairingError::ProtocolError(
                "create_init_packet called in invalid state".into(),
            ));
        }

        self.state = PairingState::ExchangingSalt;
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&self.client_salt);
        payload.extend_from_slice(b"adb-rs-client");

        SpaPacket::new(SpaMessageType::Init, 0, payload)
    }

    /// Step 2: Process server `Init` response packet, derive session key, and create `Exchange` packet.
    pub fn process_server_init(&mut self, server_packet: &SpaPacket) -> Result<SpaPacket, PairingError> {
        if self.state != PairingState::ExchangingSalt {
            return Err(PairingError::ProtocolError(
                "process_server_init called in invalid state".into(),
            ));
        }

        if server_packet.header.msg_type != SpaMessageType::Init {
            return Err(PairingError::ProtocolError(format!(
                "expected Init packet from server, got {:?}",
                server_packet.header.msg_type
            )));
        }

        if server_packet.payload.len() < 16 {
            return Err(PairingError::InvalidPayload(
                "server init payload too short for salt".into(),
            ));
        }

        let server_salt = &server_packet.payload[..16];
        let mut combined_salt = Vec::with_capacity(32);
        combined_salt.extend_from_slice(&self.client_salt);
        combined_salt.extend_from_slice(server_salt);

        let (key, iv) = derive_pairing_key(&self.pairing_code, &combined_salt)?;
        self.derived_key = Some(key);
        self.derived_iv = Some(iv);

        let auth_payload = b"ADB_SPA_PAIRING_REQUEST:OK";
        let encrypted = encrypt_payload(&key, &iv, auth_payload)?;

        self.state = PairingState::Authenticating;
        SpaPacket::new(SpaMessageType::Exchange, 1 /* encrypted flag */, encrypted)
    }

    /// Step 3: Process server `Result` response packet.
    pub fn process_server_result(&mut self, result_packet: &SpaPacket) -> Result<PairingResultStatus, PairingError> {
        if self.state != PairingState::Authenticating {
            return Err(PairingError::ProtocolError(
                "process_server_result called in invalid state".into(),
            ));
        }

        let payload = if result_packet.header.flags & 1 != 0 {
            let key = self
                .derived_key
                .ok_or_else(|| PairingError::ProtocolError("missing derived key".into()))?;
            decrypt_payload(&key, &result_packet.payload)?
        } else {
            result_packet.payload.clone()
        };

        if payload.is_empty() {
            return Err(PairingError::InvalidPayload("empty result payload".into()));
        }

        let status = PairingResultStatus::from_u8(payload[0]);
        if status == PairingResultStatus::Success {
            self.state = PairingState::Paired;
            Ok(status)
        } else {
            let err_msg = format!("pairing failed with status {:?}", status);
            self.state = PairingState::Failed(err_msg.clone());
            Err(PairingError::PairingRejected(payload[0]))
        }
    }

    /// Execute the complete pairing handshake over any Read + Write transport stream.
    pub fn execute_pairing<T: Read + Write>(&mut self, transport: &mut T) -> Result<(), PairingError> {
        let init_packet = self.create_init_packet()?;
        init_packet.write_to(transport)?;

        let server_init = SpaPacket::read_from(transport)?;
        let exchange_packet = self.process_server_init(&server_init)?;

        exchange_packet.write_to(transport)?;

        let server_result = SpaPacket::read_from(transport)?;
        let status = self.process_server_result(&server_result)?;

        if status == PairingResultStatus::Success {
            Ok(())
        } else {
            Err(PairingError::PairingRejected(status as u8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pairing_code_validation() {
        assert!(PairingClient::new("123456").is_ok());
        assert!(PairingClient::new(" 654321 ").is_ok());
        assert!(PairingClient::new("12345").is_err());
        assert!(PairingClient::new("1234567").is_err());
        assert!(PairingClient::new("abcdef").is_err());
    }

    #[test]
    fn test_spa_packet_encode_decode() {
        let packet = SpaPacket::new(SpaMessageType::Init, 0, b"hello".to_vec()).unwrap();
        let mut buf = Vec::new();
        packet.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = SpaPacket::read_from(&mut cursor).unwrap();

        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_hkdf_key_derivation() {
        let code = "123456";
        let salt = b"0123456789abcdef";
        let (key1, iv1) = derive_pairing_key(code, salt).unwrap();
        let (key2, iv2) = derive_pairing_key(code, salt).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(iv1, iv2);
        assert_ne!(key1, [0u8; 16]);

        let (key3, _) = derive_pairing_key("654321", salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 12];
        let plaintext = b"secret adb pairing message";

        let encrypted = encrypt_payload(&key, &iv, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_payload(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wire_mock_handshake() {
        let client_salt = [1u8; 16];
        let server_salt = [2u8; 16];

        let mut client = PairingClient::with_salt("654321", client_salt).unwrap();

        // 1. Client Init
        let client_init = client.create_init_packet().unwrap();
        assert_eq!(client_init.header.msg_type, SpaMessageType::Init);
        assert_eq!(&client_init.payload[..16], &client_salt);

        // 2. Server Init response
        let mut server_init_payload = Vec::new();
        server_init_payload.extend_from_slice(&server_salt);
        server_init_payload.extend_from_slice(b"adb-server");
        let server_init = SpaPacket::new(SpaMessageType::Init, 0, server_init_payload).unwrap();

        // 3. Client process Server Init & generate Exchange
        let exchange_packet = client.process_server_init(&server_init).unwrap();
        assert_eq!(exchange_packet.header.msg_type, SpaMessageType::Exchange);
        assert_eq!(exchange_packet.header.flags, 1);

        // Server side verification of Exchange packet
        let mut combined_salt = Vec::new();
        combined_salt.extend_from_slice(&client_salt);
        combined_salt.extend_from_slice(&server_salt);
        let (server_key, _) = derive_pairing_key("654321", &combined_salt).unwrap();

        let decrypted_auth = decrypt_payload(&server_key, &exchange_packet.payload).unwrap();
        assert_eq!(decrypted_auth, b"ADB_SPA_PAIRING_REQUEST:OK");

        // 4. Server Result response
        let server_result = SpaPacket::new(
            SpaMessageType::Result,
            0,
            vec![PairingResultStatus::Success as u8],
        )
        .unwrap();

        let status = client.process_server_result(&server_result).unwrap();
        assert_eq!(status, PairingResultStatus::Success);
        assert!(client.is_paired());
    }
}
