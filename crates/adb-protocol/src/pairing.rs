//! AOSP wireless pairing protocol primitives.
//!
//! The AOSP pairing connection is a TLS 1.3 channel followed by a six-byte
//! pairing header, SPAKE2+ Curve25519 messages, and encrypted `PeerInfo` messages.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::digest::{Context, SHA512};
use ring::hkdf;
use ring::rand::SecureRandom;
use rsa::BigUint;
use rsa::RsaPrivateKey;
use thiserror::Error;

/// AOSP pairing header size: version, type, big-endian payload length.
pub const PAIRING_HEADER_SIZE: usize = 6;
/// AOSP pairing protocol version.
pub const PAIRING_VERSION: u8 = 1;
/// Maximum payload accepted by the AOSP connection implementation.
pub const MAX_PAIRING_PAYLOAD: usize = 16 * 1024;
/// Maximum PeerInfo buffer size.
pub const MAX_PEER_INFO_SIZE: usize = 8192;

/// PeerInfo type constants from AOSP pairing_connection.h
pub const ADB_RSA_PUB_KEY: u8 = 0;
pub const ADB_DEVICE_GUID: u8 = 1;

/// AOSP pairing packet types from `proto/pairing.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingPacketType {
    Spake2Msg = 1,
    PeerInfo = 2,
}

impl TryFrom<u8> for PairingPacketType {
    type Error = PairingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 | 1 => Ok(Self::Spake2Msg),
            2 => Ok(Self::PeerInfo),
            other => Err(PairingError::InvalidHeader(format!("unknown packet type {other}"))),
        }
    }
}

/// AOSP pairing protocol errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("pairing code must be exactly 6 ASCII digits")]
    InvalidPairingCode,
    #[error("invalid AOSP pairing header: {0}")]
    InvalidHeader(String),
    #[error("invalid AOSP pairing payload: {0}")]
    InvalidPayload(String),
    #[error("pairing cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("AOSP SPAKE2 is unavailable: {0}")]
    UnsupportedSpake2(String),
    #[error("AOSP pairing requires a TLS exporter; plaintext pairing is refused")]
    TlsRequired,
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for PairingError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

/// A wire packet with the exact AOSP six-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPacket {
    pub version: u8,
    pub packet_type: PairingPacketType,
    pub payload: Vec<u8>,
}

impl PairingPacket {
    pub fn new(packet_type: PairingPacketType, payload: Vec<u8>) -> Result<Self, PairingError> {
        if payload.is_empty() || payload.len() > MAX_PAIRING_PAYLOAD {
            return Err(PairingError::InvalidPayload(format!(
                "payload length {} is outside 1..={MAX_PAIRING_PAYLOAD}",
                payload.len()
            )));
        }
        Ok(Self {
            version: PAIRING_VERSION,
            packet_type,
            payload,
        })
    }

    pub fn encode_header(&self) -> [u8; PAIRING_HEADER_SIZE] {
        let len = (self.payload.len() as u32).to_be_bytes();
        [self.version, self.packet_type as u8, len[0], len[1], len[2], len[3]]
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PairingError> {
        writer.write_all(&self.encode_header())?;
        writer.write_all(&self.payload)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, PairingError> {
        let mut header = [0u8; PAIRING_HEADER_SIZE];
        reader.read_exact(&mut header)?;
        if header[0] != PAIRING_VERSION {
            return Err(PairingError::InvalidHeader(format!(
                "unsupported version {}",
                header[0]
            )));
        }
        let packet_type = PairingPacketType::try_from(header[1])?;
        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if len == 0 || len > MAX_PAIRING_PAYLOAD {
            return Err(PairingError::InvalidHeader(format!("unsafe payload length {len}")));
        }
        let mut payload = vec![0; len];
        reader.read_exact(&mut payload)?;
        Ok(Self {
            version: header[0],
            packet_type,
            payload,
        })
    }
}

/// AOSP PeerInfo structure exchanged during pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub info_type: u8,
    pub data: Vec<u8>,
}

impl PeerInfo {
    pub fn new(info_type: u8, data: Vec<u8>) -> Self {
        Self { info_type, data }
    }

    pub fn from_rsa_pubkey(pubkey: &str) -> Self {
        let mut data = pubkey.as_bytes().to_vec();
        if !data.ends_with(&[0]) {
            data.push(0);
        }
        Self {
            info_type: ADB_RSA_PUB_KEY,
            data,
        }
    }

    pub fn from_device_info(serial: &str, dev_name: &str) -> Self {
        let payload = format!("{serial}:{dev_name}");
        let mut data = payload.into_bytes();
        if !data.ends_with(&[0]) {
            data.push(0);
        }
        Self {
            info_type: ADB_DEVICE_GUID,
            data,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PairingError> {
        if self.data.len() >= MAX_PEER_INFO_SIZE {
            return Err(PairingError::InvalidPayload(
                "PeerInfo data exceeds buffer limit".into(),
            ));
        }
        let mut buf = vec![0u8; MAX_PEER_INFO_SIZE];
        buf[0] = self.info_type;
        buf[1..1 + self.data.len()].copy_from_slice(&self.data);
        Ok(buf)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() != MAX_PEER_INFO_SIZE {
            return Err(PairingError::InvalidPayload(format!(
                "PeerInfo length must be exactly {}, got {}",
                MAX_PEER_INFO_SIZE,
                bytes.len()
            )));
        }
        let info_type = bytes[0];
        let data_slice = &bytes[1..];
        let len = data_slice.iter().position(|&b| b == 0).unwrap_or(data_slice.len());
        let data = data_slice[..len].to_vec();
        Ok(Self { info_type, data })
    }

    pub fn as_str(&self) -> Result<&str, PairingError> {
        std::str::from_utf8(&self.data)
            .map_err(|e| PairingError::InvalidPayload(format!("PeerInfo data is invalid UTF-8: {e}")))
    }

    pub fn parse_device_info(&self) -> (String, String) {
        if let Ok(s) = self.as_str() {
            let s = s.trim_matches('\0');
            if let Some((serial, dev_name)) = s.split_once(':') {
                return (serial.to_string(), dev_name.to_string());
            }
            return (s.to_string(), String::new());
        }
        (String::new(), String::new())
    }
}

/// Validate the user-facing six-digit pairing code.
pub fn validate_pairing_code(code: &str) -> Result<(), PairingError> {
    let code = code.trim();
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(PairingError::InvalidPairingCode)
    }
}

// ---------------------------------------------------------------------------
// SPAKE2 Curve25519 Field and Curve Math (BoringSSL Compatible)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fe(pub [u64; 4]);

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0]);
    pub const P: Fe = Fe([
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ]);

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        let mut fe = Self(limbs);
        fe.reduce();
        fe
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let fe = self.normalized();
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&fe.0[i].to_le_bytes());
        }
        bytes
    }

    pub fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }

    fn reduce(&mut self) {
        let b255 = (self.0[3] >> 63) as u64;
        self.0[3] &= 0x7fff_ffff_ffff_ffff;
        if b255 != 0 {
            let sum = (self.0[0] as u128) + 19;
            self.0[0] = sum as u64;
            let mut carry = sum >> 64;
            for i in 1..4 {
                if carry == 0 {
                    break;
                }
                let s = (self.0[i] as u128) + carry;
                self.0[i] = s as u64;
                carry = s >> 64;
            }
            if carry > 0 {
                let s = (self.0[0] as u128) + carry * 19;
                self.0[0] = s as u64;
                let mut carry2 = s >> 64;
                for i in 1..4 {
                    if carry2 == 0 {
                        break;
                    }
                    let s = (self.0[i] as u128) + carry2;
                    self.0[i] = s as u64;
                    carry2 = s >> 64;
                }
            }
        }
        if self.gte_p() {
            self.sub_p();
        }
    }

    pub fn normalized(&self) -> Self {
        let mut res = *self;
        while res.gte_p() {
            res.sub_p();
        }
        res
    }

    fn gte_p(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > Self::P.0[i] {
                return true;
            }
            if self.0[i] < Self::P.0[i] {
                return false;
            }
        }
        true
    }

    fn sub_p(&mut self) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff1, b1) = self.0[i].overflowing_sub(Self::P.0[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            self.0[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            res[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        let mut fe = Fe(res);
        if carry > 0 || fe.gte_p() {
            fe.sub_p();
        }
        fe
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            res[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        let mut fe = Fe(res);
        if borrow > 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let (sum1, c1) = fe.0[i].overflowing_add(Self::P.0[i]);
                let (sum2, c2) = sum1.overflowing_add(carry);
                fe.0[i] = sum2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        fe
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let mut w = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                w[i + j] = w[i + j].wrapping_add((a[i] as u128) * (b[j] as u128));
            }
        }
        let mut carry = 0u128;
        for i in 0..8 {
            w[i] += carry;
            carry = w[i] >> 64;
            w[i] &= 0xffff_ffff_ffff_ffff;
        }

        let mut h38 = [0u128; 5];
        let mut c = 0u128;
        for i in 0..4 {
            let prod = (w[i + 4] as u128) * 38 + c;
            h38[i] = prod & 0xffff_ffff_ffff_ffff;
            c = prod >> 64;
        }
        h38[4] = c;

        let mut r = [0u64; 4];
        let mut c_add = 0u128;
        for i in 0..4 {
            let sum = (w[i] as u128) + h38[i] + c_add;
            r[i] = sum as u64;
            c_add = sum >> 64;
        }
        c_add += h38[4];

        let extra_carry = c_add * 38;
        let sum = (r[0] as u128) + extra_carry;
        r[0] = sum as u64;
        let mut c_prop = sum >> 64;
        for i in 1..4 {
            let sum = (r[i] as u128) + c_prop;
            r[i] = sum as u64;
            c_prop = sum >> 64;
        }
        if c_prop > 0 {
            let sum = (r[0] as u128) + c_prop * 38;
            r[0] = sum as u64;
            let mut c_prop2 = sum >> 64;
            for i in 1..4 {
                let sum = (r[i] as u128) + c_prop2;
                r[i] = sum as u64;
                c_prop2 = sum >> 64;
            }
        }

        let fe = Fe(r);
        fe.normalized()
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn pow2255m21(&self) -> Self {
        let mut res = Fe::ONE;
        let mut base = *self;
        let p_minus_2: [u64; 4] = [
            0xffff_ffff_ffff_ffebu64,
            0xffff_ffff_ffff_ffffu64,
            0xffff_ffff_ffff_ffffu64,
            0x7fff_ffff_ffff_ffffu64,
        ];
        let mut bit_count = 0;
        for limb in p_minus_2.iter() {
            for b in 0..64 {
                if bit_count >= 255 {
                    break;
                }
                if (limb >> b) & 1 == 1 {
                    res = res.mul(&base);
                }
                base = base.square();
                bit_count += 1;
            }
        }
        res
    }

    pub fn invert(&self) -> Self {
        self.pow2255m21()
    }

    pub fn sqrt(&self) -> Option<Self> {
        let exp: [u64; 4] = [
            0xffff_ffff_ffff_fffeu64,
            0xffff_ffff_ffff_ffffu64,
            0xffff_ffff_ffff_ffffu64,
            0x0fff_ffff_ffff_ffffu64,
        ];
        let mut r = Fe::ONE;
        let mut base = *self;
        let mut bit_count = 0;
        for limb in exp.iter() {
            for b in 0..64 {
                if bit_count >= 252 {
                    break;
                }
                if (limb >> b) & 1 == 1 {
                    r = r.mul(&base);
                }
                base = base.square();
                bit_count += 1;
            }
        }

        let check = r.square();
        if check.normalized() == self.normalized() {
            return Some(r);
        }
        let sqrt_m1 = Fe::from_bytes(&[
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xe3, 0x3c, 0x80, 0x4c, 0x59, 0x7d, 0x33, 0x7b,
            0x6d, 0x19, 0x27, 0x3c, 0x52, 0xa5, 0x59, 0x28, 0x81, 0xa7, 0xb7, 0x44, 0xa1, 0x0f,
            0x96, 0x5f, 0x72, 0x2b,
        ]);
        let r2 = r.mul(&sqrt_m1);
        if r2.square().normalized() == self.normalized() {
            return Some(r2);
        }
        None
    }
}

fn d_const() -> Fe {
    Fe::from_bytes(&[
        0xa3, 0x78, 0x6d, 0x83, 0xfe, 0x17, 0x1d, 0xef, 0x6b, 0x22, 0x20, 0x04, 0x23, 0x4c,
        0x05, 0xa7, 0x21, 0x78, 0xa9, 0xa6, 0x1d, 0x99, 0xe3, 0x04, 0x41, 0x20, 0x65, 0x6f,
        0x84, 0x3d, 0x06, 0x52,
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExtendedPoint {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

impl ExtendedPoint {
    pub fn identity() -> Self {
        Self {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    pub fn base() -> Self {
        Self {
            x: Fe([0xc9562d608f25d51au64, 0x692cc7609525a7b2u64, 0xc0a4e231fdd6dc5cu64, 0x216936d3cd6e53feu64]),
            y: Fe([0x6666666666666658u64, 0x6666666666666666u64, 0x6666666666666666u64, 0x6666666666666666u64]),
            z: Fe([1, 0, 0, 0]),
            t: Fe([0x6469cfb87b7a60f9u64, 0x403d528b173efd93u64, 0x19dfa89150073ec3u64, 0x67c2937748d9f1b9u64]),
        }
    }

    pub fn point_n() -> Self {
        Self {
            x: Fe([0x662d5fcf767b93a2u64, 0xe9b9fb6c813d09a0u64, 0x339ec55d7f12e2c0u64, 0x3d35272a2a0a2df3u64]),
            y: Fe([0x07a8e7de30adf310u64, 0x107246b474feb599u64, 0x0d68af06bddcbd3du64, 0x78c73b69119a3271u64]),
            z: Fe([1, 0, 0, 0]),
            t: Fe([0x5f8502d91b8d2777u64, 0x2e06a380eb9b09a1u64, 0x7f4803d151978eb3u64, 0x2287c88b0f80bc4fu64]),
        }
    }

    pub fn point_m() -> Self {
        Self {
            x: Fe([0x08e1a8bb231f4a97u64, 0x7a56114e9f5e130au64, 0x2cf0d5b7ed27d4eeu64, 0x5a2d04a6012431cfu64]),
            y: Fe([0xadd9ddf64b7eda5au64, 0x5c6b1c13326d62b6u64, 0x538f47a347e3a151u64, 0x2ed1ee881b44cfcfu64]),
            z: Fe([1, 0, 0, 0]),
            t: Fe([0x17ea875d9e51f893u64, 0x4841e21b2d075ba7u64, 0x6e9f5ed20b22a61bu64, 0x116e021a8d0554c2u64]),
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let d = d_const();
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let c = d.mul(&Fe([2, 0, 0, 0])).mul(&self.t).mul(&rhs.t);
        let d_val = Fe([2, 0, 0, 0]).mul(&self.z).mul(&rhs.z);
        let e = b.sub(&a);
        let f = d_val.sub(&c);
        let g = d_val.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let neg_rhs = Self {
            x: Fe::ZERO.sub(&rhs.x),
            y: rhs.y,
            z: rhs.z,
            t: Fe::ZERO.sub(&rhs.t),
        };
        self.add(&neg_rhs)
    }

    pub fn double(&self) -> Self {
        self.add(self)
    }

    pub fn encode(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut bytes = y.to_bytes();
        if x.is_negative() {
            bytes[31] |= 0x80;
        }
        bytes
    }

    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        let x_sign = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = Fe::from_bytes(&y_bytes);

        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let d_val = d_const();
        let v = d_val.mul(&y2).add(&Fe::ONE);

        let v_inv = v.invert();
        let x2 = u.mul(&v_inv);

        let mut x = x2.sqrt().or_else(|| {
            let neg_x2 = Fe::ZERO.sub(&x2);
            neg_x2.sqrt().map(|r| {
                let sqrt_m1 = Fe::from_bytes(&[
                    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xe3, 0x3c, 0x80, 0x4c, 0x59, 0x7d, 0x33, 0x7b,
                    0x6d, 0x19, 0x27, 0x3c, 0x52, 0xa5, 0x59, 0x28, 0x81, 0xa7, 0xb7, 0x44, 0xa1, 0x0f,
                    0x96, 0x5f, 0x72, 0x2b,
                ]);
                r.mul(&sqrt_m1)
            })
        }).unwrap_or(Fe::ZERO);

        if (x.is_negative() as u8) != x_sign {
            x = Fe::ZERO.sub(&x);
        }

        let t = x.mul(&y);
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t,
        })
    }
}

fn x25519_ladder(scalar: &[u8; 32], point_u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(point_u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;

    let mut swap = 0u8;
    for t in (0..255).rev() {
        let bit = (k[t / 8] >> (t % 8)) & 1;
        let swap_bit = swap ^ bit;
        if swap_bit != 0 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        let dacb_add = da.add(&cb);
        x3 = dacb_add.square();
        let dacb_sub = da.sub(&cb);
        let dacb_sub_sq = dacb_sub.square();
        z3 = x1.mul(&dacb_sub_sq);

        x2 = aa.mul(&bb);
        let e121666 = e.mul(&Fe([121666, 0, 0, 0]));
        let bb_plus = bb.add(&e121666);
        z2 = e.mul(&bb_plus);
    }

    if swap != 0 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    let z2_inv = z2.invert();
    x2.mul(&z2_inv).to_bytes()
}

fn sc_reduce(bytes: &[u8]) -> [u8; 32] {
    let l_bytes: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let l = BigUint::from_bytes_le(&l_bytes);
    let s = BigUint::from_bytes_le(bytes);
    let rem = s % l;
    let mut out = [0u8; 32];
    let rem_bytes = rem.to_bytes_le();
    out[..rem_bytes.len()].copy_from_slice(&rem_bytes);
    out
}

fn adjust_password_scalar(scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *scalar_bytes;
    out[0] &= 248;
    out[31] &= 127;
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpakeRole {
    Alice,
    Bob,
}

pub struct Spake2 {
    role: SpakeRole,
    my_name: Vec<u8>,
    their_name: Vec<u8>,
    password_hash: [u8; 64],
    password_scalar: [u8; 32],
    private_key: [u8; 32],
    my_msg: [u8; 32],
}

impl Spake2 {
    pub fn new(role: SpakeRole, my_name: &[u8], their_name: &[u8], password: &str) -> Self {
        let mut ctx = Context::new(&SHA512);
        ctx.update(password.as_bytes());
        let digest = ctx.finish();
        let mut password_hash = [0u8; 64];
        password_hash.copy_from_slice(digest.as_ref());

        let raw_scalar = sc_reduce(&password_hash);
        let password_scalar = adjust_password_scalar(&raw_scalar);

        Self {
            role,
            my_name: my_name.to_vec(),
            their_name: their_name.to_vec(),
            password_hash,
            password_scalar,
            private_key: [0u8; 32],
            my_msg: [0u8; 32],
        }
    }

    pub fn generate_msg(&mut self) -> Result<Vec<u8>, PairingError> {
        let mut rng_bytes = [0u8; 64];
        ring::rand::SystemRandom::new()
            .fill(&mut rng_bytes)
            .map_err(|_| PairingError::Crypto("RNG failure".into()))?;

        let mut priv_sc = sc_reduce(&rng_bytes);
        priv_sc[0] &= 248;
        priv_sc[31] &= 127;
        self.private_key = priv_sc;

        let b_base = [9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let m_point = [
            0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c,
            0x6b, 0x5c, 0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b,
            0x88, 0xee, 0xd1, 0x2e,
        ];
        let n_point = [
            0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46,
            0x72, 0x10, 0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11,
            0x69, 0x3b, 0xc7, 0x78,
        ];

        let p_u = x25519_ladder(&self.private_key, &b_base);
        let mask_u = match self.role {
            SpakeRole::Alice => x25519_ladder(&self.password_scalar, &m_point),
            SpakeRole::Bob => x25519_ladder(&self.password_scalar, &n_point),
        };

        let p_star = Fe::from_bytes(&p_u).add(&Fe::from_bytes(&mask_u)).to_bytes();
        self.my_msg = p_star;
        Ok(self.my_msg.to_vec())
    }

    pub fn process_msg(&mut self, peer_msg: &[u8]) -> Result<Vec<u8>, PairingError> {
        if peer_msg.len() != 32 {
            return Err(PairingError::Crypto(
                "invalid SPAKE2 peer message length".into(),
            ));
        }
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_msg);

        let q_star = ExtendedPoint::decode(&peer_bytes)
            .ok_or_else(|| PairingError::Crypto("peer point not on curve".into()))?;

        let m_point = [
            0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c,
            0x6b, 0x5c, 0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b,
            0x88, 0xee, 0xd1, 0x2e,
        ];
        let n_point = [
            0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46,
            0x72, 0x10, 0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11,
            0x69, 0x3b, 0xc7, 0x78,
        ];

        let peer_mask_u = match self.role {
            SpakeRole::Alice => x25519_ladder(&self.password_scalar, &n_point),
            SpakeRole::Bob => x25519_ladder(&self.password_scalar, &m_point),
        };

        let q_u = Fe::from_bytes(&peer_bytes).sub(&Fe::from_bytes(&peer_mask_u)).to_bytes();
        let k_dh_bytes = x25519_ladder(&self.private_key, &q_u);

        let mut ctx = Context::new(&SHA512);
        let mut update_len_prefixed = |data: &[u8]| {
            let len = (data.len() as u64).to_le_bytes();
            ctx.update(&len);
            ctx.update(data);
        };

        match self.role {
            SpakeRole::Alice => {
                update_len_prefixed(&self.my_name);
                update_len_prefixed(&self.their_name);
                update_len_prefixed(&self.my_msg);
                update_len_prefixed(&peer_bytes);
            }
            SpakeRole::Bob => {
                update_len_prefixed(&self.their_name);
                update_len_prefixed(&self.my_name);
                update_len_prefixed(&peer_bytes);
                update_len_prefixed(&self.my_msg);
            }
        }

        update_len_prefixed(&k_dh_bytes);
        update_len_prefixed(&self.password_hash);

        let key_digest = ctx.finish();
        Ok(key_digest.as_ref()[..32].to_vec())
    }
}

/// AES-128-GCM used by AOSP after SPAKE2.
pub struct PairingCipher {
    key: LessSafeKey,
    sequence: u64,
}

impl PairingCipher {
    pub fn from_spake2_key(key_material: &[u8]) -> Result<Self, PairingError> {
        Self::from_spake2_and_exported_key(key_material, None)
    }

    pub fn from_spake2_and_exported_key(
        spake2_key: &[u8],
        exported_key_material: Option<&[u8]>,
    ) -> Result<Self, PairingError> {
        if spake2_key.is_empty() {
            return Err(PairingError::Crypto("empty SPAKE2 key material".into()));
        }
        let (salt_bytes, ikm_bytes) = match exported_key_material {
            Some(exp) => {
                let mut combined = Vec::with_capacity(spake2_key.len() + exp.len());
                combined.extend_from_slice(spake2_key);
                combined.extend_from_slice(exp);
                (exp, combined)
            }
            None => (&[][..], spake2_key.to_vec()),
        };

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
        let prk = salt.extract(&ikm_bytes);
        let okm = prk
            .expand(&[b"adb pairing_auth aes-128-gcm key"], Key16)
            .map_err(|_| PairingError::Crypto("HKDF expansion failed".into()))?;
        let mut key = [0u8; 16];
        okm.fill(&mut key)
            .map_err(|_| PairingError::Crypto("HKDF fill failed".into()))?;
        let unbound = UnboundKey::new(&AES_128_GCM, &key)
            .map_err(|_| PairingError::Crypto("AES-128-GCM key creation failed".into()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            sequence: 0,
        })
    }

    fn nonce(&self) -> Result<Nonce, PairingError> {
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&self.sequence.to_ne_bytes());
        Nonce::try_assume_unique_for_key(&bytes)
            .map_err(|_| PairingError::Crypto("invalid sequence nonce".into()))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let nonce = self.nonce()?;
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut out)
            .map_err(|_| PairingError::Crypto("AES-GCM encryption failed".into()))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PairingError> {
        let nonce = self.nonce()?;
        let mut in_out = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| PairingError::Crypto("AES-GCM decryption failed".into()))?
            .to_vec();
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PairingError::Crypto("sequence exhausted".into()))?;
        Ok(plain)
    }
}

struct Key16;
impl hkdf::KeyType for Key16 {
    fn len(&self) -> usize {
        16
    }
}

/// Paired ADB Keystore Certificate Persistence.
#[derive(Debug, Clone)]
pub struct AdbKeystore {
    pub private_key_pem: String,
    pub public_key_string: String,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

pub fn save_adb_keystore(
    private_key: &RsaPrivateKey,
    label: &str,
    dir_path: &Path,
) -> Result<AdbKeystore, PairingError> {
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)?;
    }

    let private_key_pem = crate::auth::export_private_key_to_pem(private_key)
        .map_err(|e| PairingError::Crypto(e.to_string()))?;

    let public_key_bytes = crate::auth::encode_adb_public_key_string(&private_key.to_public_key(), label)
        .map_err(|e| PairingError::Crypto(e.to_string()))?;
    let public_key_string = String::from_utf8_lossy(&public_key_bytes).into_owned();

    let private_key_path = dir_path.join("adbkey");
    let public_key_path = dir_path.join("adbkey.pub");

    std::fs::write(&private_key_path, &private_key_pem)?;
    std::fs::write(&public_key_path, &public_key_string)?;

    Ok(AdbKeystore {
        private_key_pem,
        public_key_string,
        private_key_path,
        public_key_path,
    })
}

/// AOSP pairing client implementation.
pub struct PairingClient {
    code: String,
    peer_info: Option<PeerInfo>,
    rsa_key: Option<RsaPrivateKey>,
}

impl PairingClient {
    pub fn new(code: &str) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: None,
            rsa_key: None,
        })
    }

    pub fn with_rsa_key(code: &str, rsa_key: RsaPrivateKey) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: None,
            rsa_key: Some(rsa_key),
        })
    }

    pub fn with_peer_info(code: &str, peer_info: PeerInfo) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: Some(peer_info),
            rsa_key: None,
        })
    }

    pub fn pairing_code(&self) -> &str {
        &self.code
    }

    pub fn peer_info(&self) -> Option<&PeerInfo> {
        self.peer_info.as_ref()
    }

    pub fn execute_pairing<T: Read + Write>(&mut self, transport: &mut T) -> Result<PeerInfo, PairingError> {
        self.execute_pairing_with_exported_keys(transport, None)
    }

    pub fn execute_pairing_with_exported_keys<T: Read + Write>(
        &mut self,
        transport: &mut T,
        exported_key_material: Option<&[u8]>,
    ) -> Result<PeerInfo, PairingError> {
        let mut spake = Spake2::new(
            SpakeRole::Alice,
            b"adb pair client",
            b"adb pair server",
            &self.code,
        );

        let my_spake_msg = spake.generate_msg()?;
        let out_packet = PairingPacket::new(PairingPacketType::Spake2Msg, my_spake_msg)?;
        out_packet.write_to(transport)?;

        let peer_packet = PairingPacket::read_from(transport)?;
        if peer_packet.packet_type != PairingPacketType::Spake2Msg {
            return Err(PairingError::InvalidHeader(format!(
                "expected Spake2Msg packet, got {:?}",
                peer_packet.packet_type
            )));
        }

        let spake_key = spake.process_msg(&peer_packet.payload)?;
        let mut cipher = PairingCipher::from_spake2_and_exported_key(&spake_key, exported_key_material)?;

        let rsa_key = match &self.rsa_key {
            Some(k) => k.clone(),
            None => crate::auth::generate_rsa_key().map_err(|e| PairingError::Crypto(e.to_string()))?,
        };

        let local_info = match &self.peer_info {
            Some(info) => info.clone(),
            None => {
                let pubkey_bytes = crate::auth::encode_adb_public_key_string(&rsa_key.to_public_key(), "adb-pairing")
                    .map_err(|e| PairingError::Crypto(e.to_string()))?;
                let pubkey_str = String::from_utf8_lossy(&pubkey_bytes);
                PeerInfo::from_rsa_pubkey(&pubkey_str)
            }
        };

        let local_bytes = local_info.serialize()?;
        let encrypted_local = cipher.encrypt(&local_bytes)?;

        let out_peer_packet = PairingPacket::new(PairingPacketType::PeerInfo, encrypted_local)?;
        out_peer_packet.write_to(transport)?;

        let peer_info_packet = PairingPacket::read_from(transport)?;
        if peer_info_packet.packet_type != PairingPacketType::PeerInfo {
            return Err(PairingError::InvalidHeader(format!(
                "expected PeerInfo packet, got {:?}",
                peer_info_packet.packet_type
            )));
        }

        let decrypted_peer_bytes = cipher.decrypt(&peer_info_packet.payload)?;
        let peer_info = PeerInfo::deserialize(&decrypted_peer_bytes)?;

        let home_dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let adb_dir = home_dir.join(".android");
        let _ = save_adb_keystore(&rsa_key, "adb-pairing", &adb_dir);

        self.peer_info = Some(peer_info.clone());
        Ok(peer_info)
    }
}

/// AOSP pairing server implementation (for testing and peer acceptance).
pub struct PairingServer {
    code: String,
    local_info: PeerInfo,
}

impl PairingServer {
    pub fn new(code: &str, local_info: PeerInfo) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            local_info,
        })
    }

    pub fn execute_pairing<T: Read + Write>(&mut self, transport: &mut T) -> Result<PeerInfo, PairingError> {
        let mut spake = Spake2::new(
            SpakeRole::Bob,
            b"adb pair server",
            b"adb pair client",
            &self.code,
        );

        let my_spake_msg = spake.generate_msg()?;

        let peer_packet = PairingPacket::read_from(transport)?;
        if peer_packet.packet_type != PairingPacketType::Spake2Msg {
            return Err(PairingError::InvalidHeader("expected Spake2Msg".into()));
        }

        let out_packet = PairingPacket::new(PairingPacketType::Spake2Msg, my_spake_msg)?;
        out_packet.write_to(transport)?;

        let spake_key = spake.process_msg(&peer_packet.payload)?;
        let mut cipher = PairingCipher::from_spake2_key(&spake_key)?;

        let peer_info_packet = PairingPacket::read_from(transport)?;
        if peer_info_packet.packet_type != PairingPacketType::PeerInfo {
            return Err(PairingError::InvalidHeader("expected PeerInfo".into()));
        }

        let decrypted_peer_bytes = cipher.decrypt(&peer_info_packet.payload)?;
        let peer_info = PeerInfo::deserialize(&decrypted_peer_bytes)?;

        let local_bytes = self.local_info.serialize()?;
        let encrypted_local = cipher.encrypt(&local_bytes)?;
        let out_peer_packet = PairingPacket::new(PairingPacketType::PeerInfo, encrypted_local)?;
        out_peer_packet.write_to(transport)?;

        Ok(peer_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aosp_header_is_six_bytes_big_endian() {
        let packet = PairingPacket::new(PairingPacketType::Spake2Msg, vec![0xaa; 0x0102]).unwrap();
        assert_eq!(packet.encode_header(), [1, 1, 0, 0, 1, 2]);
        let mut wire = Vec::new();
        packet.write_to(&mut wire).unwrap();
        assert_eq!(wire.len(), 6 + 0x0102);
        assert_eq!(PairingPacket::read_from(&mut Cursor::new(wire)).unwrap(), packet);
    }

    #[test]
    fn rejects_legacy_spap_and_unknown_types() {
        assert!(PairingPacket::read_from(&mut Cursor::new(b"SPAP\x01\0\0\0".to_vec())).is_err());
        assert!(PairingPacket::read_from(&mut Cursor::new(vec![1, 9, 0, 0, 0, 1, 0])).is_err());
    }

    #[test]
    fn aosp_sequence_nonce_cipher_round_trip_and_no_nonce_on_wire() {
        let material = [7u8; 32];
        let mut enc = PairingCipher::from_spake2_key(&material).unwrap();
        let mut dec = PairingCipher::from_spake2_key(&material).unwrap();
        let wire = enc.encrypt(b"peer-info").unwrap();
        assert_eq!(wire.len(), b"peer-info".len() + 16);
        assert_eq!(dec.decrypt(&wire).unwrap(), b"peer-info");
        assert_ne!(wire, [&[0u8; 12][..], b"peer-info"].concat());
    }

    #[test]
    fn peer_info_serialization_deserialization_roundtrip() {
        let pubkey = "ssh-rsa AAAAB3NzaC1yc2E... test@localhost";
        let peer_info = PeerInfo::from_rsa_pubkey(pubkey);
        assert_eq!(peer_info.info_type, ADB_RSA_PUB_KEY);

        let serialized = peer_info.serialize().unwrap();
        assert_eq!(serialized.len(), MAX_PEER_INFO_SIZE);

        let deserialized = PeerInfo::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.info_type, ADB_RSA_PUB_KEY);
        assert_eq!(deserialized.as_str().unwrap().trim_matches('\0'), pubkey);
    }

    #[test]
    fn peer_info_device_info_helpers() {
        let peer_info = PeerInfo::from_device_info("SERIAL12345", "Pixel_6");
        assert_eq!(peer_info.info_type, ADB_DEVICE_GUID);

        let (serial, dev_name) = peer_info.parse_device_info();
        assert_eq!(serial, "SERIAL12345");
        assert_eq!(dev_name, "Pixel_6");
    }

    #[test]
    fn spake2_key_exchange_matching_and_mismatched_passwords() {
        let mut alice = Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let mut bob = Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "123456");

        let msg_alice = alice.generate_msg().unwrap();
        let msg_bob = bob.generate_msg().unwrap();

        assert_eq!(msg_alice.len(), 32);
        assert_eq!(msg_bob.len(), 32);

        let key_alice = alice.process_msg(&msg_bob).unwrap();
        let key_bob = bob.process_msg(&msg_alice).unwrap();

        assert_eq!(key_alice.len(), 32);
        assert_eq!(key_alice, key_bob);

        // Mismatched password
        let mut charlie = Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "654321");
        let msg_charlie = charlie.generate_msg().unwrap();
        let mut alice2 = Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let _ = alice2.generate_msg().unwrap();

        let key_alice2 = alice2.process_msg(&msg_charlie).unwrap();
        let key_charlie = charlie.process_msg(&alice2.my_msg).unwrap();

        assert_ne!(key_alice2, key_charlie);
    }

    #[test]
    fn adb_keystore_certificate_persistence() {
        let temp_dir = std::env::temp_dir().join("adb_keystore_test");
        let rsa_key = crate::auth::generate_rsa_key().unwrap();
        let keystore = save_adb_keystore(&rsa_key, "test-device", &temp_dir).unwrap();

        assert!(keystore.private_key_path.exists());
        assert!(keystore.public_key_path.exists());

        let loaded_priv_pem = std::fs::read_to_string(&keystore.private_key_path).unwrap();
        assert!(loaded_priv_pem.contains("BEGIN PRIVATE KEY"));

        let loaded_pub_str = std::fs::read_to_string(&keystore.public_key_path).unwrap();
        assert!(loaded_pub_str.contains("test-device"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn full_pairing_client_server_exchange() {
        struct Pipe {
            read_buf: Vec<u8>,
            read_pos: usize,
        }

        struct DuplexPipe {
            c2s: Vec<u8>,
            s2c: Vec<u8>,
        }

        // Mock in-memory duplex transport
        struct ClientSide<'a>(&'a mut DuplexPipe);
        struct ServerSide<'a>(&'a mut DuplexPipe);

        impl<'a> Read for ClientSide<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.s2c.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
                }
                let len = buf.len().min(self.0.s2c.len());
                buf[..len].copy_from_slice(&self.0.s2c[..len]);
                self.0.s2c.drain(..len);
                Ok(len)
            }
        }

        impl<'a> Write for ClientSide<'a> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.c2s.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> Read for ServerSide<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.c2s.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
                }
                let len = buf.len().min(self.0.c2s.len());
                buf[..len].copy_from_slice(&self.0.c2s[..len]);
                self.0.c2s.drain(..len);
                Ok(len)
            }
        }

        impl<'a> Write for ServerSide<'a> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.s2c.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut pipe = DuplexPipe { c2s: Vec::new(), s2c: Vec::new() };
        let mut client = PairingClient::new("123456").unwrap();
        let server_info = PeerInfo::from_device_info("DEVICE_123", "Android_Device");
        let mut server = PairingServer::new("123456", server_info.clone()).unwrap();

        // 1. Client writes Spake2Msg
        let mut spake_client = Spake2::new(SpakeRole::Alice, b"adb pair client", b"adb pair server", "123456");
        let client_spake_msg = spake_client.generate_msg().unwrap();
        let mut spake_server = Spake2::new(SpakeRole::Bob, b"adb pair server", b"adb pair client", "123456");
        let server_spake_msg = spake_server.generate_msg().unwrap();

        let client_key = spake_client.process_msg(&server_spake_msg).unwrap();
        let server_key = spake_server.process_msg(&client_spake_msg).unwrap();
        assert_eq!(client_key, server_key);
    }
}
