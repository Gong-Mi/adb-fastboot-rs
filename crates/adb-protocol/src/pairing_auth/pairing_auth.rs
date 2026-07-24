//! AOSP SPAKE2+ Curve25519 pairing authentication,
//! mirroring `vendor/adb/pairing_auth/pairing_auth.cpp`.

use ring::digest::{Context, SHA512};
use ring::rand::SecureRandom;
use rsa::BigUint;

use crate::pairing::PairingError;

/// SPAKE2 role (Alice = client, Bob = server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpakeRole {
    Alice,
    Bob,
}

// ---------------------------------------------------------------------------
// Curve25519 field element (Goldilocks-style reduction: 4×64-bit limbs)
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

// ---------------------------------------------------------------------------
// ExtendedPoint (Edwards curve for SPAKE2+)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// X25519 Montgomery ladder
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// SPAKE2+
// ---------------------------------------------------------------------------

/// SPAKE2+ protocol implementation for AOSP pairing.
pub struct Spake2 {
    role: SpakeRole,
    my_name: Vec<u8>,
    their_name: Vec<u8>,
    password_hash: [u8; 64],
    password_scalar: [u8; 32],
    private_key: [u8; 32],
    pub my_msg: [u8; 32],
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

        let _q_star = ExtendedPoint::decode(&peer_bytes)
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
