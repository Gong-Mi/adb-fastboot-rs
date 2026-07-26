//! FFI bindings to the vendored AOSP `pairing_auth` C API
//! (`vendor/adb/pairing_auth/include/adb/pairing/pairing_auth.h`), which runs
//! BoringSSL SPAKE2 plus AES-128-GCM exactly as `adb pair` does.
//!
//! This module replaces the handwritten SPAKE2/curve25519 implementation for
//! production use. The C API already binds the AOSP-fixed peer names
//! ("adb pair client"/"adb pair server", NUL included) internally, so the
//! caller only supplies the password (pairing code + TLS exporter, per
//! `pairing_connection.cpp`).

use std::ffi::c_void;

use crate::pairing::PairingError;

#[allow(non_camel_case_types)]
type PairingAuthCtx = c_void;

unsafe extern "C" {
    fn pairing_auth_client_new(pswd: *const u8, len: usize) -> *mut PairingAuthCtx;
    fn pairing_auth_server_new(pswd: *const u8, len: usize) -> *mut PairingAuthCtx;
    fn pairing_auth_destroy(ctx: *mut PairingAuthCtx);
    fn pairing_auth_msg_size(ctx: *mut PairingAuthCtx) -> usize;
    fn pairing_auth_get_spake2_msg(ctx: *mut PairingAuthCtx, out_buf: *mut u8);
    fn pairing_auth_init_cipher(
        ctx: *mut PairingAuthCtx,
        their_msg: *const u8,
        msg_len: usize,
    ) -> bool;
    fn pairing_auth_safe_encrypted_size(ctx: *mut PairingAuthCtx, len: usize) -> usize;
    fn pairing_auth_encrypt(
        ctx: *mut PairingAuthCtx,
        inbuf: *const u8,
        inlen: usize,
        outbuf: *mut u8,
        outlen: *mut usize,
    ) -> bool;
    fn pairing_auth_safe_decrypted_size(
        ctx: *mut PairingAuthCtx,
        buf: *const u8,
        len: usize,
    ) -> usize;
    fn pairing_auth_decrypt(
        ctx: *mut PairingAuthCtx,
        inbuf: *const u8,
        inlen: usize,
        outbuf: *mut u8,
        outlen: *mut usize,
    ) -> bool;
}

/// Role of this peer in the pairing exchange (mirrors `PairingAuthCtx::Role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRole {
    Client,
    Server,
}

/// Owning wrapper around `PairingAuthCtx`.
///
/// Construction performs the full SPAKE2 message generation, so `msg()` is
/// infallible. `init_cipher` may only be called once, mirroring AOSP.
pub struct PairingAuth {
    ctx: *mut PairingAuthCtx,
    cipher_ready: bool,
}

// PairingAuthCtx is created/destroyed on the calling thread and holds no
// thread affinity in BoringSSL; the pairing exchange is driven from one
// thread at a time in our call sites.
unsafe impl Send for PairingAuth {}

impl PairingAuth {
    pub fn new(role: PairingRole, password: &[u8]) -> Result<Self, PairingError> {
        if password.is_empty() {
            return Err(PairingError::Crypto("empty pairing password".into()));
        }
        let ctx = unsafe {
            match role {
                PairingRole::Client => pairing_auth_client_new(password.as_ptr(), password.len()),
                PairingRole::Server => pairing_auth_server_new(password.as_ptr(), password.len()),
            }
        };
        if ctx.is_null() {
            return Err(PairingError::Crypto(
                "pairing_auth_*_new returned null".into(),
            ));
        }
        Ok(Self {
            ctx,
            cipher_ready: false,
        })
    }

    /// The SPAKE2 message to send to the peer (`pairing_auth_get_spake2_msg`).
    pub fn msg(&self) -> Vec<u8> {
        let size = unsafe { pairing_auth_msg_size(self.ctx) };
        let mut buf = vec![0u8; size];
        unsafe { pairing_auth_get_spake2_msg(self.ctx, buf.as_mut_ptr()) };
        buf
    }

    /// Process the peer's SPAKE2 message and initialize the AES-128-GCM
    /// cipher. Returns Ok(false) when the passwords did not match (AOSP
    /// `pairing_auth_init_cipher` returning false).
    pub fn init_cipher(&mut self, their_msg: &[u8]) -> Result<bool, PairingError> {
        if their_msg.is_empty() {
            return Err(PairingError::Crypto("empty peer SPAKE2 message".into()));
        }
        let ok = unsafe { pairing_auth_init_cipher(self.ctx, their_msg.as_ptr(), their_msg.len()) };
        self.cipher_ready = ok;
        Ok(ok)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
        if !self.cipher_ready {
            return Err(PairingError::Crypto("cipher not initialized".into()));
        }
        let cap = unsafe { pairing_auth_safe_encrypted_size(self.ctx, plaintext.len()) };
        let mut out = vec![0u8; cap];
        let mut outlen: usize = 0;
        let ok = unsafe {
            pairing_auth_encrypt(
                self.ctx,
                plaintext.as_ptr(),
                plaintext.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        if !ok {
            return Err(PairingError::Crypto("pairing_auth_encrypt failed".into()));
        }
        out.truncate(outlen);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PairingError> {
        if !self.cipher_ready {
            return Err(PairingError::Crypto("cipher not initialized".into()));
        }
        let cap = unsafe { pairing_auth_safe_decrypted_size(self.ctx, ciphertext.as_ptr(), ciphertext.len()) };
        let mut out = vec![0u8; cap];
        let mut outlen: usize = 0;
        let ok = unsafe {
            pairing_auth_decrypt(
                self.ctx,
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
                &mut outlen,
            )
        };
        if !ok {
            return Err(PairingError::Crypto(
                "pairing_auth_decrypt failed (wrong password or corrupt data)".into(),
            ));
        }
        out.truncate(outlen);
        Ok(out)
    }
}

impl Drop for PairingAuth {
    fn drop(&mut self) {
        unsafe { pairing_auth_destroy(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AOSP pairing_auth_test.cpp equivalent: matching passwords let both
    /// peers encrypt/decrypt; mismatched passwords fail init_cipher.
    #[test]
    fn vendored_spake2_matching_and_mismatched_passwords() {
        let mut client = PairingAuth::new(PairingRole::Client, b"123456").unwrap();
        let mut server = PairingAuth::new(PairingRole::Server, b"123456").unwrap();
        let c_msg = client.msg();
        let s_msg = server.msg();
        assert!(!c_msg.is_empty());
        assert!(client.init_cipher(&s_msg).unwrap());
        assert!(server.init_cipher(&c_msg).unwrap());

        let sealed = client.encrypt(b"hello icbc-free world").unwrap();
        let opened = server.decrypt(&sealed).unwrap();
        assert_eq!(opened, b"hello icbc-free world");

        let sealed2 = server.encrypt(b"reply").unwrap();
        let opened2 = client.decrypt(&sealed2).unwrap();
        assert_eq!(opened2, b"reply");

        // SPAKE2 does not reject a wrong password at init_cipher: it derives a
        // bogus key. Failure surfaces at AEAD decrypt (AOSP
        // pairing_auth_test.cpp semantics).
        let mut bad = PairingAuth::new(PairingRole::Client, b"654321").unwrap();
        let mut server2 = PairingAuth::new(PairingRole::Server, b"123456").unwrap();
        let s2 = server2.msg();
        let b2 = bad.msg();
        assert!(bad.init_cipher(&s2).unwrap());
        assert!(server2.init_cipher(&b2).unwrap());
        let sealed_bad = server2.encrypt(b"secret").unwrap();
        assert!(bad.decrypt(&sealed_bad).is_err());
    }
}
