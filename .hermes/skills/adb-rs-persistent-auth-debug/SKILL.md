---
name: adb-rs-persistent-auth-debug
description: "Diagnose and fix ADB persistent authorization failures, USB EPROTO, and shell close hangs in adb-fastboot-rs against AOSP reference."
triggers:
  - "adb-rs -d shell Protocol error os error 71"
  - "ADB authorization popup keeps appearing"
  - "shell hangs after output received"
  - "ADB RSA key rejected after signature"
  - "USB bulk transfer EPROTO on Termux/Android"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [android, linux]
metadata:
  hermes:
    tags: [adb, usb, auth, debugging, android, termux]
---

# ADB Persistent Auth & Transport Debug (adb-fastboot-rs)

## Overview

Three independent bugs in adb-fastboot-rs that combined to produce the symptoms:
- "Protocol error (os error 71)" on direct USB shell
- ADB authorization popup reappearing despite key being saved
- Shell commands hanging after output was received

All three are now fixed. This skill captures the diagnostic methodology.

## Root Cause 1: AUTH Token Prehash Mismatch

### Symptom
ADB authorization popup reappears on every connection even though the host key
is saved in `/data/misc/adb/adb_keys` and `strace` confirms adbd reads it.

### Wire Evidence
```
AUTH TOKEN → SIGNATURE → AUTH TOKEN   (signature rejected, adbd sends new token)
```
vs correct:
```
AUTH TOKEN → SIGNATURE → CNXN         (signature accepted)
```

### Root Cause
AOSP `client/auth.cpp` uses:
```cpp
RSA_sign(NID_sha1, token, 20, signature, key)
RSA_verify(NID_sha1, token, 20, signature, key)
```
This means the 20-byte token IS the SHA-1 digest; `NID_sha1` tells OpenSSL
what DigestInfo prefix to wrap it with for PKCS#1 v1.5.

Old adb-rs code used:
```rust
SigningKey::<Sha1>::new(private_key).sign(token)
```
This computes `SHA1(token)` then signs that hash. The double-hash produces
a different signature → adbd rejects → re-enters AUTH → popup.

### Fix
Use `rsa::signature::hazmat::PrehashSigner` / `PrehashVerifier`:
```rust
signing_key.sign_prehash(token)  // token IS the prehash, don't hash again
```

### Verification Method
1. Real-device wire test: connect TCP 127.0.0.1:5555, send CNXN,
   read AUTH TOKEN, send signature, observe response
2. Before fix: got second AUTH TOKEN (rejected)
3. After fix: got CNXN (accepted)
4. Unit test: `test_rsa_key_generation_and_sign_verify` (self-consistent)
5. End-to-end: `adb-rs -s 127.0.0.1:5555 shell echo OK` x10 all pass

### Key Insight
"adb_keys has the key" and "adbd reads adb_keys" are both true but insufficient.
The third condition — "signature bytes match what adbd expects" — was the
failure. The SHA-256 of the public key token matched, proving it's the same key.

---

## Root Cause 2: USB Bulk Read Buffer Not Packet-Aligned

### Symptom
```
Error: Io(Custom { kind: Other, error: Io("Protocol error (os error 71)") })
```
on `adb-rs -d shell ...`. EPROTO = errno 71.

### Wire Evidence
- Same command under `strace` succeeds (timing change masks the bug)
- Successful strace trace shows `USBDEVFS_BULK IN` calls work normally
- `USBDEVFS_DISCONNECT_CLAIM` succeeds, device is accessible

### Root Cause
AOSP `client/transport_usb.cpp` reads into a buffer that is a multiple of the
endpoint's `wMaxPacketSize`:
```cpp
// UsbReadMessage:
usb_read(h, buffer, usb_packet_size);  // aligned to packet boundary

// UsbReadPayload:
len = round_up(payload_length, usb_packet_size);
usb_read(h, payload_buffer, len);
```

Old adb-rs code passed the raw ADB frame buffer (24-byte header, variable payload)
directly to `USBDEVFS_BULK IN`. The Linux usbfs driver can return `EPROTO` when
the user buffer is shorter than a full USB packet.

### Fix
In `UsbTransportAdapter::read()`:
1. Round up the caller's buffer to the endpoint packet size
2. Allocate an aligned scratch buffer for the actual `USBDEVFS_BULK` ioctl
3. Copy only the caller-requested bytes from the scratch buffer
4. Discard USB packet padding (do NOT queue it as next-frame data)

### Verification Method
1. USB-feature unit test: `adapter_reads_into_packet_aligned_usb_buffer`
   - Verifies 2-byte read request results in 64-byte ioctl
2. Real device: `su -c adb-rs -d shell echo OK` — no more EPROTO

### Key Insight
strace masking the bug (success under tracing, failure without) = timing/race
indicator, not "strace changes kernel behavior." The extra syscall overhead
between `DISCONNECT_CLAIM` and first `BULK` gave the endpoint time to settle.

---

## Root Cause 3: Shell Close Hang (Stale remote_id)

### Symptom
Shell command produces correct output but process doesn't exit, eventually
times out after 10-15 seconds.

### Wire Evidence
TCP direct shell sometimes works, sometimes hangs. When it hangs, stdout is
complete but `A_CLSE` never arrives from adbd.

### Root Cause
`stream_shell_v2()` cached the `remote_id` from the initial `A_OKAY` response
in `open_service()`, then used that cached value for ALL subsequent `A_WRTE`
and `A_CLSE` ACKs:

```rust
// BUG: uses cached remote_id, not hdr.arg0
A_WRTE => {
    let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
}
A_CLSE => {
    let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
}
```

Each ADB frame carries its own `arg0` (remote_id). When adbd sends a frame
with a different remote_id than the cached one, the ACK with the stale value
is rejected. adbd then stops sending frames, including the final `A_CLSE`.

The correct pattern (already used in `protocol.rs::recv_wrte_all()`):
```rust
// CORRECT: uses the frame's own arg0
A_WRTE => {
    let ack = AdbMessageHeader::new(A_OKAY, local_id, hdr.arg0, &[]);
}
A_CLSE => {
    let ack = AdbMessageHeader::new(A_CLSE, local_id, hdr.arg0, &[]);
}
```

### Fix
Change both `A_WRTE` and `A_CLSE` handlers to use `hdr.arg0` instead of
the cached `remote_id`.

### Verification Method
`adb-rs -s 127.0.0.1:5555 shell 'echo OK'` x10, all exit immediately.

---

## Diagnostic Methodology Summary

### For Protocol Errors (EPROTO, Signature Rejection)
1. **AOSP source comparison** — always compare against the authoritative
   AOSP reference (`vendor/adb/client/`, `vendor/adb/daemon/`)
2. **Real-device wire test** — standalone Rust program that sends raw ADB
   frames to the real adbd, observing responses byte-for-byte
3. **strace of adbd** — verify what files adbd reads, what ioctls it uses
4. **Key fingerprint comparison** — SHA-256 of public key token on host vs
   lines in `/data/misc/adb/adb_keys` on device

### For USB Transport Bugs
1. `strace -e trace=ioctl` on the failing process
2. Compare against AOSP `usb_linux.cpp` / `transport_usb.cpp`
3. Check buffer alignment against endpoint `wMaxPacketSize`
4. strace-under vs strace-free behavior difference = timing evidence

### For Shell/Service Protocol Bugs
1. Compare ACK pattern against `recv_wrte_all()` in same codebase
2. Check `hdr.arg0` usage — should be per-frame, not cached
3. Test with single short command x10+ to catch intermittent failure

---

## Files Modified
- `crates/adb-protocol/src/crypto/key.rs` — prehash signer/verifier
- `crates/adb-protocol/src/crypto/rsa_2048_key.rs` — RSAKEY NUL terminator
- `crates/adb-protocol/src/usb.rs` — packet-aligned USB bulk reads
- `crates/adb-fastboot-cli/src/client/shell.rs` — per-frame remote_id for ACK/CLSE
- `crates/adb-protocol/src/auth.rs` — test token length fix
