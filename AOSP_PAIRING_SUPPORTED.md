# AOSP wireless pairing support boundary

## Evidence used

This implementation was checked against the supplemental AOSP 36.0.1 sources:

- `vendor/adb/pairing_connection/pairing_connection.cpp`
- `vendor/adb/pairing_auth/pairing_auth.cpp`
- `vendor/adb/pairing_auth/aes_128_gcm.cpp`
- `vendor/adb/proto/pairing.proto`
- `vendor/adb/tls/tls_connection.cpp`

Those sources establish:

- TLS 1.3 is established before pairing messages.
- TLS exporter label is `adb-label`, with no context, and output length 64.
- Pairing headers are `[version:u8, type:u8, payload_length:u32 BE]`.
- Version is 1; types are `SPAKE2_MSG = 0` and `PEER_INFO = 1`.
- AOSP uses BoringSSL Curve25519 `SPAKE2_CTX` with identities `adb pair client` and `adb pair server`.
- AES-128-GCM derives its key with HKDF-SHA256 info `adb pairing_auth aes-128-gcm key`.
- GCM uses a twelve-byte zero nonce with an incrementing native-endian 64-bit sequence in the first eight bytes; the nonce is not sent.

## Implemented

- `PairingPacket` implements the AOSP six-byte header and both packet types.
- Header version, type, payload bounds, fragmentation-safe reads, and big-endian length are tested.
- `PairingCipher` implements the AOSP HKDF info string, AES-128-GCM, sequence nonce, and no transmitted nonce.
- The rustls 0.23 TLS exporter API is available and `tls.rs` exposes the AOSP 64-byte exporter operation.
- Legacy `SPAP` framing, salt HKDF, explicit nonce, token, and Init/Exchange/Result messages were removed.
- CLI `adb pair HOST[:PORT]` accepts the address form but refuses to connect or claim success.

## Unsupported boundary

The current Rust dependency set does not provide the **BoringSSL-compatible Curve25519 SPAKE2** primitive used by AOSP. The cached Rust `spake2` implementation is a different Ed25519 parameterization and must not be substituted: doing so would compile but fail against Android devices. Certificate generation/persistence and the complete CLI TLS client setup are also not yet wired to the AOSP pairing lifecycle.

Therefore `PairingClient::execute_pairing` returns the typed `UnsupportedSpake2` error, and the CLI refuses plaintext and the former custom protocol. No real-device acceptance is claimed. A future implementation must add or bind the exact AOSP/BoringSSL Curve25519 SPAKE2 primitive, use the TLS exporter after a completed handshake, and implement the AOSP certificate/key persistence contract before enabling the command.
