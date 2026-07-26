# AOSP Pairing Evidence Ledger

Status: source-derived defects; not a completion claim.

Reference root: `/data/data/com.termux/files/home/android-tools-36.0.1/vendor/adb`
Rust root: `crates/adb-protocol` and `crates/adb-fastboot-cli`

## P0-1: PairingPacket enum values do not match AOSP

| AOSP source | Required behavior | Rust source | Actual behavior |
|---|---|---|---|
| `proto/pairing.proto:25-30` | `SPAKE2_MSG = 0`, `PEER_INFO = 1` | `crates/adb-protocol/src/pairing.rs:32-35` | `Spake2Msg = 1`, `PeerInfo = 2` |

The Rust decoder additionally maps both `0` and `1` to `Spake2Msg` (`pairing.rs:42`). This destroys the AOSP distinction between a valid `PEER_INFO` packet (1) and a SPAKE2 message.

## P0-2: Pairing wire framing is not AOSP framing

| AOSP source | Required behavior | Rust source | Actual behavior |
|---|---|---|---|
| `pairing_connection/pairing_connection.cpp:46-50` | packed 6-byte header: `version:u8`, `type:u8`, `payload:u32` | `pairing.rs:114-120` | writes `u32 protobuf_len` then a protobuf buffer |
| `pairing_connection/pairing_connection.cpp:204-215` | `WriteHeader` writes header and raw payload to TLS | `pairing.rs:99-111` | synthesizes protobuf fields `0x08`, type, `0x12`, length, payload |
| `pairing_connection/pairing_connection.cpp:218-249` | reads exactly the packed header and checks version/type/payload | `pairing.rs:123-175` | reads outer length then parses a custom protobuf subset |

`pairing.rs:9-10`, `:16`, and `:76` claim the exact AOSP six-byte format, but `write_to` and `read_from` implement a different protocol. An AOSP peer will reject this before cryptographic interoperability is relevant.

## P0-3: TLS exporter is mixed into PAKE at the wrong stage

AOSP sequence:

1. `pairing_connection.cpp:167-201`: TLS handshake.
2. `:190-198`: export 64 bytes of TLS keying material and append it to `pswd_`.
3. `:199`: create PairingAuth using that augmented password.
4. `pairing_auth.cpp:122-131`: BoringSSL `SPAKE2_generate_msg` receives the augmented password.
5. `pairing_auth/aes_128_gcm.cpp:37-48`: derive AES-128 key from BoringSSL SPAKE output only using HKDF-SHA256 with null salt.

Rust sequence:

- `adb_wifi.rs:281-304`: obtains TLS exporter but passes it after constructing `Spake2` from only `self.code`.
- `pairing_connection/pairing_connection.rs:112-133`: `Spake2::new(..., &self.code)` then `PairingCipher::from_spake2_and_exported_key`.
- `pairing_auth/aes_128_gcm.rs:26-40`: uses exporter as HKDF salt and appends it to IKM.

Therefore the SPAKE transcript and AES key derivation differ from AOSP twice. Repairing M/N point decoding cannot make this protocol interoperate.

## P0-4: One pairing attempt uses inconsistent host identity keys

AOSP uses the same key material for TLS client authentication and the peer information it retains:

- `client/pairing/pairing_client.cpp:139-145`: passes the client certificate and private key into `pairing_connection_client_new` before starting the pairing connection.
- `pairing_connection.cpp:167-173`: TLS is initialized from this certificate/private key.

Rust `pair_device` currently has three conflicting identity paths:

1. `adb_wifi.rs:281-287` generates RSA key **A** and TLS certificate/key derived from A.
2. `adb_wifi.rs:299-304` calls `PairingClient::new(code)`, which has no A.
3. `pairing_connection/pairing_connection.rs:135-152` sees no key and generates RSA key **B**, then sends B as `PeerInfo`.
4. `pairing_connection/pairing_connection.rs:172-176` saves B to `~/.android/adbkey` and ignores its write error.
5. `adb_wifi.rs:306-317` saves A to the same `~/.android/adbkey` path, overwriting B when both writes succeed.

The paired device retains B's public key while the host ends with A. A later ADB AUTH signature from A cannot validate against B. This provides a concrete causal chain for a pair-then-connect failure even if the packet and SPAKE paths were fixed.

## P0-5: Current SPAKE implementation panics before error handling

`cargo test --workspace --all-features` on 2026-07-25 fails:

```text
test_aosp_pairing_client_rejects_empty_stream ... FAILED
crates/adb-protocol/src/pairing_auth/pairing_auth.rs:345
called Option::unwrap() on a None value
```

Call chain: `PairingClient::execute_pairing_with_exported_keys` (`pairing_connection.rs:112-121`) calls `Spake2::generate_msg`, which reaches `ExtendedPoint::point_m()` (`pairing_auth.rs:345`). The encoded M point fails the local decoder. This is a local primitive failure; it is not evidence of an AOSP peer error.

## Repair order

1. Stop routing production `adb pair` through the current Rust pairing implementation.
2. Replace custom packet encoding with the exact AOSP 6-byte header and raw payload. Add byte fixtures sourced from AOSP behavior.
3. Pass one persistent RSA key through TLS certificate generation, `PeerInfo`, and keystore persistence. Remove all internally generated pairing keys.
4. Move TLS exporter handling before SPAKE exactly as AOSP does.
5. Do not continue patching handwritten `Fe`, `ExtendedPoint`, or SPAKE2. Bind a vendored, source-pinned AOSP/BoringSSL pairing-auth implementation first, including headers, licenses, and build provenance.
6. Only then perform real-device pairing followed by a second-process `adb connect` using the persisted same key.
