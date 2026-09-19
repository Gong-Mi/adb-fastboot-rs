# Implementation Gap Inventory

Baseline: `0e5e263`

This file separates design/implementation work from device acceptance. Passing unit, wire, or fake-peer tests is construction evidence only; it is not real-device acceptance.

## Current count

There are 28 identified design items that are not fully landed in code:

- ADB: 8
- Fastboot CLI: 12
- Fastboot protocol/image: 5
- AIDL: 4

The count is an implementation-gap count, not an acceptance score.

## ADB — 8 gaps

1. Complete `A_STLS` upgrade state machine.
2. TLS transport integration and plaintext fallback state handling.
3. Curve25519/BoringSSL-compatible SPAKE2 primitive.
4. Pairing TLS/client/certificate persistence lifecycle.
5. mDNS discovery (`_adb-tls-pairing`, `_adb-tls-connect`).
6. ADB server USB watcher and hotplug lifecycle.
7. Complete USB claim/reset/permission lifecycle.
8. `exec-out`, PTY, and transport-feature parity.

Landed since baseline `0e5e263` (no longer gaps):

- RSA AUTH client loop: persistent user key (`$HOME/.android/adbkey`,
  generated on first use), `ADB_VENDOR_KEYS` rotation, A_AUTH TOKEN →
  SIGNATURE → RSAPUBLICKEY fallback in the connect handshake (`ed9f488`,
  fake-adbd wire tests; real-device AUTH acceptance still pending).
- Install/uninstall host workflows (`install`/`uninstall` CLI, APK push +
  `pm install` shell path).
- SYNC single-file transfer wired to the CLI: `SyncStream` V1
  push (SEND→DATA*→DONE, terminal OKAY/FAIL only after DONE per
  `daemon/file_sync_service.cpp`), pull (RECV→DATA*→DONE with FAIL
  partial-file cleanup), symlink push, polite QUIT+CLSE; `push`/`pull`
  no longer fake-succeed, `install`'s post-SEND OKAY deadlock fixed;
  directory push/pull now fails explicitly (recursion remains missing).
  Daemon-faithful fake-adbd tests cover accept and FAIL paths.
- Smart-socket command loop in the ADB server (`sockets.cpp`
  `smart_socket_enqueue` semantics): the hex-length command layer stays
  active for the whole connection; `host:transport:<serial>` /
  `host:transport-any` bind a transport, and a following device service
  (`root:`, `tcpip:`, `shell:...`, ...) is converted to A_OPEN on the
  device transport with raw byte ⇄ WRTE/OKAY streaming — an official
  AOSP client (adb, scrcpy, IDE) no longer has its hex prefix forwarded
  as raw bytes to adbd. Device service without a selected transport
  fails with AOSP's `device offline (no transport)`. `host:version` now
  reports ADB_SERVER_VERSION 41 (`0029`), not the protocol version.
  Command-length cap follows MAX_PAYLOAD (1 MiB), not 4 KiB. TCP path
  only; the USB bridge keeps the legacy raw-frame relay (clone-free
  constraint documented in `bridge_device_service`).
- Feature negotiation centralization (`adb-protocol/src/features.rs`):
  `parse_banner_features` is a faithful port of AOSP `parse_banner`
  (adb.cpp:350-383) and `can_use_feature` the two-sided intersection
  (transport.cpp:1265-1268). The host CNXN payload and the
  `host:host-features` reply now come from a single
  `host_supported_features()` list containing only capabilities this
  binary implements end-to-end — the server no longer falsely reports
  `abb`/`abb_exec`/`push_sync`/`fixed_push_mkdir` it cannot execute, and
  no call site hard-codes a feature string anymore. Client shell paths
  (`shell`, `logcat`, `bugreport`, `install`'s `pm install`,
  `shell_over_adbd`) gate on the device banner via
  `shell_service_string`: a device that does not advertise `shell_v2`
  gets an explicit actionable error instead of a silently-CLSEd
  `shell,v2,raw:` open (V1 shell fallback remains gap 8's parity item).

## Fastboot CLI — 12 gaps

1. `devices -l` and network-device listing.
2. Slot management and global slot options.
3. Automatic image resolution for `flash PARTITION`.
4. Logical-partition resize and slot orchestration.
5. AVB footer/vbmeta handling.
6. `vendor_boot` ramdisk repacking.
7. Filesystem image generation for `format`.
8. `flashall` command.
9. Complete `update` task orchestration: `fastboot-info.txt`, slots, snapshots, secondary slot.
10. `wipe-super`.
11. Persistent `connect`/`disconnect` device storage.
12. Global options such as skip-reboot, skip-secondary, force, slot, disable-verity, and disable-verification.

Already landed and therefore not counted as gaps here:

- `get_staged OUT_FILE`
- Fastboot INFO/TEXT/DATA upload handling
- reboot aliases
- GSI command argument wiring
- `snapshot-update [cancel|merge]`
- `signature FILE`
- Fastboot fetch offset/size/slot ranges and max-fetch-size chunking
- `continue`
- flashing action validation

## Fastboot protocol/image — 5 gaps

1. Deeper upload/get_staged malformed-stream and error-path coverage.
2. Complete vendor_boot v3/v4 builder/parser and ramdisk replacement.
3. AVB and sparse resparse integration.
4. Exact Fastboot USB lifecycle.
5. Fastboot UDP device-mode integration beyond protocol transport tests.

## AIDL — 4 gaps

1. Full type and constant-expression validation.
2. Binder parceling and functional stub/proxy generation.
3. Annotation, stability, versioning, and backend semantics.
4. API metadata and versioning support.

## Construction priorities

### Can be implemented now from local source evidence

1. Fastboot global option model and slot helper layer.
2. Fetch range request and max-fetch-size chunking.
3. Fastboot `devices -l` output model.
4. ADB `A_STLS` state machine boundary and typed fallback behavior.
5. ADB mDNS record/service parser, without claiming discovery until a backend exists.
6. AIDL validation improvements.
7. Fastboot vendor_boot parser/building primitives, before CLI repack integration.

### Requires a deliberate dependency/architecture decision before construction

Any C/C++ fallback must be vendored into this repository, including all required public/private headers and build metadata. A system-preinstalled library or header is not an acceptable final dependency. The vendored component must record its upstream source, exact version/commit, license, patches, and reproducible build command.

1. SPAKE2: use a verified BoringSSL FFI/backend or port the exact primitive; do not invent a compatible-looking implementation.
2. mDNS discovery: choose and integrate a real Android-compatible DNS-SD backend.
3. USB daemon watcher: choose the Termux/usbfs/rusb ownership and hotplug model.
4. AVB: vendor the AOSP C implementation with headers and build metadata, or implement a compatible Rust component.
5. Filesystem generation: vendor the required C/C++ tools/library with headers, or invoke a repository-owned tool; do not rely on an untracked system binary.
6. Full `flashall`/`update`: build the AOSP-like task and slot orchestration layer first.

## Acceptance is intentionally separate

No item above is considered real-device accepted merely because code, unit tests, wire tests, or fake peers pass. Acceptance will be tracked separately after construction is complete.