# Implementation Gap Inventory

Baseline: `f556fd9`

This file separates design/implementation work from device acceptance. Passing unit, wire, or fake-peer tests is construction evidence only; it is not real-device acceptance.

## Current count

There are 33 identified design items that are not fully landed in code:

- ADB: 10
- Fastboot CLI: 16
- Fastboot protocol/image: 5
- AIDL: 4

The count is an implementation-gap count, not an acceptance score.

## ADB — 10 gaps

1. Complete `A_STLS` upgrade state machine.
2. TLS transport integration and plaintext fallback state handling.
3. Curve25519/BoringSSL-compatible SPAKE2 primitive.
4. Pairing TLS/client/certificate persistence lifecycle.
5. mDNS discovery (`_adb-tls-pairing`, `_adb-tls-connect`).
6. ADB server USB watcher and hotplug lifecycle.
7. Complete USB claim/reset/permission lifecycle.
8. Actual `sendrecv_v2` compressed transfer path, not only packet structures/flags.
9. `exec-out`, PTY, and transport-feature parity.
10. Install/uninstall host workflows.

## Fastboot CLI — 16 gaps

1. `devices -l` and network-device listing.
2. Slot management and global slot options.
3. Automatic image resolution for `flash PARTITION`.
4. Logical-partition resize and slot orchestration.
5. AVB footer/vbmeta handling.
6. `vendor_boot` ramdisk repacking.
7. Filesystem image generation for `format`.
8. `continue` command.
9. `flashall` command.
10. Complete `update` task orchestration: `fastboot-info.txt`, slots, snapshots, secondary slot.
11. Fetch offset/size/slot orchestration.
12. `wipe-super`.
13. Persistent `connect`/`disconnect` device storage.
14. Global options such as skip-reboot, skip-secondary, force, slot, disable-verity, and disable-verification.

Already landed and therefore not counted as gaps here:

- `get_staged OUT_FILE`
- Fastboot INFO/TEXT/DATA upload handling
- reboot aliases
- GSI command argument wiring
- `snapshot-update [cancel|merge]`
- `signature FILE`
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

1. Fastboot `continue`, snapshot-update, and command formatters.
2. Fastboot global option model and slot helper layer.
3. Fetch range request and max-fetch-size chunking.
4. Fastboot `devices -l` output model.
5. ADB `sendrecv_v2` compressed transfer path.
6. ADB `A_STLS` state machine boundary and typed fallback behavior.
7. ADB mDNS record/service parser, without claiming discovery until a backend exists.
8. AIDL validation improvements.
9. Fastboot vendor_boot parser/building primitives, before CLI repack integration.

### Requires a deliberate dependency/architecture decision before construction

1. SPAKE2: use a verified BoringSSL FFI/backend or port the exact primitive; do not invent a compatible-looking implementation.
2. mDNS discovery: choose and integrate a real Android-compatible DNS-SD backend.
3. USB daemon watcher: choose the Termux/usbfs/rusb ownership and hotplug model.
4. AVB and filesystem generation: decide whether to bind AOSP libraries or implement compatible Rust components.
5. Full `flashall`/`update`: build the AOSP-like task and slot orchestration layer first.

## Acceptance is intentionally separate

No item above is considered real-device accepted merely because code, unit tests, wire tests, or fake peers pass. Acceptance will be tracked separately after construction is complete.