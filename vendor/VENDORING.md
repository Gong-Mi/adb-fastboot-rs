# Vendored dependencies

All third-party source in `vendor/` is unmodified upstream code vendored for
reproducible builds. No system-preinstalled C/C++ library or header is a
build dependency.

## vendor/boringssl

- Upstream: https://android.googlesource.com/platform/external/boringssl
- Vendored from: local mirror `android-tools-36.0.1/vendor/boringssl`
  (android-tools 36.0.1 release, matching AOSP platform-tools 36.0.1)
- License: Apache License 2.0 (see `vendor/boringssl/LICENSE`; BoringSSL
  also contains OpenSSL-derived code under the OpenSSL/SSLeay licenses)
- Patches: none (unmodified copy)
- Build: CMake, target `crypto` only:
  `cmake -S vendor/boringssl -B <build> -DCMAKE_BUILD_TYPE=Release`
  `cmake --build <build> --target crypto -j`
  Requires: perl, go, cmake >= 3.x, C++17 toolchain.

## vendor/adb/pairing_auth

- Upstream: https://android.googlesource.com/platform/packages/modules/adb
  (mirror: https://android.googlesource.com/platform/system/core `adb/pairing_auth/`)
- Vendored from: local mirror `android-tools-36.0.1/vendor/adb/pairing_auth`
- License: Apache License 2.0
- Patches: none
- Files: pairing_auth.{h,cpp}, aes_128_gcm.{h,cpp}, aes_128_gcm_siv.{h,cpp}
- Build: compiled as a small static archive `adb_pairing_auth` against the
  vendored BoringSSL headers; Rust binds the C API in `pairing_auth.h`.
- Target split (`crates/adb-protocol/build.rs`): Android/Termux keeps the
  `aarch64-linux-android30` clang target, `$PREFIX` headers/libs, and
  `c++_shared`; host Linux/macOS builds the same C sources natively and links
  the host C++ runtime. Do not feed Android sysroot paths to a glibc host
  compiler. CI verifies default, `--all-features`, and `--no-default-features`
  on Ubuntu; local Termux verifies the Android target.

## crates/adb-mdns

- Upstream: https://android.googlesource.com/platform/packages/modules/adb
  `client/adbmdns/` (Rust zeroconf stack; replaced openscreen-discovery as
  the ADB mDNS backend in 26Q2)
- Vendored from: local mirror ~/adb @ 9084198a (26Q2-release)
- License: Apache License 2.0 (header on every source file)
- Files: index_min_pq.rs, netwatch.rs, netwatch/netwatch_linux{,/util}.rs,
  rr.rs, store.rs, zero_config.rs, zero_config_driver.rs,
  zero_config_driver_channel.rs, adbmdns_bridge.rs (→ src/lib.rs)
- Patches (build-porting only, no logic changes):
  1. cfg(target_os = "linux") → any(linux, android): Termux/aarch64 target
     is target_os = "android"; the netwatch linux implementation applies.
  2. libc::RTMGRP_LINK referenced as local const 0x00001: libc's android
     bindings lack the constant (rtnetlink ABI value is stable).
  3. nix feature "net" added for if_indextoname/InterfaceFlags.
- Dependencies (crates.io, no C): socket2, log, simple-dns, zerocopy,
  libc, anyhow, nix, if-addrs, mio — matches AOSP Cargo.toml.
- Verification: cargo check 0 errors; 40 unit tests passed; `adbmdns_start`
  FFI symbol present in rlib (llvm-nm). A safe Rust adapter
  `zeroconf::start_discovery(Fn(AdbMdnsUpdate, DiscoveredService))` now copies
  callback pointers into owned strings/IP/TXT records and enters the same AOSP
  zero-config worker without requiring C-ABI callbacks from the server.
  `adb-fastboot-cli/server/mdns_backend.rs` applies Create/Update/Delete to
  `TransportRegistry`; seven state tests cover duplicate creates, metadata and
  address refresh, delete, serial changes, multiple service types, USB serial
  collision, and pairing-service exclusion. Runner starts it unless
  `ADB_MDNS=0`. This is verified at the state-machine and host-service wire
  layers; no live multicast/device test is claimed.
