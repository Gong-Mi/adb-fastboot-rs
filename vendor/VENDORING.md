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
