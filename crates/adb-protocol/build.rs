//! Build script: compile the vendored BoringSSL `crypto` target and the
//! vendored AOSP `adb/pairing_auth` C API, then link them into adb-protocol.
//!
//! Layout (see vendor/VENDORING.md):
//!   vendor/boringssl                 - unmodified upstream BoringSSL
//!   vendor/adb/pairing_auth          - unmodified AOSP pairing_auth sources
//!   native/android-base-shim/include - repository-owned android-base headers
//!
//! BoringSSL is built via its own CMake build system (official path). The
//! pairing_auth C++ sources are compiled with cc against the vendored
//! BoringSSL headers and the android-base shim.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Only build the vendored C stack when the feature is enabled; otherwise
    // this build script is a no-op so the pure-Rust path stays dependency-free.
    if env::var_os("CARGO_FEATURE_PAIRING_VENDORED").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap().to_path_buf();
    let boringssl_src = workspace_root.join("vendor/boringssl");
    let pairing_auth_src = workspace_root.join("vendor/adb/pairing_auth");
    let shim_include = manifest_dir.join("native/android-base-shim/include");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", pairing_auth_src.display());
    println!("cargo:rerun-if-changed={}", shim_include.display());
    // BoringSSL is huge; only rerun when its build stamp changes.
    println!("cargo:rerun-if-changed={}", boringssl_src.join("CMakeLists.txt").display());

    // ---- 1. BoringSSL crypto via its own CMake build -------------------------
    let boringssl_build = out_dir.join("boringssl-build");
    let libcrypto = boringssl_build.join("libcrypto.a");
    if !libcrypto.exists() {
        // Termux self-built clang lacks default include/library search paths.
        let library_path = env::var("LIBRARY_PATH").unwrap_or_default();
        let termux_prefix = env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".into());
        let lib_path = if library_path.is_empty() {
            format!("{termux_prefix}/lib:/system/lib64")
        } else {
            library_path
        };
        let arch_include = format!("-isystem {termux_prefix}/include/aarch64-linux-android");
        let sys_include = format!("-isystem {termux_prefix}/include");
        let cxx_include = format!("-isystem {termux_prefix}/include/c++/v1");
        let c_flags = format!("{arch_include} {sys_include}");
        let cxx_flags = format!("{cxx_include} {arch_include} {sys_include}");

        run(
            Command::new("cmake")
                .arg("-S")
                .arg(&boringssl_src)
                .arg("-B")
                .arg(&boringssl_build)
                .arg("-DCMAKE_BUILD_TYPE=Release")
                .arg(format!("-DCMAKE_C_FLAGS={c_flags}"))
                .arg(format!("-DCMAKE_CXX_FLAGS={cxx_flags}"))
                .env("LIBRARY_PATH", &lib_path),
            "cmake configure boringssl",
        );
        let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "8".into());
        run(
            Command::new("cmake")
                .arg("--build")
                .arg(&boringssl_build)
                .arg("--target")
                .arg("crypto")
                .arg("-j")
                .arg(jobs)
                .env("LIBRARY_PATH", &lib_path),
            "cmake build boringssl crypto",
        );
    }

    // ---- 2. AOSP pairing_auth C API static archive ---------------------------
    let termux_prefix = env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".into());
    // cc-rs picks the NDK-style wrapper `aarch64-linux-android-clang++` on
    // Android targets; that wrapper pins API 24 and lacks pthread_cond_clockwait.
    // Prefer the toolchain clang++ (API-30 triple) when available.
    let cxx_compiler = env::var("CXX").unwrap_or_else(|_| {
        let clangxx = format!("{termux_prefix}/bin/clang++");
        if Path::new(&clangxx).exists() { clangxx } else { "clang++".into() }
    });
    cc::Build::new()
        .cpp(true)
        .compiler(cxx_compiler)
        .target("aarch64-linux-android30")
        .archiver(format!("{termux_prefix}/bin/llvm-ar"))
        .cpp_set_stdlib(None) // we link libc++ explicitly below (Android/Termux has no libstdc++)
        .std("c++17")
        .file(pairing_auth_src.join("pairing_auth.cpp"))
        .file(pairing_auth_src.join("aes_128_gcm.cpp"))
        .include(pairing_auth_src.join("include"))
        .include(boringssl_src.join("include"))
        .include(&shim_include)
        .flag("-D__ANDROID_API__=30")
        .flag(&format!("-isystem{termux_prefix}/include/c++/v1"))
        .flag(&format!("-isystem{termux_prefix}/include/aarch64-linux-android"))
        .flag(&format!("-isystem{termux_prefix}/include"))
        .warnings(false)
        .compile("adb_pairing_auth");

    // ---- 3. Link -------------------------------------------------------------
    println!(
        "cargo:rustc-link-search=native={}",
        boringssl_build.display()
    );
    println!("cargo:rustc-link-search=native={termux_prefix}/lib");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=dylib=c++_shared");
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {what}: {e}"));
    assert!(status.success(), "{what} failed with {status}");
}

#[allow(dead_code)]
fn exists(p: &Path) -> bool {
    p.exists()
}
