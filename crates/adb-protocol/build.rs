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
    let target = env::var("TARGET").unwrap_or_default();
    let on_android = target.contains("android");

    println!("cargo:rerun-if-changed={}", pairing_auth_src.display());
    println!("cargo:rerun-if-changed={}", shim_include.display());
    // BoringSSL is huge; only rerun when its build stamp changes.
    println!("cargo:rerun-if-changed={}", boringssl_src.join("CMakeLists.txt").display());

    // ---- 1. BoringSSL crypto via its own CMake build -------------------------
    let boringssl_build = out_dir.join("boringssl-build");
    let libcrypto = boringssl_build.join("libcrypto.a");
    if !libcrypto.exists() {
        let mut cmake = Command::new("cmake");
        cmake
            .arg("-S")
            .arg(&boringssl_src)
            .arg("-B")
            .arg(&boringssl_build)
            .arg("-DCMAKE_BUILD_TYPE=Release");

        if on_android {
            // Termux self-built clang lacks default include/library search paths.
            let library_path = env::var("LIBRARY_PATH").unwrap_or_default();
            let termux_prefix =
                env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".into());
            let lib_path = if library_path.is_empty() {
                format!("{termux_prefix}/lib:/system/lib64")
            } else {
                library_path
            };
            let arch_include = format!("-isystem {termux_prefix}/include/aarch64-linux-android");
            let sys_include = format!("-isystem {termux_prefix}/include");
            let cxx_include = format!("-isystem {termux_prefix}/include/c++/v1");
            cmake
                .arg(format!("-DCMAKE_C_FLAGS={arch_include} {sys_include}"))
                .arg(format!(
                    "-DCMAKE_CXX_FLAGS={cxx_include} {arch_include} {sys_include}"
                ))
                .env("LIBRARY_PATH", &lib_path);
        }

        run(&mut cmake, "cmake configure boringssl");
        let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "8".into());
        let mut build = Command::new("cmake");
        build
            .arg("--build")
            .arg(&boringssl_build)
            .arg("--target")
            .arg("crypto")
            .arg("-j")
            .arg(&jobs);
        if on_android {
            build.env(
                "LIBRARY_PATH",
                format!(
                    "{}/lib:/system/lib64",
                    env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".into())
                ),
            );
        }
        run(&mut build, "cmake build boringssl crypto");
    }

    // ---- 2. AOSP pairing_auth C API static archive ---------------------------
    let mut cc_build = cc::Build::new();
    cc_build
        .cpp(true)
        .std("c++17")
        .file(pairing_auth_src.join("pairing_auth.cpp"))
        .file(pairing_auth_src.join("aes_128_gcm.cpp"))
        .include(pairing_auth_src.join("include"))
        .include(boringssl_src.join("include"))
        .include(&shim_include)
        .warnings(false);

    let mut extra_link_search: Vec<PathBuf> = Vec::new();
    let mut extra_link_libs: Vec<String> = Vec::new();

    if on_android {
        let termux_prefix =
            env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".into());
        // cc-rs picks the NDK-style wrapper `aarch64-linux-android-clang++` on
        // Android targets; that wrapper pins API 24 and lacks pthread_cond_clockwait.
        // Prefer the toolchain clang++ (API-30 triple) when available.
        let cxx_compiler = env::var("CXX").unwrap_or_else(|_| {
            let clangxx = format!("{termux_prefix}/bin/clang++");
            if Path::new(&clangxx).exists() { clangxx } else { "clang++".into() }
        });
        cc_build
            .compiler(cxx_compiler)
            // cc-rs requires a target with arch-vendor-os-env components;
            // append the API level as the env component so clang selects the
            // API-30 sysroot headers (pthread_cond_clockwait needs >= 30).
            .target("aarch64-linux-android30")
            .archiver(format!("{termux_prefix}/bin/llvm-ar"))
            .cpp_set_stdlib(None) // we link libc++ explicitly below
            .flag("-D__ANDROID_API__=30")
            .flag(&format!("-isystem{termux_prefix}/include/c++/v1"))
            .flag(&format!("-isystem{termux_prefix}/include/aarch64-linux-android"))
            .flag(&format!("-isystem{termux_prefix}/include"));
        extra_link_search.push(PathBuf::from(format!("{termux_prefix}/lib")));
        extra_link_libs.push("c++_shared".into());
    } else {
        // Host (Linux/macOS CI): default toolchain, no Android sysroot flags.
        // Pairing_auth.cpp needs pthread; the C++ runtime is linked by rustc
        // via `-lstdc++`/`-lc++` through cpp_set_stdlib default detection.
        if cfg!(target_os = "linux") {
            extra_link_libs.push("stdc++".into());
        }
    }
    cc_build.compile("adb_pairing_auth");

    // ---- 3. Link -------------------------------------------------------------
    println!(
        "cargo:rustc-link-search=native={}",
        boringssl_build.display()
    );
    for p in &extra_link_search {
        println!("cargo:rustc-link-search=native={}", p.display());
    }
    println!("cargo:rustc-link-lib=static=crypto");
    for l in &extra_link_libs {
        println!("cargo:rustc-link-lib=dylib={l}");
    }
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
