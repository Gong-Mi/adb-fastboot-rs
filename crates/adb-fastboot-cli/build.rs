//! CLI build identity only; adb-protocol owns the native compilation pipeline.
use std::{env, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for name in ["ADB_RS_BUILD_REVISION", "GIT_REVISION"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let manifest = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest).parent().unwrap().parent().unwrap();
    // Do not accidentally use an enclosing repository for an unpacked archive.
    println!("cargo:rerun-if-changed={}", root.join(".git").display());
    if !root.join(".git").exists() {
        return;
    }
    // Git resolves both ordinary .git directories and linked-worktree .git files.
    // HEAD covers detach/switch; refs and packed-refs cover commits and ref packing.
    for name in ["HEAD", "refs", "packed-refs"] {
        if let Some(path) = git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        ) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(sha) = git(root, &["rev-parse", "--verify", "HEAD"]) {
        if (sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            println!("cargo:rustc-env=ADB_RS_GIT_REVISION={}", &sha[..12]);
        }
    }
}
