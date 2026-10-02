//! ADB authentication (RSA key loading/saving).
//! Maps to AOSP `vendor/adb/client/auth.cpp`.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use adb_protocol::AdbAuth;

/// Get or create the persistent ADB host identity.
pub fn default_auth() -> &'static AdbAuth {
    static AUTH: OnceLock<AdbAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        load_or_create_auth().unwrap_or_else(|e| {
            eprintln!("[adb-auth] Failed to load/create auth key: {e}, generating ephemeral key");
            AdbAuth::generate("adb-rs@localhost").expect("key generation failed")
        })
    })
}

fn adb_key_dirs() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs = Vec::with_capacity(2);
    if !home.is_empty() {
        dirs.push(PathBuf::from(&home).join(".android"));
    }
    dirs.push(PathBuf::from("/sdcard/.android"));
    dirs
}

fn load_or_create_auth() -> Result<AdbAuth, Box<dyn std::error::Error>> {
    let dirs = adb_key_dirs();

    for dir in &dirs {
        let private_path = dir.join("adbkey");
        let public_path = dir.join("adbkey.pub");

        if private_path.is_file() {
            let pem = std::fs::read_to_string(&private_path)?;
            let private_key = adb_protocol::auth::load_private_key_from_pem(&pem)?;
            let mut label = "adb-rs@localhost".to_string();
            let auth = AdbAuth::new(private_key, &label);

            if public_path.is_file() {
                let public_text = std::fs::read_to_string(&public_path)?;
                if let Ok((public_key, public_label)) =
                    adb_protocol::auth::parse_adb_public_key_string(&public_text)
                {
                    if public_key == *auth.public_key() {
                        label = if public_label.is_empty() { label } else { public_label };
                    }
                }
            }

            let auth = AdbAuth::new(auth.private_key().clone(), &label);
            if !public_path.is_file()
                || std::fs::read(&public_path)? != auth.build_rsakey_payload()?
            {
                write_auth_public_key(&auth, &public_path)?;
            }
            return Ok(auth);
        }
    }

    let auth = AdbAuth::generate("adb-rs@localhost")?;
    let pem = adb_protocol::auth::export_private_key_to_pem(auth.private_key())?;

    for dir in &dirs {
        if std::fs::create_dir_all(dir).is_ok() {
            let private_path = dir.join("adbkey");
            let public_path = dir.join("adbkey.pub");
            if write_private_key(&private_path, pem.as_bytes()).is_ok()
                && write_auth_public_key(&auth, &public_path).is_ok()
            {
                break;
            }
        }
    }

    Ok(auth)
}

fn write_private_key(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_auth_public_key(auth: &AdbAuth, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = auth.build_rsakey_payload()?;
    write_private_key(path, &bytes)
}

/// Append the host public key to /data/misc/adb/adb_keys so that future
/// SIGNATURE-based ADB connections succeed without a re-authorization dialog.
#[cfg(target_os = "android")]
pub fn persist_adb_pubkey(auth: &AdbAuth) -> Result<(), Box<dyn std::error::Error>> {
    let payload = auth.build_rsakey_payload()?;
    let key_line = if payload.ends_with(&[0]) {
        std::str::from_utf8(&payload[..payload.len() - 1])?
    } else {
        std::str::from_utf8(&payload)?
    };
    if key_line.is_empty() {
        return Ok(());
    }

    let key_path = "/data/misc/adb/adb_keys";
    let already_present = std::fs::read_to_string(key_path)
        .map(|content| content.lines().any(|l| l.trim() == key_line))
        .unwrap_or(false);
    if already_present {
        return Ok(());
    }

    use std::io::Write;
    let can_write = std::fs::OpenOptions::new().append(true).open(key_path).is_ok();
    if can_write {
        let mut f = std::fs::OpenOptions::new().append(true).open(key_path)?;
        writeln!(f, "{}", key_line)?;
    } else {
        let status = std::process::Command::new("su")
            .arg("-c")
            .arg(format!("printf '%s\\n' '{}' >> {}", key_line, key_path))
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => return Err(format!("su exited with {s}").into()),
            Err(e) => return Err(format!("failed to run su: {e}").into()),
        }
    }
    Ok(())
}

/// AOSP `adb_auth_keygen()` (client/auth.cpp:61-107): generate an
/// RSA key pair at `file` (0600) and `file.pub`.
pub fn adb_auth_keygen(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file);
    if path.exists() {
        return Err(format!("'{file}' already exists").into());
    }
    let private_path = if file.ends_with(".pub") {
        let priv_path = file.strip_suffix(".pub").unwrap_or(file);
        PathBuf::from(priv_path)
    } else {
        path.to_path_buf()
    };
    adb_protocol::auth::generate_key(&private_path)?;
    println!("[adb-rs] Generated ADB key pair:");
    println!("       Private: {}", private_path.display());
    let mut pub_path = private_path.clone();
    pub_path.set_extension("pub");
    println!("       Public:  {}", pub_path.display());
    Ok(())
}

/// AOSP `adb_auth_pubkey()` (client/auth.cpp:331-338): calculate and
/// return the public key payload from a private key file.
pub fn adb_auth_pubkey(file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(file);
    let pem = std::fs::read_to_string(path)?;
    let private_key = adb_protocol::auth::load_private_key_from_pem(&pem)?;
    let label = adb_protocol::auth::default_key_label();
    let auth = AdbAuth::new(private_key, &label);
    let bytes = auth.build_rsakey_payload()?;
    let pubkey_str = std::str::from_utf8(&bytes)?;
    Ok(pubkey_str.trim_end_matches('\0').to_string())
}

/// AOSP `adb_auth_get_userkey_path()` (client/auth.cpp:205-207).
pub fn adb_auth_get_userkey_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(adb_protocol::auth::adb_auth_get_userkey_path()?)
}

/// AOSP `get_vendor_keys()` (client/auth.cpp:228-243).
pub fn get_vendor_keys() -> Vec<PathBuf> {
    adb_protocol::auth::get_vendor_keys()
}

/// Inotify monitor for ADB key directories (AOSP: `g_monitored_paths`).
#[derive(Debug, Default)]
pub struct AdbAuthInotify {
    pub fd: Option<RawFd>,
    pub monitored_paths: HashMap<i32, PathBuf>,
}

impl AdbAuthInotify {
    /// AOSP `adb_auth_inotify_init()` (client/auth.cpp:392-416):
    /// create an inotify fd with IN_CLOEXEC | IN_NONBLOCK and watch paths for IN_CREATE | IN_MOVED_TO.
    pub fn init<P: AsRef<Path>>(paths: &[P]) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let infd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if infd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut monitored = HashMap::new();
            for p in paths {
                let path = p.as_ref();
                if let Ok(c_path) = std::ffi::CString::new(path.to_str().unwrap_or_default()) {
                    let wd = unsafe {
                        libc::inotify_add_watch(
                            infd,
                            c_path.as_ptr(),
                            libc::IN_CREATE | libc::IN_MOVED_TO,
                        )
                    };
                    if wd >= 0 {
                        monitored.insert(wd, path.to_path_buf());
                    }
                }
            }
            Ok(Self {
                fd: Some(infd),
                monitored_paths: monitored,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = paths;
            Ok(Self::default())
        }
    }

    /// AOSP `adb_auth_inotify_update()` (client/auth.cpp:341-390):
    /// read available inotify events and return any newly detected key file paths.
    pub fn update(&self) -> Vec<PathBuf> {
        let mut new_keys = Vec::new();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fd) = self.fd {
            let mut buf = [0u8; 4096];
            loop {
                let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if rc <= 0 {
                    break;
                }
                let mut offset = 0;
                while offset + std::mem::size_of::<libc::inotify_event>() <= rc as usize {
                    let event_ptr = unsafe {
                        &*(buf.as_ptr().add(offset) as *const libc::inotify_event)
                    };
                    let name_len = event_ptr.len as usize;
                    if let Some(dir) = self.monitored_paths.get(&event_ptr.wd) {
                        if (event_ptr.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0
                            && (event_ptr.mask & libc::IN_ISDIR) == 0
                        {
                            if name_len > 0 {
                                let name_bytes = &buf[offset + std::mem::size_of::<libc::inotify_event>()..offset + std::mem::size_of::<libc::inotify_event>() + name_len];
                                let name_str = std::ffi::CStr::from_bytes_until_nul(name_bytes)
                                    .map(|c| c.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                if !name_str.is_empty() && !name_str.ends_with(".pub") {
                                    new_keys.push(dir.join(name_str));
                                }
                            }
                        }
                    }
                    offset += std::mem::size_of::<libc::inotify_event>() + name_len;
                }
            }
        }
        new_keys
    }
}

impl Drop for AdbAuthInotify {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            unsafe { libc::close(fd); }
        }
    }
}

/// AOSP `adb_auth_init()` (client/auth.cpp:418-440): load user key,
/// load vendor keys, and start directory inotify monitoring.
pub fn adb_auth_init() -> Result<(Vec<AdbAuth>, AdbAuthInotify), Box<dyn std::error::Error>> {
    let keys = adb_protocol::auth::load_all_keys()?;
    let mut watch_dirs = Vec::new();
    if let Ok(dir) = adb_protocol::auth::adb_get_android_dir_path() {
        watch_dirs.push(dir);
    }
    for vendor in get_vendor_keys() {
        if vendor.is_dir() {
            watch_dirs.push(vendor);
        }
    }
    let inotify = AdbAuthInotify::init(&watch_dirs)?;
    Ok((keys, inotify))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adb_auth_keygen_and_pubkey_roundtrip() {
        let dir = std::env::temp_dir().join(format!("adb-auth-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("test_adbkey");
        let key_str = key_path.to_str().unwrap();

        // 1. Generate key pair
        adb_auth_keygen(key_str).unwrap();
        assert!(key_path.is_file());

        let pub_path = dir.join("test_adbkey.pub");
        assert!(pub_path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&key_path).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        // 2. Read public key via adb_auth_pubkey
        let pubkey_from_priv = adb_auth_pubkey(key_str).unwrap();
        let pubkey_from_file = std::fs::read_to_string(&pub_path).unwrap();
        assert_eq!(pubkey_from_priv, pubkey_from_file.trim_end_matches('\0'));

        // 3. Attempting to keygen over existing file fails
        let err = adb_auth_keygen(key_str).unwrap_err().to_string();
        assert!(err.contains("already exists"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_adb_auth_userkey_path() {
        let path = adb_auth_get_userkey_path();
        assert!(path.is_ok());
        let p = path.unwrap();
        assert!(p.ends_with(".android/adbkey"));
    }

    #[test]
    fn test_adb_auth_inotify_detects_new_key_file() {
        let dir = std::env::temp_dir().join(format!("adb-inotify-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let inotify = AdbAuthInotify::init(&[&dir]).unwrap();
        assert!(inotify.fd.is_some());

        // Create a new key file
        let key_file = dir.join("custom_key");
        std::fs::write(&key_file, b"test-key-content").unwrap();

        // Create a .pub file (should be ignored by update)
        let pub_file = dir.join("custom_key.pub");
        std::fs::write(&pub_file, b"test-pub-content").unwrap();

        // Wait briefly for inotify event to be ready
        std::thread::sleep(std::time::Duration::from_millis(50));

        let detected = inotify.update();
        assert!(detected.contains(&key_file));
        assert!(!detected.contains(&pub_file));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_adb_auth_init_loads_keys() {
        let res = adb_auth_init();
        assert!(res.is_ok());
        let (keys, inotify) = res.unwrap();
        assert!(!keys.is_empty());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(inotify.fd.is_some());
    }
}
