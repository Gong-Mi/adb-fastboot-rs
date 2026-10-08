//! ADB feature negotiation (AOSP transport.cpp:81-100/1202-1247,
//! transport.h:58-62, adb.cpp:294-316).
//!
//! Two distinct feature surfaces exist and must never be conflated:
//!
//! 1. **CNXN banner** (`host::features=...` / `device::...;features=...`):
//!    what each end of a *device transport* can speak. The client gates
//!    protocol choices on the *device* banner intersected with its own
//!    compile-time list (`CanUseFeature` = `contains(feature_set, feature)
//!    && contains(supported_features(), feature)`, transport.cpp:1267).
//! 2. **`host:host-features`** server service: what this *host/server*
//!    supports (adb.cpp:1443-1452 returns `supported_features()` plus
//!    `libusb`/`push_sync` extras).
//!
//! This module only advertises features this codebase actually implements
//! end-to-end, so a peer never trusts a capability that then fails.

/// Parse `features=` out of a CNXN banner payload.
///
/// Faithful port of AOSP `parse_banner` (adb.cpp:350-383): split on `:`,
/// take piece[2] as the property string, split it on `;` (`Split(banner,
/// ":")` keeps empties, so `"host::features=x"` → ["host","","features=x"]),
/// then each `key=value` on the FIRST `=`; the `features` value is
/// comma-separated. Note the empty-`;`-piece skip (AOSP: the list was
/// traditionally ;-terminated) and the `key_value.size() != 2` rule —
/// malformed props are ignored, never guessed.
pub fn parse_banner_features(banner: &str) -> Vec<String> {
    let pieces: Vec<&str> = banner.split(':').collect();
    if pieces.len() < 3 {
        return Vec::new();
    }
    for prop in pieces[2].split(';') {
        if prop.is_empty() {
            continue;
        }
        let mut kv = prop.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = match kv.next() {
            Some(v) => v,
            None => continue, // no '=' at all → not key=value
        };
        // AOSP Split(prop, "=") with size()!=2 skip: a second '=' means the
        // property has more than one separator — reject it.
        if value.contains('=') {
            continue;
        }
        if key == "features" {
            return value
                .split(',')
                .map(|f| f.trim_matches('\0').to_string())
                .filter(|f| !f.is_empty())
                .collect();
        }
    }
    Vec::new()
}

/// AOSP `CanUseFeature` (transport.cpp:1265-1268): the feature must be in
/// both this list and `host_supported_features()`.
pub fn can_use_feature(device_features: &[String], feature: &str) -> bool {
    device_features.iter().any(|f| f == feature)
        && host_supported_features().iter().any(|f| *f == feature)
}

/// Feature names this Rust host actually implements end-to-end and may
/// advertise on CNXN / report via `host:host-features`. A strict subset of
/// AOSP's `supported_features()` (transport.cpp:1202-1243); every entry has a
/// CLI-reachable production path (audited against AOSP ~9084198a):
///
/// - `shell_v2` — `client/shell.rs` always opens `shell,v2,raw:` and decodes
///   the ShellV2 framing (adb-protocol `shell_v2.rs`). Removing it would make
///   our own banner misdescribe the unconditional v2 usage.
/// - `cmd` — `client/adb_install.rs:184` uses `can_use_feature(dev, "cmd")` to
///   select `exec:cmd package` over `exec:pm` (AOSP adb_install.cpp:62).
/// - `apex` — streamed install appends `--apex` for `.apex` inputs
///   (client/adb_install.cpp:68-70, 227-229).
/// - `abb_exec` — install + incremental open the `abb_exec:` service with
///   NUL-joined raw args (client/adb_install.cpp:73-76, 152-158, 208-210;
///   client/commandline.h:212-222, ABB_ARG_DELIMITER = '\0').
///
/// NOT advertised — no CLI-reachable implementation here, so a peer must not
/// be allowed to rely on them:
/// - `stat_v2` / `ls_v2` / `sendrecv_v2(+ _brotli/_lz4/_zstd/_dry_run_send)`:
///   the V2 SYNC codecs exist in adb-protocol `sync.rs`, but
///   `client/file_sync.rs` speaks only V1 STAT/LIST/SEND/RECV and `-z`
///   compression is explicitly refused (`main_adb.rs` `sync_compression_option`).
///   Advertising a codec without the wire path is a false capability claim.
/// - `fixed_push_symlink_timestamp`: push does not transfer symlinks at all
///   (`file_sync.rs` walks regular files/dirs only).
/// - remount_shell, track_app, devraw, app_info, server_status,
///   openscreen_mdns, devicetracker_proto_format, track_mdns, abb,
///   fixed_push_mkdir (AOSP mkdir semantics not verified), libusb (not selected
///   by the production usbfs backend),
///   push_sync (server-service extra AOSP appends unconditionally; we only
///   have V1), delayed_ack (no batched-ack path yet).
pub fn host_supported_features() -> &'static [&'static str] {
    &["shell_v2", "cmd", "apex", "abb_exec"]
}

/// AOSP `FeatureSetToString` (transport.cpp:1249-1251): comma-joined.
pub fn features_to_string(features: &[&str]) -> String {
    features.join(",")
}

/// The CNXN payload a host sends to adbd: `host::features=<list>`
/// (adb.cpp:313-315 with `adb_device_banner = "host"`,
/// adb_trace.cpp:39).
pub fn host_cnxn_payload() -> Vec<u8> {
    format!(
        "host::features={}",
        features_to_string(host_supported_features())
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_banner_features() {
        // Typical modern device banner.
        let banner = "device::ro.product.name=raven;ro.product.model=Pixel 6 Pro;ro.product.device=raven;features=shell_v2,cmd,stat_v2,ls_v2,apex,abb,fixed_push_mkdir,sendrecv_v2,sendrecv_v2_zstd";
        let feats = parse_banner_features(banner);
        assert!(feats.contains(&"shell_v2".to_string()));
        assert!(feats.contains(&"sendrecv_v2_zstd".to_string()));
        assert_eq!(feats.len(), 9);

        // Banner without features.
        assert!(parse_banner_features("device::ro.product.name=x").is_empty());

        // NUL-terminated CNXN payload.
        let feats = parse_banner_features("host::features=shell_v2,cmd\0");
        assert_eq!(feats, vec!["shell_v2".to_string(), "cmd".to_string()]);
    }

    #[test]
    fn test_can_use_feature_requires_both_sides() {
        // Device supports it, host advertises it → usable.
        let device = vec!["shell_v2".to_string(), "apex".to_string(), "abb_exec".to_string()];
        assert!(can_use_feature(&device, "shell_v2"));
        assert!(can_use_feature(&device, "apex"));
        assert!(can_use_feature(&device, "abb_exec"));
        // Device supports something we don't implement → unusable
        // (this is why advertising abb/host-features falsely is a bug).
        assert!(!can_use_feature(&device, "abb"));
        // Host implements it but device doesn't → unusable.
        assert!(!can_use_feature(&[], "shell_v2"));
    }

    #[test]
    fn test_host_supported_features_are_only_implemented_ones() {
        let f = host_supported_features();
        // AOSP-canonical names with a CLI-reachable production path
        // (exact spellings, transport.cpp:81-100).
        for name in ["shell_v2", "cmd", "apex", "abb_exec"] {
            assert!(f.contains(&name), "missing {name}");
        }
        // Capabilities we do NOT implement must never appear.
        for bad in [
            "stat_v2",
            "ls_v2",
            "sendrecv_v2",
            "sendrecv_v2_brotli",
            "sendrecv_v2_lz4",
            "sendrecv_v2_zstd",
            "sendrecv_v2_dry_run_send",
            "fixed_push_symlink_timestamp",
            "fixed_push_mkdir",
            "abb",
            "remount_shell",
            "track_app",
            "devraw",
            "app_info",
            "server_status",
            "openscreen_mdns",
            "devicetracker_proto_format",
            "track_mdns",
            "libusb",
            "push_sync",
            "delayed_ack",
        ] {
            assert!(!f.contains(&bad), "must not advertise {bad}");
        }
    }

    #[test]
    fn test_host_cnxn_payload_shape() {
        let payload = host_cnxn_payload();
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with("host::features="), "got {s}");
        assert!(s.contains("shell_v2"));
        assert!(s.contains("apex"));
        assert!(s.contains("abb_exec"));
        assert!(!s.contains("abb,") && !s.ends_with("abb"));
    }

    /// The advertised set must be exactly the set with a production
    /// (CLI-reachable) implementation — no more, no less.
    ///
    /// Per-item audit (AOSP `supported_features()`, transport.cpp:1202-1243):
    ///   shell_v2  — client/shell.rs always opens `shell,v2,raw:`; a device
    ///               without shell_v2 was never a supported fallback here, so
    ///               the host must keep advertising it.
    ///   cmd       — client/adb_install.rs:184 `can_use_feature(dev, "cmd")`
    ///               selects `exec:cmd package` over `exec:pm`
    ///               (AOSP adb_install.cpp:62).
    ///   apex      — client/adb_install.rs appends `--apex` for `.apex`.
    ///   abb_exec  — client/adb_install.rs + incremental.rs speak `abb_exec:`.
    ///
    /// stat_v2 / ls_v2 / sendrecv_v2* / fixed_push_symlink_timestamp have no
    /// production path (see the negative tests below), so they must not appear.
    #[test]
    fn advertised_features_are_exactly_the_audited_implemented_set() {
        let mut got: Vec<&str> = host_supported_features().to_vec();
        got.sort_unstable();
        let mut expected = ["abb_exec", "apex", "cmd", "shell_v2"];
        expected.sort_unstable();
        assert_eq!(
            got, expected,
            "host_supported_features() must equal the audited implemented set"
        );
    }

    /// Negative control: capabilities whose codecs exist in adb-protocol but
    /// which no CLI path exercises must not be advertised.
    #[test]
    fn unimplemented_sync_and_symlink_features_are_not_advertised() {
        let f = host_supported_features();
        for bad in [
            "stat_v2",
            "ls_v2",
            "sendrecv_v2",
            "sendrecv_v2_brotli",
            "sendrecv_v2_lz4",
            "sendrecv_v2_zstd",
            "sendrecv_v2_dry_run_send",
            "fixed_push_symlink_timestamp",
        ] {
            assert!(!f.contains(&bad), "must not advertise unimplemented {bad:?}: {f:?}");
        }
    }

    /// Negative control: a device that advertises an unimplemented capability
    /// must not be able to unlock it, because the host half of
    /// `CanUseFeature` (transport.cpp:1265-1268) is false.
    #[test]
    fn unimplemented_features_cannot_be_unlocked_by_a_device_banner() {
        let device = [
            "sendrecv_v2_zstd".to_string(),
            "sendrecv_v2".to_string(),
            "stat_v2".to_string(),
            "ls_v2".to_string(),
            "fixed_push_symlink_timestamp".to_string(),
        ];
        for bad in [
            "sendrecv_v2_zstd",
            "sendrecv_v2",
            "stat_v2",
            "ls_v2",
            "fixed_push_symlink_timestamp",
        ] {
            assert!(
                !can_use_feature(&device, bad),
                "device banner must not unlock unimplemented {bad:?}"
            );
        }
        // Positive control: features with a production path still negotiate.
        assert!(can_use_feature(&["cmd".to_string()], "cmd"));
        assert!(can_use_feature(&["abb_exec".to_string()], "abb_exec"));
    }

    /// The wire banner a device sees must not carry unimplemented claims.
    #[test]
    fn host_cnxn_payload_does_not_advertise_unimplemented_sync_v2() {
        let s = String::from_utf8(host_cnxn_payload()).unwrap();
        for bad in [
            "stat_v2",
            "ls_v2",
            "sendrecv_v2",
            "fixed_push_symlink_timestamp",
        ] {
            assert!(!s.contains(bad), "CNXN banner must not advertise {bad}: {s}");
        }
    }
}
