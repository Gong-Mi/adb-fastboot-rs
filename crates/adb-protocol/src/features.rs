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

/// Feature names this Rust host actually implements and may advertise on
/// CNXN / report via `host-features`. Deliberately a subset of AOSP's list:
///
/// - shell_v2 / cmd           — shell v2 framing + legacy `cmd:` service.
/// - stat_v2 / ls_v2          — SYNC STAT_V2/LSTAT_V2/DENT_V2 codecs.
/// - sendrecv_v2(+bro/ls4/zstd/dry_run)
///                            — SYNC_SEND_V2/RECV_V2 + compressed DATA.
/// - fixed_push_symlink_timestamp
///                            — symlink push sends the target as DATA
///                              (file_sync_client.cpp SendSmallFile parity).
///
/// NOT advertised (unimplemented here, so we must not let a peer rely on
/// them): apex, abb, abb_exec, remount_shell, track_app, devraw, app_info,
/// server_status, openscreen_mdns, devicetracker_proto_format, track_mdns,
/// fixed_push_mkdir (no recursive push yet), libusb (no libusb backend),
/// push_sync (server-service extra AOSP appends unconditionally; we only
/// have V1), delayed_ack (no batched-ack path yet).
pub fn host_supported_features() -> &'static [&'static str] {
    &[
        "shell_v2",
        "cmd",
        "stat_v2",
        "ls_v2",
        "sendrecv_v2",
        "sendrecv_v2_brotli",
        "sendrecv_v2_lz4",
        "sendrecv_v2_zstd",
        "sendrecv_v2_dry_run_send",
        "fixed_push_symlink_timestamp",
    ]
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
        let device = vec!["shell_v2".to_string(), "apex".to_string()];
        assert!(can_use_feature(&device, "shell_v2"));
        // Device supports something we don't implement → unusable
        // (this is why advertising abb/host-features falsely is a bug).
        assert!(!can_use_feature(&device, "apex"));
        // Host implements it but device doesn't → unusable.
        assert!(!can_use_feature(&[], "shell_v2"));
    }

    #[test]
    fn test_host_supported_features_are_only_implemented_ones() {
        let f = host_supported_features();
        // AOSP-canonical names, exact spellings (transport.cpp:81-100).
        for name in [
            "shell_v2",
            "cmd",
            "stat_v2",
            "ls_v2",
            "sendrecv_v2",
            "sendrecv_v2_brotli",
            "sendrecv_v2_lz4",
            "sendrecv_v2_zstd",
            "sendrecv_v2_dry_run_send",
            "fixed_push_symlink_timestamp",
        ] {
            assert!(f.contains(&name), "missing {name}");
        }
        // Capabilities we do NOT implement must never appear.
        for bad in ["abb", "abb_exec", "apex", "remount_shell", "libusb", "push_sync"] {
            assert!(!f.contains(&bad), "must not advertise {bad}");
        }
    }

    #[test]
    fn test_host_cnxn_payload_shape() {
        let payload = host_cnxn_payload();
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with("host::features="), "got {s}");
        assert!(s.contains("shell_v2"));
        assert!(!s.contains("abb"));
    }
}
