//! `adb abb` — hand arguments to the device-side ABB (Android Binder Bridge)
//! service. Maps to AOSP `vendor/adb/client/commandline.cpp:799-822`
//! (`adb_abb()`).
//!
//! Wire contract (the reason this command cannot reuse `adb shell`):
//!
//! * `service_string = "abb:" + Join(args, ABB_ARG_DELIMITER)` with
//!   `ABB_ARG_DELIMITER = '\0'` (`adb.h:205`, joined at commandline.cpp:814).
//!   Arguments are NUL-separated on the wire — not space-joined and not
//!   shell-escaped; AOSP passes `argv` through verbatim and the device splits
//!   on NUL. Empty argument list ⇒ the service string is exactly `"abb:"`.
//! * The service then speaks ShellV2 framing in `raw` (non-PTY) mode with
//!   interactive stdin: `RemoteShell(use_shell_protocol=true,
//!   shell_type_arg=kShellServiceArgRaw, escape_char='~',
//!   empty_command=false, service_string)` (commandline.cpp:808-822). There is
//!   no `shell,v2,raw:` prefix — the service string is opened as-is
//!   (commandline.cpp:643 `adb_connect(service_string, ...)`).
//!
//! The frame pump therefore stays `client::shell`'s (`stream_shell_v2` /
//! `stream_shell_v2_server`); this module only builds the service string and
//! answers "does this device speak `abb`?".

use std::time::Duration;

use adb_protocol::{AdbServerTransport, FEATURE_ABB};

/// `ABB_ARG_DELIMITER` (`adb.h:205`): arguments are NUL-joined, never
/// space-joined.
pub const ABB_ARG_DELIMITER: char = '\0';

/// Build the abb service destination string:
/// `"abb:" + android::base::Join(args, ABB_ARG_DELIMITER)`
/// (commandline.cpp:813-814). No escaping, no whitelist — AOSP forwards the
/// user's argv untouched.
pub fn abb_service_string(args: &[String]) -> String {
    let mut service = String::from("abb:");
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            service.push(ABB_ARG_DELIMITER);
        }
        service.push_str(arg);
    }
    service
}

/// AOSP `CanUseFeature(*features, kFeatureAbb)` (commandline.cpp:800-803).
///
/// AOSP's `CanUseFeature` (transport.cpp:1265-1268) requires the feature in
/// *both* the device banner set and `supported_features()`. The host half is
/// satisfied by construction here — implementing `adb abb` is exactly what
/// makes `abb` a supported host feature in this slice, while
/// `adb_protocol::features::host_supported_features()` intentionally still
/// lists only capabilities wired end-to-end everywhere (advertising `abb`
/// there is a protocol-crate change outside this slice). So the gate is the
/// device-banner half, spelled with the protocol constant instead of a
/// literal.
pub fn device_supports_abb(device_features: &[String]) -> bool {
    device_features.iter().any(|feature| feature == FEATURE_ABB)
}

/// AOSP `StringToFeatureSet` (adb_client.cpp:440): the ADB server answers a
/// `features` query with a comma-separated feature list.
pub fn parse_feature_set(text: &str) -> Vec<String> {
    text.split(',')
        .map(|feature| feature.trim().trim_matches('\0').to_string())
        .filter(|feature| !feature.is_empty())
        .collect()
}

/// AOSP `adb_get_feature_set` (adb_client.cpp:432-448): ask the ADB server for
/// the selected transport's device features via
/// `adb_query(format_host_command("features"))`, i.e.
/// `host-serial:<serial>:features` when `-s` was given and `host:features`
/// otherwise.
///
/// A server-side transport never exposes the adbd CNXN banner on this socket,
/// so this is the only way to apply the same `abb` gate before opening the
/// `abb:` service in the server path. A failed query is reported instead of
/// being treated as "no abb" (AOSP `adb_get_feature_set_or_die` exits with the
/// server's error).
pub fn query_server_features(
    server_addr: &str,
    serial: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut server = AdbServerTransport::connect_timeout(server_addr, Duration::from_millis(300))
        .map_err(|error| format!("cannot connect to ADB server at {server_addr}: {error}"))?;
    let request = match serial {
        Some(serial) => format!("host-serial:{serial}:features"),
        None => "host:features".to_string(),
    };
    server
        .send_host_request(&request)
        .map_err(|error| format!("{request}: {error}"))?;
    server
        .read_status()
        .map_err(|error| format!("{request}: {error}"))?;
    let payload = server
        .read_payload()
        .map_err(|error| format!("{request}: {error}"))?;
    Ok(parse_feature_set(&String::from_utf8_lossy(&payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_string_is_nul_joined_after_the_abb_prefix() {
        let args = vec!["echo".to_string(), "hi".to_string()];
        assert_eq!(abb_service_string(&args), "abb:echo\0hi");
        // Two arguments ⇒ exactly one NUL, never a space.
        assert!(!abb_service_string(&args).contains(' '));
    }

    #[test]
    fn service_string_without_args_is_the_bare_prefix() {
        assert_eq!(abb_service_string(&[]), "abb:");
    }

    #[test]
    fn args_are_forwarded_verbatim_without_escaping() {
        // AOSP does not escape abb args (`escape_arg` is for exec:/cmd: paths).
        let args = vec!["ls".to_string(), "-l".to_string(), "/sdcard/my dir".to_string()];
        assert_eq!(abb_service_string(&args), "abb:ls\0-l\0/sdcard/my dir");
    }

    #[test]
    fn gate_requires_the_device_abb_feature() {
        let with_abb = parse_feature_set("cmd,shell_v2,abb,abb_exec\n");
        assert!(device_supports_abb(&with_abb));
        // `abb_exec` is a different service and must not satisfy the gate.
        let without_abb = parse_feature_set("cmd,shell_v2,abb_exec");
        assert!(!device_supports_abb(&without_abb));
        assert!(!device_supports_abb(&[]));
    }
}
