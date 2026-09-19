//! Ports of AOSP `adb_utils.cpp` helpers shared by the CLI wire layer.

/// Faithful port of `escape_arg` (adb_utils.cpp:81-102).
///
/// Wraps the argument in single quotes; every embedded `'` becomes `'\''`
/// (close quote, shell-escaped quote, reopen quote — the shell then
/// concatenates the pieces back into one string). The C++ loop's
/// `result.append(s, base, found - base)` with `found == npos` appends
/// through the end of the string, which is what the `None` arm does here.
pub fn escape_arg(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('\'');
    let mut base = 0usize;
    loop {
        match s[base..].find('\'') {
            Some(rel) => {
                let found = base + rel;
                result.push_str(&s[base..found]);
                result.push_str("'\\''");
                base = found + 1;
            }
            None => {
                result.push_str(&s[base..]);
                break;
            }
        }
    }
    result.push('\'');
    result
}

/// AOSP `adb exec-in` / `adb exec-out` service-string construction
/// (client/commandline.cpp:1802-1813): `exec:` + the program name
/// appended RAW (argv[1] is not escaped), then every following argument
/// space-joined after `escape_arg`.
///
/// Daemon side (`daemon/services.cpp:360-363`): `exec:<cmd>` runs
/// `StartSubprocess(cmd, nullptr, kRaw, kNone)` — a raw byte stream with
/// no shell-v2 framing and no PTY, which is why `exec-out` keeps binary
/// output byte-exact (the point of the command).
pub fn exec_service_string(args: &[String]) -> String {
    let mut cmd = String::from("exec:");
    let mut it = args.iter();
    if let Some(prog) = it.next() {
        cmd.push_str(prog);
    }
    for arg in it {
        cmd.push(' ');
        cmd.push_str(&escape_arg(arg));
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_arg_matches_aosp() {
        assert_eq!(escape_arg("abc"), "'abc'");
        assert_eq!(escape_arg(""), "''");
        // single embedded quote
        assert_eq!(escape_arg("a'b"), "'a'\\''b'");
        // consecutive quotes (the tricky case: ' -> '\'' twice)
        assert_eq!(escape_arg("a''b"), "'a'\\'''\\''b'");
        // leading and trailing quotes
        assert_eq!(escape_arg("'x'"), "''\\''x'\\'''");
        // spaces and specials are NOT escaped by AOSP escape_arg (single
        // quoting is enough for them):
        assert_eq!(escape_arg("-p"), "'-p'");
        assert_eq!(escape_arg("a b"), "'a b'");
        assert_eq!(escape_arg("$HOME"), "'$HOME'");
    }

    #[test]
    fn test_exec_service_string_construction() {
        // `adb exec-out screencap -p` -> "exec:screencap '-p'"
        let args: Vec<String> = ["screencap", "-p"].iter().map(|s| s.to_string()).collect();
        assert_eq!(exec_service_string(&args), "exec:screencap '-p'");

        // program name stays raw even with a quote in it (AOSP appends
        // argv[1] unescaped — preserve the exact behavior, don't "fix" it)
        let args: Vec<String> = ["i'test"].iter().map(|s| s.to_string()).collect();
        assert_eq!(exec_service_string(&args), "exec:i'test");

        // empty command list -> bare "exec:" (callers must reject first)
        assert_eq!(exec_service_string(&[]), "exec:");
    }
}
