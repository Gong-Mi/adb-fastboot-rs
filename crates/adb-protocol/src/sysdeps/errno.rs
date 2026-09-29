//! ADB errno wire mapping — mirrors AOSP `vendor/adb/sysdeps/errno.cpp`.
//!
//! ADB transports a fixed subset of errno values over the wire using
//! asm-generic Linux numbering (identical on all Android architectures).
//! Host-local errno values are translated at the boundary; anything not
//! in the table becomes EIO (5), matching AOSP's fallback.

/// The full AOSP ERRNO_VALUES table: (host errno, wire value).
/// On Linux/Android the host values ARE the wire values (AOSP
/// static_asserts this), so this map is the identity except on platforms
/// with divergent errno numbering (e.g. Windows).
const ERRNO_TABLE: &[(i32, i32)] = &[
    (libc::EPERM, 1),
    (libc::EACCES, 13),
    (libc::EEXIST, 17),
    (libc::EFAULT, 14),
    (libc::EFBIG, 27),
    (libc::EINTR, 4),
    (libc::EINVAL, 22),
    (libc::EIO, 5),
    (libc::EISDIR, 21),
    (libc::ELOOP, 40),
    (libc::EMFILE, 24),
    (libc::ENAMETOOLONG, 36),
    (libc::ENFILE, 23),
    (libc::ENOENT, 2),
    (libc::ENOMEM, 12),
    (libc::ENOSPC, 28),
    (libc::ENOTDIR, 20),
    (libc::EOVERFLOW, 75),
    (libc::EROFS, 30),
    (libc::ETXTBSY, 26),
];

/// AOSP `errno_to_wire()` (errno.cpp:82-89): translate a host errno to the
/// ADB wire value. Unknown values fall back to EIO (5).
pub fn errno_to_wire(error: i32) -> i32 {
    for (host, wire) in ERRNO_TABLE {
        if *host == error {
            return *wire;
        }
    }
    eprintln!("failed to convert errno {error} to wire");
    libc::EIO
}

/// AOSP `errno_from_wire()` (errno.cpp:91-97): translate an ADB wire errno
/// to the host value. Unknown values fall back to EIO.
///
/// NOTE: AOSP's implementation looks up `host_to_wire` in both directions
/// (an upstream quirk preserved verbatim — on Linux it is the identity
/// map so the behavior coincides with a proper reverse lookup).
pub fn errno_from_wire(error: i32) -> i32 {
    for (host, wire) in ERRNO_TABLE {
        if *host == error {
            return *host;
        }
    }
    eprintln!("failed to convert errno {error} from wire");
    libc::EIO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_errnos_map_to_wire_values() {
        assert_eq!(errno_to_wire(libc::ENOENT), 2);
        assert_eq!(errno_to_wire(libc::EACCES), 13);
        assert_eq!(errno_to_wire(libc::EINVAL), 22);
        assert_eq!(errno_to_wire(libc::ELOOP), 40);
        assert_eq!(errno_to_wire(libc::EOVERFLOW), 75);
    }

    #[test]
    fn test_identity_on_linux_like_hosts() {
        // On Linux/Android the table entries are the identity.
        for (host, wire) in ERRNO_TABLE {
            assert_eq!(host, wire);
        }
    }

    #[test]
    fn test_unknown_errno_falls_back_to_eio() {
        // 133 is not in the table (Linux EHWPOISON — not ADB wire-mapped).
        assert_eq!(errno_to_wire(133), libc::EIO);
        assert_eq!(errno_from_wire(999), libc::EIO);
    }

    #[test]
    fn test_from_wire_roundtrip() {
        assert_eq!(errno_from_wire(2), libc::ENOENT);
        assert_eq!(errno_from_wire(28), libc::ENOSPC);
    }
}
