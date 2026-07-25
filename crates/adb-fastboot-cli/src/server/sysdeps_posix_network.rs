//! POSIX network wrappers — mirrors AOSP `vendor/adb/sysdeps/posix/network.cpp`.
//!
//! Provides `adb_socket_set_rcvtimeo`, `adb_socket_set_sndtimeo`, etc.

use std::os::unix::io::RawFd;
use std::time::Duration;

/// Set socket receive timeout.
pub fn adb_socket_set_rcvtimeo(fd: RawFd, timeout: Duration) -> std::io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Set socket send timeout.
pub fn adb_socket_set_sndtimeo(fd: RawFd, timeout: Duration) -> std::io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Enable/disable TCP_NODELAY.
pub fn adb_socket_set_nodelay(fd: RawFd, nodelay: bool) -> std::io::Result<()> {
    let val: libc::c_int = if nodelay { 1 } else { 0 };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Enable SO_REUSEADDR.
pub fn adb_socket_set_reuseaddr(fd: RawFd, reuse: bool) -> std::io::Result<()> {
    let val: libc::c_int = if reuse { 1 } else { 0 };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Set SO_SNDBUF size.
pub fn adb_socket_set_sndbuf(fd: RawFd, size: i32) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}
