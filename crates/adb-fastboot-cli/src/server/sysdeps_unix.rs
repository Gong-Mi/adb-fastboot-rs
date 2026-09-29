//! POSIX system call wrappers — mirrors AOSP `vendor/adb/sysdeps_unix.cpp`.
//!
//! Provides platform-independent abstractions for:
//! - `adb_read`, `adb_write` — robust I/O with EINTR retry
//! - `adb_close`, `adb_dup2` — fd management
//! - `adb_pipe`, `adb_socketpair` — IPC
//! - `adb_poll` — event polling

use std::os::unix::io::RawFd;

/// Read with EINTR retry. Mirrors AOSP `adb_read()`.
pub fn adb_read(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Write with EINTR retry. Mirrors AOSP `adb_write()`.
pub fn adb_write(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let rc = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Close a file descriptor.
pub fn adb_close(fd: RawFd) {
    unsafe { libc::close(fd); }
}

/// Create a pipe. Returns (read_fd, write_fd).
pub fn adb_pipe() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc == 0 {
        Ok((fds[0], fds[1]))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Create a socket pair.
pub fn adb_socketpair() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc == 0 {
        Ok((fds[0], fds[1]))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Duplicate a file descriptor.
pub fn adb_dup2(old_fd: RawFd, new_fd: RawFd) -> std::io::Result<RawFd> {
    let rc = unsafe { libc::dup2(old_fd, new_fd) };
    if rc >= 0 {
        Ok(rc)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Poll for events on a single fd.
pub fn adb_poll(fd: RawFd, events: i16, timeout_ms: i32) -> std::io::Result<i32> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
    if rc >= 0 {
        Ok(rc)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// AOSP `set_tcp_keepalive()` (sysdeps_unix.cpp:24-58): enable/disable
/// SO_KEEPALIVE and set idle/interval/count (Linux: TCP_KEEPIDLE/
/// TCP_KEEPINTVL/TCP_KEEPCNT; interval <= 0 disables, count fixed at 10
/// matching AOSP).
pub fn set_tcp_keepalive(fd: RawFd, interval_sec: i32) -> bool {
    let enable: i32 = i32::from(interval_sec > 0);
    let mut ok = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, enable);
    if ok && enable == 1 {
        ok = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, interval_sec)
            && setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval_sec)
            && setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 10);
    }
    ok
}

fn setsockopt_int(fd: RawFd, level: i32, optname: i32, value: i32) -> bool {
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        ) == 0
    }
}

/// AOSP `network_peek()` (sysdeps_unix.cpp:112-128): MSG_PEEK|MSG_TRUNC
/// to learn the size of the next message without consuming it (Linux).
pub fn network_peek(fd: RawFd) -> Option<isize> {
    let upper_bound_bytes =
        unsafe { libc::recv(fd, std::ptr::null_mut(), 0, libc::MSG_PEEK | libc::MSG_TRUNC) };
    if upper_bound_bytes == -1 {
        eprintln!("network_peek error: {}", std::io::Error::last_os_error());
        None
    } else {
        Some(upper_bound_bytes)
    }
}

/// AOSP `GetOSVersion()` (sysdeps_unix.cpp:105-108): "sysname release (machine)".
pub fn get_os_version() -> String {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return String::new();
    }
    let to_str = |field: &[libc::c_char]| -> String {
        field
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8 as char)
            .collect()
    };
    format!(
        "{} {} ({})",
        to_str(&uts.sysname),
        to_str(&uts.release),
        to_str(&uts.machine)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adb_pipe_roundtrip() {
        let (r, w) = adb_pipe().unwrap();
        let data = b"hello";
        assert_eq!(adb_write(w, data).unwrap(), 5);
        let mut buf = [0u8; 5];
        assert_eq!(adb_read(r, &mut buf).unwrap(), 5);
        assert_eq!(&buf, data);
        adb_close(r);
        adb_close(w);
    }

    #[test]
    fn test_adb_socketpair() {
        let (a, b) = adb_socketpair().unwrap();
        let data = b"test";
        assert_eq!(adb_write(a, data).unwrap(), 4);
        let mut buf = [0u8; 4];
        assert_eq!(adb_read(b, &mut buf).unwrap(), 4);
        assert_eq!(&buf, data);
        adb_close(a);
        adb_close(b);
    }

    #[test]
    fn test_adb_poll_timeout() {
        let (r, _w) = adb_pipe().unwrap();
        let rc = adb_poll(r, libc::POLLIN, 10).unwrap();
        assert_eq!(rc, 0); // timeout, no data
        adb_close(r);
    }

    #[test]
    fn test_adb_dup2() {
        let (r, w) = adb_pipe().unwrap();
        let new_fd = adb_dup2(w, 100).unwrap_or_else(|_| {
            adb_close(r); adb_close(w); 100
        });
        // Just verify it doesn't crash
        adb_close(r);
        if new_fd >= 0 { adb_close(new_fd); }
    }
}
