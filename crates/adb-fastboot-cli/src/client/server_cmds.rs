//! ADB server process management: ensure running (fork-server protocol) and kill.
//!
//! Maps to AOSP `vendor/adb/` launch_server / kill_server logic.
//! Uses the fork-server protocol: pipe() → fork() → child exec's
//! "adb-rs fork-server --reply-fd N" → parent reads "OK\n".

use std::time::Duration;

use adb_protocol::AdbServerTransport;

// Temporary local copy; will be imported from host_command after step 5 merge.
const ADB_SERVER_PORT: u16 = 5037;

/// Ensure ADB server daemon is running on 127.0.0.1:5037.
/// If not running, autostarts it by spawning `adb-rs serve` in the background.
pub fn ensure_server_running() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running_at(ADB_SERVER_PORT)
}

pub fn ensure_server_running_at(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(200)).is_ok() {
        return Ok(());
    }

    eprintln!("* daemon not running; starting it now at tcp:{port} *");

    let exe = std::env::current_exe()
        .map_err(|e| format!("Cannot get executable path: {e}"))?;
    let exe_cstr = std::ffi::CString::new(
        exe.to_str()
            .ok_or("Executable path is not valid UTF-8")?,
    )
    .map_err(|_| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Executable path contains null byte",
        ))
    })?;

    let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
    let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("pipe() failed: errno={}", unsafe { *libc::__errno() }).into());
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let _ = unsafe { libc::close(pipe_read) };
        let _ = unsafe { libc::close(pipe_write) };
        return Err(format!("fork() failed: errno={}", unsafe { *libc::__errno() }).into());
    }

    if pid == 0 {
        // ---- child process ----
        unsafe {
            libc::close(pipe_read);
        }
        // Clear CLOEXEC so pipe_write survives exec()
        unsafe {
            libc::fcntl(pipe_write, libc::F_SETFD, 0);
        }

        // argv: adb-rs fork-server server --reply-fd N
        // The "server" positional arg is required by AOSP protocol.
        // Also pass -L tcp:127.0.0.1:{port} so the server binds to the
        // correct port (not just hardcoded 5037).
        let fork_server = std::ffi::CString::new("fork-server").unwrap();
        let server_mode = std::ffi::CString::new("server").unwrap();
        let listen_flag = std::ffi::CString::new("-L").unwrap();
        let listen_addr = std::ffi::CString::new(format!("tcp:127.0.0.1:{port}")).unwrap();
        let reply_fd_arg = std::ffi::CString::new("--reply-fd").unwrap();
        let reply_fd_str = std::ffi::CString::new(pipe_write.to_string()).unwrap();

        // Build null-terminated argv array
        let mut raw_args: Vec<*const libc::c_char> = Vec::with_capacity(8);
        raw_args.push(exe_cstr.as_ptr());
        raw_args.push(fork_server.as_ptr());
        raw_args.push(server_mode.as_ptr());
        raw_args.push(listen_flag.as_ptr());
        raw_args.push(listen_addr.as_ptr());
        raw_args.push(reply_fd_arg.as_ptr());
        raw_args.push(reply_fd_str.as_ptr());
        raw_args.push(std::ptr::null::<libc::c_char>());

        unsafe {
            libc::execv(exe_cstr.as_ptr(), raw_args.as_ptr());
        }
        // execv only returns on error
        unsafe {
            libc::_exit(127);
        }
    }

    // ---- parent process ----
    unsafe {
        libc::close(pipe_write);
    }

    // Wait for "OK\n" (3 bytes) from the server
    let mut ok_buf = [0u8; 3];
    let mut total_read = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    loop {
        if total_read >= 3 {
            break;
        }
        if std::time::Instant::now() > deadline {
            // Timeout — server failed to start
            unsafe {
                libc::close(pipe_read);
            }
            // Try to reap the child
            unsafe {
                libc::kill(pid, libc::SIGTERM);
                let mut status: libc::c_int = 0;
                libc::waitpid(pid, &mut status, 0);
            }
            return Err("Timeout waiting for ADB server to start".into());
        }

        let n = unsafe {
            libc::read(
                pipe_read,
                ok_buf[total_read..].as_mut_ptr() as *mut libc::c_void,
                3 - total_read,
            )
        };
        if n > 0 {
            total_read += n as usize;
        } else if n == 0 {
            // EOF without OK — server exited
            break;
        } else {
            let err = unsafe { *libc::__errno() };
            if err == libc::EINTR {
                continue;
            }
            // EAGAIN/EWOULDBLOCK — retry
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            break;
        }
    }

    unsafe {
        libc::close(pipe_read);
    }

    if &ok_buf == b"OK\n" {
        eprintln!("* daemon started successfully *");
        Ok(())
    } else {
        // Server exited before sending OK
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        Err(format!("ADB server daemon exited with status {status}").into())
    }
}

/// Kill the running ADB server on 127.0.0.1:5037.
pub fn kill_server() -> Result<(), Box<dyn std::error::Error>> {
    kill_server_at(ADB_SERVER_PORT)
}

pub fn kill_server_at(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let mut transport = match AdbServerTransport::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(t) => t,
        Err(_) => {
            // Server not running
            return Ok(());
        }
    };

    transport.send_host_request("host:kill")?;
    transport.read_status()?;

    // Wait for process termination
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(3);
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(100)).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Ok(())
}
