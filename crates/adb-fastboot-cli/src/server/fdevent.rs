//! fdevent — epoll-based event reactor (single-threaded fd event loop).
//!
//! Mirrors AOSP `vendor/adb/fdevent/fdevent_epoll.cpp` + `fdevent.cpp`.
//!
//! Uses epoll on Linux.  Host-side ADB uses thread-per-client instead,
//! so this module is available for adbd-side or embedded use.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const FDE_READ: u32 = 0x0001;
pub const FDE_WRITE: u32 = 0x0002;
pub const FDE_ERROR: u32 = 0x0004;
pub const FDE_TIMEOUT: u32 = 0x0008;

/// Epoll-based event reactor — single-threaded fd event loop.
pub struct FdEventReactor {
    epoll_fd: RawFd,
    interrupt_fd: RawFd,
    installed: HashMap<RawFd, FdEventHandler>,
    terminate: AtomicBool,
}

struct FdEventHandler {
    events: u32,
    callback: Box<dyn FnMut(RawFd, u32) + Send>,
    timeout: Option<Duration>,
    last_active: Instant,
}

impl FdEventReactor {
    pub fn new() -> Result<Self, String> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err("epoll_create1 failed".into());
        }

        let interrupt_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if interrupt_fd < 0 {
            unsafe { libc::close(epoll_fd); }
            return Err("eventfd failed".into());
        }

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: interrupt_fd as u64,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, interrupt_fd, &mut ev) } < 0 {
            unsafe { libc::close(epoll_fd); libc::close(interrupt_fd); }
            return Err("epoll_ctl ADD interrupt failed".into());
        }

        Ok(Self {
            epoll_fd,
            interrupt_fd,
            installed: HashMap::new(),
            terminate: AtomicBool::new(false),
        })
    }

    pub fn add(&mut self, fd: RawFd, events: u32, callback: Box<dyn FnMut(RawFd, u32) + Send>) {
        let mut ev = Self::epoll_events(events);
        ev.u64 = fd as u64;
        unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev); }
        self.installed.insert(fd, FdEventHandler {
            events,
            callback,
            timeout: None,
            last_active: Instant::now(),
        });
    }

    pub fn set(&mut self, fd: RawFd, events: u32) {
        if let Some(h) = self.installed.get_mut(&fd) {
            if h.events == events { return; }
            h.events = events;
            let mut ev = Self::epoll_events(events);
            ev.u64 = fd as u64;
            unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_MOD, fd, &mut ev); }
        }
    }

    pub fn remove(&mut self, fd: RawFd) {
        self.installed.remove(&fd);
        unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()); }
    }

    pub fn loop_once(&mut self, timeout_ms: Option<i32>) {
        if self.terminate.load(Ordering::Relaxed) { return; }

        let mut epoll_events = vec![
            libc::epoll_event { events: 0, u64: 0 };
            self.installed.len().max(1)
        ];

        let rc = unsafe {
            libc::epoll_wait(self.epoll_fd, epoll_events.as_mut_ptr(),
                             epoll_events.len() as i32, timeout_ms.unwrap_or(-1))
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("epoll_wait: {}", err);
            }
            return;
        }

        let now = Instant::now();
        let n = rc as usize;

        let mut triggered: Vec<(RawFd, u32)> = Vec::new();
        for i in 0..n {
            let ev = &epoll_events[i];
            let fd = ev.u64 as RawFd;
            let mut events = 0u32;
            if (ev.events & libc::EPOLLIN as u32) != 0 { events |= FDE_READ; }
            if (ev.events & libc::EPOLLOUT as u32) != 0 { events |= FDE_WRITE; }
            if (ev.events & (libc::EPOLLERR | libc::EPOLLHUP | libc::EPOLLRDHUP) as u32) != 0 {
                events |= FDE_READ | FDE_ERROR;
            }
            triggered.push((fd, events));
        }

        for (&fd, h) in &self.installed {
            if let Some(tmo) = h.timeout {
                if h.last_active.elapsed() >= tmo && !triggered.iter().any(|(f, _)| *f == fd) {
                    triggered.push((fd, FDE_TIMEOUT));
                }
            }
        }

        for (fd, events) in &triggered {
            if *fd == self.interrupt_fd {
                let mut buf: u64 = 0;
                unsafe { libc::read(self.interrupt_fd, &mut buf as *mut _ as *mut libc::c_void, 8); }
                continue;
            }
            if let Some(h) = self.installed.get_mut(fd) {
                h.last_active = now;
                (h.callback)(*fd, *events);
            }
        }
    }

    pub fn interrupt(&self) {
        let val: u64 = 1;
        unsafe { libc::write(self.interrupt_fd, &val as *const _ as *const libc::c_void, 8); }
    }

    pub fn terminate(&self) {
        self.terminate.store(true, Ordering::Relaxed);
        self.interrupt();
    }

    pub fn installed_count(&self) -> usize {
        self.installed.len()
    }

    fn epoll_events(flags: u32) -> libc::epoll_event {
        let mut e = libc::EPOLLRDHUP as u32;
        if flags & FDE_READ != 0 { e |= libc::EPOLLIN as u32; }
        if flags & FDE_WRITE != 0 { e |= libc::EPOLLOUT as u32; }
        if flags & FDE_ERROR != 0 { e |= libc::EPOLLERR as u32; }
        libc::epoll_event { events: e, u64: 0 }
    }
}

impl Drop for FdEventReactor {
    fn drop(&mut self) {
        unsafe { libc::close(self.interrupt_fd); libc::close(self.epoll_fd); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn test_create_reactor() {
        assert!(FdEventReactor::new().is_ok());
    }

    #[test]
    fn test_interrupt_wakes_loop() {
        let mut reactor = FdEventReactor::new().unwrap();
        let (tx, rx) = mpsc::channel();

        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()); }
        let (rfd, wfd) = (fds[0], fds[1]);

        let tx2 = tx.clone();
        reactor.add(rfd, FDE_READ, Box::new(move |_fd, events| {
            tx2.send(events).ok();
        }));

        let buf: u8 = 42;
        unsafe { libc::write(wfd, &buf as *const _ as *const libc::c_void, 1); }
        reactor.loop_once(Some(100));

        assert!(rx.try_recv().is_ok());
        unsafe { libc::close(rfd); libc::close(wfd); }
    }

    #[test]
    fn test_terminate() {
        let reactor = FdEventReactor::new().unwrap();
        reactor.terminate();
    }

    #[test]
    fn test_add_remove() {
        let mut reactor = FdEventReactor::new().unwrap();
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()); }
        reactor.add(fds[0], FDE_READ, Box::new(|_, _| {}));
        assert_eq!(reactor.installed_count(), 1);
        reactor.remove(fds[0]);
        assert_eq!(reactor.installed_count(), 0);
        unsafe { libc::close(fds[0]); libc::close(fds[1]); }
    }
}
