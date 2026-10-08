//! Exclusive-owner Linux usbfs asynchronous bulk transfers.
//!
//! ABI/source: Linux v6.12 include/uapi/linux/usbdevice_fs.h and
//! drivers/usb/core/devio.c (proc_do_submiturb, proc_unlinkurb,
//! processcompl, proc_reapurbnonblock, usbdev_release).
//! SUBMIT copies OUT data; IN data and status/actual_length are copied on REAP.
//! DISCARD does not reap: EINVAL can mean completion won the race. Storage
//! remains stable until matching reap, or exclusive fd close kills/frees URBs.
//! No fd duplication, borrowed caller buffers, blocking REAP or sync BULK.
use super::{usbdevfs_ioctl, UsbEndpointInfo};
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

#[repr(C)]
#[derive(Default)]
struct Urb {
    kind: u8,
    endpoint: u8,
    status: i32,
    flags: u32,
    buffer: *mut u8,
    buffer_length: i32,
    actual_length: i32,
    start_frame: i32,
    stream_id: u32,
    error_count: i32,
    signr: u32,
    usercontext: *mut libc::c_void,
}
const SUBMIT: u32 = super::_ior(b'U', 10, std::mem::size_of::<Urb>());
const DISCARD: u32 = super::ioc(0, b'U', 11, 0);
const REAP: u32 = super::ioc(1, b'U', 13, std::mem::size_of::<*mut Urb>());

// Private boundary: implementations must not retain storage after shutdown.
trait Syscalls {
    unsafe fn ioctl(&mut self, request: u32, arg: *mut libc::c_void) -> io::Result<i32>;
    fn shutdown(&mut self);
}
struct Native(Option<File>);
impl Syscalls for Native {
    unsafe fn ioctl(&mut self, request: u32, arg: *mut libc::c_void) -> io::Result<i32> {
        usbdevfs_ioctl(
            self.0
                .as_ref()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?
                .as_raw_fd(),
            request,
            arg,
        )
    }
    fn shutdown(&mut self) {
        drop(self.0.take());
    }
}

/// Transfer identity; never reused during an owner's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransferId(u64);
/// Completion keeps progress even when the kernel reports cancellation/error.
#[derive(Debug)]
pub struct Completion {
    pub id: TransferId,
    pub endpoint: u8,
    pub actual_length: usize,
    /// Exactly actual_length bytes for IN; empty for OUT.
    pub data: Vec<u8>,
    /// Linux URB status (0 or negative errno), independent of progress.
    pub status: i32,
    pub cancellation_requested: bool,
}
struct Pending {
    urb: Box<Urb>,
    buffer: Vec<u8>,
    cancellation_requested: bool,
}
struct Engine<S: Syscalls> {
    sys: S,
    pending: BTreeMap<TransferId, Pending>,
    next: u64,
    poisoned: bool,
}
impl<S: Syscalls> Engine<S> {
    fn new(sys: S) -> Self {
        Self {
            sys,
            pending: BTreeMap::new(),
            next: 1,
            poisoned: false,
        }
    }
    fn check_live(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "usbfs completion ownership uncertain; drop owner to close",
            ));
        }
        Ok(())
    }
    fn submit(&mut self, endpoint: u8, mut buffer: Vec<u8>) -> io::Result<TransferId> {
        self.check_live()?;
        if self.pending.values().any(|p| p.urb.endpoint == endpoint) {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let length = i32::try_from(buffer.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "URB length exceeds i32"))?;
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("URB identity exhausted"))?;
        let id = TransferId(self.next);
        let mut urb = Box::new(Urb {
            kind: 3,
            endpoint,
            buffer: buffer.as_mut_ptr(),
            buffer_length: length,
            ..Urb::default()
        });
        unsafe {
            self.sys.ioctl(SUBMIT, (&mut *urb as *mut Urb).cast())?;
        }
        self.next = next;
        self.pending.insert(
            id,
            Pending {
                urb,
                buffer,
                cancellation_requested: false,
            },
        );
        Ok(id)
    }
    fn poll(&mut self) -> io::Result<Option<Completion>> {
        self.check_live()?;
        if self.pending.is_empty() {
            return Ok(None);
        }
        let mut reaped: *mut Urb = std::ptr::null_mut();
        match unsafe { self.sys.ioctl(REAP, (&mut reaped as *mut *mut Urb).cast()) } {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => return Ok(None),
            Err(e) => {
                // processcompl may free a completed async even on EFAULT;
                // its identity/progress can no longer be recovered. Fail closed.
                if e.raw_os_error() == Some(libc::EFAULT) {
                    self.poisoned = true;
                }
                return Err(e);
            }
        }
        // Never dereference a returned pointer before matching our allocation.
        let id = self
            .pending
            .iter()
            .find_map(|(id, p)| {
                if std::ptr::eq(&*p.urb, reaped) {
                    Some(*id)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                self.poisoned = true;
                io::Error::new(io::ErrorKind::InvalidData, "usbfs reaped unknown URB")
            })?;
        let mut p = self.pending.remove(&id).expect("matched pending URB");
        let actual_length = usize::try_from(p.urb.actual_length)
            .ok()
            .filter(|&n| n <= p.buffer.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "usbfs actual_length outside owned buffer",
                )
            })?;
        if p.urb.status > 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "usbfs URB status must be zero or negative errno",
            ));
        }
        if p.urb.endpoint & 0x80 != 0 {
            p.buffer.truncate(actual_length);
        } else {
            p.buffer.clear();
        }
        Ok(Some(Completion {
            id,
            endpoint: p.urb.endpoint,
            actual_length,
            data: p.buffer,
            status: p.urb.status,
            cancellation_requested: p.cancellation_requested,
        }))
    }
    fn cancel(&mut self, id: TransferId) -> io::Result<()> {
        self.check_live()?;
        let p = self
            .pending
            .get_mut(&id)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        if p.cancellation_requested {
            return Ok(());
        }
        match unsafe { self.sys.ioctl(DISCARD, (&mut *p.urb as *mut Urb).cast()) } {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
            Err(e) => return Err(e),
        }
        p.cancellation_requested = true;
        Ok(())
    }
    fn wait(&mut self, budget: Duration) -> io::Result<Option<Completion>> {
        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URB wait budget overflow")
        })?;
        loop {
            if let Some(c) = self.poll()? {
                return Ok(Some(c));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || self.pending.is_empty() {
                return Ok(None);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }
}
impl<S: Syscalls> Drop for Engine<S> {
    fn drop(&mut self) {
        // Close exclusive file description BEFORE freeing user URB/buffer.
        // Never loop awaiting a reap on Drop; close abandons unreaped progress.
        self.sys.shutdown();
        self.pending.clear();
    }
}

/// Consumes a claimed UsbfsAdbDevice; supports one IN and one OUT in flight.
/// No Transport implementation yet: the server's dispatcher rejection stays.
/// This owner is intentionally non-Clone and must not share its file description.
/// Raw URB pointers also prevent accidental cross-thread sharing.
pub struct UsbfsUrbOwner {
    engine: Engine<Native>,
    endpoints: UsbEndpointInfo,
}
impl UsbfsUrbOwner {
    pub(super) fn new(fd: File, endpoints: UsbEndpointInfo) -> Self {
        Self {
            engine: Engine::new(Native(Some(fd))),
            endpoints,
        }
    }
    /// Length must be packet aligned using descriptor out_max_packet_size
    /// (the current descriptor parser enforces identical IN/OUT packet sizes).
    pub fn submit_read(&mut self, length: usize) -> io::Result<TransferId> {
        let packet = usize::from(self.endpoints.out_max_packet_size);
        if length == 0 || length > i32::MAX as usize || packet == 0 || length % packet != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IN URB length must be positive, i32-sized and packet aligned",
            ));
        }
        self.engine
            .submit(self.endpoints.bulk_in_endpoint_address, vec![0; length])
    }
    /// Owned copy; zero-length OUT explicitly submits a ZLP. Short OUT is
    /// reported, never automatically retried or treated as a complete frame.
    pub fn submit_write(&mut self, data: &[u8]) -> io::Result<TransferId> {
        if data.len() > i32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OUT URB too large",
            ));
        }
        self.engine
            .submit(self.endpoints.bulk_out_endpoint_address, data.to_vec())
    }
    pub fn poll(&mut self) -> io::Result<Option<Completion>> {
        self.engine.poll()
    }
    /// Requests DISCARD once; caller must keep polling for the final completion.
    /// Linux proc_unlinkurb calls usb_kill_urb: this syscall is NOT guaranteed
    /// a hard wall-clock bound. It never frees user storage or discards progress.
    pub fn cancel(&mut self, id: TransferId) -> io::Result<()> {
        self.engine.cancel(id)
    }
    /// Bounded userspace wait using only REAPURBNDELAY. Expiry preserves pending
    /// ownership and returns None, not a transfer timeout or automatic cancel.
    pub fn wait(&mut self, budget: Duration) -> io::Result<Option<Completion>> {
        self.engine.wait(budget)
    }
    pub fn pending_count(&self) -> usize {
        self.engine.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    enum Step {
        Pending,
        Complete(usize, i32, Vec<u8>),
        Error(i32),
        BadActual(i32),
        Unknown,
    }
    struct Fake {
        urbs: Vec<*mut Urb>,
        steps: VecDeque<Step>,
        discard_errno: Option<i32>,
        submits: usize,
        submit_errno: Option<i32>,
        closed: std::rc::Rc<std::cell::Cell<usize>>,
        reaps: usize,
        discards: usize,
    }
    impl Fake {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                urbs: vec![],
                steps: steps.into(),
                discard_errno: None,
                submits: 0,
                submit_errno: None,
                closed: Default::default(),
                reaps: 0,
                discards: 0,
            }
        }
    }
    impl Syscalls for Fake {
        unsafe fn ioctl(&mut self, req: u32, arg: *mut libc::c_void) -> io::Result<i32> {
            match req {
                SUBMIT => {
                    if let Some(errno) = self.submit_errno {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                    let u = arg.cast::<Urb>();
                    assert_eq!((*u).kind, 3);
                    assert_eq!((*u).flags, 0);
                    assert_eq!((*u).signr, 0);
                    self.urbs.push(u);
                    self.submits += 1;
                    Ok(0)
                }
                DISCARD => {
                    assert!(self.urbs.contains(&arg.cast()));
                    self.discards += 1;
                    match self.discard_errno {
                        Some(e) => Err(io::Error::from_raw_os_error(e)),
                        None => Ok(0),
                    }
                }
                REAP => match self.steps.pop_front().unwrap_or(Step::Pending) {
                    Step::Pending => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
                    Step::Error(e) => {
                        if e == libc::EFAULT {
                            self.urbs.remove(0);
                        }
                        Err(io::Error::from_raw_os_error(e))
                    }
                    Step::Unknown => {
                        *arg.cast::<*mut Urb>() = std::ptr::null_mut();
                        Ok(0)
                    }
                    Step::BadActual(actual) => {
                        let u = self.urbs.remove(0);
                        (*u).actual_length = actual;
                        *arg.cast::<*mut Urb>() = u;
                        self.reaps += 1;
                        Ok(0)
                    }
                    Step::Complete(index, status, data) => {
                        let u = self.urbs.remove(index);
                        assert!(data.len() <= (*u).buffer_length as usize);
                        if (*u).endpoint & 0x80 != 0 {
                            std::ptr::copy_nonoverlapping(data.as_ptr(), (*u).buffer, data.len());
                        }
                        (*u).status = status;
                        (*u).actual_length = data.len() as i32;
                        *arg.cast::<*mut Urb>() = u;
                        self.reaps += 1;
                        Ok(0)
                    }
                },
                _ => panic!("unexpected ioctl {req:x}"),
            }
        }
        fn shutdown(&mut self) {
            self.closed.set(self.closed.get() + 1);
            // Buffers/URBs must still be alive when fd-close replacement runs.
            for &u in &self.urbs {
                unsafe {
                    assert_eq!((*u).kind, 3);
                    if (*u).buffer_length > 0 {
                        let _ = std::ptr::read_volatile((*u).buffer);
                    }
                }
            }
            self.urbs.clear();
        }
    }
    #[test]
    fn pending_then_partial_completion_preserves_bytes_and_identity() {
        let mut e = Engine::new(Fake::new(vec![
            Step::Pending,
            Step::Complete(0, 0, b"abc".to_vec()),
        ]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        assert!(e.poll().unwrap().is_none());
        assert_eq!(e.pending.len(), 1);
        let c = e.poll().unwrap().expect("submitted URB must be reaped");
        assert_eq!(c.id, id);
        assert_eq!(c.actual_length, 3);
        assert_eq!(c.data, b"abc");
        assert_eq!(c.status, 0);
        assert!(e.poll().unwrap().is_none());
        assert_eq!(e.sys.reaps, 1);
        assert_eq!(e.sys.submits, 1);
    }
    #[test]
    fn cancel_keeps_partial_progress_until_one_reap() {
        let mut e = Engine::new(Fake::new(vec![
            Step::Pending,
            Step::Complete(0, -libc::ENOENT, b"xy".to_vec()),
        ]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        e.cancel(id).unwrap();
        e.cancel(id).unwrap();
        assert_eq!(e.sys.discards, 1);
        assert_eq!(e.pending.len(), 1);
        assert!(e.poll().unwrap().is_none());
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.actual_length, 2);
        assert_eq!(c.data, b"xy");
        assert_eq!(c.status, -libc::ENOENT);
        assert!(c.cancellation_requested);
        assert_eq!(e.cancel(id).unwrap_err().raw_os_error(), Some(libc::ENOENT));
        assert!(e.poll().unwrap().is_none());
        assert_eq!(e.sys.reaps, 1);
    }
    #[test]
    fn completion_wins_discard_einval_race() {
        let mut fake = Fake::new(vec![Step::Complete(0, 0, b"ok".to_vec())]);
        fake.discard_errno = Some(libc::EINVAL);
        let mut e = Engine::new(fake);
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        e.cancel(id).unwrap();
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.status, 0);
        assert_eq!(c.data, b"ok");
        assert!(c.cancellation_requested);
    }
    #[test]
    fn discard_error_is_not_completion_and_can_retry() {
        let mut e = Engine::new(Fake::new(vec![Step::Complete(
            0,
            -libc::ECONNRESET,
            vec![7],
        )]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        e.sys.discard_errno = Some(libc::EIO);
        assert_eq!(e.cancel(id).unwrap_err().raw_os_error(), Some(libc::EIO));
        assert!(!e.pending[&id].cancellation_requested);
        e.sys.discard_errno = None;
        e.cancel(id).unwrap();
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.data, [7]);
        assert_eq!(c.status, -libc::ECONNRESET);
    }
    #[test]
    fn reap_errno_keeps_pending_without_resubmit() {
        for errno in [libc::EINTR, libc::ENODEV, libc::EIO] {
            let mut e = Engine::new(Fake::new(vec![
                Step::Error(errno),
                Step::Complete(0, -libc::EPIPE, vec![9]),
            ]));
            let id = e.submit(0x81, vec![0; 512]).unwrap();
            assert_eq!(e.poll().unwrap_err().raw_os_error(), Some(errno));
            assert_eq!(e.pending.len(), 1);
            let c = e.poll().unwrap().unwrap();
            assert_eq!(c.id, id);
            assert_eq!(c.data, [9]);
            assert_eq!(c.status, -libc::EPIPE);
            assert_eq!(e.sys.submits, 1);
        }
    }
    #[test]
    fn duplex_out_of_order_completion_and_endpoint_admission() {
        let mut e = Engine::new(Fake::new(vec![
            Step::Complete(1, 0, b"ab".to_vec()),
            Step::Complete(0, 0, vec![3]),
        ]));
        let read = e.submit(0x81, vec![0; 512]).unwrap();
        let write = e.submit(0x01, b"abcd".to_vec()).unwrap();
        assert_eq!(
            e.submit(0x81, vec![0; 512]).unwrap_err().raw_os_error(),
            Some(libc::EBUSY)
        );
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.id, write);
        assert_eq!(c.actual_length, 2);
        assert!(c.data.is_empty());
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.id, read);
        assert_eq!(c.data, [3]);
        assert_eq!(e.sys.submits, 2);
        assert_eq!(e.sys.reaps, 2);
    }
    #[test]
    fn zero_progress_and_explicit_zlp_are_completions_not_retry() {
        let mut e = Engine::new(Fake::new(vec![
            Step::Complete(0, 0, vec![]),
            Step::Complete(0, 0, vec![]),
        ]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.id, id);
        assert_eq!(c.actual_length, 0);
        let id = e.submit(1, vec![]).unwrap();
        let c = e.poll().unwrap().unwrap();
        assert_eq!(c.id, id);
        assert_eq!(c.actual_length, 0);
        assert_eq!(e.sys.submits, 2);
    }
    #[test]
    fn wait_deadline_preserves_pending_and_is_bounded() {
        let mut e = Engine::new(Fake::new(vec![]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        let start = Instant::now();
        assert!(e.wait(Duration::from_millis(5)).unwrap().is_none());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(e.pending.len(), 1);
        assert_eq!(e.sys.submits, 1);
        assert_eq!(e.sys.discards, 0);
        e.sys.steps.push_back(Step::Complete(0, 0, vec![1, 2]));
        assert_eq!(e.wait(Duration::ZERO).unwrap().unwrap().id, id);
    }
    #[test]
    fn buffer_survives_owner_move_cancel_and_drop_closes_before_free() {
        let mut e = Engine::new(Fake::new(vec![]));
        let id = e.submit(0x81, vec![0x5a; 512]).unwrap();
        let pointer = e.sys.urbs[0];
        let closed = e.sys.closed.clone();
        let mut moved = Box::new(e);
        moved.cancel(id).unwrap();
        assert_eq!(moved.sys.urbs[0], pointer);
        assert_eq!(unsafe { *(*pointer).buffer }, 0x5a);
        drop(moved); // Fake shutdown dereferences pending buffers before free.
        assert_eq!(closed.get(), 1);
    }
    #[test]
    fn native_ioctl_errno_and_public_owner_validation() {
        let f = File::open("/dev/null").unwrap();
        let mut owner = UsbfsUrbOwner::new(
            f,
            UsbEndpointInfo {
                interface_number: 0,
                bulk_in_endpoint_address: 0x81,
                bulk_out_endpoint_address: 1,
                out_max_packet_size: 512,
            },
        );
        assert_eq!(
            owner.submit_read(24).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            owner.submit_read(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            owner.submit_read(512).unwrap_err().raw_os_error(),
            Some(libc::ENOTTY)
        );
        assert_eq!(
            owner.submit_write(b"abc").unwrap_err().raw_os_error(),
            Some(libc::ENOTTY)
        );
        assert_eq!(owner.pending_count(), 0);
        assert!(owner.wait(Duration::ZERO).unwrap().is_none());
        let mut u = Urb::default();
        assert_eq!(
            unsafe { usbdevfs_ioctl(-1, SUBMIT, &mut u) }
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }
    #[test]
    fn submit_errno_retains_no_kernel_owned_storage_and_can_retry() {
        let mut e = Engine::new(Fake::new(vec![]));
        e.sys.submit_errno = Some(libc::ENODEV);
        assert_eq!(
            e.submit(0x81, vec![0; 512]).unwrap_err().raw_os_error(),
            Some(libc::ENODEV)
        );
        assert!(e.pending.is_empty());
        assert!(e.sys.urbs.is_empty());
        e.sys.submit_errno = None;
        assert!(e.submit(0x81, vec![0; 512]).is_ok());
    }
    #[test]
    fn invalid_actual_length_fails_closed_after_exactly_one_reap() {
        for actual in [-1, 513] {
            let mut e = Engine::new(Fake::new(vec![Step::BadActual(actual)]));
            e.submit(0x81, vec![0; 512]).unwrap();
            assert_eq!(e.poll().unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(e.pending.is_empty());
            assert_eq!(e.sys.reaps, 1);
        }
    }
    #[test]
    fn efault_consumed_completion_poison_requires_close_not_retry() {
        let mut e = Engine::new(Fake::new(vec![Step::Error(libc::EFAULT)]));
        let id = e.submit(0x81, vec![0; 512]).unwrap();
        assert_eq!(e.poll().unwrap_err().raw_os_error(), Some(libc::EFAULT));
        assert_eq!(e.pending.len(), 1);
        assert!(e.sys.urbs.is_empty());
        assert!(e.poll().is_err());
        assert!(e.cancel(id).is_err());
        assert!(e.submit(1, vec![1]).is_err());
        let closed = e.sys.closed.clone();
        drop(e);
        assert_eq!(closed.get(), 1);
    }
    #[test]
    fn unknown_reap_pointer_is_not_dereferenced_and_requires_close() {
        let mut e = Engine::new(Fake::new(vec![Step::Unknown]));
        e.submit(0x81, vec![0; 512]).unwrap();
        assert_eq!(e.poll().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(e.pending.len(), 1);
        assert!(e.poll().is_err());
    }
    #[test]
    fn abi_matches_linux_uapi_native_layout() {
        use std::mem::{offset_of, size_of};
        if size_of::<usize>() == 8 {
            assert_eq!(size_of::<Urb>(), 56);
            assert_eq!(offset_of!(Urb, buffer), 16);
            assert_eq!(offset_of!(Urb, actual_length), 28);
            assert_eq!(offset_of!(Urb, usercontext), 48);
            assert_eq!(SUBMIT, 0x8038550a);
            assert_eq!(REAP, 0x4008550d);
        } else {
            assert_eq!(size_of::<Urb>(), 44);
            assert_eq!(offset_of!(Urb, buffer), 12);
            assert_eq!(offset_of!(Urb, actual_length), 20);
            assert_eq!(offset_of!(Urb, usercontext), 40);
            assert_eq!(SUBMIT, 0x802c550a);
            assert_eq!(REAP, 0x4004550d);
        }
        assert_eq!(DISCARD, 0x550b);
    }
}
