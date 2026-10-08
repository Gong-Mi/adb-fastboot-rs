use super::*;
use crate::server::models::{AuthenticatedUsbTransport, DeviceEntry, DeviceOrigin, DeviceState};
use adb_protocol::usb_android::{
    urb::{Completion, TransferId},
    urb_transport::{UrbFrameTransport, UrbIo},
};
use adb_protocol::{AdbMessageHeader, A_CLSE, A_OKAY, A_OPEN, A_WRTE};
use std::{
    collections::VecDeque,
    io,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

struct FakeUrb {
    next: u64,
    completions: VecDeque<Completion>,
    incoming: VecDeque<u8>,
    read: Option<TransferId>,
    header: Option<AdbMessageHeader>,
    local: u32,
    trace: Arc<Mutex<Vec<Vec<u8>>>>,
    closed: Arc<AtomicUsize>,
    fail_open: bool,
    fault: u8,
    zero_in: bool,
}
impl FakeUrb {
    fn frame(&mut self, cmd: u32, payload: &[u8]) {
        let h = AdbMessageHeader::new(cmd, 73, self.local, payload);
        let mut header = [0; 24];
        h.encode(&mut header);
        self.incoming.extend(header);
        self.incoming.extend(payload);
    }
    fn service(&mut self, h: AdbMessageHeader, payload: &[u8]) {
        match h.command {
            adb_protocol::A_CNXN => {
                assert_eq!(payload, adb_protocol::host_cnxn_payload());
                self.frame(adb_protocol::A_AUTH, &[7; 20]);
                // AUTH is a transport control frame, not a stream frame.
                let start = self.incoming.len() - 44;
                let mut bytes: Vec<_> = self.incoming.drain(start..).collect();
                let auth = AdbMessageHeader::new(
                    adb_protocol::A_AUTH,
                    adb_protocol::A_AUTH_TOKEN,
                    0,
                    &[7; 20],
                );
                auth.encode((&mut bytes[..24]).try_into().unwrap());
                self.incoming.extend(bytes);
            }
            adb_protocol::A_AUTH => {
                assert_eq!(h.arg0, adb_protocol::A_AUTH_SIGNATURE);
                assert_eq!(payload.len(), 256);
                let banner = b"device::features=shell_v2,cmd;model=fake-urb";
                let cnxn = AdbMessageHeader::new(
                    adb_protocol::A_CNXN,
                    adb_protocol::ADB_VERSION,
                    adb_protocol::MAX_PAYLOAD_V2,
                    banner,
                );
                let mut header = [0; 24];
                cnxn.encode(&mut header);
                self.incoming.extend(header);
                self.incoming.extend(banner);
            }
            A_OPEN => {
                self.local = h.arg0;
                assert_eq!(h.arg1, 0);
                assert_eq!(payload, b"exec:cat\0");
                self.frame(if self.fail_open { A_CLSE } else { A_OKAY }, &[]);
                if !self.fail_open {
                    self.frame(A_WRTE, &[b'x'; 64]);
                }
            }
            A_WRTE => {
                assert_eq!((h.arg0, h.arg1), (self.local, 73));
                assert_eq!(payload, &[b'y'; 64]);
                self.frame(A_OKAY, &[]);
                if self.fault == 6 {
                    self.frame(A_CLSE, &[]);
                }
            }
            A_OKAY => {
                assert_eq!((h.arg0, h.arg1), (self.local, 73));
                if self.fault == 6 {
                    self.frame(A_CLSE, &[]);
                }
            }
            A_CLSE => {
                assert_eq!((h.arg0, h.arg1), (self.local, 73));
                self.frame(A_CLSE, &[]);
            }
            _ => panic!("unexpected frame"),
        }
    }
}
impl UrbIo for FakeUrb {
    fn packet_size(&self) -> usize {
        64
    }
    fn submit_read(&mut self, n: usize) -> io::Result<TransferId> {
        assert_eq!(n % 64, 0);
        assert!(self.read.is_none());
        self.next += 1;
        let id = TransferId(self.next);
        self.read = Some(id);
        Ok(id)
    }
    fn submit_write(&mut self, b: &[u8]) -> io::Result<TransferId> {
        if self.fault == 1 {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        self.trace.lock().unwrap().push(b.to_vec());
        self.next += 1;
        let id = TransferId(self.next);
        self.completions.push_back(Completion {
            id,
            endpoint: 2,
            actual_length: if self.fault == 2 {
                b.len().saturating_sub(1)
            } else {
                b.len()
            },
            data: vec![],
            status: 0,
            cancellation_requested: false,
        });
        if b.is_empty() {
            return Ok(id);
        }
        if let Some(h) = self.header.take() {
            assert_eq!(b.len(), h.data_length as usize);
            self.service(h, b);
        } else {
            assert_eq!(b.len(), 24, "header must be separate USB transfer");
            let h = AdbMessageHeader::decode(b).unwrap();
            if h.data_length == 0 {
                self.service(h, &[]);
            } else {
                self.header = Some(h);
            }
        }
        Ok(id)
    }
    fn poll(&mut self) -> io::Result<Option<Completion>> {
        if self.fault == 3 && !self.completions.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::ENODEV));
        }
        if let Some(c) = self.completions.pop_front() {
            return Ok(Some(c));
        }
        if !self.incoming.is_empty() {
            if let Some(id) = self.read.take() {
                // Split both headers and payload, preserving every byte.
                if !self.zero_in {
                    self.zero_in = true;
                    return Ok(Some(Completion {
                        id,
                        endpoint: 0x81,
                        actual_length: 0,
                        data: vec![],
                        status: 0,
                        cancellation_requested: false,
                    }));
                }
                let data: Vec<_> = self.incoming.drain(..self.incoming.len().min(7)).collect();
                return Ok(Some(Completion {
                    id,
                    endpoint: 0x81,
                    actual_length: data.len(),
                    data,
                    status: if self.fault == 4 { -libc::ENODEV } else { 0 },
                    cancellation_requested: self.fault == 5,
                }));
            }
        }
        Ok(None)
    }
    fn cancel(&mut self, id: TransferId) -> io::Result<()> {
        if self.read == Some(id) {
            self.read = None;
        } else {
            let i = self
                .completions
                .iter()
                .position(|c| c.id == id)
                .expect("cancel known pending transfer");
            self.completions.remove(i);
        }
        Ok(())
    }
}
impl Drop for FakeUrb {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup_fault(
    fail_open: bool,
    fault: u8,
) -> (
    Arc<Mutex<TransportRegistry>>,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<AtomicUsize>,
) {
    let trace = Arc::new(Mutex::new(vec![]));
    let closed = Arc::new(AtomicUsize::new(0));
    let t = UrbFrameTransport::new(FakeUrb {
        next: 0,
        completions: VecDeque::new(),
        incoming: VecDeque::new(),
        read: None,
        header: None,
        local: 0,
        trace: trace.clone(),
        closed: closed.clone(),
        fail_open,
        fault,
        zero_in: false,
    });
    let mut reg = TransportRegistry::new();
    reg.devices.clear();
    reg.devices.push(DeviceEntry {
        serial: "fake-urb".into(),
        transport_id: 42,
        state: DeviceState::Device,
        origin: DeviceOrigin::Usb,
        product: None,
        model: None,
        device_name: None,
        transport_features: None,
    });
    reg.usb_auth.insert(
        "fake-urb".into(),
        AuthenticatedUsbTransport {
            _serial: "fake-urb".into(),
            transport: Some(Box::new(t)),
        },
    );
    (Arc::new(Mutex::new(reg)), trace, closed)
}
pub(crate) fn setup(
    fail_open: bool,
) -> (
    Arc<Mutex<TransportRegistry>>,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<AtomicUsize>,
) {
    setup_fault(fail_open, 0)
}
pub(crate) fn setup_cli() -> (
    Arc<Mutex<TransportRegistry>>,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<AtomicUsize>,
) {
    setup_fault(false, 6)
}
fn command(c: &mut TcpStream, s: &str) {
    c.write_all(format!("{:04x}{s}", s.len()).as_bytes())
        .unwrap();
}
fn status(c: &mut TcpStream) -> [u8; 4] {
    let mut b = [0; 4];
    c.read_exact(&mut b).unwrap();
    b
}
#[test]
fn usb_urb_production_smart_socket_duplex_fragmented_zlp_cleanup() {
    let (reg, trace, closed) = setup(false);
    let r = reg.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    let handle = std::thread::spawn(move || {
        run_smart_socket_loop(server, &r, &Arc::new(AtomicBool::new(true)))
    });
    command(&mut client, "host:transport:fake-urb");
    assert_eq!(&status(&mut client), b"OKAY");
    command(&mut client, "exec:cat");
    assert_eq!(&status(&mut client), b"OKAY");
    client.write_all(&[b'y'; 64]).unwrap();
    let mut output = [0; 64];
    client.read_exact(&mut output).unwrap();
    assert_eq!(output, [b'x'; 64]);
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut b = [0];
    assert_eq!(client.read(&mut b).unwrap(), 0);
    handle.join().unwrap().unwrap();
    let log = trace.lock().unwrap();
    assert!(
        log.iter().any(Vec::is_empty),
        "packet-multiple payload requires ZLP"
    );
    for cmd in [A_OPEN, A_OKAY, A_WRTE, A_CLSE] {
        assert_eq!(
            log.iter()
                .filter(|b| b.len() == 24
                    && AdbMessageHeader::decode(b).is_ok_and(|h| h.command == cmd))
                .count(),
            1
        );
    }
    drop(log);
    assert_eq!(
        closed.load(Ordering::SeqCst),
        1,
        "exclusive owner must close once"
    );
    assert!(!reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
}
#[test]
fn usb_urb_production_errno_short_out_partial_disconnect_and_cancel_fail_closed() {
    for fault in 1..=5 {
        let (reg, trace, closed) = setup_fault(false, fault);
        let r = reg.clone();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (s, _) = l.accept().unwrap();
        let h = std::thread::spawn(move || {
            run_smart_socket_loop(s, &r, &Arc::new(AtomicBool::new(true)))
        });
        command(&mut c, "host:transport:fake-urb");
        assert_eq!(&status(&mut c), b"OKAY");
        command(&mut c, "exec:cat");
        assert_eq!(&status(&mut c), b"FAIL", "fault {fault}");
        let len = status(&mut c);
        let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut error = vec![0; n];
        c.read_exact(&mut error).unwrap();
        assert!(!error.is_empty());
        let mut b = [0];
        assert_eq!(c.read(&mut b).unwrap(), 0);
        assert!(h.join().unwrap().is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        let reg = reg.lock().unwrap();
        assert!(!reg.usb_auth.contains_key("fake-urb"));
        assert_eq!(
            reg.find_by_serial("fake-urb").unwrap().state,
            DeviceState::Offline
        );
        assert!(
            trace.lock().unwrap().len() <= 2,
            "never replay uncertain OUT"
        );
    }
}

#[test]
fn usb_urb_production_server_cancel_closes_owner_and_reservation() {
    let (reg, _, closed) = setup(false);
    let r = reg.clone();
    let running = Arc::new(AtomicBool::new(true));
    let active = running.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (s, _) = l.accept().unwrap();
    let h = std::thread::spawn(move || run_smart_socket_loop(s, &r, &active));
    command(&mut c, "host:transport:fake-urb");
    assert_eq!(&status(&mut c), b"OKAY");
    command(&mut c, "exec:cat");
    assert_eq!(&status(&mut c), b"OKAY");
    // Wait for output acknowledgement before cancelling to keep this assertion
    // independent of the explicit cancellation policy that revokes output.
    let mut output = [0; 64];
    c.read_exact(&mut output).unwrap();
    running.store(false, Ordering::Release);
    let mut b = [0];
    assert_eq!(c.read(&mut b).unwrap(), 0);
    assert!(h.join().unwrap().unwrap_err().contains("cancelled"));
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(!reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
}

#[test]
fn usb_urb_production_auth_cnxn_uses_same_owner_and_banner() {
    let (reg, trace, closed) = setup(false);
    let transport = reg
        .lock()
        .unwrap()
        .usb_auth
        .get_mut("fake-urb")
        .unwrap()
        .transport
        .take()
        .unwrap();
    let auth = adb_protocol::AdbAuth::generate("usb-urb-fixture").unwrap();
    let t =
        crate::server::transport::authenticate_usb_transport(transport, "fake-urb", &reg, &auth)
            .unwrap();
    assert!(reg
        .lock()
        .unwrap()
        .find_by_serial("fake-urb")
        .unwrap()
        .transport_features
        .as_ref()
        .unwrap()
        .contains("shell_v2"));
    assert_eq!(
        trace
            .lock()
            .unwrap()
            .iter()
            .filter(|b| b.len() == 24)
            .count(),
        2
    );
    drop(t);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[test]
fn usb_urb_production_no_capability_remains_explicit_fail_before_open() {
    struct Unsupported(std::io::Cursor<Vec<u8>>);
    impl Read for Unsupported {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Write for Unsupported {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("no capability must fail before OPEN")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl adb_protocol::Transport for Unsupported {}
    let (reg, trace, closed) = setup(false);
    reg.lock()
        .unwrap()
        .usb_auth
        .get_mut("fake-urb")
        .unwrap()
        .transport = Some(Box::new(Unsupported(std::io::Cursor::new(vec![]))));
    let r = reg.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (s, _) = l.accept().unwrap();
    let h =
        std::thread::spawn(move || run_smart_socket_loop(s, &r, &Arc::new(AtomicBool::new(true))));
    command(&mut c, "host:transport:fake-urb");
    assert_eq!(&status(&mut c), b"OKAY");
    command(&mut c, "exec:cat");
    assert_eq!(&status(&mut c), b"FAIL");
    let len = status(&mut c);
    let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
    let mut e = vec![0; n];
    c.read_exact(&mut e).unwrap();
    assert!(String::from_utf8(e)
        .unwrap()
        .contains("capability unavailable"));
    assert!(h.join().unwrap().is_err());
    assert!(trace.lock().unwrap().is_empty());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(!reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
}

#[test]
fn usb_urb_production_busy_reservation_does_not_claim_or_invalidate() {
    let (reg, trace, closed) = setup(false);
    let owner = reg
        .lock()
        .unwrap()
        .usb_auth
        .get_mut("fake-urb")
        .unwrap()
        .transport
        .take()
        .unwrap();
    let r = reg.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (s, _) = l.accept().unwrap();
    let h =
        std::thread::spawn(move || run_smart_socket_loop(s, &r, &Arc::new(AtomicBool::new(true))));
    command(&mut c, "host:transport:fake-urb");
    assert_eq!(&status(&mut c), b"OKAY");
    command(&mut c, "exec:cat");
    assert_eq!(&status(&mut c), b"FAIL");
    let len = status(&mut c);
    let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
    let mut e = vec![0; n];
    c.read_exact(&mut e).unwrap();
    assert!(String::from_utf8(e).unwrap().contains("busy"));
    assert!(h.join().unwrap().is_err());
    assert_eq!(closed.load(Ordering::SeqCst), 0);
    assert!(trace.lock().unwrap().is_empty());
    assert!(reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
    drop(owner);
}

#[test]
fn usb_urb_production_open_rejection_is_fail_and_cleanup() {
    let (reg, _, closed) = setup(true);
    let r = reg.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (s, _) = listener.accept().unwrap();
    let h =
        std::thread::spawn(move || run_smart_socket_loop(s, &r, &Arc::new(AtomicBool::new(true))));
    command(&mut c, "host:transport:fake-urb");
    assert_eq!(&status(&mut c), b"OKAY");
    command(&mut c, "exec:cat");
    assert_eq!(&status(&mut c), b"FAIL");
    let len = status(&mut c);
    let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
    let mut e = vec![0; n];
    c.read_exact(&mut e).unwrap();
    assert!(String::from_utf8(e).unwrap().contains("rejected service"));
    assert!(h.join().unwrap().is_err());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(!reg.lock().unwrap().usb_auth.contains_key("fake-urb"));
}
