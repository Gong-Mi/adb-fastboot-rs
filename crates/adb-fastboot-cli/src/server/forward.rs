//! ADB Forward/Reverse host services — dispatch, spec parsing, background listeners.
//!
//! Mirrors AOSP `adb_listeners.cpp` and `forward.cpp`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_WRTE, MAX_PAYLOAD_V2};

use crate::server::models::{DeviceOrigin, ForwardRule, ReverseRule, TransportRegistry};

// ===================================================================
// TransportRegistry forward/reverse methods (extended impl)
// ===================================================================

impl TransportRegistry {
    pub(crate) fn list_forwards(&self) -> String {
        if self.forwards.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for fw in &self.forwards {
            out.push_str(&format!("{} {} {}\n", fw.serial, fw.local, fw.remote));
        }
        out
    }

    pub(crate) fn add_forward(
        &mut self,
        registry_arc: &Arc<Mutex<TransportRegistry>>,
        local_spec: &str,
        remote_spec: &str,
        no_rebind: bool,
    ) -> Result<String, String> {
        let (bound_port, canonical_local, listener) =
            if local_spec.starts_with("tcp:") || local_spec.chars().all(|c| c.is_ascii_digit()) {
                let port_str = if local_spec.starts_with("tcp:") {
                    &local_spec["tcp:".len()..]
                } else {
                    local_spec
                };
                let requested_port: u16 = port_str
                    .parse()
                    .map_err(|_| format!("invalid port in local spec: {local_spec}"))?;
                let l = TcpListener::bind(format!("127.0.0.1:{requested_port}"))
                    .map_err(|e| format!("cannot bind listener for {local_spec}: {e}"))?;
                let p = l
                    .local_addr()
                    .map_err(|e| format!("cannot get local addr: {e}"))?
                    .port();
                (p, format!("tcp:{p}"), Some(l))
            } else {
                (0, local_spec.to_string(), None)
            };

        if no_rebind && self.forwards.iter().any(|f| f.local == canonical_local) {
            return Err(format!("forward '{canonical_local}' already exists"));
        }

        self.remove_forward(&canonical_local);

        let active_flag = Arc::new(AtomicBool::new(true));

        if let Some(listener) = listener {
            let active = Arc::clone(&active_flag);
            let remote_str = remote_spec.to_string();
            let reg_arc = Arc::clone(registry_arc);
            thread::spawn(move || {
                run_forward_listener(listener, active, remote_str, reg_arc);
            });
        }

        let serial = self
            .find_any_device()
            .map(|d| d.serial.clone())
            .unwrap_or_else(|| "127.0.0.1:5555".to_string());

        self.forwards.push(ForwardRule {
            serial,
            local: canonical_local,
            remote: remote_spec.to_string(),
            active_flag,
        });

        if local_spec == "tcp:0" || local_spec == "0" {
            Ok(bound_port.to_string())
        } else {
            Ok(String::new())
        }
    }

    pub(crate) fn remove_forward(&mut self, local: &str) -> bool {
        let canonical = if !local.starts_with("tcp:") && local.chars().all(|c| c.is_ascii_digit()) {
            format!("tcp:{local}")
        } else {
            local.to_string()
        };
        let mut removed = false;
        self.forwards.retain(|f| {
            if f.local == canonical || f.local == local {
                f.active_flag.store(false, Ordering::Relaxed);
                removed = true;
                false
            } else {
                true
            }
        });
        removed
    }

    pub(crate) fn remove_all_forwards(&mut self) {
        for f in &self.forwards {
            f.active_flag.store(false, Ordering::Relaxed);
        }
        self.forwards.clear();
    }

    pub(crate) fn list_reverses(&self) -> String {
        if self.reverses.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for r in &self.reverses {
            out.push_str(&format!("{} {} {}\n", r.serial, r.remote, r.local));
        }
        out
    }

    pub(crate) fn add_reverse(&mut self, remote: &str, local: &str, no_rebind: bool) -> Result<(), String> {
        if no_rebind && self.reverses.iter().any(|r| r.remote == remote) {
            return Err(format!("reverse forward '{remote}' already exists"));
        }
        self.reverses.retain(|r| r.remote != remote);
        let serial = self
            .find_any_device()
            .map(|d| d.serial.clone())
            .unwrap_or_else(|| "127.0.0.1:5555".to_string());
        self.reverses.push(ReverseRule {
            serial,
            remote: remote.to_string(),
            local: local.to_string(),
        });
        Ok(())
    }

    pub(crate) fn remove_reverse(&mut self, remote: &str) -> bool {
        let before = self.reverses.len();
        self.reverses.retain(|r| r.remote != remote);
        before != self.reverses.len()
    }

    pub(crate) fn remove_all_reverses(&mut self) {
        self.reverses.clear();
    }
}

// ---------------------------------------------------------------------------
// Spec Pair Parsing Helper
// ---------------------------------------------------------------------------

pub(crate) fn parse_spec_pair(s: &str) -> Option<(&str, &str)> {
    if let Some((a, b)) = s.split_once(';') {
        return Some((a, b));
    }
    let prefixes = [
        "tcp:",
        "localabstract:",
        "localreserved:",
        "localfilesystem:",
        "dev:",
        "jdwp:",
    ];
    for prefix in &prefixes {
        if s.starts_with(prefix) {
            let rest = &s[prefix.len()..];
            if let Some((p1, _p2)) = rest.split_once(':') {
                let first_len = prefix.len() + p1.len();
                return Some((&s[..first_len], &s[first_len + 1..]));
            }
        }
    }
    if let Some((a, b)) = s.split_once(':') {
        return Some((a, b));
    }
    None
}

// ---------------------------------------------------------------------------
// Background TCP Forwarding Listener & Bridge
// ---------------------------------------------------------------------------

pub(crate) fn run_forward_listener(
    listener: TcpListener,
    active: Arc<AtomicBool>,
    remote_spec: String,
    registry: Arc<Mutex<TransportRegistry>>,
) {
    listener.set_nonblocking(true).ok();
    while active.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client_conn, _)) => {
                let reg = Arc::clone(&registry);
                let remote = remote_spec.clone();
                thread::spawn(move || {
                    forward_connection_to_device(client_conn, &remote, &reg);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn forward_connection_to_device(
    mut client_conn: std::net::TcpStream,
    remote: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) {
    let origin = {
        let Ok(reg) = registry.lock() else { return; };
        reg.find_any_device().map(|d| d.origin)
    };

    let Some(DeviceOrigin::Tcp { addr }) = origin else {
        return;
    };

    let Ok(mut device_stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return;
    };
    let _ = device_stream.set_nodelay(true);
    let _ = client_conn.set_nodelay(true);

    let probe = b"host::";
    let cnxn = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, probe);
    let mut hdr_buf = [0u8; 24];
    cnxn.encode(&mut hdr_buf);

    if device_stream.write_all(&hdr_buf).is_err()
        || device_stream.write_all(probe).is_err()
        || device_stream.flush().is_err()
    {
        return;
    }

    if device_stream.read_exact(&mut hdr_buf).is_err() {
        return;
    }
    let Ok(cnxn_resp) = AdbMessageHeader::decode(&hdr_buf) else {
        return;
    };
    if cnxn_resp.command != A_CNXN {
        return;
    }
    let payload_len = cnxn_resp.data_length as usize;
    if payload_len > 0 {
        let mut dummy = vec![0u8; payload_len];
        let _ = device_stream.read_exact(&mut dummy);
    }

    let local_id = 1u32;
    let open_hdr = AdbMessageHeader::new(A_OPEN, local_id, 0, remote.as_bytes());
    open_hdr.encode(&mut hdr_buf);
    if device_stream.write_all(&hdr_buf).is_err()
        || device_stream.write_all(remote.as_bytes()).is_err()
        || device_stream.flush().is_err()
    {
        return;
    }

    let remote_id = loop {
        if device_stream.read_exact(&mut hdr_buf).is_err() {
            return;
        }
        let Ok(resp) = AdbMessageHeader::decode(&hdr_buf) else {
            return;
        };
        if resp.command == A_OKAY {
            break resp.arg0;
        } else if resp.command == A_CLSE {
            return;
        }
    };

    let mut client_read = match client_conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut device_write = match device_stream.try_clone() {
        Ok(d) => d,
        Err(_) => return,
    };

    let h1 = thread::spawn(move || -> std::io::Result<()> {
        let mut buf = [0u8; 16384];
        loop {
            let n = client_read.read(&mut buf)?;
            if n == 0 {
                let clse = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let mut buf24 = [0u8; 24];
                clse.encode(&mut buf24);
                let _ = device_write.write_all(&buf24);
                let _ = device_write.flush();
                break;
            }
            let wrte = AdbMessageHeader::new(A_WRTE, local_id, remote_id, &buf[..n]);
            let mut buf24 = [0u8; 24];
            wrte.encode(&mut buf24);
            if device_write.write_all(&buf24).is_err()
                || device_write.write_all(&buf[..n]).is_err()
                || device_write.flush().is_err()
            {
                break;
            }
        }
        Ok(())
    });

    let h2 = thread::spawn(move || -> std::io::Result<()> {
        let mut buf24 = [0u8; 24];
        loop {
            if device_stream.read_exact(&mut buf24).is_err() {
                break;
            }
            let Ok(hdr) = AdbMessageHeader::decode(&buf24) else {
                break;
            };
            if hdr.command == A_WRTE {
                let mut payload = vec![0u8; hdr.data_length as usize];
                if hdr.data_length > 0 {
                    if device_stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    if client_conn.write_all(&payload).is_err() || client_conn.flush().is_err() {
                        break;
                    }
                }
                let ack = AdbMessageHeader::new(A_OKAY, local_id, remote_id, &[]);
                let mut ack_buf = [0u8; 24];
                ack.encode(&mut ack_buf);
                let _ = device_stream.write_all(&ack_buf);
                let _ = device_stream.flush();
            } else if hdr.command == A_CLSE {
                let ack = AdbMessageHeader::new(A_CLSE, local_id, remote_id, &[]);
                let mut ack_buf = [0u8; 24];
                ack.encode(&mut ack_buf);
                let _ = device_stream.write_all(&ack_buf);
                let _ = device_stream.flush();
                break;
            }
        }
        Ok(())
    });

    let _ = h1.join();
    let _ = h2.join();
}

// ---------------------------------------------------------------------------
// host:forward and host:reverse dispatch
// ---------------------------------------------------------------------------

pub(crate) fn handle_forward(
    client: &mut std::net::TcpStream,
    sub: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(), String> {
    let ok_str = |sock: &mut std::net::TcpStream, s: &str| -> Result<(), String> {
        let len_hdr = format!("{:04x}", s.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(s.as_bytes()))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let fail = |sock: &mut std::net::TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    match sub {
        "list" => {
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_forwards()
            };
            ok_str(client, &list)
        }
        "killforward-all" | "remove-all" => {
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            reg.remove_all_forwards();
            ok_str(client, "")
        }
        c if c.starts_with("killforward:") || c.starts_with("remove:") => {
            let local = if let Some(l) = c.strip_prefix("killforward:") {
                l
            } else {
                &c["remove:".len()..]
            };
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            if reg.remove_forward(local) {
                ok_str(client, "")
            } else {
                fail(client, &format!("forward '{local}' not found"))
            }
        }
        c if c.starts_with("norebind:") => {
            let rest = &c["norebind:".len()..];
            match parse_spec_pair(rest) {
                Some((local, remote)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_forward(registry, local, remote, true) {
                        Ok(res) => ok_str(client, &res),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid forward norebind format: use local;remote"),
            }
        }
        other => {
            match parse_spec_pair(other) {
                Some((local, remote)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_forward(registry, local, remote, false) {
                        Ok(res) => ok_str(client, &res),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, &format!("invalid forward: {other}")),
            }
        }
    }
}

pub(crate) fn handle_reverse(
    client: &mut std::net::TcpStream,
    sub: &str,
    registry: &Arc<Mutex<TransportRegistry>>,
) -> Result<(), String> {
    let ok_str = |sock: &mut std::net::TcpStream, s: &str| -> Result<(), String> {
        let len_hdr = format!("{:04x}", s.len());
        sock.write_all(b"OKAY")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(s.as_bytes()))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    let fail = |sock: &mut std::net::TcpStream, msg: &str| -> Result<(), String> {
        let err_bytes = msg.as_bytes();
        let len_hdr = format!("{:04x}", err_bytes.len());
        sock.write_all(b"FAIL")
            .and_then(|_| sock.write_all(len_hdr.as_bytes()))
            .and_then(|_| sock.write_all(err_bytes))
            .and_then(|_| sock.flush())
            .map_err(|e| format!("write failed: {e}"))
    };

    match sub {
        "list" => {
            let list = {
                let reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                reg.list_reverses()
            };
            ok_str(client, &list)
        }
        "killforward-all" | "killreverse-all" | "remove-all" => {
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            reg.remove_all_reverses();
            ok_str(client, "")
        }
        c if c.starts_with("killreverse:") || c.starts_with("killforward:") || c.starts_with("remove:") => {
            let remote = if let Some(r) = c.strip_prefix("killreverse:") {
                r
            } else if let Some(r) = c.strip_prefix("killforward:") {
                r
            } else {
                &c["remove:".len()..]
            };
            let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
            if reg.remove_reverse(remote) {
                ok_str(client, "")
            } else {
                fail(client, &format!("reverse forward '{remote}' not found"))
            }
        }
        c if c.starts_with("norebind:") => {
            let rest = &c["norebind:".len()..];
            match parse_spec_pair(rest) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, true) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid reverse format: use remote;local or remote:local"),
            }
        }
        c if c.starts_with("forward:") => {
            let rest = &c["forward:".len()..];
            match parse_spec_pair(rest) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, false) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, "invalid reverse format: use remote;local or remote:local"),
            }
        }
        other => {
            match parse_spec_pair(other) {
                Some((remote, local)) => {
                    let mut reg = registry.lock().map_err(|e| format!("lock: {e}"))?;
                    match reg.add_reverse(remote, local, false) {
                        Ok(()) => ok_str(client, ""),
                        Err(msg) => fail(client, &msg),
                    }
                }
                None => fail(client, &format!("invalid reverse: {other}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_CNXN, MAX_PAYLOAD_V2};

    use super::*;
    use crate::server::models::TransportRegistry;

    #[test]
    fn test_parse_spec_pair() {
        assert_eq!(
            parse_spec_pair("tcp:8080;tcp:9000"),
            Some(("tcp:8080", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("tcp:8080:tcp:9000"),
            Some(("tcp:8080", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("localabstract:foo;tcp:9000"),
            Some(("localabstract:foo", "tcp:9000"))
        );
        assert_eq!(
            parse_spec_pair("localabstract:foo:tcp:9000"),
            Some(("localabstract:foo", "tcp:9000"))
        );
        assert_eq!(parse_spec_pair("invalid"), None);
    }

    #[test]
    fn test_registry_forward_management() {
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        {
            let mut reg = registry.lock().unwrap();
            let res = reg.add_forward(&registry, "tcp:0", "tcp:9000", false).unwrap();
            assert!(!res.is_empty());
            assert!(reg.list_forwards().contains("tcp:9000"));

            let res_dup = reg.add_forward(&registry, &format!("tcp:{res}"), "tcp:9000", true);
            assert!(res_dup.is_err());

            assert!(reg.remove_forward(&format!("tcp:{res}")));
            assert!(reg.list_forwards().is_empty());
        }
    }

    #[test]
    fn test_registry_reverse_management() {
        let mut reg = TransportRegistry::new();
        assert!(reg.add_reverse("tcp:8080", "tcp:9000", false).is_ok());
        assert!(reg.list_reverses().contains("tcp:8080 tcp:9000"));

        assert!(reg.add_reverse("tcp:8080", "tcp:9000", true).is_err());

        assert!(reg.remove_reverse("tcp:8080"));
        assert!(reg.list_reverses().is_empty());
    }
}
