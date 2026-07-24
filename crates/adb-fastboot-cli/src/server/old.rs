//! Old monolithic ADB server module — kept for tests until fully migrated.
//! All production code has been moved to sub-modules (models, handler, runner,
//! forward, bridge, watcher).

// Re-export everything from the parent server module so `super::*` in tests works.
pub(crate) use super::{
    dispatch_host_service, parse_adb_host_port, parse_spec_pair,
    is_usable_state, DeviceState, DeviceOrigin, DeviceEntry, TransportRegistry,
    run_server, run_server_fork, run_server_on_port, run_server_with_listener,
};

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use adb_protocol::{AdbMessageHeader, ADB_VERSION, A_CNXN, MAX_PAYLOAD_V2};

    use super::*;

    #[test]
    fn test_parse_adb_host_port_supports_ipv4_hostname_and_bracketed_ipv6() {
        assert_eq!(parse_adb_host_port("127.0.0.1:5555").unwrap(), ("127.0.0.1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("device.local:5555").unwrap(), ("device.local".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[::1]:5555").unwrap(), ("::1".to_string(), 5555));
        assert_eq!(parse_adb_host_port("[fe80::1%wlan0]:5555").unwrap(), ("fe80::1%wlan0".to_string(), 5555));
    }

    #[test]
    fn test_parse_adb_host_port_rejects_ambiguous_or_invalid_addresses() {
        assert!(parse_adb_host_port("::1:5555").is_err());
        assert!(parse_adb_host_port("[::1]").is_err());
        assert!(parse_adb_host_port("host:not-a-port").is_err());
        assert!(parse_adb_host_port("host:0").is_err());
        assert!(parse_adb_host_port(":5555").is_err());
    }

    #[test]
    fn test_host_connect_ipv6_wire_and_canonical_serial() {
        let device_listener = TcpListener::bind("[::1]:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut request_header = [0u8; 24];
            stream.read_exact(&mut request_header).unwrap();
            let request = AdbMessageHeader::decode(&request_header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response_payload = b"device::features=shell_v2;";
            let response = AdbMessageHeader::new(
                A_CNXN,
                ADB_VERSION,
                MAX_PAYLOAD_V2,
                response_payload,
            );
            let mut response_header = [0u8; 24];
            response.encode(&mut response_header);
            stream.write_all(&response_header).unwrap();
            stream.write_all(response_payload).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let command = format!("host:connect:[::1]:{}", device_addr.port());
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let mut client = TcpStream::connect(server_addr).unwrap();
        let mut status = [0u8; 4];
        client.read_exact(&mut status).unwrap();
        assert_eq!(&status, b"OKAY");
        let mut length = [0u8; 4];
        client.read_exact(&mut length).unwrap();
        let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
        let mut payload = vec![0u8; length];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(std::str::from_utf8(&payload).unwrap(), format!("[::1]:{}", device_addr.port()));

        server.join().unwrap();
        device.join().unwrap();
        let reg = registry.lock().unwrap();
        assert!(reg.find_by_serial(&format!("[::1]:{}", device_addr.port())).is_some());
    }

    #[test]
    fn test_transport_selection_accepts_only_aosp_online_states() {
        assert!(is_usable_state(DeviceState::Device));
        assert!(is_usable_state(DeviceState::Recovery));
        assert!(is_usable_state(DeviceState::Sideload));
        assert!(is_usable_state(DeviceState::Bootloader));
        assert!(!is_usable_state(DeviceState::Offline));
        assert!(!is_usable_state(DeviceState::Authorizing));
        assert!(!is_usable_state(DeviceState::Connecting));
        assert!(!is_usable_state(DeviceState::NoPerm));
    }

    #[test]
    fn test_connect_consumes_response_cnxn_banner_length() {
        use std::net::TcpListener;
        use std::thread;

        let device_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let banner = b"device::features=shell_v2;".to_vec();
        let device = thread::spawn(move || {
            let (mut stream, _) = device_listener.accept().unwrap();
            let mut header = [0u8; 24];
            stream.read_exact(&mut header).unwrap();
            let request = AdbMessageHeader::decode(&header).unwrap();
            let mut request_payload = vec![0u8; request.data_length as usize];
            stream.read_exact(&mut request_payload).unwrap();

            let response = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, &banner);
            response.encode(&mut header);
            stream.write_all(&header).unwrap();
            stream.write_all(&banner).unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            let command = format!("host:connect:{device_addr}");
            dispatch_host_service(&mut stream, &command, &server_registry, &server_running).unwrap();
        });

        let _client = TcpStream::connect(server_addr).unwrap();
        server.join().unwrap();
        device.join().unwrap();

        let serial = device_addr.to_string();
        let reg = registry.lock().unwrap();
        assert_eq!(reg.find_by_serial(&serial).unwrap().transport_features.as_deref(),
                   Some("device::features=shell_v2;"));
    }

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
    fn test_track_devices_emits_initial_snapshot() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:track-devices",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut okay = [0u8; 4];
        client.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        let snapshot_len = usize::from_str_radix(std::str::from_utf8(&len).unwrap(), 16).unwrap();
        let mut snapshot = vec![0u8; snapshot_len];
        client.read_exact(&mut snapshot).unwrap();
        assert!(std::str::from_utf8(&snapshot).is_ok());

        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn test_wait_for_device_acknowledges_available_transport() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(TransportRegistry::new()));
        registry.lock().unwrap().devices.push(DeviceEntry {
            serial: "test-device".to_string(),
            transport_id: 1,
            state: DeviceState::Device,
            origin: DeviceOrigin::Tcp {
                addr: "127.0.0.1:5555".parse().unwrap(),
            },
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
        let running = Arc::new(AtomicBool::new(true));
        let server_registry = Arc::clone(&registry);
        let server_running = Arc::clone(&running);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            dispatch_host_service(
                &mut stream,
                "host:wait-for-device",
                &server_registry,
                &server_running,
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"OKAY");
        running.store(false, Ordering::Relaxed);
        drop(client);
        server.join().unwrap();
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
