use fastboot_protocol::{FastbootResponse, FastbootTransport};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn getvar_all_collects_multiple_info_responses_from_fake_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut command = [0u8; 10];
        socket.read_exact(&mut command).unwrap();
        assert_eq!(&command, b"getvar:all");
        // A real peer sends one or more INFO packets followed by the terminal status.
        socket
            .write_all(b"INFOproduct:demo\nINFOcurrent-slot: a\nOKAY")
            .unwrap();
    });

    let mut transport = fastboot_protocol::FastbootTcpTransport::raw_connect(addr).unwrap();
    transport.send_cmd("getvar:all").unwrap();
    let mut info = Vec::new();
    let response = transport.recv_response_with_info(&mut info).unwrap();

    assert_eq!(info, vec!["product:demo\n", "current-slot: a\n"]);
    assert_eq!(response, FastbootResponse::Okay(String::new()));
    server.join().unwrap();
}

#[test]
fn set_active_sends_aosp_wire_command_to_fake_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut command = [0u8; 12];
        socket.read_exact(&mut command).unwrap();
        assert_eq!(&command, b"set_active:b");
        socket.write_all(b"OKAY").unwrap();
    });

    let mut transport = fastboot_protocol::FastbootTcpTransport::raw_connect(addr).unwrap();
    transport.send_cmd("set_active:b").unwrap();
    assert_eq!(transport.recv_response().unwrap(), FastbootResponse::Okay(String::new()));
    server.join().unwrap();
}

#[test]
fn fastboot_boot_payload_and_boot_command_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let boot_payload = fastboot_protocol::BootImageBuilder::new()
        .kernel(b"dummy kernel payload".to_vec())
        .ramdisk(b"dummy ramdisk payload".to_vec())
        .build();

    let payload_len = boot_payload.len();
    let expected_dl_cmd = format!("download:{:08x}", payload_len);

    let expected_payload = boot_payload.clone();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();

        // 1. Receive download command
        let mut cmd_buf = vec![0u8; expected_dl_cmd.len()];
        socket.read_exact(&mut cmd_buf).unwrap();
        assert_eq!(String::from_utf8(cmd_buf).unwrap(), expected_dl_cmd);

        // 2. Respond DATA<len_hex>
        let data_resp = format!("DATA{:08x}", payload_len);
        socket.write_all(data_resp.as_bytes()).unwrap();

        // 3. Receive payload
        let mut payload_buf = vec![0u8; payload_len];
        socket.read_exact(&mut payload_buf).unwrap();
        assert_eq!(payload_buf, expected_payload);

        // 4. Respond OKAY post-download
        socket.write_all(b"OKAY").unwrap();

        // 5. Receive boot command
        let mut boot_cmd = [0u8; 4];
        socket.read_exact(&mut boot_cmd).unwrap();
        assert_eq!(&boot_cmd, b"boot");

        // 6. Respond OKAYbooting
        socket.write_all(b"OKAYbooting").unwrap();
    });

    let mut transport = fastboot_protocol::FastbootTcpTransport::raw_connect(addr).unwrap();

    // Step 1: Send download
    let dl_cmd = fastboot_protocol::download(payload_len as u32);
    transport.send_cmd(&dl_cmd).unwrap();
    let dl_resp = transport.recv_response().unwrap();
    assert_eq!(dl_resp, FastbootResponse::Data(payload_len as u32));

    // Step 2: Send payload
    transport.write_all(&boot_payload).unwrap();
    transport.flush().unwrap();
    let post_dl_resp = transport.recv_response().unwrap();
    assert_eq!(post_dl_resp, FastbootResponse::Okay(String::new()));

    // Step 3: Send boot command
    transport.send_cmd("boot").unwrap();
    let boot_resp = transport.recv_response().unwrap();
    assert_eq!(boot_resp, FastbootResponse::Okay("booting".to_string()));

    server.join().unwrap();
}

#[test]
fn fetch_command_uses_aosp_optional_range_fields() {
    assert_eq!(fastboot_protocol::fetch("boot", None, None), "fetch:boot");
    assert_eq!(
        fastboot_protocol::fetch("boot", Some(0x1000), None),
        "fetch:boot:0x00001000"
    );
    assert_eq!(
        fastboot_protocol::fetch("boot", Some(0x1000), Some(0x2000)),
        "fetch:boot:0x00001000:0x00002000"
    );
}
