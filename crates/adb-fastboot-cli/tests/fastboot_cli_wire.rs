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
