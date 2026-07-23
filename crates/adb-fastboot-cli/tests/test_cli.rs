use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use adb_protocol::{
    AdbMessageHeader, ShellV2Packet, SyncMessageHeader, Transport, ADB_VERSION, A_CNXN, A_OKAY, A_OPEN, A_WRTE,
    MAX_PAYLOAD_V2, SYNC_DATA, SYNC_DONE, SYNC_OKAY, SYNC_RECV, SYNC_SEND,
};
use fastboot_protocol::{FastbootResponse, FastbootTransport};

#[test]
fn test_fastboot_flash_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        
        // 1. Expect download:00000005
        let mut buf = [0u8; 128];
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"download:00000005");

        // Send DATA00000005
        socket.write_all(b"DATA00000005").unwrap();

        // 2. Expect 5 bytes payload
        let mut payload = [0u8; 5];
        socket.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"HELLO");

        // Send INFO + OKAY for download phase
        socket.write_all(b"INFOwriting data...\n").unwrap();
        socket.write_all(b"OKAY").unwrap();

        // 3. Expect flash:boot
        let n2 = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n2], b"flash:boot");
        socket.write_all(b"OKAY").unwrap();
    });

    let mut transport = fastboot_protocol::FastbootTcpTransport::raw_connect(addr.to_string()).unwrap();
    
    // Step 1: download:00000005
    let dl_cmd = fastboot_protocol::download(5);
    transport.send_cmd(&dl_cmd).unwrap();
    let dl_resp = transport.recv_response().unwrap();
    assert_eq!(dl_resp, FastbootResponse::Data(5));

    // Step 2: payload bytes
    transport.write_all(b"HELLO").unwrap();
    transport.flush().unwrap();
    let post_dl_resp = transport.recv_response().unwrap();
    assert_eq!(post_dl_resp, FastbootResponse::Okay("".to_string()));

    // Step 3: flash:boot
    let flash_cmd = fastboot_protocol::flash("boot");
    transport.send_cmd(&flash_cmd).unwrap();
    let flash_resp = transport.recv_response().unwrap();
    assert_eq!(flash_resp, FastbootResponse::Okay("".to_string()));

    server_thread.join().unwrap();
}

#[test]
fn test_fastboot_new_commands_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 128];

        // 1. Expect create-logical-partition:system_a:1048576
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"create-logical-partition:system_a:1048576");
        socket.write_all(b"OKAY").unwrap();

        // 2. Expect delete-logical-partition:system_a
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"delete-logical-partition:system_a");
        socket.write_all(b"OKAY").unwrap();

        // 3. Expect resize-logical-partition:system_a:2097152
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"resize-logical-partition:system_a:2097152");
        socket.write_all(b"OKAY").unwrap();

        // 4. Expect boot
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"boot");
        socket.write_all(b"OKAY").unwrap();

        // 5. Expect fetch:boot:0x0:0x1000
        let n = socket.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"fetch:boot:0x0:0x1000");
        socket.write_all(b"OKAY").unwrap();
    });

    let mut transport = fastboot_protocol::FastbootTcpTransport::raw_connect(addr.to_string()).unwrap();

    // 1. create-logical-partition
    let cmd1 = fastboot_protocol::create_logical_partition("system_a", 1048576);
    transport.send_cmd(&cmd1).unwrap();
    let resp1 = transport.recv_response().unwrap();
    assert_eq!(resp1, FastbootResponse::Okay("".to_string()));

    // 2. delete-logical-partition
    let cmd2 = fastboot_protocol::delete_logical_partition("system_a");
    transport.send_cmd(&cmd2).unwrap();
    let resp2 = transport.recv_response().unwrap();
    assert_eq!(resp2, FastbootResponse::Okay("".to_string()));

    // 3. resize-logical-partition
    let cmd3 = fastboot_protocol::resize_logical_partition("system_a", 2097152);
    transport.send_cmd(&cmd3).unwrap();
    let resp3 = transport.recv_response().unwrap();
    assert_eq!(resp3, FastbootResponse::Okay("".to_string()));

    // 4. boot
    let cmd4 = fastboot_protocol::boot();
    transport.send_cmd(&cmd4).unwrap();
    let resp4 = transport.recv_response().unwrap();
    assert_eq!(resp4, FastbootResponse::Okay("".to_string()));

    // 5. fetch
    let cmd5 = fastboot_protocol::fetch("boot", 0, 4096);
    transport.send_cmd(&cmd5).unwrap();
    let resp5 = transport.recv_response().unwrap();
    assert_eq!(resp5, FastbootResponse::Okay("".to_string()));

    server_thread.join().unwrap();
}

#[test]
fn test_adb_push_sync_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();

        // 1. Handshake A_CNXN
        let mut hdr_buf = [0u8; 24];
        socket.read_exact(&mut hdr_buf).unwrap();
        let hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut cnxn_payload = vec![0u8; hdr.data_length as usize];
        socket.read_exact(&mut cnxn_payload).unwrap();

        let resp_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, b"device::");
        let mut resp_buf = [0u8; 24];
        resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(b"device::").unwrap();

        // 2. Expect A_OPEN(sync:)
        socket.read_exact(&mut hdr_buf).unwrap();
        let open_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut open_payload = vec![0u8; open_hdr.data_length as usize];
        socket.read_exact(&mut open_payload).unwrap();
        assert_eq!(&open_payload, b"sync:");

        // Reply A_OKAY(local_id=2, remote_id=1)
        let okay_hdr = AdbMessageHeader::new(A_OKAY, 2, open_hdr.arg0, &[]);
        okay_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 3. Expect A_WRTE (SYNC_SEND + DATA + DONE)
        socket.read_exact(&mut hdr_buf).unwrap();
        let wrte_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut wrte_payload = vec![0u8; wrte_hdr.data_length as usize];
        socket.read_exact(&mut wrte_payload).unwrap();

        // Ack A_OKAY
        let ack_hdr = AdbMessageHeader::new(A_OKAY, 2, wrte_hdr.arg0, &[]);
        ack_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // Verify SYNC_SEND in payload
        let sync_req_hdr = SyncMessageHeader::decode(&wrte_payload[..8]).unwrap();
        assert_eq!(sync_req_hdr.id, SYNC_SEND);

        // Send SYNC_OKAY in A_WRTE frame
        let mut sync_okay_buf = Vec::new();
        let sync_okay_hdr = SyncMessageHeader::new(SYNC_OKAY, 0);
        let mut sync_hdr_buf = [0u8; 8];
        sync_okay_hdr.encode(&mut sync_hdr_buf);
        sync_okay_buf.extend_from_slice(&sync_hdr_buf);

        let wrte_resp_hdr = AdbMessageHeader::new(A_WRTE, 2, wrte_hdr.arg0, &sync_okay_buf);
        wrte_resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(&sync_okay_buf).unwrap();
    });

    let mut transport = adb_protocol::TcpTransport::connect(addr.to_string()).unwrap();

    // Handshake
    let cnxn_payload = b"host::features=push_sync";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload).unwrap();
    let (cnxn_ack, _) = transport.recv_message().unwrap();
    assert_eq!(cnxn_ack.command, A_CNXN);

    // Open sync channel
    let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, b"sync:");
    transport.send_message(&open_hdr, b"sync:").unwrap();
    let (okay_ack, _) = transport.recv_message().unwrap();
    assert_eq!(okay_ack.command, A_OKAY);

    // Push SYNC_SEND + DATA + DONE
    let mut sync_payload = Vec::new();
    adb_protocol::sync::build_sync_send_req("/sdcard/test.txt", 0o100644, &mut sync_payload).unwrap();
    adb_protocol::sync::build_sync_data_chunk(b"TESTDATA", &mut sync_payload).unwrap();
    adb_protocol::sync::build_sync_done(1720000000, &mut sync_payload).unwrap();

    let wrte_hdr = AdbMessageHeader::new(A_WRTE, 1, okay_ack.arg0, &sync_payload);
    transport.send_message(&wrte_hdr, &sync_payload).unwrap();

    let (wrte_ack, _) = transport.recv_message().unwrap();
    assert_eq!(wrte_ack.command, A_OKAY);

    let (sync_resp_hdr, sync_resp_payload) = transport.recv_message().unwrap();
    assert_eq!(sync_resp_hdr.command, A_WRTE);
    let sync_stat = SyncMessageHeader::decode(&sync_resp_payload[..8]).unwrap();
    assert_eq!(sync_stat.id, SYNC_OKAY);

    server_thread.join().unwrap();
}

#[test]
fn test_adb_pull_sync_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();

        // 1. Handshake A_CNXN
        let mut hdr_buf = [0u8; 24];
        socket.read_exact(&mut hdr_buf).unwrap();
        let hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut cnxn_payload = vec![0u8; hdr.data_length as usize];
        socket.read_exact(&mut cnxn_payload).unwrap();

        let resp_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, b"device::");
        let mut resp_buf = [0u8; 24];
        resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(b"device::").unwrap();

        // 2. Expect A_OPEN(sync:)
        socket.read_exact(&mut hdr_buf).unwrap();
        let open_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut open_payload = vec![0u8; open_hdr.data_length as usize];
        socket.read_exact(&mut open_payload).unwrap();
        assert_eq!(&open_payload, b"sync:");

        // Reply A_OKAY(local_id=2, remote_id=1)
        let okay_hdr = AdbMessageHeader::new(A_OKAY, 2, open_hdr.arg0, &[]);
        okay_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 3. Expect A_WRTE (SYNC_RECV)
        socket.read_exact(&mut hdr_buf).unwrap();
        let wrte_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut wrte_payload = vec![0u8; wrte_hdr.data_length as usize];
        socket.read_exact(&mut wrte_payload).unwrap();

        // Ack A_OKAY
        let ack_hdr = AdbMessageHeader::new(A_OKAY, 2, wrte_hdr.arg0, &[]);
        ack_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // Verify SYNC_RECV in payload
        let sync_req_hdr = SyncMessageHeader::decode(&wrte_payload[..8]).unwrap();
        assert_eq!(sync_req_hdr.id, SYNC_RECV);

        // Send SYNC_DATA + SYNC_DONE in A_WRTE frame
        let mut sync_stream = Vec::new();
        adb_protocol::sync::build_sync_data_chunk(b"PULLED_CONTENT", &mut sync_stream).unwrap();
        adb_protocol::sync::build_sync_done(0, &mut sync_stream).unwrap();

        let wrte_resp_hdr = AdbMessageHeader::new(A_WRTE, 2, wrte_hdr.arg0, &sync_stream);
        wrte_resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(&sync_stream).unwrap();
    });

    let mut transport = adb_protocol::TcpTransport::connect(addr.to_string()).unwrap();

    // Handshake
    let cnxn_payload = b"host::features=push_sync";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload).unwrap();
    let (cnxn_ack, _) = transport.recv_message().unwrap();
    assert_eq!(cnxn_ack.command, A_CNXN);

    // Open sync channel
    let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, b"sync:");
    transport.send_message(&open_hdr, b"sync:").unwrap();
    let (okay_ack, _) = transport.recv_message().unwrap();
    assert_eq!(okay_ack.command, A_OKAY);

    // Pull SYNC_RECV
    let mut sync_req = Vec::new();
    adb_protocol::sync::build_sync_recv_req("/sdcard/remote.txt", &mut sync_req).unwrap();
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, 1, okay_ack.arg0, &sync_req);
    transport.send_message(&wrte_hdr, &sync_req).unwrap();

    let (wrte_ack, _) = transport.recv_message().unwrap();
    assert_eq!(wrte_ack.command, A_OKAY);

    let (sync_resp_hdr, sync_resp_payload) = transport.recv_message().unwrap();
    assert_eq!(sync_resp_hdr.command, A_WRTE);
    
    let sync_data_hdr = SyncMessageHeader::decode(&sync_resp_payload[..8]).unwrap();
    assert_eq!(sync_data_hdr.id, SYNC_DATA);
    let content = &sync_resp_payload[8..8 + sync_data_hdr.length as usize];
    assert_eq!(content, b"PULLED_CONTENT");

    let done_hdr = SyncMessageHeader::decode(&sync_resp_payload[8 + sync_data_hdr.length as usize..]).unwrap();
    assert_eq!(done_hdr.id, SYNC_DONE);

    server_thread.join().unwrap();
}

#[test]
fn test_adb_server_devices_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut req_len_buf = [0u8; 4];
        socket.read_exact(&mut req_len_buf).unwrap();
        let len = usize::from_str_radix(std::str::from_utf8(&req_len_buf).unwrap(), 16).unwrap();
        let mut req_buf = vec![0u8; len];
        socket.read_exact(&mut req_buf).unwrap();
        assert_eq!(&req_buf, b"host:devices-l");

        socket.write_all(b"OKAY").unwrap();
        let payload = b"127.0.0.1:5555          device product:test model:test_dev\n";
        let len_hdr = format!("{:04x}", payload.len());
        socket.write_all(len_hdr.as_bytes()).unwrap();
        socket.write_all(payload).unwrap();
    });

    let mut transport = adb_protocol::AdbServerTransport::connect(addr.to_string()).unwrap();
    let dev_list = transport.execute_host_command("host:devices-l").unwrap();
    assert!(dev_list.contains("127.0.0.1:5555"));
    assert!(dev_list.contains("device"));

    server_thread.join().unwrap();
}

#[test]
fn test_adb_interactive_shell_wire_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();

        // 1. Handshake A_CNXN
        let mut hdr_buf = [0u8; 24];
        socket.read_exact(&mut hdr_buf).unwrap();
        let hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut cnxn_payload = vec![0u8; hdr.data_length as usize];
        socket.read_exact(&mut cnxn_payload).unwrap();

        let resp_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, b"device::features=shell_v2");
        let mut resp_buf = [0u8; 24];
        resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(b"device::features=shell_v2").unwrap();

        // 2. Expect A_OPEN("shell,v2,raw:")
        socket.read_exact(&mut hdr_buf).unwrap();
        let open_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut open_payload = vec![0u8; open_hdr.data_length as usize];
        socket.read_exact(&mut open_payload).unwrap();
        assert_eq!(&open_payload, b"shell,v2,raw:");

        // Reply A_OKAY(local_id=2, remote_id=open_hdr.arg0)
        let okay_hdr = AdbMessageHeader::new(A_OKAY, 2, open_hdr.arg0, &[]);
        okay_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 3. Expect A_WRTE (WindowSizeChange or Stdin)
        socket.read_exact(&mut hdr_buf).unwrap();
        let wrte_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut wrte_payload = vec![0u8; wrte_hdr.data_length as usize];
        socket.read_exact(&mut wrte_payload).unwrap();

        let (pkt, _) = ShellV2Packet::parse(&wrte_payload).unwrap();
        match pkt {
            ShellV2Packet::WindowSizeChange { rows, cols } => {
                assert!(rows > 0);
                assert!(cols > 0);
            }
            _ => panic!("Expected WindowSizeChange packet, got {:?}", pkt),
        }

        // Ack A_OKAY
        let ack_hdr = AdbMessageHeader::new(A_OKAY, 2, wrte_hdr.arg0, &[]);
        ack_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 4. Send stdout + exit code
        let mut resp_payload = Vec::new();
        ShellV2Packet::Stdout(b"interactive shell ready\n").encode(&mut resp_payload);
        ShellV2Packet::ExitCode(0).encode(&mut resp_payload);

        let wrte_resp_hdr = AdbMessageHeader::new(A_WRTE, 2, open_hdr.arg0, &resp_payload);
        wrte_resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(&resp_payload).unwrap();
    });

    let mut transport = adb_protocol::TcpTransport::connect(addr.to_string()).unwrap();

    // Handshake
    let cnxn_payload = b"host::features=shell_v2";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload).unwrap();
    let (cnxn_ack, _) = transport.recv_message().unwrap();
    assert_eq!(cnxn_ack.command, A_CNXN);

    // Open shell v2 raw channel
    let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, b"shell,v2,raw:");
    transport.send_message(&open_hdr, b"shell,v2,raw:").unwrap();
    let (okay_ack, _) = transport.recv_message().unwrap();
    assert_eq!(okay_ack.command, A_OKAY);

    // Send WindowSizeChange
    let winsz_pkt = ShellV2Packet::WindowSizeChange { rows: 24, cols: 80 };
    let mut winsz_payload = Vec::new();
    winsz_pkt.encode(&mut winsz_payload);
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, 1, okay_ack.arg0, &winsz_payload);
    transport.send_message(&wrte_hdr, &winsz_payload).unwrap();

    let (wrte_ack, _) = transport.recv_message().unwrap();
    assert_eq!(wrte_ack.command, A_OKAY);

    let (shell_resp_hdr, shell_resp_payload) = transport.recv_message().unwrap();
    assert_eq!(shell_resp_hdr.command, A_WRTE);
    let (parsed_out, consumed) = ShellV2Packet::parse(&shell_resp_payload).unwrap();
    assert_eq!(parsed_out, ShellV2Packet::Stdout(b"interactive shell ready\n"));

    let (parsed_exit, _) = ShellV2Packet::parse(&shell_resp_payload[consumed..]).unwrap();
    assert_eq!(parsed_exit, ShellV2Packet::ExitCode(0));

    server_thread.join().unwrap();
}

#[test]
fn test_adb_sync_list_dent_wire_sequence() {
    use adb_protocol::sync::{build_sync_list_req, SyncDentResponse};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();

        // 1. Handshake A_CNXN
        let mut hdr_buf = [0u8; 24];
        socket.read_exact(&mut hdr_buf).unwrap();
        let hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut cnxn_payload = vec![0u8; hdr.data_length as usize];
        socket.read_exact(&mut cnxn_payload).unwrap();

        let resp_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, b"device::");
        let mut resp_buf = [0u8; 24];
        resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(b"device::").unwrap();

        // 2. Expect A_OPEN(sync:)
        socket.read_exact(&mut hdr_buf).unwrap();
        let open_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut open_payload = vec![0u8; open_hdr.data_length as usize];
        socket.read_exact(&mut open_payload).unwrap();
        assert_eq!(&open_payload, b"sync:");

        // Reply A_OKAY(local_id=2, remote_id=1)
        let okay_hdr = AdbMessageHeader::new(A_OKAY, 2, open_hdr.arg0, &[]);
        okay_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // 3. Expect A_WRTE (SYNC_LIST)
        socket.read_exact(&mut hdr_buf).unwrap();
        let wrte_hdr = AdbMessageHeader::decode(&hdr_buf).unwrap();
        let mut wrte_payload = vec![0u8; wrte_hdr.data_length as usize];
        socket.read_exact(&mut wrte_payload).unwrap();

        // Ack A_OKAY
        let ack_hdr = AdbMessageHeader::new(A_OKAY, 2, wrte_hdr.arg0, &[]);
        ack_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();

        // Verify SYNC_LIST in payload
        let sync_req_hdr = SyncMessageHeader::decode(&wrte_payload[..8]).unwrap();
        assert_eq!(sync_req_hdr.id, adb_protocol::SYNC_LIST);

        // Build SYNC_DENT responses
        let mut dent_stream = Vec::new();
        let dent1 = SyncDentResponse {
            id: adb_protocol::SYNC_DENT,
            mode: 0o100644,
            size: 512,
            mtime: 1720000000,
            namelen: 8,
            name: "file.txt".to_string(),
        };
        let dent2 = SyncDentResponse {
            id: adb_protocol::SYNC_DENT,
            mode: 0o040755,
            size: 0,
            mtime: 1720000000,
            namelen: 6,
            name: "subdir".to_string(),
        };
        dent1.encode(&mut dent_stream).unwrap();
        dent2.encode(&mut dent_stream).unwrap();

        // Append SYNC_DONE
        let done_dent = SyncDentResponse {
            id: adb_protocol::SYNC_DONE,
            mode: 0,
            size: 0,
            mtime: 0,
            namelen: 0,
            name: String::new(),
        };
        done_dent.encode(&mut dent_stream).unwrap();

        let wrte_resp_hdr = AdbMessageHeader::new(A_WRTE, 2, wrte_hdr.arg0, &dent_stream);
        wrte_resp_hdr.encode(&mut resp_buf);
        socket.write_all(&resp_buf).unwrap();
        socket.write_all(&dent_stream).unwrap();
    });

    let mut transport = adb_protocol::TcpTransport::connect(addr.to_string()).unwrap();

    // Handshake
    let cnxn_payload = b"host::features=push_sync";
    let cnxn_hdr = AdbMessageHeader::new(A_CNXN, ADB_VERSION, MAX_PAYLOAD_V2, cnxn_payload);
    transport.send_message(&cnxn_hdr, cnxn_payload).unwrap();
    let (cnxn_ack, _) = transport.recv_message().unwrap();
    assert_eq!(cnxn_ack.command, A_CNXN);

    // Open sync channel
    let open_hdr = AdbMessageHeader::new(A_OPEN, 1, 0, b"sync:");
    transport.send_message(&open_hdr, b"sync:").unwrap();
    let (okay_ack, _) = transport.recv_message().unwrap();
    assert_eq!(okay_ack.command, A_OKAY);

    // Send SYNC_LIST
    let mut list_req = Vec::new();
    build_sync_list_req("/sdcard/testdir", &mut list_req).unwrap();
    let wrte_hdr = AdbMessageHeader::new(A_WRTE, 1, okay_ack.arg0, &list_req);
    transport.send_message(&wrte_hdr, &list_req).unwrap();

    let (wrte_ack, _) = transport.recv_message().unwrap();
    assert_eq!(wrte_ack.command, A_OKAY);

    let (sync_resp_hdr, sync_resp_payload) = transport.recv_message().unwrap();
    assert_eq!(sync_resp_hdr.command, A_WRTE);

    // Decode two SyncDentResponses
    let dent1 = SyncDentResponse::decode(&sync_resp_payload[..28]).unwrap();
    assert_eq!(dent1.id, adb_protocol::SYNC_DENT);
    assert_eq!(dent1.name, "file.txt");
    assert_eq!(dent1.size, 512);

    let dent2 = SyncDentResponse::decode(&sync_resp_payload[28..28 + 26]).unwrap();
    assert_eq!(dent2.id, adb_protocol::SYNC_DENT);
    assert_eq!(dent2.name, "subdir");
    assert_eq!(dent2.mode, 0o040755);

    server_thread.join().unwrap();
}
