//! Run the production executable; all endpoints are ephemeral loopback fixtures.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn finish(mut child: std::process::Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(8);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("target-selection CLI timed out: {:?}", child.wait_with_output().unwrap());
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "CLI never reached the selected endpoint");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn tcp_target(prefix: bool, from_environment: bool, args: &[String]) -> Output {
    let correct = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = correct.local_addr().unwrap().to_string();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    other.set_nonblocking(true).unwrap();
    let other_address = other.local_addr().unwrap().to_string();
    let selector = if prefix { format!("tcp:{address}") } else { address };
    let peer = thread::spawn(move || {
        let mut socket = accept(&correct);
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hello = [0; 4];
        socket.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"FB01");
        socket.write_all(b"FB01").unwrap();
        let mut length = [0; 8];
        socket.read_exact(&mut length).unwrap();
        let length = u64::from_be_bytes(length) as usize;
        assert!(length > 0 && length < 4096);
        let mut command = vec![0; length];
        socket.read_exact(&mut command).unwrap();
        let reply = if command == b"getvar:version" { b"OKAYtarget-B".as_slice() } else { b"FAILfixture-stop".as_slice() };
        socket.write_all(&(reply.len() as u64).to_be_bytes()).unwrap();
        socket.write_all(reply).unwrap();
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastboot-rs"));
    if from_environment {
        command.env("ANDROID_SERIAL", &selector);
    } else {
        command.args(["-s", &selector]);
        command.env("ANDROID_SERIAL", format!("tcp:{other_address}"));
    }
    let child = command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let output = finish(child);
    assert!(peer.join().is_ok(), "target fixture failed for {args:?}: {output:?}");
    assert!(matches!(other.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock), "must never connect to the overridden endpoint");
    output
}

#[test]
fn executable_standard_tcp_prefix_and_legacy_endpoint_reach_the_selected_peer() {
    for prefixed in [true, false] {
        for args in [vec!["getvar".into(), "version".into()], vec!["devices".into()]] {
            let output = tcp_target(prefixed, false, &args);
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("target-B"));
        }
    }
}

#[test]
fn executable_android_serial_is_used_only_when_cli_serial_is_absent() {
    let output = tcp_target(true, true, &["getvar".into(), "version".into()]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("target-B"));
    let output = tcp_target(true, false, &["getvar".into(), "version".into()]);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn executable_command_families_share_the_same_explicit_target() {
    let directory = std::env::temp_dir().join(format!("fastboot-target-cli-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let image = directory.join("image.bin").to_str().unwrap().to_owned();
    std::fs::write(&image, vec![0; 256]).unwrap();
    let output_file = directory.join("output.bin").to_str().unwrap().to_owned();
    let archive = directory.join("update.zip").to_str().unwrap().to_owned();
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    zip.start_file("android-info.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"require product=fixture\n").unwrap();
    zip.finish().unwrap();
    let commands: Vec<Vec<String>> = vec![
        vec!["set-active", "b"], vec!["flash", "boot", &image],
        vec!["erase", "boot"], vec!["reboot"], vec!["reboot-bootloader"],
        vec!["reboot-recovery"], vec!["reboot-fastboot"], vec!["oem", "diagnose"],
        vec!["create-logical-partition", "scratch", "1024"],
        vec!["delete-logical-partition", "scratch"],
        vec!["resize-logical-partition", "scratch", "2048"],
        vec!["boot", &image], vec!["flash:raw", "boot", &image],
        vec!["fetch", "boot", &output_file], vec!["continue"], vec!["signature", &image],
        vec!["snapshot-update", "merge"], vec!["format", "userdata"],
        vec!["get-staged", &output_file], vec!["stage", &image], vec!["wipe-super", &image],
        vec!["shutdown"], vec!["flashing", "get_unlock_ability"], vec!["gsi", "status"],
        vec!["update", &archive],
    ].into_iter().map(|args| args.into_iter().map(str::to_owned).collect()).collect();
    for args in commands {
        // The peer rejects the first command and closes. No operation reaches
        // hardware; this asserts the target chosen for every opening family.
        let _ = tcp_target(true, false, &args);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn executable_connect_and_disconnect_use_private_storage_without_other_target_io() {
    let directory = std::env::temp_dir().join(format!("fastboot-target-storage-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = format!("tcp:{}", listener.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let mut socket = accept(&listener);
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hello = [0; 4];
        socket.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"FB01");
        socket.write_all(b"FB01").unwrap();
        assert_eq!(socket.read(&mut [0; 1]).unwrap(), 0, "connect must not send a device command");
    });
    let output = finish(Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["connect", &target]).env("HOME", &directory).env("ANDROID_SERIAL", "tcp:invalid:bad")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    peer.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read_to_string(directory.join(".fastboot/devices")).unwrap(), format!("{target}\n"));
    let output = finish(Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["disconnect", &target]).env("HOME", &directory).env("ANDROID_SERIAL", "tcp:invalid:bad")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    assert!(output.status.success(), "{output:?}");
    assert!(!directory.join(".fastboot/devices").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn executable_conflicting_transport_options_fail_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("tcp:{}", listener.local_addr().unwrap());
    let output = finish(Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["--usb", "-s", &target, "getvar", "version"])
        .env_remove("ANDROID_SERIAL").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--usb"), "{output:?}");
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn executable_udp_prefix_reaches_udp_backend_not_tcp() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let selector = format!("udp:{}", socket.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let mut packet = [0; 8192];
        for (id, response) in [(1u8, vec![0, 9]), (2u8, vec![0, 1, 2, 0]), (3u8, Vec::new()), (3u8, b"OKAYudp-target".to_vec())] {
            let (n, address) = socket.recv_from(&mut packet).unwrap();
            assert!(n >= 4);
            assert_eq!(packet[0], id);
            assert_eq!(packet[1], 0);
            if id == 3 && response.is_empty() {
                assert_eq!(packet[4..n].strip_suffix(b"\0").unwrap_or(&packet[4..n]), b"getvar:version");
            }
            let mut reply = packet[..4].to_vec();
            reply.extend(response);
            socket.send_to(&reply, address).unwrap();
        }
    });
    let output = finish(Command::new(env!("CARGO_BIN_EXE_fastboot-rs"))
        .args(["-s", &selector, "getvar", "version"]).env_remove("ANDROID_SERIAL")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    peer.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("udp-target"));
}
