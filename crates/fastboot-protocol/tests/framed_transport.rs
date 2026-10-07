use fastboot_protocol::{FastbootResponse, FastbootTcpTransport, FastbootTransport};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn framed_peer(messages: Vec<Vec<u8>>) -> (FastbootTcpTransport, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut handshake = [0; 4];
        stream.read_exact(&mut handshake).unwrap();
        assert_eq!(&handshake, b"FB01");
        stream.write_all(b"FB01").unwrap();
        let mut wire = Vec::new();
        for message in messages {
            wire.extend_from_slice(&(message.len() as u64).to_be_bytes());
            wire.extend_from_slice(&message);
        }
        stream.write_all(&wire).unwrap();
    });
    (FastbootTcpTransport::connect(address).unwrap(), peer)
}

fn receive<T: FastbootTransport>(transport: &mut T) -> (Vec<String>, FastbootResponse) {
    let mut info = Vec::new();
    let response = transport.recv_response_with_info(&mut info).unwrap();
    (info, response)
}

#[test]
fn boxed_and_borrowed_generic_receivers_use_the_tcp_frame_parser() {
    let (transport, peer) = framed_peer(vec![
        b"INFOOKAY/FAIL/DATA are text".to_vec(),
        b"TEXTFAIL/DATA/OKAY are text".to_vec(),
        b"FAILreal rejection with OKAY/DATA inside".to_vec(),
        b"OKAYnext response with FAIL/DATA inside".to_vec(),
    ]);
    let mut boxed: Box<dyn FastbootTransport> = Box::new(transport);
    let mut borrowed = &mut boxed;
    let (info, response) = receive(&mut borrowed);
    assert_eq!(info, ["OKAY/FAIL/DATA are text", "FAIL/DATA/OKAY are text"]);
    assert_eq!(response, FastbootResponse::Fail("real rejection with OKAY/DATA inside".into()));
    assert_eq!(receive(&mut boxed).1, FastbootResponse::Okay("next response with FAIL/DATA inside".into()));
    peer.join().unwrap();
}

#[test]
fn empty_read_does_not_consume_the_next_frame() {
    let (mut transport, peer) = framed_peer(vec![b"OKAYstill available".to_vec()]);
    assert_eq!(transport.read(&mut []).unwrap(), 0);
    assert_eq!(receive(&mut transport).1, FastbootResponse::Okay("still available".into()));
    peer.join().unwrap();
}

#[test]
fn partial_data_reads_preserve_next_status_for_the_generic_receiver() {
    let (mut transport, peer) = framed_peer(vec![
        b"DATA0000000c".to_vec(),
        b"OKAYFAILDATA".to_vec(),
        b"INFOOKAY FAIL DATA after payload".to_vec(),
        b"FAILpost-data rejection".to_vec(),
        b"OKAYnext response".to_vec(),
    ]);
    assert_eq!(receive(&mut transport).1, FastbootResponse::Data(12));
    let mut first = [0; 3];
    transport.read_exact(&mut first).unwrap();
    let mut rest = [0; 9];
    transport.read_exact(&mut rest).unwrap();
    assert_eq!([first.as_slice(), rest.as_slice()].concat(), b"OKAYFAILDATA");
    let (info, response) = receive(&mut transport);
    assert_eq!(info, ["OKAY FAIL DATA after payload"]);
    assert_eq!(response, FastbootResponse::Fail("post-data rejection".into()));
    assert_eq!(receive(&mut transport).1, FastbootResponse::Okay("next response".into()));
    peer.join().unwrap();
}

#[test]
fn raw_generic_receiver_preserves_coalesced_data_and_terminal_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"DATA00000005HELLOFAILraw rejectionOKAYnext").unwrap();
    });
    let mut transport = FastbootTcpTransport::raw_connect(address).unwrap();
    assert_eq!(receive(&mut transport).1, FastbootResponse::Data(5));
    let mut data = [0; 5];
    transport.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"HELLO");
    assert_eq!(receive(&mut transport).1, FastbootResponse::Fail("raw rejection".into()));
    assert_eq!(receive(&mut transport).1, FastbootResponse::Okay("next".into()));
    peer.join().unwrap();
}

// Retain compatibility for custom byte-stream mocks without the old blanket impl.
struct RawMock(std::io::Cursor<Vec<u8>>);

impl Read for RawMock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.0.read(buf) }
}
impl Write for RawMock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { Ok(buf.len()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
impl FastbootTransport for RawMock {}

#[test]
fn explicit_raw_mock_retains_default_command_and_response_support() {
    let mut transport = RawMock(std::io::Cursor::new(b"OKAYmock".to_vec()));
    transport.send_cmd("getvar:version").unwrap();
    assert_eq!(receive(&mut transport).1, FastbootResponse::Okay("mock".into()));
    assert!(transport.send_cmd(&"x".repeat(4097)).is_err());
}
