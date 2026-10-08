#![cfg(feature = "usb")]
use adb_protocol::{AdbMessageHeader, Transport, TransportError, A_WRTE};
use adb_protocol::usb::{UsbEndpointInfo, UsbTransport, UsbTransportAdapter, UsbTransportError};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    requests: Vec<Vec<u8>>,
    outcomes: VecDeque<Result<usize, UsbTransportError>>,
}
struct Endpoint(Arc<Mutex<State>>);
impl UsbTransport for Endpoint {
    fn endpoint_info(&self) -> UsbEndpointInfo {
        UsbEndpointInfo { interface_number: 7, bulk_in_endpoint_address: 0x85,
            bulk_out_endpoint_address: 0x06, out_max_packet_size: 64 }
    }
    fn bulk_read(&mut self, _: u8, _: &mut [u8]) -> Result<usize, UsbTransportError> { unreachable!() }
    fn bulk_write(&mut self, ep: u8, b: &[u8]) -> Result<usize, UsbTransportError> {
        assert_eq!(ep, 0x06);
        let mut s = self.0.lock().unwrap();
        s.requests.push(b.to_vec());
        s.outcomes.pop_front().unwrap_or(Ok(b.len()))
    }
}
fn fixture(outcomes: Vec<Result<usize, UsbTransportError>>) -> (Box<dyn Transport>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State { outcomes: outcomes.into(), ..State::default() }));
    (Box::new(UsbTransportAdapter::new(Endpoint(state.clone()))), state)
}

#[test]
fn usb_frame_boundaries_and_integrity() {
    for len in [0, 1, 40, 63, 64, 65, 128, 512, 1024, 1024 * 1024] {
        let payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
        let h = AdbMessageHeader::new(A_WRTE, 37, 911, &payload);
        let mut bytes = [0; 24]; h.encode(&mut bytes);
        let (mut transport, state) = fixture(vec![]);
        transport.send_message(&h, &payload).unwrap();
        let mut expected = vec![bytes.to_vec()];
        if len != 0 { expected.push(payload.clone()); }
        if len != 0 && len % 64 == 0 { expected.push(vec![]); }
        assert_eq!(state.lock().unwrap().requests, expected);
        let decoded = AdbMessageHeader::decode(&bytes).unwrap();
        assert_eq!((decoded.arg0, decoded.arg1), (37, 911));
        decoded.verify_payload(&payload).unwrap();
    }
}

#[test]
fn usb_frame_failure_is_terminal_without_replay() {
    for phase in 0..3 {
        for outcome in [Ok(0), Ok(3), Ok(999), Err(UsbTransportError::Timeout),
            Err(UsbTransportError::Disconnected), Err(UsbTransportError::Io("errno 71".into()))] {
            // A successful ZLP returns zero; this is not zero progress.
            if phase == 2 && outcome == Ok(0) { continue; }
            let payload = vec![0xa5; 64];
            let h = AdbMessageHeader::new(A_WRTE, 37, 911, &payload);
            let mut outcomes = vec![Ok(24), Ok(64)]; outcomes.truncate(phase);
            outcomes.push(outcome);
            let (mut transport, state) = fixture(outcomes);
            assert!(transport.send_message(&h, &payload).is_err(), "phase {phase}");
            assert_eq!(state.lock().unwrap().requests.len(), phase + 1);
            // A damaged USB frame cannot be safely resumed or restarted.
            assert!(transport.send_message(&h, &payload).is_err());
            assert_eq!(state.lock().unwrap().requests.len(), phase + 1);
        }
    }
}

#[test]
fn usb_frame_length_mismatch_rejected_before_io() {
    let h = AdbMessageHeader::new(A_WRTE, 37, 911, b"abc");
    let (mut transport, state) = fixture(vec![]);
    assert!(matches!(transport.send_message(&h, b"ab"), Err(TransportError::Protocol(_))));
    assert!(state.lock().unwrap().requests.is_empty());
    transport.send_message(&h, b"abc").unwrap();
}
