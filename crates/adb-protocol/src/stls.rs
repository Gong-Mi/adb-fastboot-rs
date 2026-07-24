//! Typed ADB `A_STLS` protocol boundary.
//!
//! This module models the packet-level transition described by AOSP's ADB
//! transport code. It deliberately does not perform a TLS handshake: callers
//! receive an explicit `UpgradeTls` action and must supply the TLS backend.

use thiserror::Error;

use crate::constants::{A_AUTH, A_CNXN, A_STLS, A_STLS_VERSION, A_STLS_VERSION_MIN};
use crate::header::AdbMessageHeader;

/// A packet relevant to the initial ADB connection/TLS transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StlsPacket {
    /// A plaintext or post-TLS connection response.
    Cnxn {
        version: u32,
        max_payload: u32,
        banner: Vec<u8>,
    },
    /// A legacy plaintext authentication packet. Authentication itself is
    /// outside this state boundary.
    Auth { auth_type: u32, payload: Vec<u8> },
    /// A request to start the stream TLS protocol.
    Stls { version: u32 },
}

impl StlsPacket {
    /// Decode a received ADB frame into the subset understood by this state
    /// machine. Unknown commands are rejected rather than accidentally being
    /// treated as a successful handshake response.
    pub fn parse(header: &AdbMessageHeader, payload: &[u8]) -> Result<Self, StlsError> {
        header
            .verify_payload(payload)
            .map_err(|_| StlsError::PayloadLength {
                expected: header.data_length as usize,
                actual: payload.len(),
            })?;

        match header.command {
            A_CNXN => Ok(Self::Cnxn {
                version: header.arg0,
                max_payload: header.arg1,
                banner: payload.to_vec(),
            }),
            A_AUTH => Ok(Self::Auth {
                auth_type: header.arg0,
                payload: payload.to_vec(),
            }),
            A_STLS => {
                if !payload.is_empty() || header.arg1 != 0 {
                    return Err(StlsError::MalformedRequest {
                        reason: "A_STLS must have an empty payload and arg1=0",
                    });
                }
                Ok(Self::Stls { version: header.arg0 })
            }
            command => Err(StlsError::UnexpectedCommand { command }),
        }
    }
}

/// State of the packet-level connection negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StlsState {
    /// The initial CNXN has been sent; either plaintext CNXN, AUTH, or STLS is
    /// expected.
    AwaitingResponse,
    /// Legacy RSA AUTH is in progress. Auth handling remains with `auth.rs`.
    AwaitingAuth,
    /// A valid A_STLS request was received; the caller must now establish TLS.
    AwaitingTls,
    /// TLS is ready and the caller must resend CNXN over the encrypted stream.
    AwaitingEncryptedCnxn,
    /// A CNXN response has completed negotiation.
    Established,
}

/// Action requested from the caller after consuming a packet or completing
/// the externally-owned TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StlsAction {
    /// Continue legacy authentication handling.
    HandleAuth,
    /// Upgrade the byte stream using the indicated ADB TLS version.
    UpgradeTls { version: u32 },
    /// Send the original CNXN again over the encrypted stream.
    SendEncryptedCnxn,
    /// Negotiation completed without TLS. This is a normal CNXN response, not
    /// a downgrade after A_STLS.
    EstablishedPlaintext,
    /// Negotiation completed after the A_STLS transition.
    EstablishedTls,
}

/// Explicit errors for unsupported or invalid A_STLS transitions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StlsError {
    #[error("unexpected ADB handshake command {command:#x}")]
    UnexpectedCommand { command: u32 },
    #[error("invalid ADB frame payload length: expected {expected}, got {actual}")]
    PayloadLength { expected: usize, actual: usize },
    #[error("malformed A_STLS request: {reason}")]
    MalformedRequest { reason: &'static str },
    #[error("unsupported A_STLS version {version:#x}; supported range starts at {minimum:#x}")]
    UnsupportedVersion { version: u32, minimum: u32 },
    #[error("A_STLS requires a TLS backend for version {version:#x}; plaintext fallback is refused")]
    TlsRequired { version: u32 },
    #[error("invalid A_STLS state transition from {state:?} on {packet:?}")]
    InvalidTransition { state: StlsState, packet: StlsPacket },
}

/// Small, transport-independent A_STLS state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StlsStateMachine {
    state: StlsState,
}

impl Default for StlsStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StlsStateMachine {
    pub const fn new() -> Self {
        Self {
            state: StlsState::AwaitingResponse,
        }
    }

    pub const fn state(&self) -> StlsState {
        self.state
    }

    /// Consume a received handshake packet. `A_STLS` always produces an
    /// explicit TLS action; this API never silently falls back to plaintext.
    pub fn on_packet(&mut self, packet: StlsPacket) -> Result<StlsAction, StlsError> {
        match (self.state, &packet) {
            (StlsState::AwaitingResponse | StlsState::AwaitingAuth, StlsPacket::Cnxn { .. }) => {
                self.state = StlsState::Established;
                Ok(StlsAction::EstablishedPlaintext)
            }
            (StlsState::AwaitingResponse, StlsPacket::Auth { .. }) => {
                self.state = StlsState::AwaitingAuth;
                Ok(StlsAction::HandleAuth)
            }
            (StlsState::AwaitingAuth, StlsPacket::Auth { .. }) => Ok(StlsAction::HandleAuth),
            (StlsState::AwaitingResponse | StlsState::AwaitingAuth, StlsPacket::Stls { version }) => {
                if *version < A_STLS_VERSION_MIN || *version != A_STLS_VERSION {
                    return Err(StlsError::UnsupportedVersion {
                        version: *version,
                        minimum: A_STLS_VERSION_MIN,
                    });
                }
                self.state = StlsState::AwaitingTls;
                Ok(StlsAction::UpgradeTls { version: *version })
            }
            (_, packet) => Err(StlsError::InvalidTransition {
                state: self.state,
                packet: packet.clone(),
            }),
        }
    }

    /// Mark the externally-owned TLS handshake complete. The next packet must
    /// be the encrypted CNXN response after the caller resends CNXN.
    pub fn on_tls_ready(&mut self) -> Result<StlsAction, StlsError> {
        if self.state != StlsState::AwaitingTls {
            return Err(StlsError::InvalidTransition {
                state: self.state,
                packet: StlsPacket::Stls {
                    version: A_STLS_VERSION,
                },
            });
        }
        self.state = StlsState::AwaitingEncryptedCnxn;
        Ok(StlsAction::SendEncryptedCnxn)
    }

    /// Apply the no-TLS policy to a received packet. A normal plaintext CNXN
    /// remains valid, while A_STLS returns a typed error and leaves the state
    /// unchanged so the caller cannot accidentally continue on plaintext.
    pub fn on_packet_without_tls(&mut self, packet: StlsPacket) -> Result<StlsAction, StlsError> {
        if let StlsPacket::Stls { version } = packet {
            if version < A_STLS_VERSION_MIN || version != A_STLS_VERSION {
                return Err(StlsError::UnsupportedVersion {
                    version,
                    minimum: A_STLS_VERSION_MIN,
                });
            }
            return Err(StlsError::TlsRequired { version });
        }
        self.on_packet(packet)
    }

    /// Consume the CNXN response received after TLS upgrade.
    pub fn on_encrypted_cnxn(&mut self, packet: StlsPacket) -> Result<StlsAction, StlsError> {
        if self.state != StlsState::AwaitingEncryptedCnxn {
            return Err(StlsError::InvalidTransition {
                state: self.state,
                packet,
            });
        }
        if !matches!(packet, StlsPacket::Cnxn { .. }) {
            return Err(StlsError::InvalidTransition {
                state: self.state,
                packet,
            });
        }
        self.state = StlsState::Established;
        Ok(StlsAction::EstablishedTls)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> (AdbMessageHeader, Vec<u8>) {
        (AdbMessageHeader::new(command, arg0, arg1, payload), payload.to_vec())
    }

    #[test]
    fn parses_a_stls_version_and_requires_empty_payload() {
        let (header, payload) = frame(A_STLS, A_STLS_VERSION, 0, &[]);
        assert_eq!(StlsPacket::parse(&header, &payload), Ok(StlsPacket::Stls { version: A_STLS_VERSION }));

        let (header, payload) = frame(A_STLS, A_STLS_VERSION, 1, &[]);
        assert!(matches!(StlsPacket::parse(&header, &payload), Err(StlsError::MalformedRequest { .. })));
    }

    #[test]
    fn plaintext_cnxn_establishes_without_being_called_tls_fallback() {
        let (header, payload) = frame(A_CNXN, 1, 4096, b"device::features=shell_v2");
        let packet = StlsPacket::parse(&header, &payload).unwrap();
        let mut machine = StlsStateMachine::new();
        assert_eq!(machine.on_packet(packet), Ok(StlsAction::EstablishedPlaintext));
        assert_eq!(machine.state(), StlsState::Established);
    }

    #[test]
    fn stls_requires_tls_then_resends_cnxn_on_encrypted_stream() {
        let (header, payload) = frame(A_STLS, A_STLS_VERSION, 0, &[]);
        let mut machine = StlsStateMachine::new();
        let packet = StlsPacket::parse(&header, &payload).unwrap();
        assert_eq!(machine.on_packet(packet), Ok(StlsAction::UpgradeTls { version: A_STLS_VERSION }));
        assert_eq!(machine.on_tls_ready(), Ok(StlsAction::SendEncryptedCnxn));

        let (cnxn_header, cnxn_payload) = frame(A_CNXN, 1, 4096, b"device::tls");
        let cnxn = StlsPacket::parse(&cnxn_header, &cnxn_payload).unwrap();
        assert_eq!(machine.on_encrypted_cnxn(cnxn), Ok(StlsAction::EstablishedTls));
    }

    #[test]
    fn unsupported_version_and_missing_tls_are_typed_errors() {
        let mut machine = StlsStateMachine::new();
        let result = machine.on_packet(StlsPacket::Stls { version: A_STLS_VERSION_MIN - 1 });
        assert_eq!(result, Err(StlsError::UnsupportedVersion {
            version: A_STLS_VERSION_MIN - 1,
            minimum: A_STLS_VERSION_MIN,
        }));
        let err = machine.on_packet_without_tls(StlsPacket::Stls { version: A_STLS_VERSION });
        assert_eq!(err, Err(StlsError::TlsRequired { version: A_STLS_VERSION }));
        assert_eq!(machine.state(), StlsState::AwaitingResponse);
    }

    #[test]
    fn encrypted_path_rejects_plaintext_or_auth_packets() {
        let mut machine = StlsStateMachine::new();
        machine.on_packet(StlsPacket::Stls { version: A_STLS_VERSION }).unwrap();
        machine.on_tls_ready().unwrap();
        let err = machine.on_encrypted_cnxn(StlsPacket::Auth { auth_type: 1, payload: vec![] });
        assert!(matches!(err, Err(StlsError::InvalidTransition { state: StlsState::AwaitingEncryptedCnxn, .. })));
    }
}
