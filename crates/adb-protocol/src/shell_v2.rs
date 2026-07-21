use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::constants::*;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ShellV2Error {
    #[error("Packet incomplete: need at least 5 bytes header")]
    HeaderTooShort,
    #[error("Packet payload too short: need {expected} bytes, got {got}")]
    PayloadTooShort { expected: usize, got: usize },
    #[error("Unknown shell stream id: {0}")]
    UnknownStreamId(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellV2Packet<'a> {
    Stdin(&'a [u8]),
    Stdout(&'a [u8]),
    Stderr(&'a [u8]),
    ExitCode(u8),
    CloseStdin,
    WindowSizeChange { rows: u16, cols: u16 },
}

impl<'a> ShellV2Packet<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, usize), ShellV2Error> {
        if buf.len() < 5 {
            return Err(ShellV2Error::HeaderTooShort);
        }

        let id = buf[0];
        let len = LittleEndian::read_u32(&buf[1..5]) as usize;

        if buf.len() < 5 + len {
            return Err(ShellV2Error::PayloadTooShort {
                expected: 5 + len,
                got: buf.len(),
            });
        }

        let payload = &buf[5..5 + len];
        let consumed = 5 + len;

        let pkt = match id {
            SHELL_ID_STDIN => ShellV2Packet::Stdin(payload),
            SHELL_ID_STDOUT => ShellV2Packet::Stdout(payload),
            SHELL_ID_STDERR => ShellV2Packet::Stderr(payload),
            SHELL_ID_EXIT => {
                let code = payload.first().copied().unwrap_or(0);
                ShellV2Packet::ExitCode(code)
            }
            SHELL_ID_CLOSE_STDIN => ShellV2Packet::CloseStdin,
            SHELL_ID_WINDOW_SIZE_CHANGE => {
                let rows = if payload.len() >= 2 {
                    LittleEndian::read_u16(&payload[0..2])
                } else {
                    0
                };
                let cols = if payload.len() >= 4 {
                    LittleEndian::read_u16(&payload[2..4])
                } else {
                    0
                };
                ShellV2Packet::WindowSizeChange { rows, cols }
            }
            _ => return Err(ShellV2Error::UnknownStreamId(id)),
        };

        Ok((pkt, consumed))
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ShellV2Packet::Stdin(data) => {
                out.push(SHELL_ID_STDIN);
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(data);
            }
            ShellV2Packet::Stdout(data) => {
                out.push(SHELL_ID_STDOUT);
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(data);
            }
            ShellV2Packet::Stderr(data) => {
                out.push(SHELL_ID_STDERR);
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(data);
            }
            ShellV2Packet::ExitCode(code) => {
                out.push(SHELL_ID_EXIT);
                out.extend_from_slice(&1u32.to_le_bytes());
                out.push(*code);
            }
            ShellV2Packet::CloseStdin => {
                out.push(SHELL_ID_CLOSE_STDIN);
                out.extend_from_slice(&0u32.to_le_bytes());
            }
            ShellV2Packet::WindowSizeChange { rows, cols } => {
                out.push(SHELL_ID_WINDOW_SIZE_CHANGE);
                out.extend_from_slice(&4u32.to_le_bytes());
                out.extend_from_slice(&rows.to_le_bytes());
                out.extend_from_slice(&cols.to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_v2_stdout_roundtrip() {
        let text = b"Linux dali 6.6.50+ #1 SMP PREEMPT";
        let original = ShellV2Packet::Stdout(text);

        let mut encoded = Vec::new();
        original.encode(&mut encoded);

        let (parsed, consumed) = ShellV2Packet::parse(&encoded).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_shell_v2_exit_code() {
        let original = ShellV2Packet::ExitCode(0);
        let mut encoded = Vec::new();
        original.encode(&mut encoded);

        let (parsed, _) = ShellV2Packet::parse(&encoded).unwrap();
        assert_eq!(parsed, ShellV2Packet::ExitCode(0));
    }
}
