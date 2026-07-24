//! ADB mDNS service and TXT record parsing primitives.
//!
//! AOSP ADB uses standard mDNS / DNS-SD service types for discovery:
//! - `_adb._tcp.local.` (Classic ADB over TCP/Wi-Fi)
//! - `_adb-tls-connect._tcp.local.` (Secure ADB connection over TLS 1.3)
//! - `_adb-tls-pairing._tcp.local.` (Secure ADB pairing service)

use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;

/// Recognized ADB mDNS service types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdbMdnsServiceType {
    /// Classic unencrypted ADB over TCP (`_adb._tcp`).
    Classic,
    /// Secure ADB TLS connection (`_adb-tls-connect._tcp`).
    TlsConnect,
    /// Secure ADB TLS pairing (`_adb-tls-pairing._tcp`).
    TlsPairing,
}

impl AdbMdnsServiceType {
    /// Service string identifier (e.g. `_adb-tls-connect._tcp`).
    pub const fn service_name(&self) -> &'static str {
        match self {
            Self::Classic => "_adb._tcp",
            Self::TlsConnect => "_adb-tls-connect._tcp",
            Self::TlsPairing => "_adb-tls-pairing._tcp",
        }
    }

    /// Full mDNS service domain suffix (e.g. `_adb-tls-connect._tcp.local.`).
    pub const fn full_domain(&self) -> &'static str {
        match self {
            Self::Classic => "_adb._tcp.local.",
            Self::TlsConnect => "_adb-tls-connect._tcp.local.",
            Self::TlsPairing => "_adb-tls-pairing._tcp.local.",
        }
    }

    /// Match a raw service name or full domain against recognized ADB service types.
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim().trim_end_matches('.');
        if trimmed == "_adb._tcp" || trimmed == "_adb._tcp.local" {
            Some(Self::Classic)
        } else if trimmed == "_adb-tls-connect._tcp" || trimmed == "_adb-tls-connect._tcp.local" {
            Some(Self::TlsConnect)
        } else if trimmed == "_adb-tls-pairing._tcp" || trimmed == "_adb-tls-pairing._tcp.local" {
            Some(Self::TlsPairing)
        } else {
            None
        }
    }
}

/// Errors occurring during ADB mDNS record parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MdnsError {
    #[error("unrecognized or unsupported mDNS service name {0:?}")]
    UnknownServiceType(String),
    #[error("invalid DNS-SD TXT record attribute length: expected {expected}, got {got}")]
    InvalidTxtLength { expected: usize, got: usize },
    #[error("missing host port in mDNS service record")]
    MissingPort,
}

/// Discovered ADB mDNS service record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbMdnsService {
    pub service_type: AdbMdnsServiceType,
    pub instance_name: String,
    pub host_name: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
}

impl AdbMdnsService {
    /// Create a new mDNS service record.
    pub fn new(
        service_type: AdbMdnsServiceType,
        instance_name: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            service_type,
            instance_name: instance_name.into(),
            host_name: None,
            addresses: Vec::new(),
            port,
            txt_records: HashMap::new(),
        }
    }

    /// Attempt to extract the device serial number from TXT records or instance name.
    ///
    /// AOSP mDNS TXT records for `_adb-tls-connect` often populate a `serial`
    /// attribute (e.g. `serial=12345678`). Instance names also take the form
    /// `adb-<serial>-_adb-tls-connect._tcp.local.`.
    pub fn device_serial(&self) -> Option<String> {
        if let Some(serial) = self.txt_records.get("serial") {
            if !serial.is_empty() {
                return Some(serial.clone());
            }
        }

        // Check if instance name starts with "adb-"
        if let Some(rest) = self.instance_name.strip_prefix("adb-") {
            let end = rest
                .find("-_")
                .or_else(|| rest.find("._"))
                .or_else(|| rest.find('.'))
                .unwrap_or(rest.len());
            let serial_part = &rest[..end];
            if !serial_part.is_empty() {
                return Some(serial_part.to_string());
            }
        }

        None
    }
}

/// Parse a raw DNS-SD TXT record payload into key-value pairs.
///
/// In DNS-SD (RFC 6763 section 6), TXT records consist of one or more
/// length-prefixed bytes `[len, key=value...]`.
pub fn parse_txt_record(raw: &[u8]) -> Result<HashMap<String, String>, MdnsError> {
    let mut map = HashMap::new();
    let mut offset = 0;

    while offset < raw.len() {
        let len = raw[offset] as usize;
        offset += 1;

        if len == 0 {
            continue;
        }

        if offset + len > raw.len() {
            return Err(MdnsError::InvalidTxtLength {
                expected: len,
                got: raw.len() - offset,
            });
        }

        let kv_bytes = &raw[offset..offset + len];
        offset += len;

        if let Ok(kv_str) = std::str::from_utf8(kv_bytes) {
            if let Some((k, v)) = kv_str.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            } else {
                map.insert(kv_str.trim().to_string(), String::new());
            }
        }
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_service_types() {
        assert_eq!(
            AdbMdnsServiceType::parse("_adb._tcp"),
            Some(AdbMdnsServiceType::Classic)
        );
        assert_eq!(
            AdbMdnsServiceType::parse("_adb-tls-connect._tcp.local."),
            Some(AdbMdnsServiceType::TlsConnect)
        );
        assert_eq!(
            AdbMdnsServiceType::parse("_adb-tls-pairing._tcp.local"),
            Some(AdbMdnsServiceType::TlsPairing)
        );
        assert_eq!(AdbMdnsServiceType::parse("unknown_service"), None);
    }

    #[test]
    fn parses_dns_sd_txt_record() {
        // [length, "serial=12345678", length, "v=1"]
        let raw = b"\x0fserial=12345678\x03v=1";
        let parsed = parse_txt_record(raw).unwrap();
        assert_eq!(parsed.get("serial"), Some(&"12345678".to_string()));
        assert_eq!(parsed.get("v"), Some(&"1".to_string()));
    }

    #[test]
    fn extracts_serial_from_txt_record_or_instance_name() {
        let mut service = AdbMdnsService::new(
            AdbMdnsServiceType::TlsConnect,
            "adb-SER12345-_adb-tls-connect._tcp.local.",
            5555,
        );
        service.addresses.push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        assert_eq!(service.device_serial(), Some("SER12345".to_string()));

        service.txt_records.insert("serial".to_string(), "EXPLICIT999".to_string());
        assert_eq!(service.device_serial(), Some("EXPLICIT999".to_string()));
    }
}
