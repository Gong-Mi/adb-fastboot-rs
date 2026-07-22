use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FastbootResponseError {
    #[error("Response too short (less than 4 bytes)")]
    TooShort,
    #[error("Unknown fastboot response prefix: {0}")]
    UnknownPrefix(String),
    #[error("Invalid DATA payload size: {0}")]
    InvalidDataSize(String),
}

/// Fastboot response status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastbootResponse {
    Okay(String),
    Fail(String),
    Data(u32),
    Info(String),
    Text(String),
}

impl FastbootResponse {
    pub fn parse(buf: &[u8]) -> Result<Self, FastbootResponseError> {
        if buf.len() < 4 {
            return Err(FastbootResponseError::TooShort);
        }

        let prefix = match std::str::from_utf8(&buf[0..4]) {
            Ok(p) => p,
            Err(_) => return Err(FastbootResponseError::UnknownPrefix(format!("{:?}", &buf[0..4]))),
        };

        let payload = &buf[4..];

        match prefix {
            "OKAY" => Ok(FastbootResponse::Okay(String::from_utf8_lossy(payload).to_string())),
            "FAIL" => Ok(FastbootResponse::Fail(String::from_utf8_lossy(payload).to_string())),
            "INFO" => Ok(FastbootResponse::Info(String::from_utf8_lossy(payload).to_string())),
            "TEXT" => Ok(FastbootResponse::Text(String::from_utf8_lossy(payload).to_string())),
            "DATA" => {
                if payload.len() != 8 {
                    return Err(FastbootResponseError::InvalidDataSize(
                        String::from_utf8_lossy(payload).to_string(),
                    ));
                }
                let hex_str = match std::str::from_utf8(payload) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(FastbootResponseError::InvalidDataSize(
                            String::from_utf8_lossy(payload).to_string(),
                        ))
                    }
                };
                let size = u32::from_str_radix(hex_str, 16).map_err(|_| {
                    FastbootResponseError::InvalidDataSize(hex_str.to_string())
                })?;
                Ok(FastbootResponse::Data(size))
            }
            _ => Err(FastbootResponseError::UnknownPrefix(prefix.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fastboot_response_okay() {
        let resp = FastbootResponse::parse(b"OKAY0.1").unwrap();
        assert_eq!(resp, FastbootResponse::Okay("0.1".to_string()));
    }

    #[test]
    fn test_fastboot_response_fail() {
        let resp = FastbootResponse::parse(b"FAILpartition not found").unwrap();
        assert_eq!(resp, FastbootResponse::Fail("partition not found".to_string()));
    }

    #[test]
    fn test_fastboot_response_data() {
        let resp = FastbootResponse::parse(b"DATA00100000").unwrap();
        assert_eq!(resp, FastbootResponse::Data(0x00100000));
    }

    #[test]
    fn test_fastboot_response_info() {
        let resp = FastbootResponse::parse(b"INFOerasing 'boot'...").unwrap();
        assert_eq!(resp, FastbootResponse::Info("erasing 'boot'...".to_string()));
    }

    #[test]
    fn test_fastboot_response_text() {
        let resp = FastbootResponse::parse(b"TEXTconsole message").unwrap();
        assert_eq!(resp, FastbootResponse::Text("console message".to_string()));
    }

    #[test]
    fn test_fastboot_response_invalid_data() {
        // Invalid length for DATA payload
        assert_eq!(
            FastbootResponse::parse(b"DATA123"),
            Err(FastbootResponseError::InvalidDataSize("123".to_string()))
        );
        // Non-hex character for DATA payload
        assert_eq!(
            FastbootResponse::parse(b"DATA0010000G"),
            Err(FastbootResponseError::InvalidDataSize("0010000G".to_string()))
        );
    }

    #[test]
    fn test_fastboot_response_errors() {
        assert_eq!(FastbootResponse::parse(b"OK"), Err(FastbootResponseError::TooShort));
        assert!(matches!(
            FastbootResponse::parse(b"UNKNtest"),
            Err(FastbootResponseError::UnknownPrefix(_))
        ));
    }
}
