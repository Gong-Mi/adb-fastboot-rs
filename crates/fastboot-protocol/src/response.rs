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

        let message = String::from_utf8_lossy(&buf[4..]).trim().to_string();

        match prefix {
            "OKAY" => Ok(FastbootResponse::Okay(message)),
            "FAIL" => Ok(FastbootResponse::Fail(message)),
            "INFO" => Ok(FastbootResponse::Info(message)),
            "DATA" => {
                let hex_str = message.trim();
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
}
