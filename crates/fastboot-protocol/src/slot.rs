//! A/B slot selection shared by Fastboot command builders and the CLI.

use std::fmt;

/// The values accepted by AOSP fastboot's `--slot` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSelection {
    /// Let the bootloader/current-slot policy select the slot.
    Current,
    /// A concrete slot name, normally `a`, `b`, ... .
    Named(String),
    /// Apply an operation to every slot (multi-command orchestration is a CLI concern).
    All,
    /// Resolve to the slot other than the current slot (device query required).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    Invalid(String),
    RequiresDeviceResolution(&'static str),
}

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(slot) => write!(f, "invalid slot '{slot}'; expected a slot name, 'all', or 'other'"),
            Self::RequiresDeviceResolution(slot) => {
                write!(f, "slot '{slot}' requires device slot discovery and is not available for a single command")
            }
        }
    }
}

impl std::error::Error for SlotError {}

impl SlotSelection {
    /// Parse the spelling used by AOSP (`a`, `b`, `all`, or `other`).
    pub fn parse(value: Option<&str>) -> Result<Self, SlotError> {
        let Some(value) = value else { return Ok(Self::Current); };
        match value {
            "all" => Ok(Self::All),
            "other" => Ok(Self::Other),
            value if !value.is_empty()
                && value.len() == 1
                && value.as_bytes()[0].is_ascii_lowercase() =>
                Ok(Self::Named(value.to_string())),
            value => Err(SlotError::Invalid(value.to_string())),
        }
    }

    /// Append the selected suffix to a partition's first token.
    ///
    /// Fastboot partition modifiers (for example `vendor_boot:default`) stay
    /// intact; only the partition token receives `_SLOT`. Existing matching
    /// suffixes are not duplicated.
    pub fn partition_name(&self, partition: &str) -> Result<String, SlotError> {
        let Some((base, rest)) = partition.split_once(':') else {
            return self.partition_base_name(partition);
        };
        let name = self.partition_base_name(base)?;
        Ok(format!("{name}:{rest}"))
    }

    fn partition_base_name(&self, partition: &str) -> Result<String, SlotError> {
        match self {
            Self::Current => Ok(partition.to_string()),
            Self::Named(slot) => {
                let suffix = format!("_{slot}");
                if partition.ends_with(&suffix) {
                    Ok(partition.to_string())
                } else {
                    Ok(format!("{partition}{suffix}"))
                }
            }
            Self::All => Err(SlotError::RequiresDeviceResolution("all")),
            Self::Other => Err(SlotError::RequiresDeviceResolution("other")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aosp_slot_values() {
        assert_eq!(SlotSelection::parse(None).unwrap(), SlotSelection::Current);
        assert_eq!(SlotSelection::parse(Some("a")).unwrap(), SlotSelection::Named("a".into()));
        assert_eq!(SlotSelection::parse(Some("all")).unwrap(), SlotSelection::All);
        assert_eq!(SlotSelection::parse(Some("other")).unwrap(), SlotSelection::Other);
        assert!(SlotSelection::parse(Some("_a")).is_err());
        assert!(SlotSelection::parse(Some("A")).is_err());
        assert!(SlotSelection::parse(Some("a1")).is_err());
    }

    #[test]
    fn suffixing_is_centralized_and_preserves_modifiers() {
        let slot = SlotSelection::Named("b".into());
        assert_eq!(slot.partition_name("boot").unwrap(), "boot_b");
        assert_eq!(slot.partition_name("boot_b").unwrap(), "boot_b");
        assert_eq!(slot.partition_name("vendor_boot:default").unwrap(), "vendor_boot_b:default");
        assert!(SlotSelection::All.partition_name("boot").is_err());
    }
}