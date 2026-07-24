/// Fastboot command formatting helper functions

/// Formats a `getvar` command for Fastboot.
///
/// Example: `getvar("version")` returns `"getvar:version"`.
pub fn getvar(variable: &str) -> String {
    format!("getvar:{}", variable)
}

/// Formats a `flash` command for Fastboot.
///
/// Example: `flash("boot")` returns `"flash:boot"`.
pub fn flash(partition: &str) -> String {
    format!("flash:{}", partition)
}

/// Formats an `erase` command for Fastboot.
///
/// Example: `erase("userdata")` returns `"erase:userdata"`.
pub fn erase(partition: &str) -> String {
    format!("erase:{}", partition)
}

/// Formats a `reboot` command for Fastboot.
///
/// If `target` is `None` or empty, returns `"reboot"`.
/// If `target` is `Some("bootloader")`, returns `"reboot-bootloader"`.
/// If `target` is `Some("reboot-bootloader")`, returns `"reboot-bootloader"`.
pub fn reboot(target: Option<&str>) -> String {
    match target {
        Some(t) if !t.trim().is_empty() => {
            let trimmed = t.trim();
            if trimmed.starts_with("reboot-") {
                trimmed.to_string()
            } else {
                format!("reboot-{}", trimmed)
            }
        }
        _ => "reboot".to_string(),
    }
}

/// Formats a `download` command for Fastboot.
///
/// Example: `download(0x100000)` returns `"download:00100000"`.
pub fn download(size: u32) -> String {
    format!("download:{:08x}", size)
}

/// Formats a `create-logical-partition` command for Fastboot.
///

pub fn create_logical_partition(partition: &str, size: u64) -> String {
    format!("create-logical-partition:{}:{}", partition, size)
}

/// Formats a `delete-logical-partition` command for Fastboot.
///

pub fn delete_logical_partition(partition: &str) -> String {
    format!("delete-logical-partition:{}", partition)
}

/// Formats a `resize-logical-partition` command for Fastboot.
///

pub fn resize_logical_partition(partition: &str, size: u64) -> String {
    format!("resize-logical-partition:{}:{}", partition, size)
}

/// Formats a snapshot-update command for Fastboot.
///
/// AOSP sends `snapshot-update:<command>`, where the command may be empty,
/// `cancel`, or `merge`.
pub fn snapshot_update(command: Option<&str>) -> String {
    format!("snapshot-update:{}", command.unwrap_or(""))
}

/// Formats a `boot` command for Fastboot.
///

pub fn boot() -> String {
    "boot".to_string()
}

/// Formats a `fetch` command for Fastboot.
///

pub fn fetch(partition: &str, offset: u64, size: u64) -> String {
    format!("fetch:{}:0x{:08x}:0x{:08x}", partition, offset, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getvar() {
        assert_eq!(getvar("version"), "getvar:version");
        assert_eq!(getvar("all"), "getvar:all");
    }

    #[test]
    fn test_flash() {
        assert_eq!(flash("boot"), "flash:boot");
        assert_eq!(flash("system"), "flash:system");
    }

    #[test]
    fn test_erase() {
        assert_eq!(erase("userdata"), "erase:userdata");
    }

    #[test]
    fn test_reboot() {
        assert_eq!(reboot(None), "reboot");
        assert_eq!(reboot(Some("")), "reboot");
        assert_eq!(reboot(Some("bootloader")), "reboot-bootloader");
        assert_eq!(reboot(Some("reboot-bootloader")), "reboot-bootloader");
        assert_eq!(reboot(Some("fastboot")), "reboot-fastboot");
    }

    #[test]
    fn test_download() {
        assert_eq!(download(0x100000), "download:00100000");
        assert_eq!(download(0), "download:00000000");
        assert_eq!(download(0xFFFFFFFF), "download:ffffffff");
    }

    #[test]
    fn test_create_logical_partition() {
        assert_eq!(
            create_logical_partition("system_a", 1048576),
            "create-logical-partition:system_a:1048576"
        );
    }

    #[test]
    fn test_delete_logical_partition() {
        assert_eq!(
            delete_logical_partition("system_a"),
            "delete-logical-partition:system_a"
        );
    }

    #[test]
    fn test_resize_logical_partition() {
        assert_eq!(
            resize_logical_partition("system_a", 2097152),
            "resize-logical-partition:system_a:2097152"
        );
    }

    #[test]
    fn test_snapshot_update() {
        assert_eq!(snapshot_update(None), "snapshot-update:");
        assert_eq!(snapshot_update(Some("cancel")), "snapshot-update:cancel");
        assert_eq!(snapshot_update(Some("merge")), "snapshot-update:merge");
    }

    #[test]
    fn test_boot() {
        assert_eq!(boot(), "boot");
    }

    #[test]
    fn test_fetch() {
        assert_eq!(
            fetch("boot", 0, 4096),
            "fetch:boot:0x00000000:0x00001000"
        );
        assert_eq!(
            fetch("system", 0x10000, 0x80000),
            "fetch:system:0x00010000:0x00080000"
        );
    }
}
