use std::path::PathBuf;

/// AOSP 兼容的分区/别名与镜像文件名映射列表。
pub const AOSP_IMAGE_MAPPINGS: &[(&str, &str)] = &[
    ("boot", "boot.img"),
    ("bootloader", "bootloader.img"),
    ("init_boot", "init_boot.img"),
    ("dtbo", "dtbo.img"),
    ("dts", "dt.img"),
    ("odm", "odm.img"),
    ("odm_dlkm", "odm_dlkm.img"),
    ("product", "product.img"),
    ("pvmfw", "pvmfw.img"),
    ("radio", "radio.img"),
    ("recovery", "recovery.img"),
    ("super", "super.img"),
    ("system", "system.img"),
    ("system_dlkm", "system_dlkm.img"),
    ("system_ext", "system_ext.img"),
    ("userdata", "userdata.img"),
    ("vbmeta", "vbmeta.img"),
    ("vbmeta_system", "vbmeta_system.img"),
    ("vbmeta_vendor", "vbmeta_vendor.img"),
    ("vendor", "vendor.img"),
    ("vendor_boot", "vendor_boot.img"),
    ("vendor_dlkm", "vendor_dlkm.img"),
    ("vendor_kernel_boot", "vendor_kernel_boot.img"),
    ("cache", "cache.img"),
];

/// 根据 partition 名与 FILE 参数/ANDROID_PRODUCT_OUT 环境变量解析镜像文件路径。
///
/// 遵循 AOSP fastboot `find_item` 逻辑：
/// 1. 若显式提供 `file`，则直接使用该路径。
/// 2. 若未提供 `file`，则查询 `product_out`。若未设置，返回错误。
/// 3. 若 `product_out` 已设置，则查找匹配的分区别名对应的镜像文件名（如 `"dts"` -> `"dt.img"`），
///    未在表中显式列出的分区则默认使用 `<partition>.img`。若分区带 `_a`/`_b` 槽位后缀，
///    也会尝试匹配去除槽位后缀后的基础分区别名。
pub fn resolve_image_path(
    partition: &str,
    file: Option<&str>,
    product_out: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(f) = file {
        let trimmed = f.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let out_dir = match product_out {
        Some(dir) if !dir.trim().is_empty() => dir.trim(),
        _ => {
            return Err(format!(
                "cannot determine image filename for '{}': ANDROID_PRODUCT_OUT is not set and no file was specified",
                partition
            ));
        }
    };

    let base_partition = partition
        .strip_suffix("_a")
        .or_else(|| partition.strip_suffix("_b"))
        .unwrap_or(partition);

    let img_name = AOSP_IMAGE_MAPPINGS
        .iter()
        .find(|(nickname, _)| *nickname == partition || *nickname == base_partition)
        .map(|(_, filename)| (*filename).to_string())
        .unwrap_or_else(|| format!("{}.img", partition));

    let mut path = PathBuf::from(out_dir);
    path.push(img_name);
    Ok(path)
}

/// 解析 wipe-super 命令的 super_empty.img 路径。
///
/// 遵循 AOSP fastboot `wipe-super` 逻辑：
/// 1. 若显式提供 `image` 参数，则直接使用。
/// 2. 若未提供 `image` 参数，则查找 `<ANDROID_PRODUCT_OUT>/super_empty.img`。
pub fn resolve_super_empty_path(
    image: Option<&str>,
    product_out: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(img) = image {
        let trimmed = img.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let out_dir = match product_out {
        Some(dir) if !dir.trim().is_empty() => dir.trim(),
        _ => {
            return Err(
                "cannot determine super_empty image filename: ANDROID_PRODUCT_OUT is not set and no image was specified".to_string()
            );
        }
    };

    let mut path = PathBuf::from(out_dir);
    path.push("super_empty.img");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_image_path_explicit_file() {
        let path = resolve_image_path("boot", Some("/custom/boot.img"), None).unwrap();
        assert_eq!(path, PathBuf::from("/custom/boot.img"));
    }

    #[test]
    fn test_resolve_image_path_product_out_standard() {
        let path = resolve_image_path("boot", None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/boot.img"));
    }

    #[test]
    fn test_resolve_image_path_product_out_mapped_nickname() {
        let path = resolve_image_path("dts", None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/dt.img"));
    }

    #[test]
    fn test_resolve_image_path_product_out_with_slot_suffix() {
        let path = resolve_image_path("dts_a", None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/dt.img"));

        let path = resolve_image_path("system_b", None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/system.img"));
    }

    #[test]
    fn test_resolve_image_path_product_out_custom_partition() {
        let path = resolve_image_path("my_part", None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/my_part.img"));
    }

    #[test]
    fn test_resolve_image_path_missing_env() {
        let res = resolve_image_path("boot", None, None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("ANDROID_PRODUCT_OUT is not set"));
    }

    #[test]
    fn test_resolve_super_empty_path_explicit() {
        let path = resolve_super_empty_path(Some("/tmp/my_super_empty.img"), None).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/my_super_empty.img"));
    }

    #[test]
    fn test_resolve_super_empty_path_product_out() {
        let path = resolve_super_empty_path(None, Some("/out/dir")).unwrap();
        assert_eq!(path, PathBuf::from("/out/dir/super_empty.img"));
    }

    #[test]
    fn test_resolve_super_empty_path_missing_env() {
        let res = resolve_super_empty_path(None, None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("ANDROID_PRODUCT_OUT is not set"));
    }
}
