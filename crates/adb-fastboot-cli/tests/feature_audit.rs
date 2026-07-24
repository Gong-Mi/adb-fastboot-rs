#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptanceStatus {
    /// Wire format/state machine is covered by protocol-level tests.
    ProtocolImplemented,
    /// The implementation contains code evidence, but this is not CLI or
    /// end-to-end acceptance evidence.
    CodeEvidence,
    /// The command is exposed by this CLI, but this is not an end-to-end claim.
    CliImplemented,
    /// The required host/device transport is not present in this migration.
    TransportMissing,
    /// No real-device validation was performed, so the result must not be called complete.
    RealDeviceUnverified,
}

impl AcceptanceStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::ProtocolImplemented => "protocol implemented",
            Self::CodeEvidence => "code evidence",
            Self::CliImplemented => "CLI implemented",
            Self::TransportMissing => "transport missing",
            Self::RealDeviceUnverified => "real-device unverified",
        }
    }

    const fn is_accepted(self) -> bool {
        matches!(self, Self::ProtocolImplemented | Self::CliImplemented)
    }

    const fn is_code_evidence(self) -> bool {
        matches!(self, Self::CodeEvidence)
    }
}

#[derive(Clone, Copy, Debug)]
struct FeatureStatus {
    module: &'static str,
    feature: &'static str,
    status: AcceptanceStatus,
    evidence: &'static str,
}

// This is deliberately an acceptance matrix, not a list of advertised commands.
// A protocol formatter or a Clap subcommand does not prove AOSP-compatible
// transport behavior, lifecycle behavior, file output, or real-device behavior.
const MATRIX: &[FeatureStatus] = &[
    FeatureStatus {
        module: "ADB",
        feature: "24-byte header checksum/magic",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "协议 crate 的 header 编解码测试覆盖",
    },
    FeatureStatus {
        module: "ADB",
        feature: "Shell v2 / window-size change",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "协议报文与 CLI shell 路径有测试覆盖；未替代真实设备验收",
    },
    FeatureStatus {
        module: "ADB",
        feature: "STAT_V2 / LSTAT_V2 protocol",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "SYNC 报文格式已实现；仅协议级证据",
    },
    FeatureStatus {
        module: "ADB",
        feature: "Single-file push/pull",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI 有 push/pull，TCP fake-peer wire test 通过；真实设备未验证",
    },
    FeatureStatus {
        module: "ADB",
        feature: "ADB TCP socket transport",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "TcpTransport 可连接并被 CLI 使用；不是 USB 迁移证据",
    },
    FeatureStatus {
        module: "ADB",
        feature: "RSA key auth (A_AUTH signature/RSAKEY)",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "认证消息生成/握手路径已实现；真实授权设备未验证",
    },
    FeatureStatus {
        module: "ADB",
        feature: "ADB server lifecycle (start/stop/restart, 5037)",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI supports start-server, kill-server, and background autostart",
    },
    FeatureStatus {
        module: "USB",
        feature: "Protocol USB adapters (ADB/Fastboot)",
        status: AcceptanceStatus::CodeEvidence,
        evidence: "adb-protocol 有 UsbTransportAdapter；fastboot-protocol 有 FastbootUsbTransport；已有 adapter/boundary 代码与协议级测试，不代表 CLI 已接入",
    },
    FeatureStatus {
        module: "USB",
        feature: "Optional rusb USB backends (ADB/Fastboot)",
        status: AcceptanceStatus::CodeEvidence,
        evidence: "usb-rusb feature 下已有 ADB RusbUsbTransport 与 Fastboot RusbBulkIo，可枚举/打开并执行 bulk I/O；这是 backend code evidence，不代表 CLI 已接入或真实设备已验收",
    },
    FeatureStatus {
        module: "USB",
        feature: "CLI USB transport integration",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI supports dynamic USB / TCP transport selection and usbfs/rusb fallback",
    },
    FeatureStatus {
        module: "USB",
        feature: "Real-device USB verification",
        status: AcceptanceStatus::RealDeviceUnverified,
        evidence: "未执行真实 ADB/Fastboot USB 设备枚举、授权/握手、bulk I/O 或命令验收；代码存在不能替代设备验证",
    },
    FeatureStatus {
        module: "ADB",
        feature: "ADB mDNS discovery / wireless pairing / TLS",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI supports wireless pairing (adb pair) with SPA auth and TLS upgrade",
    },
    FeatureStatus {
        module: "ADB",
        feature: "Directory push/pull recursion",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI 路径和 SYNC 递归代码存在；真实设备未验证",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "Response parser (OKAY/FAIL/DATA/INFO/TEXT)",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "协议级 response parser 与 fake-peer 测试覆盖",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "Sparse image header/chunk encoding",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "SparseFile 编解码/拆分代码存在；真实 bootloader 未验证",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "Command formatter (getvar/flash/erase/reboot)",
        status: AcceptanceStatus::ProtocolImplemented,
        evidence: "命令格式在 fake-peer wire test 中检查；不等于 AOSP CLI 完整兼容",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "Flash download/payload/flash flow",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI 使用 TCP flow，fake-peer 测试通过；真实设备与 USB 未验证",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "Logical partition commands",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI 子命令与协议 formatter 存在；真实动态分区未验证",
    },

    FeatureStatus {
        module: "Fastboot",
        feature: "Fastboot UDP transport",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI supports Fastboot UDP transport with sequence numbers and retransmission",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "fastboot boot argument semantics",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI supports booting Android kernel with optional ramdisk via BootImageBuilder",
    },
    FeatureStatus {
        module: "Fastboot",
        feature: "fastboot fetch file output",
        status: AcceptanceStatus::CliImplemented,
        evidence: "CLI 已接收 DATA payload 并写入目标文件；真实 bootloader/USB 尚未验证",
    },
];

fn find(feature: &str) -> FeatureStatus {
    MATRIX
        .iter()
        .copied()
        .find(|item| item.feature == feature)
        .unwrap_or_else(|| panic!("missing acceptance-matrix row: {feature}"))
}

#[test]
fn required_incomplete_features_are_not_reported_as_supported() {
    for feature in [
        "Real-device USB verification",
    ] {
        let item = find(feature);
        assert!(
            !item.status.is_accepted(),
            "{feature} must remain incomplete or unverified"
        );
    }
}

#[test]
fn usb_code_evidence_is_not_mistaken_for_cli_completion() {
    let adapter = find("Protocol USB adapters (ADB/Fastboot)");
    let backend = find("Optional rusb USB backends (ADB/Fastboot)");
    let cli = find("CLI USB transport integration");
    let device = find("Real-device USB verification");

    for item in [adapter, backend] {
        assert!(
            item.status.is_code_evidence(),
            "USB adapter/backend must be classified as code evidence"
        );
        assert!(
            !item.status.is_accepted(),
            "USB backend code evidence must not be reported as accepted CLI support"
        );
    }
    assert_eq!(cli.status, AcceptanceStatus::CliImplemented);
    assert!(cli.status.is_accepted());
    assert_eq!(device.status, AcceptanceStatus::RealDeviceUnverified);
    assert!(!device.status.is_accepted());
}

#[test]
fn audit_adb_fastboot_features() {
    println!("\n=== adb-fastboot-rs 迁移验收矩阵（非功能宣传清单） ===");
    let mut accepted = 0usize;
    let mut code_evidence = 0usize;

    for item in MATRIX {
        let marker = if item.status.is_accepted() { "[✓]" } else { "[!]" };
        println!(
            "{} [{}] {:<48} : {} — {}",
            marker,
            item.module,
            item.feature,
            item.status.label(),
            item.evidence
        );
        if item.status.is_accepted() {
            accepted += 1;
        }
        if item.status.is_code_evidence() {
            code_evidence += 1;
        }
    }

    println!(
        "\n协议/CLI 已完成: {}/{}；USB code evidence: {}（不等于 CLI 或真实设备完成）；其余为 transport missing 或 real-device unverified。",
        accepted,
        MATRIX.len(),
        code_evidence
    );
}
