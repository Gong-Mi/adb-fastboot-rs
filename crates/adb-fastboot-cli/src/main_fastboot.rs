use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use clap::{Parser, Subcommand};
use fastboot_protocol::{FastbootTcpTransport, FastbootTransport};
#[cfg(feature = "usb")]
use fastboot_protocol::usb_android::UsbfsFastbootDevice;
use zip::ZipArchive;


#[derive(Parser)]
#[command(name = "fastboot-rs", author, version, about = "Rust Fastboot Command-Line Interface")]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    /// Use the opt-in rusb Fastboot USB backend instead of TCP.
    #[arg(long, global = true)]
    usb: bool,

    #[command(subcommand)]
    command: Commands,
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_str, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_max_download_size(val: &str) -> Option<usize> {
    let s = val.trim();
    if s.is_empty() {
        return None;
    }

    let s_lower = s.to_lowercase();
    let (num_str, multiplier): (&str, usize) = if s_lower.ends_with("gb") || s_lower.ends_with("g") {
        let len = if s_lower.ends_with("gb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024 * 1024 * 1024)
    } else if s_lower.ends_with("mb") || s_lower.ends_with("m") {
        let len = if s_lower.ends_with("mb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024 * 1024)
    } else if s_lower.ends_with("kb") || s_lower.ends_with("k") {
        let len = if s_lower.ends_with("kb") { 2 } else { 1 };
        (&s[..s.len() - len], 1024)
    } else if s_lower.ends_with("b") && !s_lower.starts_with("0x") && !s.chars().all(|c| c.is_ascii_hexdigit()) {
        (&s[..s.len() - 1], 1)
    } else {
        (s, 1)
    };

    let num_str = num_str.trim();
    if num_str.is_empty() {
        return None;
    }

    let base_val = if let Some(hex_str) = num_str.strip_prefix("0x").or_else(|| num_str.strip_prefix("0X")) {
        usize::from_str_radix(hex_str, 16).ok()?
    } else if let Ok(n) = num_str.parse::<usize>() {
        n
    } else {
        usize::from_str_radix(num_str, 16).ok()?
    };

    base_val.checked_mul(multiplier)
}

#[derive(Subcommand)]
enum Commands {
    /// List connected fastboot devices
    Devices,
    /// Get variable value from bootloader
    Getvar {
        variable: String,
    },
    /// Set the active A/B slot (AOSP CLI spelling: set_active SLOT; wire: set_active:SLOT)
    #[command(name = "set_active", visible_alias = "set-active")]
    SetActive {
        slot: String,
    },
    /// Flash partition with image. If FILE is not specified, looks up ANDROID_PRODUCT_OUT
    /// environment variable (AOSP-style) to find <ANDROID_PRODUCT_OUT>/<partition>.img
    Flash {
        partition: String,
        file: Option<String>,
    },
    /// Package kernel/ramdisk as boot image and flash to partition (AOSP flash:raw).
    /// Usage: flash:raw <partition> <kernel> [ramdisk [second]]
    #[command(name = "flash:raw")]
    FlashRaw {
        partition: String,
        kernel: String,
        /// Optional ramdisk image file
        ramdisk: Option<String>,
        /// Optional second boot image file
        second: Option<String>,
    },
    /// Erase partition
    Erase {
        partition: String,
    },
    /// Reboot device
    #[command(name = "reboot")]
    Reboot {
        target: Option<String>,
    },
    /// Reboot into the bootloader (AOSP fastboot alias).
    #[command(name = "reboot-bootloader")]
    RebootBootloader,
    /// Reboot into recovery (AOSP fastboot alias).
    #[command(name = "reboot-recovery")]
    RebootRecovery,
    /// Reboot into fastbootd (AOSP fastboot alias).
    #[command(name = "reboot-fastboot")]
    RebootFastboot,
    /// Send OEM command
    Oem {
        #[arg(required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Create dynamic logical partition
    CreateLogicalPartition {
        partition: String,
        #[arg(value_parser = parse_u64)]
        size: u64,
    },
    /// Delete dynamic logical partition
    DeleteLogicalPartition {
        partition: String,
    },
    /// Resize dynamic logical partition
    ResizeLogicalPartition {
        partition: String,
        #[arg(value_parser = parse_u64)]
        size: u64,
    },
    /// Download and boot a kernel image with optional ramdisk
    Boot {
        kernel: String,
        ramdisk: Option<String>,
        second: Option<String>,
    },
    /// Fetch a partition image to a local file
    Fetch {
        partition: String,
        out_file: String,
    },
    /// Continue booting after flash operations (re-send to device)
    Continue,
    /// Shut down the device (sends reboot-shutdown)
    Shutdown,
    /// Format a partition (sends format:<partition> or format:<partition_type>:<partition>)
    Format {
        partition: String,
        #[arg(long)]
        partition_type: Option<String>,
    },
    /// Read staged data from the device into OUT_FILE (sends get_staged)
    GetStaged {
        /// Destination file for the staged bytes.
        out_file: String,
    },
    /// Stage data onto the device for a subsequent command (reverse of get_staged).
    /// Reads from FILE and sends download:DATA with streamed chunks.
    Stage {
        /// Path to the file to stage.
        #[arg(required = true)]
        file: Option<String>,
    },
    /// Send flashing command to bootloader (e.g. lock, unlock, close, lock_critical, unlock_critical)
    Flashing {
        #[arg(value_parser = ["unlock", "lock", "unlock_critical", "lock_critical", "get_unlock_ability"])]
        action: String,
    },
    /// GSI command
    Gsi {
        #[arg(value_parser = ["wipe", "disable", "status"])]
        action: String,
    },
    /// Flash all partitions from an update.zip package
    Update {
        /// Path to the update.zip file
        zip_file: String,
    },
}

fn resolve_target_addr(serial: Option<&str>, default_port: u16) -> String {
    match serial {
        Some(s) if s.contains(':') => s.to_string(),
        Some(s) => format!("{}:{}", s, default_port),
        None => format!("127.0.0.1:{}", default_port),
    }
}

#[cfg(feature = "usb")]
type UsbFastbootTransport = fastboot_protocol::FastbootUsbTransport<fastboot_protocol::usb_android::UsbfsFastbootDevice>;

enum FastbootConnection {
    Tcp(FastbootTcpTransport),
    Udp(fastboot_protocol::FastbootUdpTransport),
    #[cfg(feature = "usb")]
    Usb(UsbFastbootTransport),
}

impl std::io::Read for FastbootConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.read(buf),
            Self::Udp(transport) => transport.read(buf),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.read(buf),
        }
    }
}

impl std::io::Write for FastbootConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.write(buf),
            Self::Udp(transport) => transport.write(buf),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(transport) => transport.flush(),
            Self::Udp(transport) => transport.flush(),
            #[cfg(feature = "usb")]
            Self::Usb(transport) => transport.flush(),
        }
    }
}

fn open_transport(
    usb: bool,
    addr: &str,
    timeout: Duration,
) -> Result<FastbootConnection, Box<dyn std::error::Error>> {
    if usb {
        #[cfg(feature = "usb")]
        {
            return fastboot_protocol::usb_android::UsbfsFastbootDevice::open_transport()
                .map(FastbootConnection::Usb)
                .map_err(|error| {
                    format!("failed to open Fastboot USB transport: {error}").into()
                });
        }
        #[cfg(not(feature = "usb"))]
        {
            let _ = (addr, timeout);
            return Err("USB support is not enabled; rebuild with `--features usb`".into());
        }
    }

    if let Some(udp_addr) = addr.strip_prefix("udp:") {
        return fastboot_protocol::FastbootUdpTransport::connect_timeout(udp_addr, timeout)
            .map(FastbootConnection::Udp)
            .map_err(|error| error.into());
    }

    FastbootTcpTransport::connect_timeout(addr, timeout)
        .map(FastbootConnection::Tcp)
        .map_err(|error| error.into())
}

/// 读取文件全部字节，出错时 exit(1)。
fn read_file_bytes(path: &str) -> Vec<u8> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法打开文件 '{}': {}", path, e);
            std::process::exit(1);
        }
    };
    let mut data = Vec::new();
    if let Err(e) = f.read_to_end(&mut data) {
        eprintln!("[fastboot-rs] 错误: 读取文件 '{}' 失败: {}", path, e);
        std::process::exit(1);
    }
    if data.is_empty() {
        eprintln!("[fastboot-rs] 错误: 文件 '{}' 为空", path);
        std::process::exit(1);
    }
    data
}

/// 下载内存中的 payload 并发送 boot 命令。
fn download_and_boot_payload<T: FastbootTransport>(
    transport: &mut T,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = payload.len();
    if file_size > u32::MAX as usize {
        eprintln!(
            "[fastboot-rs] 错误: payload 大小 ({}) 超过 u32 上限 ({}); 协议限制",
            file_size,
            u32::MAX
        );
        std::process::exit(1);
    }

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
            limit, limit
        );
    }

    // Step 1: 发送 download 命令
    let download_cmd = fastboot_protocol::download(file_size as u32);
    transport.send_cmd(&download_cmd)?;
    let dl_resp = transport.recv_response()?;
    match dl_resp {
        fastboot_protocol::FastbootResponse::Data(expected_len) => {
            if expected_len != file_size as u32 {
                eprintln!(
                    "[fastboot-rs] 错误: 设备请求 {} 字节，但 payload 为 {} 字节",
                    expected_len, file_size
                );
                std::process::exit(1);
            }
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            eprintln!("[fastboot-rs] download 失败: {}", reason);
            std::process::exit(1);
        }
        other => {
            eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
            std::process::exit(1);
        }
    }

    // Step 2: 分块发送 payload
    let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
    println!(
        "[fastboot-rs] 发送 payload ({} 字节, 分块大小: {} 字节)...",
        file_size, chunk_size
    );
    let mut offset = 0usize;
    while offset < file_size {
        let to_send = (file_size - offset).min(chunk_size);
        let chunk = &payload[offset..offset + to_send];
        if let Err(e) = transport.write_all(chunk) {
            eprintln!(
                "[fastboot-rs] 错误: 写入 transport 失败 at offset {}: {}",
                offset, e
            );
            std::process::exit(1);
        }
        offset += to_send;
    }
    transport.flush()?;

    // Step 3: 读取 payload 发送完成后的 OKAY/FAIL
    let post_dl_resp = transport.recv_response()?;
    if let fastboot_protocol::FastbootResponse::Fail(reason) = &post_dl_resp {
        eprintln!("[fastboot-rs] payload 发送失败: {}", reason);
        std::process::exit(1);
    }
    println!("[fastboot-rs] Download 完成: {:?}", post_dl_resp);

    // Step 4: 发送 boot 命令
    println!("[fastboot-rs] 发送 boot 命令...");
    transport.send_cmd("boot")?;

    Ok(())
}

/// 下载内存中的 payload 并发送 flash 命令到指定分区。
fn download_and_flash_payload<T: FastbootTransport>(
    transport: &mut T,
    payload: &[u8],
    partition: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = payload.len();
    if file_size > u32::MAX as usize {
        eprintln!(
            "[fastboot-rs] 错误: payload 大小 ({}) 超过 u32 上限 ({}); 协议限制",
            file_size,
            u32::MAX
        );
        std::process::exit(1);
    }

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
            limit, limit
        );
    }

    // Step 1: 发送 download 命令
    let download_cmd = fastboot_protocol::download(file_size as u32);
    transport.send_cmd(&download_cmd)?;
    let dl_resp = transport.recv_response()?;
    match dl_resp {
        fastboot_protocol::FastbootResponse::Data(expected_len) => {
            if expected_len != file_size as u32 {
                eprintln!(
                    "[fastboot-rs] 错误: 设备请求 {} 字节，但 payload 为 {} 字节",
                    expected_len, file_size
                );
                std::process::exit(1);
            }
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            eprintln!("[fastboot-rs] download 失败: {}", reason);
            std::process::exit(1);
        }
        other => {
            eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
            std::process::exit(1);
        }
    }

    // Step 2: 分块发送 payload
    let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
    println!(
        "[fastboot-rs] 发送 boot image payload ({} 字节, 分块大小: {} 字节)...",
        file_size, chunk_size
    );
    let mut offset = 0usize;
    while offset < file_size {
        let to_send = (file_size - offset).min(chunk_size);
        let chunk = &payload[offset..offset + to_send];
        if let Err(e) = transport.write_all(chunk) {
            eprintln!(
                "[fastboot-rs] 错误: 写入 transport 失败 at offset {}: {}",
                offset, e
            );
            std::process::exit(1);
        }
        offset += to_send;
    }
    transport.flush()?;

    // Step 3: 读取 payload 发送完成后的 OKAY/FAIL
    let post_dl_resp = transport.recv_response()?;
    if let fastboot_protocol::FastbootResponse::Fail(reason) = &post_dl_resp {
        eprintln!("[fastboot-rs] payload 发送失败: {}", reason);
        std::process::exit(1);
    }
    println!("[fastboot-rs] Download 完成: {:?}", post_dl_resp);

    // Step 4: 发送 flash 命令到指定分区
    println!("[fastboot-rs] 发送 flash:{} 命令...", partition);
    let flash_cmd = fastboot_protocol::flash(partition);
    transport.send_cmd(&flash_cmd)?;

    Ok(())
}

/// Boot 命令发送后的响应处理（设备可能立即重启）。
fn handle_boot_response(
    mut transport: FastbootConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let boot_resp = transport.recv_response();
    match &boot_resp {
        Ok(fastboot_protocol::FastbootResponse::Okay(msg)) => {
            println!("[fastboot-rs] Boot OK: {}", msg);
            let disconnected = wait_for_disconnect(transport, Duration::from_secs(5));
            if disconnected {
                println!("[fastboot-rs] 设备已断开 — boot 确认");
            } else {
                eprintln!(
                    "[fastboot-rs] 警告: 设备未在 5s 内断开 (boot 可能仍在进行)"
                );
            }
        }
        Ok(fastboot_protocol::FastbootResponse::Fail(reason)) => {
            eprintln!("[fastboot-rs] Boot FAIL: {}", reason);
            std::process::exit(1);
        }
        Ok(other) => {
            println!("[fastboot-rs] Boot 响应: {:?}", other);
        }
        Err(e) => {
            eprintln!(
                "[fastboot-rs] 信息: 设备已断开 (boot 正在启动): {}",
                e
            );
        }
    }
    Ok(())
}

fn fetch_to_file(
    transport: &mut FastbootConnection,
    partition: &str,
    out_file: &str,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    let mut output = File::create(out_file)?;
    // AOSP FastBootDriver::Fetch uses `fetch:<partition>` when no range is requested.
    transport.send_cmd(&format!("fetch:{}", partition))?;
    let response = recv_data_response(transport, "fetch")?;
    let size = match response {
        fastboot_protocol::FastbootResponse::Data(size) if size > 0 => size as usize,
        fastboot_protocol::FastbootResponse::Data(_) => {
            return Err("fetch failed: device returned zero bytes".into());
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            return Err(format!("fetch failed: {}", reason).into());
        }
        other => {
            return Err(format!("unexpected fetch response: {:?}", other).into());
        }
    };

    let mut remaining = size;
    let mut buffer = [0u8; 1024 * 1024];
    while remaining > 0 {
        let chunk_size = remaining.min(buffer.len());
        transport.read_exact(&mut buffer[..chunk_size])?;
        output.write_all(&buffer[..chunk_size])?;
        remaining -= chunk_size;
    }
    output.sync_all()?;
    let final_response = transport.recv_response()?;
    if let fastboot_protocol::FastbootResponse::Fail(reason) = &final_response {
        return Err(format!("fetch failed after receiving data: {}", reason).into());
    }
    Ok(final_response)
}

/// Read the DATA status for commands whose response is followed by a byte payload.
/// AOSP FastBootDriver::RunAndReadBuffer accepts INFO/TEXT packets before DATA and
/// then reads exactly the advertised number of bytes. Keep that framing separate from
/// the payload consumer so fetch and get_staged cannot accidentally treat INFO as DATA.
fn recv_data_response(
    transport: &mut FastbootConnection,
    operation: &str,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    let mut info_logs = Vec::new();
    let response = match transport {
        // TCP keeps response bytes read ahead of DATA in its internal buffer. Calling
        // the inherent method here is important: the blanket trait implementation
        // cannot preserve those bytes for the subsequent payload read.
        FastbootConnection::Tcp(transport) => transport.recv_response_with_info(&mut info_logs)?,
        FastbootConnection::Udp(transport) => {
            FastbootTransport::recv_response_with_info(transport, &mut info_logs)?
        }
        #[cfg(feature = "usb")]
        FastbootConnection::Usb(transport) => {
            FastbootTransport::recv_response_with_info(transport, &mut info_logs)?
        }
    };
    for info in info_logs {
        println!("[fastboot-rs] INFO {}", info);
    }
    match response {
        fastboot_protocol::FastbootResponse::Data(size) => {
            Ok(fastboot_protocol::FastbootResponse::Data(size))
        }
        fastboot_protocol::FastbootResponse::Fail(reason) => {
            Err(format!("{operation} failed: {reason}").into())
        }
        other => Err(format!("unexpected {operation} response: {other:?}").into()),
    }
}

fn recv_and_print_info(
    transport: &mut impl FastbootTransport,
) -> Result<fastboot_protocol::FastbootResponse, Box<dyn std::error::Error>> {
    let mut info_logs = Vec::new();
    let response = transport.recv_response_with_info(&mut info_logs)?;
    for info in info_logs {
        println!("[fastboot-rs] INFO {}", info);
    }
    Ok(response)
}

/// 发送 reboot 命令后，等待设备断开连接。
///
/// 通过在线程中执行阻塞读取来检测连接断开：
/// - 如果读取返回错误 → 设备已断开 → reboot 成功
/// - 如果读取返回数据（不应发生）或超时 → 返回 false
///
/// 注意：此函数获取 transport 的所有权，因为我们需要将其移入线程。
fn wait_for_disconnect(transport: FastbootConnection, timeout: Duration) -> bool {
    let (tx, rx) = mpsc::channel::<bool>();

    thread::spawn(move || {
        let mut t = transport;
        let mut buf = [0u8; 1];
        // 阻塞读取；设备重启时 TCP 连接会 RST，read 立即返回错误
        let result = Read::read(&mut t, &mut buf);
        let _ = tx.send(result.is_err());
    });

    match rx.recv_timeout(timeout) {
        Ok(true) => true,   // read 返回错误 → 设备断开
        Ok(false) => false, // read 返回了数据（异常）
        Err(mpsc::RecvTimeoutError::Timeout) => false,   // 超时，设备未断开
        Err(mpsc::RecvTimeoutError::Disconnected) => false, // 线程 panic 等异常
    }
}

fn run_reboot(
    use_usb: bool,
    addr: &str,
    target: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = open_transport(use_usb, addr, Duration::from_secs(3))?;
    let cmd = fastboot_protocol::reboot(target);
    transport.send_cmd(&cmd)?;

    // A rebooting device may close the connection before returning a status.
    match transport.recv_response() {
        Ok(response) => println!("[fastboot-rs] Reboot response: {:?}", response),
        Err(error) => eprintln!(
            "[fastboot-rs] Warning: Could not read reboot response (device may be disconnecting): {}",
            error
        ),
    }

    if wait_for_disconnect(transport, Duration::from_secs(5)) {
        println!("[fastboot-rs] Device disconnected — reboot confirmed");
    } else {
        eprintln!(
            "[fastboot-rs] Warning: Device did not disconnect within 5s timeout (reboot may still be in progress)"
        );
    }
    Ok(())
}

/// 解析 android-info.txt，检查设备兼容性。
///
/// 兼容 AOSP CheckRequirements() 逻辑：
/// - `require board=<board>`  → getvar:product 检查
/// - `require version-*=<val>` → getvar 检查对应变量
/// - `require partition-exists=<name>` → getvar:has-slot:<name> 检查
/// - `require force=<val>` → 始终要求 force_flash
/// - 行首 `require` 后的 `inverse` 标签反转检查
/// - 不支持的行打印警告并跳过
fn check_android_info<T: FastbootTransport>(
    transport: &mut T,
    data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // 格式: require [inverse] <name>=<value> [or <value2>...]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "require" {
            eprintln!("[fastboot-rs] android-info.txt 语法警告: {line}");
            continue;
        }

        let mut idx = 1;
        let invert = parts.len() > 2 && parts[1] == "inverse";
        if invert {
            idx += 1;
        }

        if idx >= parts.len() {
            eprintln!("[fastboot-rs] android-info.txt 语法警告: {line}");
            continue;
        }

        let kv = parts[idx];
        if let Some(eq_pos) = kv.find('=') {
            let var = &kv[..eq_pos];
            let expected = &kv[eq_pos + 1..];

            // 解析额外的可选值: ["or val2", "or val3", ...]
            let mut options = vec![expected];
            let mut i = idx + 1;
            while i < parts.len() {
                if parts[i] == "or" && i + 1 < parts.len() {
                    options.push(parts[i + 1]);
                    i += 2;
                } else {
                    break;
                }
            }

            match var {
                "partition-exists" => {
                    // 检查分区是否存在
                    let query = format!("getvar:has-slot:{}", options[0]);
                    if transport.send_cmd(&query).is_ok() {
                        if let Ok(resp) = transport.recv_response() {
                            match resp {
                                fastboot_protocol::FastbootResponse::Okay(val) => {
                                    if val != "yes" && val != "no" {
                                        eprintln!(
                                            "[fastboot-rs] 错误: 设备缺少所需分区 '{}'",
                                            options[0]
                                        );
                                        std::process::exit(1);
                                    }
                                }
                                _ => {
                                    eprintln!(
                                        "[fastboot-rs] 错误: 设备缺少所需分区 '{}'",
                                        options[0]
                                    );
                                    std::process::exit(1);
                                }
                            }
                        }
                    }
                }
                other => {
                    // getvar:other 并检查值
                    let query = format!("getvar:{other}");
                    if let Err(e) = transport.send_cmd(&query) {
                        eprintln!("[fastboot-rs] 警告: 无法获取变量 '{other}': {e}");
                        continue;
                    }
                    let actual = match transport.recv_response() {
                        Ok(fastboot_protocol::FastbootResponse::Okay(val)) => val,
                        Ok(fastboot_protocol::FastbootResponse::Fail(reason)) => {
                            eprintln!("[fastboot-rs] getvar:{other} FAILED: {reason}");
                            String::new()
                        }
                        _ => {
                            eprintln!("[fastboot-rs] 警告: 无法获取变量 '{other}'");
                            continue;
                        }
                    };

                    let met = options.iter().any(|opt| actual.trim() == *opt);
                    if invert {
                        if met {
                            eprintln!(
                                "[fastboot-rs] 错误: 设备 {other} 是 '{actual}'，但 update 要求不是 {}",
                                options.join(" 或 ")
                            );
                            std::process::exit(1);
                        }
                    } else if !met {
                        eprintln!(
                            "[fastboot-rs] 错误: 设备 {other} 是 '{actual}'，但 update 要求 {}",
                            options.join(" 或 ")
                        );
                        std::process::exit(1);
                    }
                }
            }
        } else {
            eprintln!("[fastboot-rs] android-info.txt 语法警告: {line}");
        }
    }
    Ok(())
}

/// AOSP 兼容的分区镜像列表及刷写顺序。
///
/// 每一项：(分区名, zip内文件名, 是否可选)
/// 按此顺序刷写，仅刷写 zip 中存在的镜像。
const AOSP_IMAGES: &[(&str, &str, bool)] = &[
    ("boot",           "boot.img",           false),
    ("bootloader",     "bootloader.img",     true),
    ("init_boot",      "init_boot.img",      true),
    ("dtbo",           "dtbo.img",           true),
    ("dts",            "dt.img",             true),
    ("odm",            "odm.img",            true),
    ("odm_dlkm",       "odm_dlkm.img",       true),
    ("product",        "product.img",        true),
    ("pvmfw",          "pvmfw.img",          true),
    ("radio",          "radio.img",          true),
    ("recovery",       "recovery.img",       true),
    ("super",          "super.img",          true),
    ("system",         "system.img",         false),
    ("system_dlkm",    "system_dlkm.img",    true),
    ("system_ext",     "system_ext.img",     true),
    ("userdata",       "userdata.img",       true),
    ("vbmeta",         "vbmeta.img",         true),
    ("vbmeta_system",  "vbmeta_system.img",  true),
    ("vbmeta_vendor",  "vbmeta_vendor.img",  true),
    ("vendor",         "vendor.img",         true),
    ("vendor_boot",    "vendor_boot.img",    true),
    ("vendor_dlkm",    "vendor_dlkm.img",    true),
    ("vendor_kernel_boot", "vendor_kernel_boot.img", true),
    ("cache",          "cache.img",          true),
];

/// 执行 fastboot update：解析 update.zip，刷写所有分区镜像。
fn do_update<T: FastbootTransport>(
    transport: &mut T,
    zip_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: 打开 update.zip ---
    let zip_file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法打开 update.zip '{zip_path}': {e}");
            std::process::exit(1);
        }
    };

    let mut archive = match ZipArchive::new(zip_file) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法解析 zip 文件 '{zip_path}': {e}");
            std::process::exit(1);
        }
    };

    println!("[fastboot-rs] 已打开 update.zip ({} 个条目)", archive.len());

    // --- Step 2: 读取并检查 android-info.txt ---
    let android_info = match archive.by_name("android-info.txt") {
        Ok(mut entry) => {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            println!("[fastboot-rs] android-info.txt 大小: {} 字节", contents.len());
            contents
        }
        Err(e) => {
            eprintln!("[fastboot-rs] 错误: 无法读取 android-info.txt: {e}");
            std::process::exit(1);
        }
    };

    // 显示设备信息 (AOSP DumpInfo 风格)
    println!("[fastboot-rs] --------------------------------------------");
    for &var in &["version-bootloader", "version-baseband", "serialno"] {
        let query = format!("getvar:{var}");
        if transport.send_cmd(&query).is_ok() {
            if let Ok(resp) = transport.recv_response() {
                if let fastboot_protocol::FastbootResponse::Okay(val) = resp {
                    println!("[fastboot-rs] {var}: {val}");
                }
            }
        }
    }
    println!("[fastboot-rs] --------------------------------------------");

    // 检查兼容性
    check_android_info(transport, &android_info)?;
    println!("[fastboot-rs] 设备兼容性检查通过");

    // 获取 max-download-size
    let max_download_size = match transport.send_cmd("getvar:max-download-size") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                parse_max_download_size(&val)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(limit) = max_download_size {
        println!(
            "[fastboot-rs] Bootloader max-download-size: {limit} bytes ({limit:#x})"
        );
    }

    // 获取当前 slot
    let current_slot = match transport.send_cmd("getvar:current-slot") {
        Ok(_) => match transport.recv_response() {
            Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                let s = val.trim().to_string();
                if !s.is_empty() { Some(s) } else { None }
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(ref slot) = current_slot {
        println!("[fastboot-rs] 当前 slot: {slot}");
    }

    // --- Step 3: 按 AOSP 顺序刷写分区镜像 ---
    // 收集 zip 中存在的镜像文件名以便快速查找
    let zip_names: std::collections::HashSet<String> = archive
        .file_names()
        .map(|n| n.to_string())
        .collect();

    println!("[fastboot-rs] 开始刷写分区镜像...\n");

    for &(partition, img_name, optional) in AOSP_IMAGES {
        // 检查 zip 中是否存在此镜像
        if !zip_names.contains(img_name) {
            if optional {
                println!(
                    "[fastboot-rs]   {img_name}: 未找到，跳过（可选）"
                );
            } else {
                eprintln!(
                    "[fastboot-rs] 错误: 必需的镜像 '{img_name}' 在 zip 中未找到"
                );
                std::process::exit(1);
            }
            continue;
        }

        println!("[fastboot-rs] >>> 刷写 {img_name} -> 分区 {partition}");

        // 从 zip 读取镜像数据
        let image_data = match archive.by_name(img_name) {
            Ok(mut entry) => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                data
            }
            Err(e) => {
                eprintln!(
                    "[fastboot-rs] 错误: 无法从 zip 读取 '{img_name}': {e}"
                );
                std::process::exit(1);
            }
        };

        let file_size = image_data.len();
        if file_size == 0 {
            eprintln!("[fastboot-rs] 错误: 镜像 '{img_name}' 为空");
            std::process::exit(1);
        }
        if file_size > u32::MAX as usize {
            eprintln!(
                "[fastboot-rs] 错误: 镜像 '{img_name}' 大小 ({file_size}) 超过 u32 上限"
            );
            std::process::exit(1);
        }

        println!(
            "[fastboot-rs]   {img_name}: {file_size} 字节"
        );

        let partition_with_slot = if let Some(ref slot) = current_slot {
            if !partition.ends_with('_') {
                format!("{partition}_{slot}")
            } else {
                partition.to_string()
            }
        } else {
            partition.to_string()
        };

        let need_split = match max_download_size {
            Some(limit) if limit > 0 && file_size > limit => true,
            _ => false,
        };

        if need_split {
            // 需要做 sparse split
            let limit = max_download_size.unwrap();

            let is_sparse = file_size >= 28
                && u32::from_le_bytes(image_data[..4].try_into().unwrap())
                    == fastboot_protocol::SPARSE_HEADER_MAGIC;

            let sparse_file = if is_sparse {
                match fastboot_protocol::SparseFile::from_bytes(&image_data) {
                    Ok(sf) => sf,
                    Err(e) => {
                        eprintln!(
                            "[fastboot-rs] 错误: 解析 sparse 文件 '{img_name}' 失败: {e}"
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                fastboot_protocol::SparseFile::from_raw(&image_data, 4096)
            };

            let splits = match sparse_file.split(limit) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 分割镜像 '{img_name}' 失败: {e}"
                    );
                    std::process::exit(1);
                }
            };

            println!(
                "[fastboot-rs]   {img_name}: 大小超过 max-download-size，分割为 {} 个 sparse chunk",
                splits.len()
            );

            for (idx, split_file) in splits.iter().enumerate() {
                let payload = split_file.encode();
                println!(
                    "[fastboot-rs]   发送 chunk {}/{} ({} 字节)...",
                    idx + 1,
                    splits.len(),
                    payload.len()
                );

                // download
                let dl_cmd = fastboot_protocol::download(payload.len() as u32);
                transport.send_cmd(&dl_cmd)?;
                let dl_resp = transport.recv_response()?;
                match dl_resp {
                    fastboot_protocol::FastbootResponse::Data(expected) => {
                        if expected != payload.len() as u32 {
                            eprintln!(
                                "[fastboot-rs] 错误: 设备请求 {expected} 字节，但 chunk 为 {} 字节",
                                payload.len()
                            );
                            std::process::exit(1);
                        }
                    }
                    fastboot_protocol::FastbootResponse::Fail(reason) => {
                        eprintln!(
                            "[fastboot-rs] download 失败 (chunk {}/{}): {reason}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                    other => {
                        eprintln!(
                            "[fastboot-rs] 意外的 download 响应 (chunk {}/{}): {other:?}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                }

                // 发送 payload
                transport.write_all(&payload)?;
                transport.flush()?;

                let post_resp = transport.recv_response()?;
                if let fastboot_protocol::FastbootResponse::Fail(reason) = post_resp {
                    eprintln!(
                        "[fastboot-rs] payload 发送失败 (chunk {}/{}): {reason}",
                        idx + 1,
                        splits.len()
                    );
                    std::process::exit(1);
                }

                // flash
                let flash_cmd = fastboot_protocol::flash(&partition_with_slot);
                transport.send_cmd(&flash_cmd)?;
                let flash_resp = transport.recv_response()?;
                match &flash_resp {
                    fastboot_protocol::FastbootResponse::Okay(val) => {
                        println!(
                            "[fastboot-rs]   {img_name} chunk {}/{} OK: {val}",
                            idx + 1,
                            splits.len()
                        );
                    }
                    fastboot_protocol::FastbootResponse::Fail(reason) => {
                        eprintln!(
                            "[fastboot-rs] 错误: 刷写 {img_name} chunk {}/{} 失败: {reason}",
                            idx + 1,
                            splits.len()
                        );
                        std::process::exit(1);
                    }
                    other => {
                        println!(
                            "[fastboot-rs]   {img_name} chunk {}/{} 响应: {other:?}",
                            idx + 1,
                            splits.len()
                        );
                    }
                }
            }
        } else {
            // 不需要 split：直接 download + flash
            let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024);
            let download_cmd = fastboot_protocol::download(file_size as u32);
            transport.send_cmd(&download_cmd)?;
            let dl_resp = transport.recv_response()?;
            match dl_resp {
                fastboot_protocol::FastbootResponse::Data(expected) => {
                    if expected != file_size as u32 {
                        eprintln!(
                            "[fastboot-rs] 错误: 设备请求 {expected} 字节，但镜像为 {file_size} 字节"
                        );
                        std::process::exit(1);
                    }
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] download 失败 ({img_name}): {reason}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("[fastboot-rs] 意外的 download 响应 ({img_name}): {other:?}");
                    std::process::exit(1);
                }
            }

            // 分块发送 payload
            let mut offset = 0usize;
            while offset < file_size {
                let to_send = (file_size - offset).min(chunk_size);
                let chunk = &image_data[offset..offset + to_send];
                transport.write_all(chunk)?;
                offset += to_send;
            }
            transport.flush()?;

            let post_resp = transport.recv_response()?;
            if let fastboot_protocol::FastbootResponse::Fail(reason) = &post_resp {
                eprintln!("[fastboot-rs] payload 发送失败 ({img_name}): {reason}");
                std::process::exit(1);
            }

            // 发送 flash 命令
            let flash_cmd = fastboot_protocol::flash(&partition_with_slot);
            transport.send_cmd(&flash_cmd)?;
            let flash_resp = transport.recv_response()?;
            match &flash_resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs]   {img_name} -> {partition_with_slot} OK: {val}");
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 刷写 {img_name} -> {partition_with_slot} 失败: {reason}"
                    );
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs]   {img_name} -> {partition_with_slot} 响应: {other:?}");
                }
            }
        }
    }

    println!("\n[fastboot-rs] 所有分区已刷写完成。");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = resolve_target_addr(cli.serial.as_deref(), 5554);
    let use_usb = cli.usb;

    match cli.command {
        Commands::Devices => {
            println!("List of fastboot devices (fastboot-rs pure rust protocol)");
            if use_usb {
                #[cfg(feature = "usb")]
                {
                    match UsbfsFastbootDevice::enumerate() {
                        Ok(devices) => {
                            if devices.is_empty() {
                                println!("no devices found");
                            }
                            for device in &devices {
                                let serial = device.serial.as_deref().unwrap_or("????????");
                                println!("{}\tfastboot", serial);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error enumerating fastboot USB devices: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(feature = "usb"))]
                {
                    let _ = addr;
                    eprintln!("USB support is not enabled; rebuild with `--features usb`");
                    std::process::exit(1);
                }
            } else {
                match open_transport(false, &addr, Duration::from_secs(2)) {
                    Ok(mut transport) => {
                        if let Ok(_) = transport.send_cmd("getvar:version") {
                            if let Ok(resp) = transport.recv_response() {
                                println!("{}\tfastboot ({:?})", addr, resp);
                            } else {
                                println!("{}\tfastboot", addr);
                            }
                        } else {
                            println!("{}\tfastboot", addr);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Getvar { variable } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("getvar:{}", variable);
            transport.send_cmd(&cmd)?;
            if variable == "all" {
                // AOSP-compatible output for getvar all:
                //   (bootloader) key: value
                //   ...
                //   Finished. Total time: X.XXXs
                let start = std::time::Instant::now();
                let mut info_logs = Vec::new();
                let _resp = transport.recv_response_with_info(&mut info_logs)?;
                for info in info_logs {
                    println!("(bootloader) {}", info);
                }
                let elapsed = start.elapsed();
                println!("Finished. Total time: {:.3}s", elapsed.as_secs_f64());
            } else {
                let resp = recv_and_print_info(&mut transport)?;
                println!("[fastboot-rs] Response: {:?}", resp);
            }
        }
        Commands::SetActive { slot } => {
            if slot.is_empty() {
                return Err("set_active requires a non-empty SLOT".into());
            }
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            // AOSP fastboot's SetActive() sends the protocol command set_active:SLOT.
            transport.send_cmd(&format!("set_active:{}", slot))?;
            let resp = recv_and_print_info(&mut transport)?;
            println!("[fastboot-rs] Set active slot '{}' response: {:?}", slot, resp);
        }
        Commands::Flash { partition, file } => {
            // Resolve image path: use explicit file if provided, otherwise
            // fall back to ANDROID_PRODUCT_OUT/<partition>.img (AOSP find_item behavior)
            let image_path = match file {
                Some(path) => path,
                None => {
                    match std::env::var("ANDROID_PRODUCT_OUT") {
                        Ok(out_dir) => {
                            let path = format!("{}/{}.img", out_dir, partition);
                            println!(
                                "[fastboot-rs] Image path not specified; derived from ANDROID_PRODUCT_OUT: {}",
                                path
                            );
                            path
                        }
                        Err(_) => {
                            eprintln!(
                                "Error: no image file specified and ANDROID_PRODUCT_OUT is not set.\n\
                                 Either provide FILE argument or set ANDROID_PRODUCT_OUT environment variable\n\
                                 to the build output directory containing {} partition images.",
                                partition
                            );
                            std::process::exit(1);
                        }
                    }
                }
            };

            // Step 1: Open file and get size via metadata (avoids loading entire file into memory)
            let mut image_file = match File::open(&image_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening image file '{}': {}", image_path, e);
                    std::process::exit(1);
                }
            };
            let file_size = match image_file.metadata() {
                Ok(m) => m.len() as usize,
                Err(e) => {
                    eprintln!("Error reading metadata for '{}': {}", image_path, e);
                    std::process::exit(1);
                }
            };

            if file_size == 0 {
                eprintln!("Error: image file '{}' is empty", image_path);
                std::process::exit(1);
            }

            // u32 overflow check for the download command
            if file_size > u32::MAX as usize {
                eprintln!(
                    "Error: image file '{}' size ({}) exceeds u32 max ({}); protocol limit",
                    image_path,
                    file_size,
                    u32::MAX
                );
                std::process::exit(1);
            }

            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] Connected to fastboot target {}", addr);

            // Fetch max-download-size if available
            let max_download_size = match transport.send_cmd("getvar:max-download-size") {
                Ok(_) => match transport.recv_response() {
                    Ok(fastboot_protocol::FastbootResponse::Okay(val)) => parse_max_download_size(&val),
                    _ => None,
                },
                _ => None,
            };

            if let Some(limit) = max_download_size {
                println!("[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})", limit, limit);
            }

            let need_split = match max_download_size {
                Some(limit) => limit > 0 && file_size > limit,
                None => false,
            };

            if need_split {
                // For sparse splitting, we must load the entire file into memory
                // (sparse parsing requires random access to the full data)
                let image_data = match std::fs::read(&image_path) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error reading image file '{}': {}", image_path, e);
                        std::process::exit(1);
                    }
                };

                let limit = max_download_size.unwrap();
                println!(
                    "[fastboot-rs] Image size ({} bytes) exceeds max-download-size ({} bytes). Splitting image into sparse chunks...",
                    image_data.len(),
                    limit
                );

                let is_sparse = image_data.len() >= 28
                    && u32::from_le_bytes(image_data[0..4].try_into().unwrap()) == fastboot_protocol::SPARSE_HEADER_MAGIC;

                let sparse_file = if is_sparse {
                    match fastboot_protocol::SparseFile::from_bytes(&image_data) {
                        Ok(sf) => sf,
                        Err(e) => {
                            eprintln!("Error parsing sparse file: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    fastboot_protocol::SparseFile::from_raw(&image_data, 4096)
                };

                let splits = match sparse_file.split(limit) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error splitting image: {}", e);
                        std::process::exit(1);
                    }
                };

                println!("[fastboot-rs] Split into {} sparse chunk file(s)", splits.len());

                use std::io::Write;
                for (idx, split_file) in splits.iter().enumerate() {
                    let payload = split_file.encode();
                    println!(
                        "[fastboot-rs] Sending split chunk {}/{} ({} bytes)...",
                        idx + 1,
                        splits.len(),
                        payload.len()
                    );

                    let download_cmd = fastboot_protocol::download(payload.len() as u32);
                    transport.send_cmd(&download_cmd)?;
                    let dl_resp = transport.recv_response()?;
                    match dl_resp {
                        fastboot_protocol::FastbootResponse::Data(expected_len) => {
                            if expected_len != payload.len() as u32 {
                                eprintln!(
                                    "Error: Device requested {} bytes, but chunk payload is {} bytes",
                                    expected_len,
                                    payload.len()
                                );
                                std::process::exit(1);
                            }
                        }
                        fastboot_protocol::FastbootResponse::Fail(reason) => {
                            eprintln!("Error download failed for chunk {}: {}", idx + 1, reason);
                            std::process::exit(1);
                        }
                        other => {
                            eprintln!("Unexpected download response for chunk {}: {:?}", idx + 1, other);
                            std::process::exit(1);
                        }
                    }

                    transport.write_all(&payload)?;
                    transport.flush()?;

                    let post_dl_resp = transport.recv_response()?;
                    if let fastboot_protocol::FastbootResponse::Fail(reason) = post_dl_resp {
                        eprintln!("Error after payload send for chunk {}: {}", idx + 1, reason);
                        std::process::exit(1);
                    }

                    let flash_cmd = fastboot_protocol::flash(&partition);
                    transport.send_cmd(&flash_cmd)?;
                    let flash_resp = transport.recv_response()?;
                    println!(
                        "[fastboot-rs] Flash response for split chunk {}/{}: {:?}",
                        idx + 1,
                        splits.len(),
                        flash_resp
                    );
                }
            } else {
                // Non-split path: stream DATA payload in chunks from file to transport,
                // avoiding loading the entire image into memory.
                let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024); // 16MB default
                println!(
                    "[fastboot-rs] Flashing partition '{}' with image '{}' ({} bytes, chunk size: {} bytes)",
                    partition, image_path, file_size, chunk_size
                );

                // Step 1: Send download command
                let download_cmd = fastboot_protocol::download(file_size as u32);
                transport.send_cmd(&download_cmd)?;
                let dl_resp = transport.recv_response()?;
                match dl_resp {
                    fastboot_protocol::FastbootResponse::Data(expected_len) => {
                        if expected_len != file_size as u32 {
                            eprintln!("Error: Device requested {} bytes, but local file is {} bytes", expected_len, file_size);
                            std::process::exit(1);
                        }
                    }
                    fastboot_protocol::FastbootResponse::Fail(reason) => {
                        eprintln!("Error download failed: {}", reason);
                        std::process::exit(1);
                    }
                    other => {
                        eprintln!("Unexpected download response: {:?}", other);
                        std::process::exit(1);
                    }
                }

                // Step 2: Stream payload data in chunks, reading from file on-demand
                println!("[fastboot-rs] Sending image payload in chunks ({} bytes total)...", file_size);
                let mut buffer = vec![0u8; chunk_size];
                let mut remaining = file_size;
                let mut chunk_index = 0u64;

                while remaining > 0 {
                    let to_read = remaining.min(chunk_size);
                    if let Err(e) = image_file.read_exact(&mut buffer[..to_read]) {
                        eprintln!("Error reading from '{}' at offset {}: {}", image_path, file_size - remaining, e);
                        std::process::exit(1);
                    }
                    if let Err(e) = transport.write_all(&buffer[..to_read]) {
                        eprintln!(
                            "Error writing to transport at chunk {} (offset {}): {}",
                            chunk_index,
                            file_size - remaining,
                            e
                        );
                        std::process::exit(1);
                    }
                    remaining -= to_read;
                    chunk_index += 1;
                }
                transport.flush()?;

                let post_dl_resp = transport.recv_response()?;
                if let fastboot_protocol::FastbootResponse::Fail(reason) = post_dl_resp {
                    eprintln!("Error after payload send: {}", reason);
                    std::process::exit(1);
                }

                // Step 3: Send flash command
                let flash_cmd = fastboot_protocol::flash(&partition);
                transport.send_cmd(&flash_cmd)?;
                let flash_resp = transport.recv_response()?;
                println!("[fastboot-rs] Flash response for partition '{}': {:?}", partition, flash_resp);
            }
        }
        Commands::Erase { partition } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("erase:{}", partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Erase response: {:?}", resp);
        }
        Commands::Reboot { target } => run_reboot(use_usb, &addr, target.as_deref())?,
        Commands::RebootBootloader => run_reboot(use_usb, &addr, Some("bootloader"))?,
        Commands::RebootRecovery => run_reboot(use_usb, &addr, Some("recovery"))?,
        Commands::RebootFastboot => run_reboot(use_usb, &addr, Some("fastboot"))?,
        Commands::Oem { command } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("oem {}", command.join(" "));
            transport.send_cmd(&cmd)?;
            let resp = recv_and_print_info(&mut transport)?;
            println!("[fastboot-rs] OEM response: {:?}", resp);
        }
        Commands::CreateLogicalPartition { partition, size } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::create_logical_partition(&partition, size);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Create logical partition response: {:?}", resp);
        }
        Commands::DeleteLogicalPartition { partition } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::delete_logical_partition(&partition);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Delete logical partition response: {:?}", resp);
        }
        Commands::ResizeLogicalPartition { partition, size } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = fastboot_protocol::resize_logical_partition(&partition, size);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            println!("[fastboot-rs] Resize logical partition response: {:?}", resp);
        }
        Commands::Boot { kernel, ramdisk, second } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {}", addr);

            let boot_payload: Vec<u8>;

            if let Some(ramdisk_path) = &ramdisk {
                // --- 有 ramdisk: 打包为 boot image ---
                println!(
                    "[fastboot-rs] 打包 boot image (kernel={}, ramdisk={})",
                    kernel, ramdisk_path
                );

                // 读取 kernel
                let kernel_data = read_file_bytes(&kernel);
                // 读取 ramdisk
                let ramdisk_data = read_file_bytes(ramdisk_path);

                // 检查 kernel 是否已经是完整 boot image
                if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                    println!(
                        "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                    );
                    boot_payload = kernel_data;
                } else {
                    let second_bytes = second.as_ref().map(|p| read_file_bytes(p));
                    let second_data = second_bytes.as_deref().unwrap_or(&[]);
                    println!(
                        "[fastboot-rs] 构建 boot image (header v4, page_size=4096)..."
                    );
                    boot_payload = fastboot_protocol::boot_image::BootImageBuilder::new()
                        .kernel(kernel_data)
                        .ramdisk(ramdisk_data)
                        .second(second_data.to_vec())
                        .build();
                    println!(
                        "[fastboot-rs] boot image 构建完成: {} 字节",
                        boot_payload.len()
                    );
                }

                if let Some(ref s) = second {
                    println!("[fastboot-rs] second 已打包: {}", s);
                }
            } else {
                // --- 无 ramdisk: 检查 kernel 是否为完整 boot image ---
                let kernel_data = read_file_bytes(&kernel);
                if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                    println!(
                        "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                    );
                    boot_payload = kernel_data;
                } else {
                    println!(
                        "[fastboot-rs] 无 ramdisk，使用 BootImageBuilder 构建 boot image..."
                    );
                    let second_bytes = second.as_ref().map(|p| read_file_bytes(p));
                    let second_data = second_bytes.as_deref().unwrap_or(&[]);
                    boot_payload = fastboot_protocol::boot_image::BootImageBuilder::new()
                        .kernel(kernel_data)
                        .second(second_data.to_vec())
                        .build();
                }
            }

            // --- 公共流程: download boot_payload + boot ---
            download_and_boot_payload(&mut transport, &boot_payload)?;
            return handle_boot_response(transport);
        }
        Commands::FlashRaw {
            partition,
            kernel,
            ramdisk,
            second,
        } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {}", addr);

            // 读取 kernel
            let kernel_data = read_file_bytes(&kernel);

            let boot_payload: Vec<u8> = if kernel_data.starts_with(&fastboot_protocol::boot_image::BOOT_MAGIC) {
                println!(
                    "[fastboot-rs] kernel 文件已包含 BOOT_MAGIC，直接作为 boot image 发送"
                );
                kernel_data
            } else {
                // 读取可选 ramdisk
                let ramdisk_data = match &ramdisk {
                    Some(path) => read_file_bytes(path),
                    None => Vec::new(),
                };
                // 读取可选 second
                let second_data = match &second {
                    Some(path) => read_file_bytes(path),
                    None => Vec::new(),
                };

                println!(
                    "[fastboot-rs] 构建 boot image (kernel={}, ramdisk={}字节, second={}字节, header v4, page_size=4096)...",
                    kernel,
                    ramdisk_data.len(),
                    second_data.len(),
                );

                let built = fastboot_protocol::boot_image::build_boot_image(
                    &kernel_data,
                    &ramdisk_data,
                    &second_data,
                    &[], // dtb — 暂不提供
                    4096,
                    4,
                );
                println!(
                    "[fastboot-rs] boot image 构建完成: {} 字节",
                    built.len()
                );
                built
            };

            // download + flash 流程
            download_and_flash_payload(&mut transport, &boot_payload, &partition)?;

            // 读取 flash 响应
            let flash_resp = transport.recv_response()?;
            match &flash_resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!(
                        "[fastboot-rs] 成功刷写分区 '{}': {}",
                        partition, val
                    );
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!(
                        "[fastboot-rs] 错误: 刷写分区 '{}' 失败: {}",
                        partition, reason
                    );
                    std::process::exit(1);
                }
                other => {
                    println!(
                        "[fastboot-rs] 刷写分区 '{}' 响应: {:?}",
                        partition, other
                    );
                }
            }
        }
        Commands::Fetch { partition, out_file } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let resp = fetch_to_file(&mut transport, &partition, &out_file)?;
            println!(
                "[fastboot-rs] Fetched partition '{}' to '{}': {:?}",
                partition, out_file, resp
            );
        }
        Commands::Continue => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("continue")?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Continue OK: {}", val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Continue FAIL: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Continue response: {:?}", other);
                }
            }
        }
        Commands::Format { partition, partition_type } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = match &partition_type {
                Some(pt) => format!("format:{}:{}", pt, partition),
                None => format!("format:{}", partition),
            };
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Format OK: {}", val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Format FAIL: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Format response: {:?}", other);
                }
            }
        }
        Commands::GetStaged { out_file } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("get_staged")?;
            let data_size = match recv_data_response(&mut transport, "get_staged")? {
                fastboot_protocol::FastbootResponse::Data(size) if size > 0 => size as usize,
                fastboot_protocol::FastbootResponse::Data(_) => {
                    return Err("get_staged failed: device returned zero bytes".into());
                }
                _ => unreachable!("recv_data_response only returns DATA"),
            };
            let mut output = File::create(&out_file)?;
            let mut remaining = data_size;
            let mut buffer = [0u8; 1024 * 1024];
            while remaining > 0 {
                let chunk_size = remaining.min(buffer.len());
                transport.read_exact(&mut buffer[..chunk_size])?;
                output.write_all(&buffer[..chunk_size])?;
                remaining -= chunk_size;
            }
            output.sync_all()?;
            let final_resp = transport.recv_response()?;
            match final_resp {
                fastboot_protocol::FastbootResponse::Okay(msg) => {
                    println!("[fastboot-rs] GetStaged wrote {} bytes to '{}': {}", data_size, out_file, msg);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    return Err(format!("get_staged failed after receiving data: {reason}").into());
                }
                other => return Err(format!("unexpected get_staged final response: {other:?}").into()),
            }
        }
        Commands::Stage { file } => {
            // 准备数据源：打开文件或读取 stdin
            let (mut data_source, file_size): (Box<dyn std::io::Read>, usize) = match file {
                Some(ref path) => {
                    let file = match File::open(path) {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("[fastboot-rs] 错误: 无法打开文件 '{}': {}", path, e);
                            std::process::exit(1);
                        }
                    };
                    let size = match file.metadata() {
                        Ok(m) => m.len() as usize,
                        Err(e) => {
                            eprintln!("[fastboot-rs] 错误: 无法读取文件元数据 '{}': {}", path, e);
                            std::process::exit(1);
                        }
                    };
                    if size == 0 {
                        eprintln!("[fastboot-rs] 错误: 文件 '{}' 为空", path);
                        std::process::exit(1);
                    }
                    if size > u32::MAX as usize {
                        eprintln!(
                            "[fastboot-rs] 错误: 文件 '{}' 大小 ({}) 超过 u32 上限 ({}); 协议限制",
                            path,
                            size,
                            u32::MAX
                        );
                        std::process::exit(1);
                    }
                    (Box::new(file) as Box<dyn std::io::Read>, size)
                }
                None => {
                    // 从 stdin 读取全部数据（需要提前知道大小才能发送 download 命令）
                    let mut buf = Vec::new();
                    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                        eprintln!("[fastboot-rs] 错误: 读取 stdin 失败: {}", e);
                        std::process::exit(1);
                    }
                    if buf.is_empty() {
                        eprintln!("[fastboot-rs] 错误: stdin 无数据");
                        std::process::exit(1);
                    }
                    if buf.len() > u32::MAX as usize {
                        eprintln!(
                            "[fastboot-rs] 错误: stdin 数据大小 ({}) 超过 u32 上限 ({}); 协议限制",
                            buf.len(),
                            u32::MAX
                        );
                        std::process::exit(1);
                    }
                    let size = buf.len();
                    (Box::new(std::io::Cursor::new(buf)) as Box<dyn std::io::Read>, size)
                }
            };

            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {}", e);
                    std::process::exit(1);
                }
            };
            println!(
                "[fastboot-rs] 已连接至 {}，开始 stage {} 字节数据...",
                addr, file_size
            );

            // Step 1: 获取 max-download-size
            let max_download_size = match transport.send_cmd("getvar:max-download-size") {
                Ok(_) => match transport.recv_response() {
                    Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                        parse_max_download_size(&val)
                    }
                    _ => None,
                },
                _ => None,
            };

            let chunk_size = max_download_size.unwrap_or(16 * 1024 * 1024); // 默认 16MB
            if let Some(limit) = max_download_size {
                println!(
                    "[fastboot-rs] Bootloader max-download-size: {} bytes ({:#x})",
                    limit, limit
                );
            }
            println!(
                "[fastboot-rs] 发送 download 命令 ({} bytes, 分块大小: {} bytes)...",
                file_size, chunk_size
            );

            // Step 2: 发送 download 命令
            let download_cmd = fastboot_protocol::download(file_size as u32);
            transport.send_cmd(&download_cmd)?;
            let dl_resp = transport.recv_response()?;
            match dl_resp {
                fastboot_protocol::FastbootResponse::Data(expected_len) => {
                    if expected_len != file_size as u32 {
                        eprintln!(
                            "[fastboot-rs] 错误: 设备请求 {} 字节，但本地数据为 {} 字节",
                            expected_len, file_size
                        );
                        std::process::exit(1);
                    }
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] download 失败: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    eprintln!("[fastboot-rs] 意外的 download 响应: {:?}", other);
                    std::process::exit(1);
                }
            }

            // Step 3: 分块发送 DATA payload
            println!("[fastboot-rs] 分块发送 payload...");
            let mut buffer = vec![0u8; chunk_size];
            let mut remaining = file_size;
            let mut chunk_index = 0u64;

            while remaining > 0 {
                let to_read = remaining.min(chunk_size);
                if let Err(e) = data_source.read_exact(&mut buffer[..to_read]) {
                    eprintln!(
                        "[fastboot-rs] 错误: 读取数据失败 at offset {}: {}",
                        file_size - remaining,
                        e
                    );
                    std::process::exit(1);
                }
                if let Err(e) = transport.write_all(&buffer[..to_read]) {
                    eprintln!(
                        "[fastboot-rs] 错误: 写入 transport 失败 at chunk {} (offset {}): {}",
                        chunk_index,
                        file_size - remaining,
                        e
                    );
                    std::process::exit(1);
                }
                remaining -= to_read;
                chunk_index += 1;
            }
            transport.flush()?;

            // Step 4: 读取最终 OKAY/FAIL 响应
            let final_resp = transport.recv_response()?;
            match &final_resp {
                fastboot_protocol::FastbootResponse::Okay(msg) => {
                    println!("[fastboot-rs] Stage 成功: {}", msg);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Stage 失败: {}", reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Stage 响应: {:?}", other);
                }
            }
        }
        Commands::Shutdown => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            transport.send_cmd("reboot-shutdown")?;
            let resp = transport.recv_response();
            match &resp {
                Ok(fastboot_protocol::FastbootResponse::Okay(val)) => {
                    println!("[fastboot-rs] Shutdown OK: {}", val);
                }
                Ok(fastboot_protocol::FastbootResponse::Fail(reason)) => {
                    eprintln!("[fastboot-rs] Shutdown FAIL: {}", reason);
                    std::process::exit(1);
                }
                Ok(other) => {
                    println!("[fastboot-rs] Shutdown response: {:?}", other);
                }
                Err(e) => {
                    // 设备可能已经断开（断电），读不到响应也是正常的
                    eprintln!(
                        "[fastboot-rs] Warning: Could not read shutdown response \
                         (device may be powering off): {}",
                        e
                    );
                }
            }
            let disconnected = wait_for_disconnect(transport, Duration::from_secs(5));
            if disconnected {
                println!("[fastboot-rs] Device disconnected — shutdown confirmed");
            } else {
                eprintln!(
                    "[fastboot-rs] Warning: Device did not disconnect within 5s timeout \
                     (shutdown may still be in progress)"
                );
            }
        }
        Commands::Flashing { action } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            let cmd = format!("flashing:{}", action);
            transport.send_cmd(&cmd)?;
            let resp = transport.recv_response()?;
            match &resp {
                fastboot_protocol::FastbootResponse::Okay(val) => {
                    println!("[fastboot-rs] Flashing '{}' 成功: {}", action, val);
                }
                fastboot_protocol::FastbootResponse::Fail(reason) => {
                    eprintln!("[fastboot-rs] Flashing '{}' 失败: {}", action, reason);
                    std::process::exit(1);
                }
                other => {
                    println!("[fastboot-rs] Flashing '{}' 响应: {:?}", action, other);
                }
            }
        }
        Commands::Update { zip_file } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[fastboot-rs] 错误: {e}");
                    std::process::exit(1);
                }
            };
            println!("[fastboot-rs] 已连接至 fastboot 目标 {addr}");
            do_update(&mut transport, &zip_file)?;
        }
        Commands::Gsi { action } => {
            let mut transport = match open_transport(use_usb, &addr, Duration::from_secs(3)) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            transport.send_cmd(&format!("gsi:{action}"))?;
            let response = recv_and_print_info(&mut transport)?;
            if let fastboot_protocol::FastbootResponse::Fail(reason) = response {
                return Err(format!("gsi:{action} failed: {reason}").into());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_exposes_global_usb_opt_in() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--usb"));
        assert!(help.contains("devices"));
        assert!(help.contains("getvar"));
    }

    #[test]
    #[cfg(not(feature = "usb"))]
    fn usb_mode_reports_feature_requirement_without_touching_tcp() {
        let error = match open_transport(true, "127.0.0.1:5554", Duration::from_secs(1)) {
            Ok(_) => panic!("USB mode must fail clearly when the optional feature is disabled"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("USB support is not enabled"));
        assert!(error.contains("--features usb"));
    }

    #[test]
    fn cli_accepts_usb_before_and_after_subcommand() {
        for args in [
            ["fastboot-rs", "--usb", "getvar", "version"],
            ["fastboot-rs", "getvar", "version", "--usb"],
        ] {
            let cli = Cli::try_parse_from(args).expect("--usb should be a global option");
            assert!(cli.usb);
            assert!(matches!(cli.command, Commands::Getvar { ref variable } if variable == "version"));
        }
    }

    #[test]
    fn test_parse_max_download_size() {
        assert_eq!(parse_max_download_size("0x20000000"), Some(536870912));
        assert_eq!(parse_max_download_size("0X04000000"), Some(67108864));
        assert_eq!(parse_max_download_size("536870912"), Some(536870912));
        assert_eq!(parse_max_download_size("  0x100000 \n"), Some(1048576));
        assert_eq!(parse_max_download_size("invalid"), None);
        assert_eq!(parse_max_download_size(""), None);
    }

    #[test]
    fn test_parse_max_download_size_suffixes() {
        assert_eq!(parse_max_download_size("512MB"), Some(536870912));
        assert_eq!(parse_max_download_size("1024K"), Some(1048576));
        assert_eq!(parse_max_download_size("1GB"), Some(1073741824));
        assert_eq!(parse_max_download_size("256M"), Some(268435456));
        assert_eq!(parse_max_download_size("1024kb"), Some(1048576));
        assert_eq!(parse_max_download_size("512 mb"), Some(536870912));
        assert_eq!(parse_max_download_size("0x200MB"), Some(536870912));
    }

    #[test]
    fn test_boot_accepts_kernel_and_optional_ramdisk_second() {
        // 验证 CLI 参数解析：kernel 为必选，ramdisk/second 为可选（positional args）
        let cli = Cli::try_parse_from([
            "fastboot-rs",
            "boot",
            "boot.img",
            "ramdisk.img",
            "second.img",
        ])
        .expect("boot with all positional args should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "boot.img");
                assert_eq!(ramdisk.as_deref(), Some("ramdisk.img"));
                assert_eq!(second.as_deref(), Some("second.img"));
            }
            _ => panic!("expected Boot command"),
        }

        // kernel + ramdisk
        let cli = Cli::try_parse_from(["fastboot-rs", "boot", "kernel.img", "ramdisk.img"])
            .expect("boot with kernel and ramdisk should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "kernel.img");
                assert_eq!(ramdisk.as_deref(), Some("ramdisk.img"));
                assert!(second.is_none());
            }
            _ => panic!("expected Boot command"),
        }

        // 仅 kernel 参数
        let cli = Cli::try_parse_from(["fastboot-rs", "boot", "kernel.img"])
            .expect("boot with kernel only should parse");
        match cli.command {
            Commands::Boot {
                ref kernel,
                ref ramdisk,
                ref second,
            } => {
                assert_eq!(kernel, "kernel.img");
                assert!(ramdisk.is_none());
                assert!(second.is_none());
            }
            _ => panic!("expected Boot command"),
        }
    }

    #[test]
    fn fetch_accepts_info_before_data_like_aosp_run_and_read_buffer() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut command = [0u8; 10];
            socket.read_exact(&mut command).unwrap();
            assert_eq!(&command, b"fetch:boot");
            socket.write_all(b"INFOreading boot\nDATA00000005HELLOOKAYdone").unwrap();
        });
        let mut transport = FastbootConnection::Tcp(
            fastboot_protocol::FastbootTcpTransport::raw_connect(addr).unwrap(),
        );
        let path = std::env::temp_dir().join(format!(
            "fastboot-rs-fetch-info-test-{}",
            std::process::id()
        ));

        let response = fetch_to_file(&mut transport, "boot", path.to_str().unwrap()).unwrap();
        assert_eq!(
            response,
            fastboot_protocol::FastbootResponse::Okay("done".to_string())
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"HELLO");
        std::fs::remove_file(path).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn get_staged_requires_a_destination_file_like_aosp_cli() {
        let cli = Cli::try_parse_from(["fastboot-rs", "get-staged", "staged.bin"])
            .expect("AOSP get_staged takes an output file");
        assert!(matches!(
            cli.command,
            Commands::GetStaged { ref out_file } if out_file == "staged.bin"
        ));
    }

    #[test]
    fn aosp_reboot_variant_commands_parse_without_a_target_argument() {
        for (name, expected) in [
            ("reboot-bootloader", "bootloader"),
            ("reboot-recovery", "recovery"),
            ("reboot-fastboot", "fastboot"),
        ] {
            let cli = Cli::try_parse_from(["fastboot-rs", name])
                .expect("AOSP reboot variant should parse");
            let actual = match cli.command {
                Commands::RebootBootloader => "bootloader",
                Commands::RebootRecovery => "recovery",
                Commands::RebootFastboot => "fastboot",
                _ => panic!("expected a reboot variant"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn aosp_stage_requires_an_input_file() {
        assert!(Cli::try_parse_from(["fastboot-rs", "stage"]).is_err());
    }

    #[test]
    fn flashing_rejects_unknown_action_and_oem_requires_a_command() {
        assert!(Cli::try_parse_from(["fastboot-rs", "flashing", "unlock"]).is_ok());
        assert!(Cli::try_parse_from(["fastboot-rs", "flashing", "unknown"]).is_err());
        assert!(Cli::try_parse_from(["fastboot-rs", "oem"]).is_err());
    }
}
