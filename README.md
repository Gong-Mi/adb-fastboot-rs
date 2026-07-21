# adb-fastboot-rs

100% 纯 Rust 实现的 Android Debug Bridge (ADB) 与 Fastboot 协议库及命令行工具套件。

针对 Termux / Android 原生环境与交叉编译场景设计，零 C/C++ FFI 依赖、零 `libusb` / `abseil` / `protobuf` C 库依赖，天然支持 64K 页大小与 Termux / Android 系统。

## 📦 Workspace 架构设计

```text
adb-fastboot-rs/
├── Cargo.toml
├── crates/
│   ├── adb-protocol/              # Pure Rust ADB Wire 协议编解码 crate
│   │   ├── src/header.rs          # 24-byte 消息头组包/解包、Magic 校验与 Checksum 算子
│   │   ├── src/shell_v2.rs        # Shell v2 多路复用帧解析 (stdout/stderr/exit_code)
│   │   ├── src/sync.rs            # 文件同步 SYNC 协议头与 STAT/SEND/RECV 结构体
│   │   └── src/constants.rs       # 协议 Command 标量常数定义
│   ├── fastboot-protocol/         # Pure Rust Fastboot 协议与 Sparse 图像解析 crate
│   │   ├── src/response.rs        # Status 响应解析器 (OKAY/FAIL/DATA/INFO)
│   │   └── src/sparse.rs          # Android Sparse Image (sparse_header_t/chunk_header_t)
│   └── adb-fastboot-cli/          # 统一二进制入口 CLI crate
│       ├── src/main_adb.rs        # adb-rs 命令行工具 (shell, push, pull, devices, reboot)
│       └── src/main_fastboot.rs   # fastboot-rs 命令行工具 (flash, erase, getvar, oem, reboot)
```

## 🚀 编译与构建

项目使用 Cargo Workspace 组织，要求 Rust 2021 edition 或更高版本。

```bash
# 编译 Debug 产物与运行测试
cargo test --lib

# 构建 Release 优化二进制产物
cargo build --release
```

编译产物位于 `target/release/`：
- `target/release/adb-rs`
- `target/release/fastboot-rs`

## 🛠️ 命令使用说明

### 1. `adb-rs` (ADB 命令行工具)

```bash
# 查看帮助与子命令
./adb-rs --help

# 列表展示已连接设备
./adb-rs devices

# 执行远程 Shell 命令 (支持 Shell v2 协议与 PTY 交互)
./adb-rs shell "id; getprop ro.build.fingerprint"

# 推送本地文件到设备端
./adb-rs push ./local_payload.so /data/local/tmp/preload.so

# 从设备端拉取文件
./adb-rs pull /sdcard/vk_debug.log ./vk_debug.log

# 重启设备到指定模式 (bootloader / recovery)
./adb-rs reboot bootloader
```

### 2. `fastboot-rs` (Fastboot 命令行工具)

```bash
# 查看 Fastboot 帮助与子命令
./fastboot-rs --help

# 列表展示 Fastboot 模式下的设备
./fastboot-rs devices

# 查询 Bootloader 变量 (如 max-download-size, current-slot, unlocked)
./fastboot-rs getvar unlocked

# 刷写镜像到指定分区 (支持 Sparse 图像自动解析)
./fastboot-rs flash boot ./boot.img

# 擦除指定分区
./fastboot-rs erase userdata

# 发送自定义 OEM / Bootloader 解锁指令
./fastboot-rs oem unlock

# 重启设备
./fastboot-rs reboot
```

## 🧪 单元测试

运行协议编解码与状态机逻辑测试：

```bash
cargo test --lib
```

测试覆盖范围：
- ADB 24-byte Header checksum/magic 验证与异常破坏侦测
- ADB Shell v2 多通道流 (`stdout`, `stderr`, `exit_code`, `winsize`) 编解码
- ADB SYNC 文件传输协议头解析
- Fastboot 响应状态机 (`OKAY`, `FAIL`, `DATA`, `INFO`)
- Android Sparse 镜像头结构体 (`SPARSE_HEADER_MAGIC`) 与 Chunk Header 解码

## 📄 License

MIT OR Apache-2.0
