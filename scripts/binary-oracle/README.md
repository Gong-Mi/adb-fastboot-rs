# 二进制 oracle 差分夹具（scripts/binary-oracle）

给 `adb-fastboot-rs` 做逆向/移植时的**复用夹具**：一个假 ADB server、一个假
fastboot 设备、一个与协议无关的录包代理、一套命令矩阵和差异分类器。

它解决的是同一个问题：**怎么证明 Rust 实现的行为与真实实现一致**，而不是
"跑起来没报错"。

```
scripts/binary-oracle/
  framing.py              # 可插拔 codec（AdbSmartSocket / FastbootTcp）+ 逐帧 transcript
  variants.py             # 协议变体注册表：codec + transport + vocabulary + known/unknown
  server.py               # 假 ADB server（host 服务 / 设备服务 / sync / shell v2）
  fakefastbootd.py        # 假 fastboot 设备（分区、slot、AVB 场景、故障注入）
  record_proxy.py         # 协议无关录包代理（闭源参考件专用入口）
  run_matrix.py           # adb 命令矩阵 -> 一条 JSON/用例
  run_fb_matrix.py        # fastboot 命令矩阵 -> 一条 JSON/用例
  diff_report.py          # 两份 adb 结果差异表
  diff_fb.py              # 两份 fastboot 结果差异表（wire / side / state / rc 分类）
  examples/
    fastboot_one_case.py    # 不依赖任何 C 二进制的最小可跑用例（自带断言）
    fake_fastboot_client.py # 供 run_fb_matrix.py 使用的假客户端（只验夹具，不当 oracle）
```

纯标准库，无第三方依赖；`python3` 3.9+。不碰 `crates/`，不参与 `cargo build`。

---

## 1. 为什么用"第二份独立实现"当 oracle

自写 mock 有一个绕不过去的毛病：**mock 的期望值来自我读协议时的理解**。于是
一旦我理解错了，mock 和被测实现会一起错，测试全绿，缺陷照旧。这类夹具的
`OKAY` 只证明"两边符合我的想象"。

差分 oracle 把错误源挪到别处：

| | 自写 mock | 第二份独立实现（C 参考件） |
|---|---|---|
| 期望值来源 | 我对协议的理解 | 另一份能跑的实现 |
| 我理解错时 | mock 与被测一起错，全绿 | 两份实现在同一流量上分歧，红 |
| 新命令/未知字段 | 只能测我想到的 | 未知命令也会落到 transcript，暴露未知 |
| 覆盖边界 | 我写的分支 | 实现作者写过的分支 |

所以这里的定位是：**夹具负责"给同样的输入、记录同样的字节"，谁是正确答案
由两份实现互相当裁判**。夹具自己不充当局者，只保证两侧看到的是同一场戏。

这也是 `framing.py` 里 transcript 记 `sha256` 而不只记"文本"的原因：差异要能
定位到具体字节，而不是"输出不一样"。

### 已知的取舍（写在前面，免得被当成保证）

- `Codec.write_msg` 把**带长度前缀的整帧**记进 `tx`，`read_msg` 只记**剥掉前缀
  后的载荷**（前缀被 codec 消费掉了）。所以：设备方向的帧型有字节级证据，
  客户端请求方向的帧型靠"能解析"间接证明，不靠"记录到了前缀"。
  改这个语义会影响已有 `diff_*.py` 的 actor 约定，故保持原样。
- 夹具的"成功"以设备侧状态为准（`partitions.json` / `device.jsonl`），不以
  客户端的 `OKAY` 为准。

---

## 2. 两条运行路径

### A. 有源码、能编译：C 参考件 + 假设备

适用：AOSP `adb` / `fastboot`、任何能本地编译的上游或 fork。

```bash
# 一侧跑 C 二进制，一侧跑 Rust 二进制，输入完全一致
python3 scripts/binary-oracle/run_fb_matrix.py /path/to/c-fastboot   out/c.json
python3 scripts/binary-oracle/run_fb_matrix.py /path/to/fastboot-rs  out/r.json
python3 scripts/binary-oracle/diff_fb.py out/c.json out/r.json out/diff.md
```

`run_fb_matrix.py` 为每个用例：挑空闲端口 → 起 `fakefastbootd.py` → 用
`-s tcp:127.0.0.1:PORT` 驱动被测二进制 → 收 CLI 结果 + 设备侧命令序列 +
设备侧最终分区状态。adb 侧同理（`run_matrix.py` + `server.py`，
`ANDROID_ADB_SERVER_PORT` 指过去，`HOME` 隔离）。

**oracle 只认"独立实现"**。拿 Rust 实现去跑两次再比对是自证，不在本夹具的
主张范围内；`examples/fake_fastboot_client.py` 只用于验证夹具自身，README 与
PR 里都不把它当 oracle。

### B. 只有闭源件：录包当代替品

适用：Huawei `hadb`、厂商 `hdc`、只有 vendored `.so`/APK 的 daemon。

闭源件不能任意驱动，也就没有"同一输入跑两份"的条件；但**字节流本身**可以
当语料：

```bash
# 1) 让真实客户端连代理，代理转发给真实 daemon，逐块记录两个方向
python3 scripts/binary-oracle/record_proxy.py \
    --listen 7300 --upstream 127.0.0.1:7301 --out cap/hadb.jsonl

# 2) 客户端照常指向 127.0.0.1:7300（代理不负责拉起客户端）
# 3) 从 cap/hadb.jsonl 反推：握手、帧长、服务名表、能力字段
# 4) 把反推出的结构写成 codec + vocabulary，注册成变体，再用 A 路径做回归
```

`record_proxy.py` **不假设任何帧型**：按 `recv(65536)` 的原始分块记录
`{dir, t, len, hex, sha256}`（`c2s` / `s2c`）。分块边界是 TCP 的边界，不是
协议的边界——这一点必须在解读时自己重新对齐，代理不替你猜。

同一条路径也可以反向用来**验收夹具**：把代理插在"假设备"和客户端之间，
看夹具产生的字节流是否与真机抓到的语料同构。

---

## 3. 新增协议变体

一个变体 = **codec（帧型）+ transport（怎么把客户端指过来）+ vocabulary（能
懂的词表）**。三者都显式声明，未知项留空，让未知流量变成 FAIL/记录而不是静默
成功。

### 3.1 写 codec

`framing.py` 里继承 `Codec`，只需实现四个东西：

```python
class HadbRaw(Codec):
    name = "hadb"
    handshake_rx = None        # 对端先发的固定字节；没有就 None
    handshake_tx = None        # 自己回的字节
    client_speaks_first = False  # 谁先开口，是协议的一部分，别猜

    def read_msg(self):        # 返回一条消息的 payload，或 None 表示对端关闭
        ...
    def write_msg(self, payload):
        ...
```

规矩：

- **禁止把厂商帧型归一化成 AOSP 帧型**。`hadb` 若是二进制长度前缀，就写二进制
  codec；不要"反正内容一样"先塞进 `AdbSmartSocket`。帧型差异通常正是发现本身。
- 未知命令不要 `raise`：让它落进 transcript，后面的 `diff` 才有东西可看。
- 超长/畸形帧记 `protocol-error` 并断开，不要静默跳过（否则"没差异"是假的）。
- 有握手就先确认方向。`FastbootTcp` 就是反例受害者：客户端先发 `FB01`
  （`client_speaks_first = True`），设备侧是收后发；写反了两边互等，看起来像
  夹具坏了。

### 3.2 写 vocabulary

`vocabulary` 是"命令前缀 → 行为"的表，用于让夹具回答已知命令；**不在表里的
命令必须走 FAIL 分支并记录**，不能默认回 `OKAY`。

### 3.3 注册

```python
HADB = Variant(
    name="huawei-hadb",
    codec=None,                # 未抓包前保持 None：没有帧型就不许被 runner 驱动
    transport="raw-tcp",
    serial_form="-s {serial}",
    vocabulary={},             # 抓到之前故意为空
    known="Nothing verified. Name only.",
    unknown="framing（hex 长度 vs 二进制）、握手/鉴权、服务词表、能力名、"
            "是否复用 A_* 包类型、USB-only vs TCP。",
    capture_hint="先 record_proxy 抓一对客户端/daemon，再按 3.1 写 codec。",
)
```

`known` / `unknown` 两个字段是**证据分级**，必须保留并且诚实：`known` 只写
真验过的（抓包/源码/实测），`unknown` 写清还没验的。`codec=None` 是刻意的
fail-closed——它让 `huawei-hadb` 无法被"顺手"当成 AOSP adb 跑，避免假设变成
结论。`python3 variants.py` 会打印注册表，`<unconfirmed>` 就是提醒。

---

## 4. 怎么跑（都是实际执行过的命令）

前置：仓库内任意 cwd，脚本按 `__file__` 找同目录模块，不依赖 `$HOME` 或任何
外部绝对路径。生成物默认落到 `scripts/binary-oracle/work/`（已 gitignore），
可用 `BINARY_ORACLE_WORK=/some/tmp` 改道。

### 4.1 语法/帧型自检（无网络、无设备）

```bash
python3 -m py_compile scripts/binary-oracle/*.py scripts/binary-oracle/examples/*.py
python3 scripts/binary-oracle/framing.py
```

```
adb: 2 msgs round-tripped, framing bytes match on the wire
fastboot: 2 msgs round-tripped, framing bytes match on the wire
framing selftest OK
```

自检断言的是**字节**：`host:version` 在线上必须是
`30303063 686f73743a76657273696f6e`（ASCII `%04x` 前缀，不是二进制长度），
fastboot 必须是 `000000000000000e` + payload（8 字节大端）。

### 4.2 一个最小 fastboot 用例（不需要 C 二进制）

```bash
python3 scripts/binary-oracle/examples/fastboot_one_case.py
```

它自己起 `fakefastbootd.py`、自己当客户端，跑
`getvar:version → download → flash:boot`，然后**读设备侧状态**验收：

```
getvar:version -> b'OKAY0.4'
download:00000400 -> b'DATA00000400'
  payload  -> b'OKAY'
flash:boot -> b'OKAY'
device flash event: resolved=boot_a bytes=1024 sha256=785b0751fc2c53dc…
boot_a head: 000102030405060708090a0b0c0d0e0f (offset 0 matches payload)
PASS: split-flash landed byte-for-byte in boot_a
```

注意验收逻辑：`flash boot` 解析到 `boot_a`、落盘 1024 字节、`boot_a` 头部
16 字节等于载荷前 16 字节。客户端说 `OKAY` 不算通过。

### 4.3 矩阵 + 差异分类（用假客户端验证夹具本身）

```bash
W=$(mktemp -d)
BINARY_ORACLE_WORK=$W python3 scripts/binary-oracle/run_fb_matrix.py \
    scripts/binary-oracle/examples/fake_fastboot_client.py $W/c.json \
    getvar-version getvar-product flash-boot erase-boot
cp $W/c.json $W/r.json
python3 scripts/binary-oracle/diff_fb.py $W/c.json $W/r.json
```

```
# cases=4 identical=4 divergent=0
| case | diff | C fastboot | fastboot-rs |
|---|---|---|---|
```

空表是"同一份结果与自己比"，用来证明 diff 不虚报。**反向对照**（把一侧的
`flash:boot` 改成 `flash:boot_b`）后：

```
# cases=4 identical=3 divergent=1
| `flash-boot` | wire, side, state | download:00000400 / flash:boot | download:00000400 / flash:boot_b |
```

`diff_fb.py` 的分类含义：`wire`=设备侧命令序列不同，`side`=实际发生的写/擦
不同（分区名、解析后的 slot、字节数、sha256），`state`=最终分区状态不同，
`rc`/`stdout`/`stderr`=CLI 表现不同。这样"夹具没对齐"和"产品有缺陷"不会混成
一条"输出不一致"。

### 4.4 录包路径（闭源件/未知协议）

两个终端：

```bash
# T1：假设备（或真 daemon）在 7301；Termux 上 /tmp 不可写，走 TMPDIR
python3 scripts/binary-oracle/fakefastbootd.py 7301 "${TMPDIR:-/tmp}/fbdev" '{}'

# T2：代理监听 7300，转发到 7301
python3 scripts/binary-oracle/record_proxy.py \
    --listen 7300 --upstream 127.0.0.1:7301 --out "${TMPDIR:-/tmp}/cap.jsonl"

# T3：客户端指向代理
python3 scripts/binary-oracle/examples/fake_fastboot_client.py \
    -s tcp:127.0.0.1:7300 getvar product
```

`"${TMPDIR:-/tmp}/cap.jsonl"` 得到（实测）：

```
c2s 4  46423031
s2c 4  46423031
c2s 22 000000000000000e6765747661723a70726f64756374
s2c 24 00000000000000104f4b415966616b655f70726f6475...
```

即"握手 4 字节 → 8 字节大端帧长 → 载荷"，与 `framing.py` 里的 codec 一致；
`sha256` 用来跟别的语料做同构比对。

### 4.5 CI 自检（独立 workflow、非阻塞）

`.github/workflows/binary-oracle.yml` 在每次 push / PR 上跑一个只依赖 `python3`
的冒烟作业，防止夹具本身腐化（改坏了接口、示例却没被发现）：

```bash
# 1) 语法
python3 -m py_compile scripts/binary-oracle/*.py scripts/binary-oracle/examples/*.py
# 2) README 4.2 的例子（假设备 + python 客户端，不需要 C/Rust 二进制）
python3 scripts/binary-oracle/examples/fastboot_one_case.py
# 3) 断言输出含 PASS: —— 例子只在设备侧字节校验通过后才打印这行
```

约束（有意为之）：

- **独立 workflow，不进 required checks**。作业失败在 PR 的 check 列表里可见，
  但不挡合并；`ci.yml` 一行没动，现有 required check 语义不变。
- **不碰产品代码**，不编译任何 crate，不需要 Rust 工具链或系统依赖。
- 时间上限：作业 `timeout-minutes: 5`，每个实际步骤 `timeout 60` 秒
  （本地实测整条例子 ~0.2s）。
- 只有"编译都能过但示例已经跑不通"这类夹具腐化会红；矩阵/录包路径仍然不在 CI
  里（见 §6），因为它们需要外部输入。

---

## 5. 证据边界

这套夹具能证明的：**在给定输入下，两份实现在字节层面/设备状态层面一致**。

它不能证明的：

- **不是真机**。分区表、slot、AVB 状态是模型；真实 bootloader 的拒绝理由、
  厂商扩展、super/动态分区行为、`is-logical` 语义都没有覆盖。
- **不覆盖驱动与 USB 层**。走的是 TCP 传输（AOSP 的 `FB01` / adb smart socket），
  usbfs 枚举、端点、bulk 时序完全在外面。
- **不覆盖时序与并发**。超时、重传、多连接竞争、半包、慢读只做了有限的故障
  注入（`fail_download` / `short_data` / `fail_after_download` / `fail_flash` /
  `strict_slots`），不是时序模型。
- **不覆盖断电/中断**。写到一半掉电、擦除中断、重启后 slot 元数据这类场景没有
  建模。
- **不覆盖鉴权**。adb key/AUTH 握手、`hadb` 可能的厂商鉴权都没实现。
- **transcript 是分块记录**（`record_proxy`）或按 codec 解析后的记录
  （`framing.Transcript`），两者都不等于链路层的完整复现。

一句话：夹具用来**把差异定到字节**，不用来宣布"这个实现是对的"。真机、驱动、
时序、断电这四类结论必须另有证据。

---

## 6. 未做项

- 只有**冒烟级** CI 覆盖（§4.5：`py_compile` + `fastboot_one_case.py`，独立 workflow、
  非阻塞）。**矩阵与录包路径不在 CI 里**：它们需要一个可执行的客户端二进制或真实
  录包作为输入，仓库内没有。
- `variants.py` 里只有 `aosp-adb-35`、`aosp-fastboot-35` 两个可驱动变体；
  `huawei-hadb` 是空壳占位，等真实录包。
- 没有 adb 的"半包/超时"故障注入（fastboot 侧已有一部分）。
- 没有把 `record_proxy` 的语料自动转成 codec 骨架（目前靠人工对齐分块）。
- 没有仓库内的大 JSON 语料：所有输入都由脚本按需生成，状态写到
  `BINARY_ORACLE_WORK` / `work/`。
