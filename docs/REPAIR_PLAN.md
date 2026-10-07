# ADB/Fastboot 修复实施方案

目标：保留已有实现，按独立可证伪合同修确认缺陷，恢复单一累计施工线；不把局部绿宣传成完整官方替代品。

输入身份：main 8f12c5e512790d7e6253788ac30e4a3c9825bcaa；旧验收候选7b2aa0ae920ffdf78436935659583e9967ddc126。AOSP Android17：ADB 9084198a2d4b0f6a0f174260fb42da33485b684d；system/core 545d2487e38192a2ce25040897ced877cf6b4f53。它们是方案基线，不是滚动完成头；实际进度和证据放PR。

架构：生产CLI为入口，codec/transport/server所有权/命令事务/验证器分开失败域。正确Rust API/命名保留，不按同名数重写。独立分支/PR，父代理单写者整合，默认不merge main；实体实验另授权。

路径约定：下文裸 `main_adb.rs`、`main_fastboot.rs`、`client/`、`server/` 均以 `crates/adb-fastboot-cli/src/` 为根；裸 `tests/` 以 `crates/adb-fastboot-cli/tests/` 为根；`adb-protocol/`、`fastboot-protocol/` 等 crate 路径以 `crates/` 为根。根目录的 AGENTS、docs、scripts、.github 不使用这些缩写。

## P0 规矩与可执行验收门

文件：AGENTS.md、docs/TESTING.md、scripts/run_rust_tests.py、scripts/test_rust_test_runner.py、.github/workflows/ci.yml。
方法：local locked/offline focused，CI default/all/none各check/test。记录原rc/log和HEAD/tree/overlay；零执行/无summary/假绿summary/超时/运行前后身份不同不能PASS，skip/ignored单列。运行期间必须冻结源码，端点快照不认证所有临时改回；timeout为整条Cargo命令预算。fake cargo退出42、参数注入、binary日志及脱组stdout负控；独立sparse oracle单独job显式执行。
验收：门禁负控全成立；真实本地Rust目标；CI使用同一runner，不硬编码总数。

## P1 回收Fastboot漏合修复

文件：fastboot-protocol/src/{sparse.rs,usb_android.rs}，adb-fastboot-cli/src/main_fastboot.rs，tests/{fastboot_sparse_cli.rs,fastboot_target_cli.rs}。
方法：从最新main merge旧累计候选；仅这五个Fastboot文件变化，所有最新ADB安装/incremental逐文件保留。不能用旧树覆盖新main。
验收：B/不回退、actual syscall count、同一模拟分区sparse结果、真CLI framed/sparse/target与新累计CI。

## P2 Fastboot终态/安全选项/计划预检（依赖P1）

方法：遍历main_fastboot.rs所有download_and_boot_payload/flash_image_file/do_update出口；payload后严格OKAY，非法DATA/FAIL/EOF不得flash/boot/下一分区。未消费set-active/force/skip-secondary等正确实现前I/O前拒绝。update完整计划/必需镜像先预检，has-slot控制后缀，mandatory查询错误不continue放行。
反例：post-data DATA、晚FAIL、第二必需镜像缺失、错误slot/非A-B镜像、getvar EOF、每分卷失败。真CLI断言操作记录/模拟存储以及不再写/切槽/重启。

复审后的独立子切片：
- P2a：小sparse也必须无条件严格校验sum(chunk_sz)==total_blks及CRC块等结构；不能只有split执行validator。坏后序镜像必须在boot首次download前拒绝。
- P2b：按官方packed AvbFooter读取vbmeta_offset（footer20..28，非旧8..16），checked算术/边界；实际vbmeta变换在首次download前验证，不允许前序flash后panic。
- P2c：ZIP重名检查在库按名字去重前进行；file_names/by_index不能恢复已覆盖项。解析真实central directory/count/offset并验证ZIP64等适用域，任何歧义在写I/O前拒绝。
以上各自独立PR与坏输入负控，不用37项既有事务绿替代这些新反例。

## P3 APEX及完整安装输入门（可并行）

文件：main_adb.rs安装分支、client/adb_install.rs、真CLI安装tests。
方法：撤旧apk-only门，独立apex capability，APEX真实streamed，不误送push/incremental；PM options按AOSP透传，安装-d不能混成全局USB-d。ordinary multiple/multi-package真CLI验证不同parent/child、staged/timeout、失败abandon。
反例：缺feature、坏后缀/模式、write/link/commit失败与丢参数。helper测试不替代入口。

## P4 STAT/SYNC流边界（可并行）

文件：client/file_sync.rs、adb-protocol/src/sync.rs、tests/adb_sync_cli.rs。
方法：STAT v1固定16B [STAT,mode,size,mtime]无length；direct/server都正确读。替换20B同错夹具，以AOSP独立字节为oracle。合并/分片不假设一WRTE一SYNC记录；文件和mode/mtime核对，短读/EOF不伪造成功。
后续：目录真实CLI接线、--sync changed/new、压缩feature gate、-P/-L/-d传递。

## P5 生产STLS/TLS（可并行）

文件：main_adb.rs握手、client/transport.rs、adb-protocol/src/{stls.rs,transport.rs,tls.rs}、真实加密tests。
方法：device STLS→host STLS→TLS→device CNXN，不重发host CNXN。共享生产helper，证书/config/握手错误fail-closed。真实TLS fakeadbd加密CNXN/OPEN及失败；实际TLS incremental后台供块不以force明文fork代替。
后续pair→connect复用同一持久hostkey，不每次pair替换旧身份；设备层仍独立。当前测试门还需独立host/server key、从客户端证书实际SPKI匹配固定授权host pubkey及错误身份负控；证书数量和CertificateVerify签名不替代授权身份。补合流后的真实加密APEX成功/失败及feature gate，并在no-default腿明确验证STLS拒绝，不能把TLS suite 0 tests算验收。

## P6 server/目标/安装传输所有权（依赖P5；独立PR）

文件：server/{smart_socket.rs,bridge.rs,transport.rs,models.rs}、adb-protocol/src/transport.rs、client/transport.rs、main_adb.rs相关入口。
方案：每transport唯一reader、stream分派、ACK背压、明确close/cancel/join；不能只补clone留下双reader争抢。真server连fakeadbd，非1 stream并发/双向/EOF/取消收口。安装统一选中target，USBserial/-d/server地址/networkserial不丢；选中server后不再CNXN。
反例：设备等待stdin、WRTE/OKAY交错、错reader、同serial换地址、missing/多设备、IP:PORT被冒号截断；常规/增量fallback同一target。

第一切片状态：每连接唯一 I/O owner 的 duplex 路径已落地（新增 `server/duplex.rs`，server 侧重复 CNXN/AUTH 握手并入共享路径），已合入累计候选 `b9c43b1` 并通过五 job CI。独立审查（head `24e45ce`）结论：无阻塞新回归；五项核对通过——握手仍用同一 `default_auth()` 持久 key 与等价的 `persist_adb_pubkey`；服务路径取 transport 所有权、无 `try_clone_box`、`SharedTransport` 在 server 已零引用；删掉的旧函数无存活调用点；USB 服务在 OPEN 前显式 FAIL（读毕请求再 FAIL，避免 RST）。

遗留项（已分线）：
- 关闭阶段 drain 用 `CLOSE_TIMEOUT=1s` 固定硬上限（`duplex.rs`），与 output 侧 `PROGRESS_TIMEOUT=10s` 竞争，慢消费者（<~1MB/s）可能截断尾部 → 独立分支改为进展式有界。
- 死代码：`bridge_to_device`、`ensure_usb_auth`、`device_service_to_socket`、`services` 模块整体已无 src 引用 — 属结构卫生，需单独清理切片。
- 测试缺口：慢消费者/大 payload 无真实进程覆盖；USB 拒绝仅单测；握手 5s 绝对预算（等待用户授权对话框可能判败）未测。

USB dispatcher、全局持久 multiplex、delayed ACK、实体设备与 AOSP 互操作未验。

## P7 shell/exec输入输出与退出码（依赖P6）

文件：client/{shell.rs,exec_out.rs,protocol.rs}和main_adb.rs。
方法：跨WRTE累计shell_v2，stdout/stderr分流、远端exit决定CLIrc；真实stdin/window-size/EOF/Ctrl-C/resize，exec-in不等对端先输出才送stdin。
反例：shell false、stderr-only、每字节分片、exec-in cat、半帧EOF、取消和超时。断言字节/rc/FD和线程退出。

## P8 forward/reverse/JDWP/attach/detach/reconnect（依赖P6）

文件：server/{forward.rs,handler.rs,services.rs}、client/{detach.rs,host_command.rs}和main_adb.rs。
方法：reverse走设备reverse:forward:*且有数据面；forward保留选中设备和local-spec；JDWP设备服务非空host假结果；attach/detach对齐host契约；reconnect scope和wait transport/state实际参与选择。
反例：双设备仅B流量、norebind冲突、remove关闭监听、死亡/重连、错误transport不能让disconnect假成功。

## P9 bugreport/sideload（依赖P6/P7）

文件：client/bugreport.rs、新sideload模块、main_adb.rs。
方法：bugreportz取设备结果并pull有效ZIP，legacy文本不冒充ZIP；sideload-host:size:blocksize按需供块，fallback只按AOSP协商，不自造filename头或整包一帧。
反例：PENDING/FAIL、坏ZIP、非顺序/重复/越界块、末短块、EOF/error；真CLI文件/wire核对，recovery设备层独立未验。

## P10 mDNS/身份/版本/能力宣告（依赖P5/P6）

DNS广告≠已认证Device，包含pairing服务列表，Create/Update/Delete完整；安装Pythonzeroconf的CI腿独立广播。重连/授权失败不标ready，删除未实际接入能力宣告；版本注入真实构建身份，不deadbeef。

## P11 剩余子系统及发布合同

确认缺陷关闭后施工fastdeploy APK patch+device agent与abb interactive完整依赖，不用普通incremental冒充。Fastboot format生成filesystem image再flash；USB/UDP按真实packet边界解析，覆盖INFO/TEXT含状态词、seq/ID/wrap/重传耗尽。
发布逐命令限定输入/target/feature/平台，故意变异serial/count/终态/sparseoffset/failure-stop对应门禁必须红；累计release+矩阵复验。实体usbfs/fastbootd/备用设备写后读回需授权、备份及救援，不承诺任意输入无bug或断电原子性。

## 停工条件

只有setup error、缺oracle、共享树被别人推进或下一动作有设备风险时，停该失败域说明证据，其他独立线继续；新确认缺陷纳入对应PR，不树外口头TODO。尚未施工的项不得由文档计为完成。
