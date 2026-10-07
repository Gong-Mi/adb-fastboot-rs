# Rust 测试流程参考：本地、CI与证据边界

## 固定流程

AGENTS规矩 → 固定base/head/worktree和AOSP SHA → 一条用户合同/独立oracle → 可编译RED → 生产修复 → 同断言GREEN → 相关回归 → 显式文件提交/推送 → exact-head CI → 累计树复验 → PR回写。

共用`scripts/run_rust_tests.py`。PASS仅认证选定宿主测试；有ignored输出PASS_WITH_IGNORED，不认证设备。原命令、rc、完整日志、HEAD/tree/overlay和passed/failed/ignored写result.json，默认位于$XDG_CACHE_HOME/adb-fastboot-rs-tests（未设置则$HOME/.cache）。证据在源码树外，target按worktree绝对路径隔离；源码边跑边改则结果无效。

本地默认locked/offline，CI显式--online；不得隐式消耗手机移动数据。当前timeout覆盖整条Cargo命令（包括冷编译），没有单独的编译/用例计时器：日志仍在编译阶段时应报告build blocker，不叫测试RED。取消/超时有界停止尚归本runner拥有的leader/进程组，不等待后代stdout EOF；脱组会话不在这一终止合同内，不能承诺已杀掉任意后代。原始bytes直接落盘，并保存最终.log快照，异常/非UTF-8输出不得留下PASS。源码只做运行前后快照对账，临时修改后恢复可能不被发现；调用者必须在运行期间冻结源码，端点一致不是连续未改的证明。显式--output-dir重跑要选新路径，不能覆盖旧RED/GREEN证据。

## 本地运行

在目标worktree根执行，先查实际rustc host/编译器、依赖cache、负载及writable temp。Termux不使用/tmp；Hermes会话可设置下面scratch目录。

```sh
export TMPDIR="$HOME/.hermes/cache/scratch"
python3 -B scripts/test_rust_test_runner.py
python3 -B .github/scripts/test_ci_gate.py

# 库级合同，不是CLI
python3 scripts/run_rust_tests.py --package fastboot-protocol --lib --filter sparse::tests

# 明确执行真实CLI目标的全部用例
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --test fastboot_cli_framed --all-cases
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --test fastboot_sparse_cli --all-cases
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --test fastboot_target_cli --all-cases
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --test adb_sync_cli --all-cases
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --test incremental_cli --all-cases

# CLI crate有bin，不假定存在lib
python3 scripts/run_rust_tests.py --package adb-fastboot-cli --bin fastboot-rs --filter target_

# 外部独立oracle：缺工具应BLOCKED，不算通过
command -v simg2img
python3 scripts/run_rust_tests.py --scope oracle --package fastboot-protocol --lib --filter test_split_simg2img_oracle
```

新增回归先核实实际target/test名，再--filter或--all-cases。fastboot_cli_wire和test_cli有直接调用库的用例，不能按文件名当CLI验收。

必要时直接用等价Cargo命令，同样独立target：

```sh
CARGO_TARGET_DIR=/absolute/owned-target cargo test --locked --offline -p fastboot-protocol --lib sparse::tests
CARGO_TARGET_DIR=/absolute/owned-target cargo test --locked --offline -p adb-fastboot-cli --bin adb-rs client::file_sync::tests
```

--no-default-features不保证无C编译：CLI的adb-protocol依赖默认仍启用pairing-vendored。默认CLI含usb/tls，production pairing使用vendored AOSP/BoringSSL；实际feature图/target决定build.rs。

## CI矩阵与独立oracle

push main、任何base的pull_request及workflow_dispatch触发。三个独立feature腿，fail-fast=false，各跑workspace check/test并保留独立rc：

```sh
python3 scripts/run_rust_tests.py --scope matrix --features default --online --jobs 2 --target-dir "$PWD/target" --output-dir "$RUNNER_TEMP/rust-default"
python3 scripts/run_rust_tests.py --scope matrix --features all --online --jobs 2 --target-dir "$PWD/target" --output-dir "$RUNNER_TEMP/rust-all"
python3 scripts/run_rust_tests.py --scope matrix --features none --online --jobs 2 --target-dir "$PWD/target" --output-dir "$RUNNER_TEMP/rust-none"
```

CI target在隔离虚机，可在该job内缓存；不套到共享本地worktree。Clippy warning advisory，编译/deny失败必须传播。独立sparse-oracle job安装distro AOSP衍生simg2img，显式执行ignored用例，不用Rust自解码作为独立真值。

AOSP test_adb.py是CLI/server测试，不是设备全集；缺zeroconf、Windows/上游skip逐项说明。当前GNU矩阵不能替代Android/Bionic release/runtime层，缺层保留NOT RUN。

## exact-head与防漏合

```sh
git rev-parse HEAD
gh pr view NUMBER --repo Gong-Mi/adb-fastboot-rs --json headRefOid,baseRefName,mergeable,statusCheckRollup
gh api 'repos/Gong-Mi/adb-fastboot-rs/actions/runs?head_sha=FULL_SHA&per_page=100'
gh run view RUN --repo Gong-Mi/adb-fastboot-rs --json headSha,status,conclusion,jobs
gh run view RUN --repo Gong-Mi/adb-fastboot-rs --log
```

按触发条件确定适用run集合，total_count须与实际枚举一致，超过一页分页。空列表不是成功；先查冲突/trigger。记录PR合成merge的实际checkout，必要时比候选与checkout tree；同tree不认证版本注入相同。

```sh
git merge-base --is-ancestor CHILD_HEAD FINAL_HEAD
git cherry FINAL_HEAD CHILD_BRANCH
git diff VERIFIED_BASE FINAL_HEAD -- relevant/source/path
```

ancestry或patch-id单项不足；最终代码和回归都要在累计树。父PR先合，后来合到旧父分支的子修复不会自动进入main。

## 逐能力最低判据

| 能力 | 自动化合同 | 独立未验层 |
|---|---|---|
| install/APEX | 真CLI前置门、feature、wire/payload、commit/abandon | server/USB/TLS各后端与真实PM |
| STLS | 双端明文STLS、真实TLS、加密CNXN/OPEN、失败不降级 | pair→connect持久身份 |
| bridge | 唯一reader、非1stream、双向/ACK/CLSE、EOF/cancel/join | 并发/连续服务和真实USB |
| SYNC | AOSP固定STAT、分片/合并、最终文件/metadata、EOF/error | 目录/压缩/目标与真实adbd |
| Fastboot identity/I/O | 指定B无A流量，缺失/歧义拒绝，实际count/短写/错误 | 实际枚举/claim/kernel/hotplug |
| flash/update | DATA大小、准确payload、post-data/final OKAY，失败无后续写/切槽/重启 | 实际分区读回、fastbootd、断电恢复 |
| sparse | 同一分区offset0逐次施加、DONT_CARE保留、独立libsparse oracle | 大镜像内存/物理传输 |

物理刷写另有明确授权、精确设备/产物、备份和救援；普通本地/CI测试不执行它。host失败停止不保证固件写原子性。
