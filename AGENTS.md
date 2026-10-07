# ADB/Fastboot 施工与验收规矩

读取 `docs/TESTING.md` 和 `docs/REPAIR_PLAN.md`。本工具会改变持久状态，测试数、函数名、feature 宣告和 CI 绿灯不是整项目完成证明。

1. 先钉 live main、PR head/base、worktree dirty state 和 AOSP tag/SHA。ADB参考是 packages/modules/adb，Fastboot是system/core。既有设计和PR评论优先于猜测。
2. 一个失败域一个分支/PR；单写者负责累计整合。每个worktree独立绝对Cargo target，不共享可变构建目录，不改其他人的现场或全局工具链。
3. 回归先行：独立oracle → 可编译的行为RED → 最小生产修复 → 同断言GREEN。环境/编译故障不叫RED；characterization不伪称历史TDD。
4. 能力必须穿过真实CLI入口：扩展名/选项/目标/capability门 → dispatch → helper → wire → 终态/rc。helper测试、自己组帧、手写feature表不能认证可执行CLI。
5. 指定目标不能失败后换设备；歧义必须拒绝。identity、实际I/O、完整事务是独立门。
6. Fastboot必须严格接受DATA长度和payload后OKAY；意外DATA、短写、零进展、EOF、超时或FAIL不算成功。失败后不得继续依赖写、切槽、重启。host停止不等于设备写入原子性。
7. 未接入的选项/服务在危险I/O前明确拒绝，禁止解析后忽略、恒空结果、伪ZIP或自造服务串。
8. STLS/TLS验收必须有明文STLS交换、真实TLS与加密ADB帧；TLS echo和强制明文fork不能代替它。
9. 每transport唯一帧reader、明确stream分派、ACK背压和close/cancel/join。fd clone不复制接收队列，不能用竞争reader冒充双向桥接。
10. 本地默认locked/offline、聚焦lib/bin/integration target；全workspace default/all/none矩阵交CI。用run_rust_tests.py记录原命令/rc/raw log、HEAD/tree/overlay和实际passed/failed/ignored。
11. 门禁先做负控：退出42、零执行、无summary、假绿summary、超时与运行前后源码身份不一致不能PASS。--filter不能注入Cargo/libtest选项，异常状态必须fail-closed并保留原始bytes。运行期间禁止编辑源码：端点快照不能检测所有改后恢复。不得用末端tail/grep吞失败，不硬编码会随正常加例漂移的总数。
12. skipped/ignored/filtered与passed分开报告。GNU CI、Android/Bionic编译/本机运行、实体USB和设备副作用读回分别验收。独立oracle必须显式执行。
13. 每批targeted→相关回归→exact-head累计CI。核对所有适用run/job和实际checkout；旧头绿、部分绿、零run都不是当前整体通过。
14. 子PR合入后验证进入最终累计树：ancestry、patch equivalence、最终源码和回归缺一不可。父PR先合不会携带后来才合到旧父分支的子修复。
15. 提交前再查dirty state，仅stage任务文件；push/PR/评论/合并后读回精确对象。独立审查不能代替实际执行。
16. 修/继续不授权实体刷写、重启、删除或覆盖默认分支。物理实验另行授权、备份、恢复和独立读回。
17. 方案只放REPAIR_PLAN，复跑方法只放TESTING；进度/原始证据链接放PR，不新增重复完成报告。现有aosp-diff是索引，不是证明；更新时同步当前头、汇总与Remaining，保留历史标签。
