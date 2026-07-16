# 功能验收防伪与信任边界

功能清单不是信任根。`functional_acceptance_policy.json` 独立固定全部必选 requirement、runner、逐节点、最低通过数和外部证据 ID；验证器内置该文件的 SHA-256，策略文件被单独篡改时直接失败。

当前受信策略摘要为 `1b83360e3eadc66e86fb422a43f2151103840db8a84168dc91867df41d93228e`。本次策略冻结覆盖账号退役与所有权转移、审计控制台与安全 CSV 导出、文件审批、离线接管及故障恢复、Linux 主机十二项签名证据、浏览器企业流程和 PostgreSQL 并发线性化校验；后端与前端最低通过数分别固定为 434 和 182。正式变更策略时必须同步复核并更新验证器中的固定摘要；仅修改 JSON 会被判定为 `FAIL`。

测试 runner 必须生成 JUnit/Vitest JSON 原始机器工件。验收记录逐节点状态、起止时间、退出码、运行平台、Git HEAD、内容指纹、原始工件 SHA-256 与最终结果哈希；仅输出 `145 passed` 等聚合字符串不能通过。

外部证据必须使用 Ed25519 签名，并绑定验收方在本次运行前签发的一次性 challenge。受信公钥与 challenge 由目标 Linux 主机上、仓库外、root 所有且权限为 `0400/0600` 的信任存储提供；成功核验后 challenge 原子改名为 consumed。缺少私钥、公钥、challenge、签名或任一绑定字段时，runtime-functional 必须保持 `BLOCKED`。

私钥不得进入仓库、镜像、`.env`、日志或验收工件。公钥轮换必须更新独立策略并重新固定策略 digest，且接受双人复核。

目标 Linux 主机调用示例：

```bash
python -m scripts.functional_acceptance \
  --profile runtime-functional \
  --run-tests \
  --trust-store /etc/heyi-acceptance/collector-public-keys.json \
  --challenge-store /var/lib/heyi-acceptance/challenges \
  --json
```

公钥文件必须由 root 所有且权限为 `0400` 或 `0600`；challenge 目录必须由 root 所有且权限为 `0700`，其中每个 challenge 文件也必须为 root 所有且权限为 `0400/0600`。两者都必须位于仓库之外。通过签名验证后，对应 challenge 文件会原子改名为 `.consumed`，重放同一证据会被阻断。
