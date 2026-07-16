# 离线发布信任链

本文定义离线 Registry 制品导入与旧部署纳管之间的强制信任边界。它只描述技术授权链，不替代企业密钥托管、双人复核、介质交接和商业发布审批。

## 固定信任根

目标主机唯一允许的发布验签公钥为：

```text
/etc/heyi-release/trusted-release-public.pem
```

该文件及全部父目录必须由 `root` 所有、不可由组或其他用户写入，文件模式只能为 `0400` 或 `0444`，路径中不得包含符号链接。`import-offline-registry-bundle.sh` 即使收到内容相同的其他公钥文件，也会失败关闭；调用参数必须逐字等于上述 canonical 路径。

导入器会在验签前把固定公钥复制到受保护的事务快照，并计算 SHA-256。该摘要同时写入：

- `registry-import-<manifest-sha256>.json` 的 `trusted_key_sha256`；
- `highest-release.json` 的 `trusted_key_sha256`。

两个状态文件都使用 schema v2。`highest-release.json` 只允许八个精确字段，不接受缺字段、额外字段、重复 JSON 键或旧 schema。

新发行序号必须严格大于最高已接受序号。若传输确认或最终响应丢失而重跑同一个已签名 bundle，导入器会在任何临时 Registry 网络、容器或 pull 之前生成确定性的 expected receipt/highest，并仅在两个状态文件、固定信任根以及九个本机镜像的 ID、RepoDigest 和平台全部一致时返回 `AUDITED_NOOP`。序号更小、同序号状态缺失或任一字段冲突均失败关闭；回执目录会在最高状态推进前先完成持久化屏障。

`install` 与未来重新开放的 `upgrade` 在 `preflight-offline.sh` 中使用同一信任合同：它独立检查固定公钥的 canonical 路径、owner、mode、link count、大小与全部父目录权限，实算 SHA-256，并同时严格解析导入回执和最高发布状态。JSON 中的重复键、`NaN`/`Infinity`、非 schema v2、额外字段或公钥摘要漂移都会在启动任何业务容器前失败关闭。当前 `active_upgrade` 生产验证仍显式禁用，因此 upgrade 分支只用于验证失败关闭，不能作为可执行升级能力。

## 接管证据信任根

发布信任根只授权目标 release，不授权 legacy adoption 证据 signer。生产接管另行固定以下独立预置材料：

```text
/etc/heyi-adoption/trusted-evidence-public.pem
/etc/heyi-adoption/trusted-evidence-public.sha256
```

公钥及其一行小写 SHA-256 指纹必须由独立密钥托管/CMDB 渠道预置并双人复核。`adopt-offline.sh` 不接受调用者提供 evidence 公钥或私钥；它在任何旧栈变更前验证 canonical 固定路径、owner、mode、单硬链接、全部父目录权限、指纹内容与公钥实算摘要。即使攻击者生成结构正确、包含合法 `release_authorization_sha256` 的新钥匙对自签证据，也不能替代该信任根。

退役、中止与完成收据的短时签名私钥只允许在批准窗口映射至 `/run/heyi-adoption-signing/evidence-signing.key`。它不是持久信任根，不得写入 `/etc`、`/srv`、bundle、镜像、COS 或备份；入口会用固定 challenge 验证其与独立预置公钥匹配，并在关键边界重复检查换钥。维护结束后必须卸载/清除该介质。该过渡设计依赖受限 sudo、双人签名仪式和无任意 root shell；后续若改为外部 signer，应保持相同固定公钥与事务 challenge 语义。

## 纳管时的交叉绑定

`adopt-offline.sh` 在允许旧项目退役前按以下顺序执行：

1. 验证固定 adoption 证据公钥、独立指纹和短时 signer challenge，拒绝调用者自选 keypair；
2. 验证受保护的 legacy plan、binding key、签名备份和当前旧部署拓扑；
3. 通过 legacy retirement predictive dry-run 完成 plan HMAC/文件/拓扑验证；
4. 从 canonical JSON 精确读取 plan schema v4、`kind`、`project`、发布授权对象及其 SHA-256，并验证文件 SHA-256 等于操作员确认的 plan SHA-256；
5. 独立读取固定 release 信任根并实算公钥 SHA-256；
6. 要求 Registry 导入回执和 `highest-release.json` 的发布身份完全一致；
7. 要求两者的 `release_git_sha` 精确等于已确认 plan 的 `git_sha`；
8. 要求两者的 `trusted_key_sha256` 精确等于固定 release 信任根的实算摘要。

任一字段不一致、状态文件为旧格式、JSON 含重复键或公钥在验证期间发生变化，纳管都会在修改旧项目之前停止。

## 旧状态迁移

缺少 `trusted_key_sha256` 的旧回执或 schema v1 `highest-release.json` 不会被自动升级，也不能通过手工补字段继续使用。必须：

1. 保存现有状态文件、签名制品和主机备份，纳入审计归档；
2. 由 root 将旧信任状态移入只读隔离目录，禁止原地编辑；
3. 使用固定信任根重新执行完整的签名 bundle 导入；
4. 确认新生成的两个 schema v2 状态文件记录相同的公钥摘要与发布 Git SHA；
5. 重新生成并确认 legacy plan，再执行 predictive adoption。

旧回执只能作为历史证据，不能继续充当部署授权。

## Plan schema v4 授权闭环

`legacy_offline_adoption.py plan` 不再接受操作员提供 target manifest 或 Git SHA。它固定读取信任根和 `highest-release.json`，从 release ID 派生受保护的 bundle manifest，再从 manifest SHA-256 派生唯一 Registry 导入回执。release sequence、release ID、Git SHA、schema head、manifest、release assets、签名集合与公钥摘要共同写入 plan 的发布授权对象，并形成 `release_authorization_sha256`。

challenge、prepared state、详细恢复证据和顶层签名备份证据均携带同一个发布授权摘要。`prepare`、`finalize`、`retire` 与 `reactivate` 每次执行都会重新验证固定信任根、最高发布、回执和 manifest；schema v3 及更早计划、旧 prepared state，以及缺少 schema v3 `operation_scope` 的旧备份证据一律 fail-closed，不能通过手工补字段继续使用。

`verify-upgrade-backup.py` 不接受操作员提供的“期望发布授权摘要”。它从固定状态重新构造 canonical authorization，要求 schema v3 证据内的 `release_authorization_sha256`、证据 manifest 与命令选择的 manifest 三方一致，并重新哈希全部备份制品。`operation_scope` 必须同时存在于签名证据和调用方参数中；旧栈接管固定为 `legacy_adoption`，常规升级合同固定为 `active_upgrade`，不允许互换。fresh 模式还要求相对当前时间仍新鲜；但当前 public `active_upgrade` 路径始终 fail-closed，只有 `legacy_adoption` 可进入生产执行路径。

校验器本身只执行证据密码学与结构校验，不负责判断接管事务是否已经进入 durable 状态。生产入口由 `adopt-offline.sh` 先确认同一事务的旧栈退休意图、最终退役收据或接管事务日志已经持久化，才进入 `legacy_adoption` durable 验证分支并仅跳过相对当前墙钟的过期检查；签名、schema v3、scope、结构时序、全部制品摘要、固定发布授权和 manifest 校验一项不少。`active_upgrade` 永远不能使用 durable resume；独立手工调用不能把该参数当作启动新事务的授权、恢复证明或绕过时效门禁的运维开关。
