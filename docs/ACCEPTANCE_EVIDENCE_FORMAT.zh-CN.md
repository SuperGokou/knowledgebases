# 终验正式证据格式

本文定义 `scripts/acceptance.py --profile final` 消费的脱敏证据。证据文件不得包含 `.env` 值、账号、密码、Token、API Key、数据库连接串、公网 IP、企业文档正文或预签名 URL。路径必须是相对证据 JSON 所在目录的相对路径；验收器拒绝绝对路径、目录穿越、符号链接、哈希不匹配和超过 1 MiB 的证据 JSON。

## 工作树身份

正式证据中的 `target.git_head` 与 `target.content_fingerprint` 必须和验收时工作树完全一致。内容指纹由 Git HEAD、tracked binary diff SHA-256 和未跟踪文件名/内容清单 SHA-256 组合计算。最终报告只保存哈希和状态计数，不披露文件名或文件内容。工作树非干净状态时，即使其他 Gate 全部成功，`final` 仍为 `FAIL`。

## 可信 Node 执行器绑定

浏览器与前端测试的执行器不是不受控的 PATH 依赖。顶层 `scripts/acceptance.py --profile final` 必须通过 `--node-executable` 选择仓库外的绝对规范路径；在 Linux `final`/`ci` 中，该 Node 普通文件及其全部祖先目录必须由 root 所有、不可被组或其他用户写入，且任何符号链接都会被拒绝。验收器在净化子进程环境前以无跟随方式打开文件、核对元数据并计算 SHA-256，再把规范路径、摘要和 root 所有权要求传给 `scripts.functional_acceptance`；功能验收器会在真正执行 Node 前重新验证同一绑定。

Node 二进制、可执行文件内容和可写 PATH 不属于正式证据包，也不得由证据 JSON 指定。绑定不完整、摘要变化、文件替换、仓库内路径或不安全权限均使 `FUNCTIONAL-P0-001` 保持 `blocked`，不能用已有 JUnit/Vitest JSON 或人工声明绕过。

## 恶意文件链路证据

```json
{
  "schema_version": 1,
  "kind": "malware",
  "status": "complete",
  "target": {
    "os": "linux",
    "git_head": "<git-head>",
    "content_fingerprint": "<sha256>"
  },
  "checks": {
    "clamav_database_preflight": {"status": "passed", "artifact": "clamav-db.json", "sha256": "<sha256>"},
    "eicar_quarantined": {"status": "passed", "artifact": "eicar.json", "sha256": "<sha256>"},
    "clean_file_released": {"status": "passed", "artifact": "clean-file.json", "sha256": "<sha256>"},
    "minio_scan_approval_download": {"status": "passed", "artifact": "full-chain.json", "sha256": "<sha256>"}
  }
}
```

四项必须全部来自目标 Linux 环境并通过：ClamAV 病毒库预检、EICAR 隔离、干净文件放行，以及 MinIO 上传到扫描、审批和下载的全链路。代码存在、单元测试或模拟对象不能代替目标机证据。

## Codex 深度安全扫描终态证据

```json
{
  "schema_version": 1,
  "kind": "security-scan",
  "status": "complete",
  "policy_status": "passed",
  "target": {
    "git_head": "<git-head>",
    "content_fingerprint": "<sha256>"
  },
  "report": {"artifact": "security-report.json", "sha256": "<sha256>"},
  "summary": {
    "open_critical": 0,
    "open_high": 0,
    "open_medium": 0,
    "open_low": 0
  }
}
```

只有扫描状态为 `complete`、策略状态为 `passed`、正式报告哈希可验证、Critical/High 未关闭项均为 0，并且扫描目标与当前 Git/工作树内容一致时才通过。扫描仍在运行、扫描了旧 revision、报告缺失或只有线程/工具错误说明时一律 `blocked`。

## 离线镜像证据

`final` 不读取镜像清单内容进报告。镜像验证必须复用同一个 root-only canonical contract：

```bash
CONTRACT_RESULT=$(sudo sh deploy/tencent/create-offline-contract.sh \
  /srv/heyi-knowledgebases-offline/shared/runtime.env \
  /srv/heyi-knowledgebases-offline/releases/<content-sha>/release.env)
CONTRACT_DIR=${CONTRACT_RESULT%% *}
CONTRACT_SHA256=${CONTRACT_RESULT#* }
trap 'sudo sh deploy/tencent/remove-offline-contract.sh \
  "$CONTRACT_DIR" "$CONTRACT_SHA256"' EXIT

sudo sh deploy/tencent/verify-offline-images.sh verify \
  --contract-dir "$CONTRACT_DIR" \
  --contract-sha256 "$CONTRACT_SHA256"
```

`create-offline-contract.sh` 会输出 `CONTRACT_DIR CONTRACT_SHA256`；示例的退出 trap 只会在重新核验摘要后删除该 contract。上面的手工 `verify-offline-images.sh verify` **只验证镜像清单、Compose 渲染与本机镜像身份，不读取 Registry 导入收据，也不读取 `highest-release.json`**。清单缺失、与 `docker compose config --images` 不一致，或任一精确 RepoDigest/config image ID/`linux/amd64` 平台无法由本机 `docker image inspect` 证明时，该手工镜像检查失败。

完整 `final` 必须先通过 `OFFLINE-P0-001`：以 root 对同一 canonical contract 执行 `preflight-offline.sh`，由预检校验签名 Registry 导入收据、最高已接受发布状态、目标发布与签名资产摘要；随后 `OFFLINE-IMAGES-P0-001` 才执行上述镜像身份检查。`install-offline.sh` 与 `deploy-offline.sh` 已按该顺序调用预检与镜像验证。签名收据缺失、不安全、与目标发布不匹配或不是最高已接受发布时，由完整预检记为 `blocked`；不能用手工 `verify-offline-images.sh` 的成功替代该门禁。classic `docker load` 成功本身也不是通过条件；`local`/`ci` 的 Compose 解析只属于开发 Smoke。

## 容量与灾备签名证据

`CAPACITY-P0-001` 与 `DR-P0-001` 不再是不可解除的静态阻断，但也不会根据文件名、人工说明或单元测试自动放行。两项 Gate 均要求显式提供：证据 JSON、64 字节原始 Ed25519 detached signature、PEM Ed25519 公钥以及不可变 `release_id`。三类文件必须位于目标 Linux 主机的绝对路径，root 所有、不可被组或其他用户写入、不是符号链接且只有一个硬链接；公钥还必须位于证据目录和代码仓库之外的独立信任根。验收器对证据原始字节验签，并核对公钥 DER 指纹、当前 Git HEAD、工作树内容指纹、发布编号、时效、相对工件路径、字节数和 SHA-256。缺失、重复 JSON key、额外字段、旧发布、过期、未来时间、错误签名、工件替换或不安全权限一律返回 `blocked`。

### 组合容量证据

信封使用 [enterprise-capacity-evidence-v1.schema.json](./schemas/enterprise-capacity-evidence-v1.schema.json)，最长有效期 24 小时，并且必须恰好引用以下三个受签名信封哈希保护的 JSON 工件：

1. `control_plane_report`：必须是 `scripts/enterprise_capacity_gate.py` 生成的 `PASS_CONTROL_PLANE`，所有检查通过，并继续诚实标记 `evidence_classification=not_model_capacity` 与五十亿 Token/日 `UNVERIFIED_NO_GO`；
2. `real_model_benchmark`：必须来自真实供应商或私有推理集群，`stub_used=false`、`synthetic_responses=false`，至少 1,000 个身份、连续 1,800 秒，按实际输出 Token 计算的吞吐不低于 `5,000,000,000 / 86,400` Token/s，错误率不高于 0.1%；
3. `provider_quota`：必须证明真实供应商或私有推理集群的每日配额不少于 50 亿 Token，且成本模型与数据驻留已复核，证据不得包含密钥。供应商类型、供应商 ID 与模型 ID 必须和真实模型压测工件完全一致，不能用另一个模型或供应商的配额替代。

控制面桩流量仍然有价值，但它只能证明队列、配额、超时、数据库和对象存储控制面。桩吞吐、请求次数、理论换算或 `MODELLED_NOT_MEASURED` 均不能代替 `real_model_benchmark`。模型工件的详细字段以验收器实现和本节约束为准；任何“实测 Token 数 / 稳态秒数”不足时即使报告中的投影值较高也会被拒绝。

### 全量灾备恢复证据

信封使用 [enterprise-disaster-recovery-evidence-v1.schema.json](./schemas/enterprise-disaster-recovery-evidence-v1.schema.json)，最长有效期 30 天，并且必须恰好引用以下四个 JSON 工件：

1. `restore_drill_report`：全新隔离主机的真实全量恢复，禁止 simulation/test double；独立备份、PostgreSQL PITR、对象版本或复制均验证通过；时间戳实算 `RPO ≤ 900 秒`、`RTO ≤ 14,400 秒`；
2. `database_integrity`：源端与恢复端 schema head、表数、行数一致且校验通过；
3. `object_integrity`：源端与恢复端对象总数一致，至少 1,000 个对象逐个 SHA-256 匹配，匹配率必须为 100%；工件必须携带去标识化的 `object_id_sha256 + source_sha256 + restored_sha256` 样本清单，验收器会逐项比较、拒绝重复对象，并重新计算清单摘要；
4. `functional_smoke`：恢复环境的登录、检索、下载与来源引用闭环全部通过，且证据不含秘密。

`legacy_offline_adoption.py` 产生的签名备份与隔离恢复工件可以作为原始恢复材料，但旧版 `offline-upgrade-backup` 顶层证据本身没有当前最终发布的 `git_head + content_fingerprint + release_id` 三重绑定，也没有完整 RPO/RTO 与 1,000 对象抽检契约，因此不能直接让 `DR-P0-001` 通过。必须由独立验收签署方复核原始工件后生成上述严格信封；不得修改旧证据伪造缺失字段。
