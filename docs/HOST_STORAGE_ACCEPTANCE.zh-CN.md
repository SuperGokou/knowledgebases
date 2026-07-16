# 通用 Linux 主机与存储实证验收

> 适用目标：Linux amd64/x86_64，8 vCPU、16 GB 内存、300 GB SSD。本文只定义验收证据，不读取 `.env`，也不包含 SSH、IP、账号或业务凭据。

## 判定原则

仅有 CPU、内存和磁盘容量不能证明“300 GB SSD”与真实上传链路可用。正式验收必须同时提交：

1. `findmnt` 与 `lsblk` 采集的目标挂载、块设备、文件系统和 rotational 身份；
2. 在目标数据盘专用空目录中运行的有界 fio 原始结果；
3. 由业务容量压测反推并审批的 IOPS/P99 阈值文件；
4. 专用可销毁验收卷上完整的存储水位 API 链路证据。

任一证据缺失时结果是 `BLOCKED`，证据存在但规格或行为不符合时是 `FAIL`。开发机、其他磁盘或手写 `status=passed` 不能代替目标主机证据。

## SSD 与 fio 证据

先根据业务容量压测形成阈值 JSON。阈值不是本项目拍脑袋给出的固定数值，必须包含审批后的 `capacity_test_reference`，并覆盖 `sequential_write`、`random_read`、`random_write`、`fsync` 四种负载：

```json
{
  "schema_version": 1,
  "capacity_test_reference": "受控容量测试报告编号",
  "capacity_test_artifact": "capacity-test.json",
  "capacity_test_sha256": "对应文件的64位SHA-256",
  "provider_spec_verified": false,
  "workloads": {
    "sequential_write": {"minimum_iops": 0, "maximum_p99_latency_ms": 0},
    "random_read": {"minimum_iops": 0, "maximum_p99_latency_ms": 0},
    "random_write": {"minimum_iops": 0, "maximum_p99_latency_ms": 0},
    "fsync": {"minimum_iops": 0, "maximum_p99_latency_ms": 0}
  }
}
```

示例中的 `0` 是不可运行占位符；采集器会拒绝非正数，并校验容量测试产物的相对路径和 SHA-256。云虚拟盘无法可靠报告 rotational 时，必须先核验云厂商卷规格，把 `provider_spec_verified` 设为 `true`，同时增加 `provider_spec_artifact` 和 `provider_spec_sha256`，并仍须通过 fio。

在目标数据挂载下创建仅供验收的空目录和一次性 challenge。采集器会拒绝符号链接、跨文件系统目录、挂载根目录、marker 不匹配或包含其他文件的目录，并最多创建 4 GiB 测试文件；默认每项运行 30 秒，单项上限 120 秒，结束后删除测试文件。

```bash
CHALLENGE="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
sudo install -d -m 0700 /srv/heyi-acceptance-fio
printf '%s\n' "$CHALLENGE" | sudo tee /srv/heyi-acceptance-fio/.kb-acceptance-destroyable-volume >/dev/null

python3 -m scripts.collect_host_io_evidence \
  --disk-path /srv \
  --test-directory /srv/heyi-acceptance-fio \
  --challenge "$CHALLENGE" \
  --thresholds /srv/acceptance-policy/host-io-thresholds.json \
  > artifacts/host-io.json

python3 -m scripts.host_preflight \
  --disk-path /srv \
  --io-evidence artifacts/host-io.json \
  > artifacts/host-preflight.json
```

HDD 直接 `FAIL`。rotational 未知且无供应商规格证据时 `FAIL`；缺块设备或 fio 原始结果时 `BLOCKED`。

## 存储水位真实链路证据

正式水位证据必须在与业务卷隔离、可整体销毁的验收卷产生。证据 manifest 必须包含 `destructive_volume=true`、卷 ID、绝对挂载点、至少 16 字符的随机 challenge、文件系统与 MinIO 双向核对标志，以及下列 25 个互不重复的原始 JSON 产物及 SHA-256：

- 69/70/79/80/89/90 六个水位分别执行 `single`、`multipart`、`retry`、`concurrent_reservation`；
- 对象已用 179 GB、再请求 1 GB 的 `object_stop_180gb`；
- 每个场景保存 HTTP 状态、稳定 reason code、quota 前后值、对象数量/字节前后值和未完成 Multipart 会话前后值。

预期策略：69/70/79% 全部允许；80/89% 仅 single 允许，其余返回 `storage_bulk_uploads_paused`；90% 全部返回 `storage_capacity_critical`；180 GB 停止线返回 `object_storage_stop_line_reached`。所有拒绝场景的 quota、对象和 Multipart 会话必须完全回滚；任何泄漏都 `FAIL`。

manifest 与其 `raw/` 产物放在同一证据目录后执行。manifest 和每个 raw 产物必须声明受控采集器 `producer=heyi-storage-watermark-harness`、版本和相同 challenge；raw 产物还必须逐项包含 API 结果、文件系统探针、MinIO 探针和 quota 探针，验收器会把它们与 manifest 交叉核对：

```bash
python3 -m scripts.storage_chain_collector --list-plan
```

上述命令永远只输出 25 场景计划，不写卷、不请求 API。正式执行还要求目标 Linux 上存在一个受控、仅用于验收的本机 controller。controller 必须实际调用当前部署的业务 HTTP API，并对同一专用卷上的文件系统、MinIO、数据库 quota 与 Multipart 会话做前后探测；内存模拟、固定 JSON 或开发机代理不属于正式证据。controller 缺失、权限不足、场景准备失败或清理失败都返回 `BLOCKED`。

拓扑文件不得包含密码、Token、S3 密钥或数据库 DSN，只能引用权限为 `0400`/`0600` 的独立 Token 文件：

```json
{
  "schema_version": 1,
  "collector_mode": "real",
  "api_url": "https://kb.internal.example/api/v1",
  "control_url": "https://127.0.0.1:9443",
  "volume_id": "storage-acceptance-volume-001",
  "mount_target": "/srv/heyi-watermark-acceptance",
  "object_root": "/srv/heyi-watermark-acceptance/minio",
  "knowledge_base_id": "00000000-0000-4000-8000-000000000001",
  "deployment_id": "release-20260713-001",
  "repository": "/opt/heyi/knowledge-base",
  "token_file": "/run/secrets/storage-acceptance-controller-token",
  "ca_bundle": "/etc/heyi/pki/internal-ca.pem"
}
```

先创建一次性 challenge，并在专用挂载根写入同值 marker。证据目录必须位于可销毁卷之外且为空。只有显式提供 `--execute-destructive` 才会执行：

```bash
CHALLENGE="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
printf '%s\n' "$CHALLENGE" | sudo tee \
  /srv/heyi-watermark-acceptance/.kb-acceptance-destroyable-volume >/dev/null

python3 -m scripts.storage_chain_collector \
  --execute-destructive \
  --topology /srv/acceptance-policy/storage-chain-topology.json \
  --challenge "$CHALLENGE" \
  --output-directory /srv/heyi-watermark-evidence/run-001

python3 -m scripts.storage_watermark_preflight \
  --disk-path /srv/heyi-watermark-acceptance \
  --object-root /srv/heyi-watermark-acceptance/minio \
  --chain-evidence /srv/heyi-watermark-evidence/run-001/watermark-chain.json \
  > artifacts/storage-watermark-preflight.json
```

v2 manifest 绑定目标 `deployment_id`、Git HEAD、完整 worktree content fingerprint、开始/结束时间、26 个原始工件（25 场景 + 清理证明）的逐项 SHA-256，以及总体 `sha256-chain-v1` attestation。验收器拒绝 `collector_mode=fake`、`status=test-only`、绝对 artifact 路径、目录穿越、符号链接、超过大小上限的文件、SHA-256/attestation 不匹配、目标指纹不一致、缺场景、重复场景、清理失败以及 quota/对象/Multipart 泄漏。证据结构由 `docs/schemas/storage-chain-evidence-v2.schema.json` 定义。

没有专用目标卷或真实 controller 时必须保留 `BLOCKED`，不得复制开发机结果、手写 JSON 或用纯函数单元测试签署通过。采集器测试中的 fake transport 只验证编排和 fail-closed，生成的 `test-only` 证据会被正式验真器拒绝。

## 交付保留物

- 阈值文件及其审批来源；
- `host-io.json` 与 `host-preflight.json`；
- v2 水位 manifest、25 个场景 raw 产物、清理 raw 产物、测试前后 `df`、MinIO 对象指标和 Multipart 列表；
- `storage-watermark-preflight.json`；
- 目标部署版本、采集开始/结束时间和受控执行人签名。

这些证据只证明对应版本、对应卷和对应时间窗；主机、云盘规格、挂载或应用版本变化后必须重新采集。
