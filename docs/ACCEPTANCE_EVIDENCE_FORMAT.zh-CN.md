# 终验正式证据格式

本文定义 `scripts/acceptance.py --profile final` 消费的脱敏证据。证据文件不得包含 `.env` 值、账号、密码、Token、API Key、数据库连接串、公网 IP、企业文档正文或预签名 URL。路径必须是相对证据 JSON 所在目录的相对路径；验收器拒绝绝对路径、目录穿越、符号链接、哈希不匹配和超过 1 MiB 的证据 JSON。

## 工作树身份

正式证据中的 `target.git_head` 与 `target.content_fingerprint` 必须和验收时工作树完全一致。内容指纹由 Git HEAD、tracked binary diff SHA-256 和未跟踪文件名/内容清单 SHA-256 组合计算。最终报告只保存哈希和状态计数，不披露文件名或文件内容。工作树非干净状态时，即使其他 Gate 全部成功，`final` 仍为 `FAIL`。

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

`final` 不读取镜像清单内容进报告，而是在目标机执行：

```bash
sh deploy/tencent/verify-offline-images.sh verify \
  /srv/heyi-knowledgebases-offline/shared/offline.env \
  /srv/heyi-knowledgebases-offline/shared/offline.env.images
```

清单缺失、与 `docker compose config --images` 不一致、任一镜像未 `docker load` 或无法 `docker image inspect` 时记为 `blocked`。`local`/`ci` 的 Compose 解析只属于开发 Smoke。
