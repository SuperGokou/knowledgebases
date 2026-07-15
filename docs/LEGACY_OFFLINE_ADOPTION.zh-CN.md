# 旧版离线栈安全接管与恢复证明

> 适用对象：现存 Docker Compose 项目 `heyi-kb-offline`。本流程只解决“在不删除数据的前提下，为旧栈建立可验证备份并精确退役容器/网络”。目标版本的安装、迁移与切流属于后续独立事务。

## 安全结论

`scripts/legacy_offline_adoption.py` 默认只读。任何会停止服务、创建恢复演练容器或退役旧资源的命令，都必须同时给出：

1. `--execute`；
2. `--confirm-project heyi-kb-offline`；
3. `--confirm-plan-sha256 <受保护计划摘要>`。

退役还需要第四项确认：

```text
--confirm-preserve-data PRESERVE_BIND_DATA_AND_NAMED_VOLUMES
```

工具只允许调用绝对路径 `/usr/bin/docker` 与 `/usr/bin/openssl`，固定安全 `PATH`，使用参数数组且不启用 shell。它不会执行 Compose `down`、容器强制删除、卷删除、全局清理、Docker daemon 重启，也不会操作其他 Compose 项目或受保护端口 `10050`。

## 强制边界

- 仅接受项目名 `heyi-kb-offline`、所有者 `jiangsu-heyi-knowledgebases`、栈标记 `offline`。
- 可写 bind mount 必须位于 `/srv/heyi-knowledgebases-offline/data`。
- 只允许边缘服务发布 `19443`、`19444`；发现 `10050` 或其他端口立即失败。
- 项目网络若连接任何非本项目容器，立即失败。
- 退役只停止并删除已重新检查标签、镜像和 ID 的精确容器，以及端点为空的精确项目网络。
- 命名卷与 bind 数据根永不删除；失败时使用受 HMAC 绑定的旧 Compose/env 重建原栈。
- 数据库迁移完成后禁止恢复旧 API、禁止 Alembic downgrade；此时只能 forward-fix。

## 私密数据与 COS

以下内容禁止进入 COS、Git、README、工单、聊天或普通验收附件：

- `runtime.env` 及其他含密环境文件；
- PostgreSQL 逻辑备份；
- MinIO 对象字节；
- Caddy CA 加密归档及其离线解密私钥。

每个备份运行目录都包含 `.NO_COS_PRIVATE_DATA`。只有不含秘密值的已签名公共证据可按企业审批流转。

运行密钥和环境文件只记录带域隔离的 HMAC 绑定，不记录普通 SHA-256，避免对低熵秘密做离线枚举。Caddy CA 在内存中打包后，立即使用离线接收者证书执行 AES-256 CMS 加密；CA 明文归档不会写入服务器文件系统。接收者私钥必须始终留在离线介质/离线机器，服务器不得持有。

## 四阶段流程

### 0. 主机隔离基线

先按 `docs/HOST_ISOLATION_GUARD.zh-CN.md` 创建主机快照。其编排规则是：先 `snapshot`，接管每个阶段后再 `verify`；仅排除 `heyi-kb-offline` 与验收临时项目，必须证明端口 `10050` 的原所有者未变化。

进入维护窗口前还应确认：

- 操作系统为 Linux，当前用户为 root；
- `/srv/heyi-knowledgebases-offline/{data,state,backups}` 均为 root 所有且不可被组/其他用户写入；
- `/usr/bin/docker`、`/usr/bin/openssl` 存在；
- Docker daemon、其他应用和端口 `10050` 正常；
- 备份盘和恢复演练盘容量满足“全部对象 + 三倍数据库备份 + 5 GiB 余量”。

### 1. 生成不可变计划

绑定密钥必须是 root-only、至少 32 随机字节的 Base64URL 文件。计划输出只能位于固定状态目录。

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py plan \
  --binding-key /etc/heyi-adoption/binding.key \
  --runtime-env /srv/heyi-knowledgebases-offline/shared/runtime.env \
  --compose-file /srv/heyi-knowledgebases-offline/releases/legacy/compose.yml \
  --legacy-env-file /srv/heyi-knowledgebases-offline/releases/legacy/release.env \
  --target-manifest /srv/heyi-knowledgebases-offline/releases/<target>/release.env.images \
  --git-sha <40位提交SHA> \
  --output-plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json
```

保存命令输出的 `plan_sha256`。先由操作员和复核员分别核对容器、镜像、挂载、网络、端口和目标镜像清单。

### 2. 准备备份

第一次不带 `--execute` 运行并审阅 dry-run。第二次由双人共同输入计划摘要并执行：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py prepare \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --run-id <UTC时间-变更单号> \
  --ca-root /srv/heyi-knowledgebases-offline/data/caddy/pki/authorities/local \
  --ca-recipient-certificate /etc/heyi-adoption/offline-recipient.pem \
  --evidence-signing-key /etc/heyi-acceptance/upgrade-evidence.key \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub
```

正式执行时追加三个执行确认参数。工具先停止边缘/写入服务，保留 PostgreSQL 与 MinIO 仅用于逻辑读取，生成：

- PostgreSQL custom dump、无角色密码的 globals、schema-only dump、逐表精确行数；
- MinIO 全对象镜像和流式 NDJSON `key/size/SHA-256` 清单；
- 只存在密文的 Caddy CA CMS 归档；
- 已签名的离线 CA 恢复挑战。

无论备份成功与否，工具都会先恢复并验证旧栈原运行集合。若恢复失败，阶段失败且禁止继续。

### 3. 离线 CA 恢复与隔离全量恢复

将 CMS 密文和已签名挑战通过批准的离线介质带到隔离机器。不得使用 COS。离线机器验证挑战签名，以接收者私钥解密，验证 CA 文件数与 HMAC 挑战，并实际建立一个可签发/验证测试证书的临时 CA。随后用离线验收私钥签署严格 JSON attestation：

```json
{
  "schema_version": 1,
  "kind": "heyi-caddy-ca-restore-drill",
  "project": "heyi-kb-offline",
  "challenge_sha256": "<挑战文件SHA-256>",
  "encrypted_archive_sha256": "<挑战内密文摘要>",
  "plaintext_opaque_hmac_sha256": "<挑战内HMAC>",
  "file_count": 1,
  "recipient_certificate_sha256": "<挑战内证书摘要>",
  "status": "passed",
  "tested_at": "<RFC3339 UTC>",
  "private_key_location": "offline-only",
  "server_private_key_present": false,
  "cos_used": false
}
```

把 attestation、签名和仅公钥放回 root-only 验收目录。先 dry-run，再追加三个执行确认参数运行 `finalize`：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py finalize \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --prepared-state /srv/heyi-knowledgebases-offline/backups/<run-id>/evidence/prepared-state.json \
  --ca-restore-attestation /etc/heyi-adoption/ca-restore-attestation.json \
  --ca-restore-attestation-signature /etc/heyi-adoption/ca-restore-attestation.sig \
  --ca-restore-attestation-public-key /etc/heyi-adoption/ca-restore-attestation.pub \
  --evidence-signing-key /etc/heyi-acceptance/upgrade-evidence.key \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub
```

恢复演练只创建带固定 ownership/purpose 标签的内部 Docker 网络、临时 PostgreSQL 与 MinIO，不发布任何端口。它验证 schema head、每张表行数、每个对象大小和 SHA-256；完成后只删除本次 challenge 精确匹配的临时容器、网络和 scratch 目录。成功后生成兼容 `deploy/tencent/verify-upgrade-backup.py` 的 24 小时有效签名证据。

### 4. 精确退役旧容器与网络

只有签名证据仍在 24 小时有效期内，且 CA、数据库、MinIO 隔离恢复全部通过，才允许执行。先 dry-run 查看将删除的精确 ID：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py retire \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --evidence /srv/heyi-knowledgebases-offline/backups/<run-id>/evidence/upgrade-backup-evidence.json \
  --evidence-signature /srv/heyi-knowledgebases-offline/backups/<run-id>/evidence/upgrade-backup-evidence.sig \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub \
  --evidence-signing-key /etc/heyi-acceptance/upgrade-evidence.key
```

正式执行追加所有四项确认。退役收据与签名先在 `.pending-*` 目录生成并验签；容器、网络、卷和 bind 根复核完成后，收据目录才会原子发布为 `evidence/retirement/`。任何中途失败都会使用受保护的旧 Compose/env 恢复旧栈。

退役成功后不要手工清理数据或卷。立即执行主机隔离 `verify`，再由独立目标发布事务安装新版本。目标迁移开始后，回滚边界切换为 forward-only。

## 验证与已知限制

开发机门禁：

```bash
python -m ruff check scripts/legacy_offline_adoption.py tests/test_legacy_offline_adoption.py
python -m mypy --strict scripts/legacy_offline_adoption.py
python -m pytest tests/test_legacy_offline_adoption.py -q
python -m bandit -q -r scripts/legacy_offline_adoption.py
```

Windows 测试只验证纯逻辑和安全契约；Docker 生命周期、root 权限、目录 fsync、OpenSSL CMS、PostgreSQL/MinIO 全量恢复必须在与目标一致的 Linux 8 核/16 GiB/300 GiB SSD 预生产主机上执行。没有目标机签名证据时，结论必须保持 **NO-GO**。
