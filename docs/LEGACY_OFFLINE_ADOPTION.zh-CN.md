# 旧版离线栈安全接管与恢复证明

> 适用对象：现存 Docker Compose 项目 `heyi-kb-offline`。本流程在不删除数据的前提下，为旧栈建立可验证备份，并把 `deploy/tencent/adopt-offline.sh` 定义为预测预检与闭合切换的唯一入口。入口同时提供 non-cutover 的 predictive-only 路径和受确认的执行路径；操作员不得把裸 `retire` 与 `install-offline.sh` 拆成两个独立变更。

> [!WARNING]
> 本手册定义的是安全执行条件，不是当前环境的上线批准。磁盘静态加密、共享主机资源余量、PostgreSQL/MinIO/CA 真实恢复演练、VPN/安全组、模型出口审批及最终签名验收证据任一缺失时，结论仍为 **NO-GO**。

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
- 可写 bind mount 必须位于 `/srv/heyi-knowledgebases-offline/data`；符号链接、命名卷或其他数据根不能冒充目标 bind 路径。
- 目标新栈只允许直接复用 `/srv/heyi-knowledgebases-offline/data/postgres` 与 `/srv/heyi-knowledgebases-offline/data/minio`：旧 PostgreSQL 必须把前者直接挂载到 `/var/lib/postgresql/data`，且在线执行 `SHOW server_version_num` 必须证明 major 为 `17`；旧 MinIO 必须把后者直接挂载到 `/data`。任一路径、挂载类型或 PostgreSQL major 不匹配都必须在退役前失败关闭，转入经审批的逻辑恢复迁移，不能直接接管。
- 旧 `proxy`/`maintenance-page` 的容器 `/data` 必须直接绑定 `/srv/heyi-knowledgebases-offline/data/caddy-data`。CA 主机目录只能由该挂载推导为 `/srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local`，操作员提供的其他路径一律拒绝。
- 只允许边缘服务发布 `19443`、`19444`；发现 `10050` 或其他端口立即失败。
- 项目网络若连接任何非本项目容器，立即失败。
- 退役只停止并删除已重新检查标签、镜像和 ID 的精确容器，以及端点为空的精确项目网络。
- 旧业务写入者的停止操作固定使用 140 秒优雅停机时间；不得使用 `docker kill`、`docker rm -f` 或更短的现场参数绕过在途请求清算。
- 命名卷与 bind 数据根永不删除；失败时使用受 HMAC 绑定的旧 Compose/env 重建原栈。
- 只有数据库迁移尚未开始、退役收据验签通过且所有资源仍与计划一致时，才允许以 `PRE_MIGRATION_ONLY` 边界恢复旧栈。数据库迁移开始后禁止恢复旧 API、禁止 Alembic downgrade；此时只能保持维护入口并 forward-fix。

## 私密数据与 COS

以下内容禁止进入 COS、Git、README、工单、聊天或普通验收附件：

- `runtime.env` 及其他含密环境文件；
- PostgreSQL 逻辑备份；
- MinIO 对象字节；
- Caddy CA 加密归档及其离线解密私钥。

每个备份运行目录都包含 `.NO_COS_PRIVATE_DATA`。只有不含秘密值的已签名公共证据可按企业审批流转。

运行密钥和环境文件只记录带域隔离的 HMAC 绑定，不记录普通 SHA-256，避免对低熵秘密做离线枚举。Caddy CA 在内存中打包后，立即使用离线接收者证书执行 AES-256 CMS 加密；CA 明文归档不会写入服务器文件系统。接收者私钥必须始终留在离线介质/离线机器，服务器不得持有。

## 受控接管流程

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
  --compose-file /srv/heyi-knowledgebases-offline/releases/<legacy-a>/deploy/tencent/compose.offline.yml \
  --compose-file /srv/heyi-knowledgebases-offline/releases/<legacy-b>/deploy/tencent/compose.offline.yml \
  --legacy-env-file /srv/heyi-knowledgebases-offline/releases/<legacy-a>/release.env \
  --legacy-env-file /srv/heyi-knowledgebases-offline/releases/<legacy-b>/release.env \
  --target-manifest /srv/heyi-knowledgebases-offline/releases/<target>/release.env.images \
  --git-sha <40位提交SHA> \
  --output-plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json
```

`--compose-file` 和 `--legacy-env-file` 均按实际旧发布文件重复传入；每个由容器 `com.docker.compose.project.config_files` 标签引用的 Compose 绝对路径必须恰好出现一次，不能遗漏、重复或用合并后的临时文件代替。停止状态的一次性容器只允许已知的 `api-preflight`、`clamav-db-preflight`、`migrate` 与 `bootstrap`，不会在恢复时重新运行。保存命令输出的 `plan_sha256`，再由操作员和复核员分别核对容器、镜像、挂载、网络、端口和目标镜像清单。

### 2. 准备备份

第一次不带 `--execute` 运行并审阅 dry-run。第二次由双人共同输入计划摘要并执行：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py prepare \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --run-id <UTC时间-变更单号> \
  --ca-root /srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local \
  --ca-recipient-certificate /etc/heyi-adoption/offline-recipient.pem \
  --evidence-signing-key /etc/heyi-acceptance/upgrade-evidence.key \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub
```

正式执行时追加三个执行确认参数。`--ca-root` 必须与旧 Caddy `/data` bind 推导出的上述主机路径完全一致；不能用另一个仍位于数据根内的目录代替。工具先停止边缘/写入服务，保留 PostgreSQL 与 MinIO 仅用于逻辑读取，生成：

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

### 4. `adopt-offline.sh` 预测性目标预检

只有签名证据仍在 24 小时有效期内，且 CA、数据库、MinIO 隔离恢复全部通过，才可运行预测性接管门禁。下面命令**不带 `--execute`**，只创建并验证目标 canonical contract，验签发布/Registry/备份证据，验证环境、镜像、Compose、主机隔离基线，运行旧栈 `retire` dry-run，并证明预期退役收据路径和旧状态收据可安全归档。它不会停止旧栈、启动目标栈或改变端口：

```bash
export TARGET_RELEASE=/srv/heyi-knowledgebases-offline/releases/<target-content-sha>
export RUNTIME_ENV=/srv/heyi-knowledgebases-offline/shared/runtime.env
export TARGET_RELEASE_ENV=$TARGET_RELEASE/release.env
export LEGACY_PLAN=/srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json
export BACKUP_RUN=/srv/heyi-knowledgebases-offline/backups/<run-id>

sudo sh "$TARGET_RELEASE/deploy/tencent/adopt-offline.sh" \
  --runtime-env "$RUNTIME_ENV" \
  --release-env "$TARGET_RELEASE_ENV" \
  --legacy-plan "$LEGACY_PLAN" \
  --legacy-binding-key /etc/heyi-adoption/binding.key \
  --backup-evidence "$BACKUP_RUN/evidence/upgrade-backup-evidence.json" \
  --backup-signature "$BACKUP_RUN/evidence/upgrade-backup-evidence.sig" \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub \
  --evidence-signing-key /etc/heyi-acceptance/upgrade-evidence.key \
  --retirement-receipt "$BACKUP_RUN/evidence/retirement/receipt.json" \
  --retirement-signature "$BACKUP_RUN/evidence/retirement/receipt.sig" \
  --host-isolation-baseline /srv/heyi-kb-evidence/host-isolation-before.json \
  --host-isolation-hmac-key /srv/heyi-kb-evidence/host-isolation.hmac \
  --confirm-project heyi-kb-offline \
  --confirm-plan-sha256 "<plan-sha256>" \
  --confirm-preserve-data PRESERVE_BIND_DATA_AND_NAMED_VOLUMES
```

预测成功的固定输出是 `adoption: predictive-only PASS; legacy project unchanged; execute=false`。它只说明本次输入与目标机当前状态满足切换前置条件，不是上线批准，也不延长 24 小时备份证据有效期。当前发布的 Schema head 为 `20260715_0021`；`offline_contract_files` 当前共有 39 个固定条目，其中 3 个是环境/镜像清单，36 个是 `release/` 发布控制面资产。数量或清单发生变化时必须重新构建、签名并导入整个发布包，不能手工补文件。

双人复核 predictive-only 输出、计划摘要和变更单后，使用**完全相同的参数**重新运行上面的命令，并在末尾追加 `--execute`。闭合事务在同一个 root-only 项目锁中按固定顺序执行：预测预检 → 准备隔离安装合同 → 精确退役 → 退役收据验签 → 主机零漂移复核 → 旧收据带 SHA-256 原子归档 → 写入 HMAC 绑定的接管事务日志 → 目标安装 → 最终主机复核 → 签名完成收据。任何人都不得跳过入口而单独调用退役、安装或迁移命令。

目标安装会在执行迁移命令前先持久化 `migration_invoked`，该状态是不可逆边界。若目标安装在此之前失败，闭合入口会调用受签名发布约束的 `offline-pre-migration-abort.py`：先 dry-run，再只停止并删除与合同及事务精确绑定的 `api-preflight`、`clamav-db-preflight`、`llm-egress-preflight` 容器，删除精确 owner marker，恢复 reconcile service/timer 的“从未安装”基线，归档未提交的安装状态与切换意图，并再次证明目标容器、网络、项目卷、owner marker 均为零。它不删除 bind 数据、命名数据卷，不执行全局 Docker 操作，并生成状态为 `aborted_pre_migration`、边界为 `PRE_MIGRATION_ONLY` 的签名收据。

`adopt-offline.sh` 必须独立复验中止收据签名、事务日志摘要、计划/退役/合同身份、目标资源为零、reconcile 基线及主机零漂移，全部通过后才恢复已归档的旧收据并调用旧栈恢复。没有签名中止收据时，即使目标安装尚未创建容器，也不得恢复旧栈；入口必须失败关闭。若 `migration_invoked` 已持久化、目标安装已提交、清理不完整、收据或签名无效、身份不一致，或者是否执行过迁移无法证明，入口必须保持旧 API 关闭，进入维护入口并输出 `POST_MIGRATION_FORWARD_FIX_ONLY`；此后只能前向修复，禁止恢复旧 API 或执行 Alembic downgrade。

### 5. `reactivate PRE_MIGRATION_ONLY` 恢复契约

`reactivate` 不是数据库降级工具。它只接受签名退役收据、同一接管事务下的签名目标中止收据、未变化的发布状态绑定、通过 HMAC 的主机隔离基线、空闲的 `19443/19444`、精确保留的数据根/卷，以及与退役前一致的 PostgreSQL 17 Schema。下面的不带 `--execute` 命令仅用于复核恢复条件；只有闭合入口先验签目标 `PRE_MIGRATION_ONLY` 中止收据并再次证明目标资源与主机隔离基线一致，才可追加执行确认：

```bash
sudo /usr/bin/python3 -I "$TARGET_RELEASE/scripts/legacy_offline_adoption.py" reactivate \
  --plan "$LEGACY_PLAN" \
  --binding-key /etc/heyi-adoption/binding.key \
  --retirement-receipt "$BACKUP_RUN/evidence/retirement/receipt.json" \
  --retirement-signature "$BACKUP_RUN/evidence/retirement/receipt.sig" \
  --target-abort-receipt "/srv/heyi-knowledgebases-offline/state/legacy-adoption/transactions/<32位事务ID>/target-pre-migration-abort/receipt.json" \
  --target-abort-signature "/srv/heyi-knowledgebases-offline/state/legacy-adoption/transactions/<32位事务ID>/target-pre-migration-abort/receipt.sig" \
  --adoption-transaction "<32位事务ID>" \
  --evidence-public-key /etc/heyi-acceptance/upgrade-evidence.pub \
  --host-isolation-baseline /srv/heyi-kb-evidence/host-isolation-before.json \
  --host-isolation-hmac-key /srv/heyi-kb-evidence/host-isolation.hmac \
  --confirm-project heyi-kb-offline \
  --confirm-plan-sha256 "<plan-sha256>" \
  --confirm-restore-boundary PRE_MIGRATION_ONLY
```

人工可以运行上述 dry-run，但**不得手工追加 `--execute`**。执行恢复只能由持有同一项目锁、接管日志与签名证据的 `adopt-offline.sh` 失败处理分支发起。成功状态必须为 `reactivated-pre-migration-only`；它仅按已签名的每服务 Compose 绑定恢复长期服务，旧 proxy 最后启动，停止状态的一次性容器永不恢复。任何数据库 major/Schema、安装状态、容器、端口、卷、bind、计划、退役收据或主机基线漂移都会失败关闭。数据库迁移已经调用或是否调用无法证明时，严禁运行该命令，只能保持维护入口并交付 forward-fix。

## 验证与已知限制

开发机门禁：

```bash
python -m ruff check scripts/legacy_offline_adoption.py tests/test_legacy_offline_adoption.py
python -m mypy --strict scripts/legacy_offline_adoption.py
python -m pytest tests/test_legacy_offline_adoption.py tests/test_offline_adoption_transaction.py tests/test_offline_pre_migration_abort.py tests/test_legacy_adoption_document_contract.py -q
python -m bandit -q -r scripts/legacy_offline_adoption.py deploy/tencent/offline-pre-migration-abort.py
```

Windows 测试只验证纯逻辑和安全契约；Docker 生命周期、root 权限、目录 fsync、OpenSSL CMS、PostgreSQL/MinIO 全量恢复必须在与目标一致的 Linux 8 核/16 GiB/300 GiB SSD 预生产主机上执行。没有目标机签名证据时，结论必须保持 **NO-GO**。
