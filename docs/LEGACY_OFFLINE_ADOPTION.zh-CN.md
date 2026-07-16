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

### 接管证据签名职责

生产接管入口不接受操作员传入 `--evidence-public-key` 或 `--evidence-signing-key`。目标机永久保存的 adoption 信任材料只有独立预置的公钥及其经 CMDB/变更单渠道复核的一行小写 SHA-256：

```text
/etc/heyi-adoption/trusted-evidence-public.pem
/etc/heyi-adoption/trusted-evidence-public.sha256
```

两者及全部父目录必须由 `root` 所有、不可被组或其他用户写入、不得包含符号链接或多硬链接；公钥与指纹文件模式只能为 `0400` 或 `0444`。指纹文件必须精确为 `64` 位小写十六进制加一个换行。接管入口会在任何 Docker 变更前实算公钥摘要，并用该公钥验证备份证据；操作员提供的新钥匙对、相同内容但不同路径的公钥和被替换的指纹文件都不会进入生产参数面。

闭合事务仍需为退役、中止和完成收据签名。现阶段签名私钥只能在双人批准的维护窗口内，以只读短时介质映射到固定路径：

```text
/run/heyi-adoption-signing/evidence-signing.key
```

该文件不是目标机信任根，不得写入 `/etc`、`/srv`、镜像、离线 bundle、COS、日志或备份；模式必须为 `0400`，维护窗口结束后立即卸载/清除，重启后不得残留。入口在 predictive preflight 和每个签名/恢复边界都以固定 challenge 验证该短时私钥与独立预置公钥匹配；不匹配或中途换钥会在旧栈变更前失败，或在已开始事务中进入 fail-closed/维护路径。`prepare` 在读取 binding/plan、枚举 Docker、创建备份运行目录、写入 `.NO_COS_PRIVATE_DATA`、停止旧栈或执行任何备份之前，先通过随机输入的真实 OpenSSL 签名/验签 challenge 验证固定短时私钥；生成 CA 恢复 challenge 签名之前再次执行同一密码学检查。`finalize` 在读取 prepared state、枚举 Docker、创建 scratch、运行隔离恢复或写入验收证据前执行入口 challenge，并在首个恢复证据落盘前复验；`retire` 在读取计划、枚举 Docker、发布 durable intent 或删除任何资源前执行入口 challenge，并在发布签名 intent 前复验。错误 signer 的验收标准是上述下游与持久化 mutation 调用数严格为 `0`。运行操作员只能通过受限 sudo 规则执行固定入口，不得拥有任意 root shell 或直接读取签名介质。

`release_authorization_sha256` 与 adoption signer 是两个不可互相替代的门禁：前者只证明目标 release、manifest 与 Registry 状态获得发布授权；上述 `/etc/heyi-adoption` 信任根只证明备份/接管证据来自批准 signer。两者必须同时通过。当前 schema 不把 adoption 私钥当作 release 授权的一部分，也不得用发布公钥替代 adoption 证据公钥。

## 强制边界

- 仅接受项目名 `heyi-kb-offline`、所有者 `jiangsu-heyi-knowledgebases`、栈标记 `offline`。
- 可写 bind mount 必须位于 `/srv/heyi-knowledgebases-offline/data`；符号链接、命名卷或其他数据根不能冒充目标 bind 路径。
- 目标新栈只允许直接复用 `/srv/heyi-knowledgebases-offline/data/postgres` 与 `/srv/heyi-knowledgebases-offline/data/minio`：旧 PostgreSQL 必须把前者直接挂载到 `/var/lib/postgresql/data`，且在线执行 `SHOW server_version_num` 必须证明 major 为 `17`；旧 MinIO 必须把后者直接挂载到 `/data`。任一路径、挂载类型或 PostgreSQL major 不匹配都必须在退役前失败关闭，转入经审批的逻辑恢复迁移，不能直接接管。
- 从实时验证 inventory 读取的旧 `proxy`，以及存在时的 `maintenance-page`，其容器 `/data` 都必须以可写 bind 直接绑定 `/srv/heyi-knowledgebases-offline/data/caddy-data`。CA 主机目录只能由该挂载精确推导为 `/srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local`；不能仅凭“位于 `DATA_ROOT` 下”放行，操作员提供的其他子目录或伪 CA 路径一律拒绝。
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

运行密钥和环境文件只记录带域隔离的 HMAC 绑定，不记录普通 SHA-256，避免对低熵秘密做离线枚举。Caddy CA 在内存中打包后，立即使用离线接收者证书执行 AES-256 CMS 加密；CA 明文归档不会写入服务器文件系统。接收者私钥必须始终留在离线介质/离线机器，服务器不得持有。生产端只接受 CA 根目录中的 `root.crt`、`root.key`、`intermediate.crt`、`intermediate.key` 四个普通文件，不接受任何额外或嵌套条目；私钥必须为 root 所有、单硬链接且权限只能是 `0400` 或 `0600`。每个文件都通过 `O_NOFOLLOW` 打开并在读取前后复核文件描述符与路径身份，目录命名空间发生漂移时立即失败关闭。

生产端必须先通过受保护、单硬链接且不可替换的文件描述符读取并验证**恰好一张**接收者证书，再读取任何 CA 文件或创建 CMS 临时文件/目标文件。证书必须当前有效、不得尚未生效，必须使用 RSA 且不少于 3072 位，并以 critical `Key Usage` 明确允许 `Key Encipherment`；弱 RSA、非 RSA、证书链、过期/尚未生效或用途不符均须在接触 CA 私钥前 fail-closed。OpenSSL 的校验与加密必须复用同一受保护描述符，证书摘要必须来自同一份已验证字节，防止路径替换和摘要/收件者不一致。

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
  --output-plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json
```

`--compose-file` 和 `--legacy-env-file` 均按实际旧发布文件重复传入；每个由容器 `com.docker.compose.project.config_files` 标签引用的 Compose 绝对路径必须恰好出现一次，不能遗漏、重复或用合并后的临时文件代替。停止状态的一次性容器只允许已知的 `api-preflight`、`clamav-db-preflight`、`migrate` 与 `bootstrap`，不会在恢复时重新运行。运行环境只接受受控键集合：`REQUIRED_RUNTIME_KEYS` 必须存在且非空，其他已知可选键允许为空并仍以原始文件字节参与 HMAC 绑定；未知键和重复键一律拒绝，文件内容不会被 source 或当作命令执行。

计划 schema v4 不再接受操作员输入目标清单路径或 Git SHA。工具固定读取 `/etc/heyi-release/trusted-release-public.pem` 与 `/srv/heyi-knowledgebases-offline/state/highest-release.json`，从最高发布的 `release_id` 唯一派生 `/srv/heyi-knowledgebases-offline/artifacts/<release-id>/offline-registry-bundle/release.env.images`，再从清单 SHA-256 唯一派生 `/srv/heyi-knowledgebases-offline/state/registry-import-<manifest-sha256>.json`。Git SHA 只能来自已验证的 Registry 回执；公钥、最高发布、回执和清单的精确 descriptor 共同形成 `release_authorization_sha256`。`prepare`、`finalize`、`retire` 和 `reactivate` 每次都会重新读取这些固定路径，任一替换、最高发布推进或内容漂移都 fail-closed。保存命令输出的 `plan_sha256` 与 `release_authorization_sha256`，再由操作员和复核员核对容器、镜像、挂载、网络、端口和目标发布授权。

schema v4 仍只记录同一发布内固定的 `scripts/host_isolation_guard.py` 相对路径及其 SHA-256；执行时必须从当前已物化发布根重新解析并校验该文件，因此构建包路径与服务器发布路径可以不同，但不得用计划内绝对路径、`..` 或其他相对路径覆盖控制脚本。schema v3 及更早计划会 fail-closed，升级后必须重新执行 `plan` 并重新完成双人复核。

### 2. 准备备份

第一次不带 `--execute` 运行并审阅 dry-run。第二次由双人共同输入计划摘要并执行：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py prepare \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --run-id <UTC时间-变更单号> \
  --ca-root /srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local \
  --ca-recipient-certificate /etc/heyi-adoption/offline-recipient.pem \
  --ca-attestation-public-key /etc/heyi-adoption/ca-restore-attestation.pub \
  --evidence-signing-key /run/heyi-adoption-signing/evidence-signing.key \
  --evidence-public-key /etc/heyi-adoption/trusted-evidence-public.pem
```

正式执行时追加三个执行确认参数。`--ca-root` 必须与旧 Caddy `/data` bind 推导出的上述主机路径完全一致；不能用另一个仍位于数据根内的目录代替。工具先停止边缘/写入服务，保留 PostgreSQL 与 MinIO 仅用于逻辑读取，生成：

- PostgreSQL custom dump、无角色密码的 globals、schema-only dump、逐表精确行数；
- MinIO 全对象镜像和流式 NDJSON `key/size/SHA-256` 清单；
- 只存在密文的 Caddy CA CMS 归档；
- 已签名的离线 CA 恢复挑战。

无论备份成功与否，工具都会先恢复并验证旧栈原运行集合。若恢复失败，阶段失败且禁止继续。

### 3. 离线 CA 恢复与隔离全量恢复

将 CMS 密文和已签名 challenge v2 通过批准的离线介质带到隔离机器。不得使用 COS、SFTP、邮件、聊天、临时 HTTP 或任何网络文件传输。`binding.key` 必须通过**单独批准的离线介质**交付，禁止通过网络传输；接收者私钥、离线 attestation 私钥和 `binding.key` 始终留在隔离机/离线密钥介质。

执行前必须物理断开以太网、Wi-Fi、蓝牙、VPN 和其他网络接口，并从独立 CMDB/信任库取得 challenge 签名公钥的 PEM 文件 SHA-256。把 challenge、公钥和签名放在同一介质上，不能替代该独立指纹固定。若使用预先批准的容器，`--network none` 只能作为附加控制，不能替代宿主机物理断网。

隔离机上的输入目录、密钥介质挂载点和输出目录必须由 root 拥有且不可被 group/other 写入；输出目录固定为 `0700`。宿主机必须禁用 swap，或仅使用已通过企业审批且密钥不落在同一介质上的全盘加密 swap；不得依赖 Python 引用释放代替物理内存保护。工具在读取任何敏感文件前把 `RLIMIT_CORE` 的软、硬限制都降为零，并通过 Linux `prctl(PR_SET_DUMPABLE, 0)` 关闭且回读进程 dumpability，任一步无法确认即 fail-closed。

下面的仓库内工具仅支持固定的 root-owned OpenSSL 3.x，先验签 challenge，核对 challenge v2 绑定的离线 attestation 公钥，验证 CMS/接收者证书摘要与大小。接收者证书必须处于有效期内、包含 `Key Encipherment`，并使用不少于 3072 位的 RSA 密钥；CMS 必须只有一个 RSA recipient，密钥传输固定为 RSA-OAEP（OAEP SHA-256、MGF1 SHA-256），内容加密固定为 AES-256-CBC。工具在解密前解析并验证上述 CMS 契约，以接收者私钥在内存中解密，对**原始 tar bytes** 复算 `HMAC-SHA256(decoded_binding_key, b"heyi-caddy-ca-v1\0" + plaintext)`，只接受固定四个 Caddy CA 文件。恢复的 root/intermediate 私钥只允许 RSA ≥ 3072 位或 NIST P-256/P-384/P-521，证书签名不得使用 SHA-1/MD5；随后通过 sealed memfd 真实证明 root 可签发临时 subordinate、intermediate 可签发和验证临时服务器证书。同一真实 OpenSSL 链路还必须证明错误主机名和缺失 intermediate 两个负向控制均验证失败。CA 明文不会写入文件系统：

```bash
sudo /usr/bin/python3 -I /opt/heyi-approved-release/scripts/offline_ca_restore_drill.py \
  --challenge /mnt/challenge/ca-restore-challenge.json \
  --challenge-signature /mnt/challenge/ca-restore-challenge.sig \
  --challenge-public-key /mnt/challenge/upgrade-evidence.pub \
  --expected-challenge-public-key-sha256 <独立CMDB渠道取得的64位小写SHA-256> \
  --cms-archive /mnt/escrow/caddy-ca.cms.p7m \
  --recipient-certificate /mnt/recipient/offline-recipient.pem \
  --recipient-private-key /mnt/recipient/offline-recipient.key \
  --binding-key /mnt/binding-media/binding.key \
  --attestation-signing-key /mnt/attestation-key/ca-restore-attestation.key \
  --attestation-public-key /mnt/attestation-key/ca-restore-attestation.pub \
  --output-attestation /mnt/offline-output/ca-restore-attestation.json \
  --output-signature /mnt/offline-output/ca-restore-attestation.sig
```

工具固定使用 root-owned、不可被 group/other 写入的 `/usr/bin/openssl`，拒绝符号链接、不安全权限、超限输入、重复/额外 JSON 键、过期 challenge、非规范 tar、未绑定签名公钥和任何已有输出文件。默认执行不修改任何输入，只在同一 root-only `0700` 目录中以 `0400` 权限创建一次两个新输出。发布阶段先以 `O_EXCL` 创建目录级锁，再使用同文件系统 hard-link 的 no-replace 语义分别发布签名和 attestation；任一目标已存在或另一个发布者持有锁时立即失败，绝不覆盖。捕获到的 `SIGINT`/`KeyboardInterrupt` 会按已记录的设备号与 inode 回滚本次正式路径和临时文件，先在锁仍存在时 `fsync` 回滚结果，再删除锁并二次 `fsync`，随后原样抛出中断。若断电或 `SIGKILL` 留下 `.offline-ca-restore-drill.lock`，必须先确认没有演练进程、没有已发布的单边输出并完成双人复核，才可删除该锁；工具不会自动接管不明锁。工具随后自验 RSA-SHA256 签名。成功输出的严格 JSON 与 `finalize` 完全兼容：

```json
{
  "schema_version": 1,
  "kind": "heyi-caddy-ca-restore-drill",
  "project": "heyi-kb-offline",
  "challenge_sha256": "<挑战文件SHA-256>",
  "encrypted_archive_sha256": "<挑战内密文摘要>",
  "plaintext_opaque_hmac_sha256": "<挑战内HMAC>",
  "file_count": 4,
  "recipient_certificate_sha256": "<挑战内证书摘要>",
  "status": "passed",
  "tested_at": "<RFC3339 UTC>",
  "private_key_location": "offline-only",
  "server_private_key_present": false,
  "cos_used": false
}
```

CA 明文、接收者私钥、attestation 私钥和 `binding.key` 释放进程内引用并卸载离线介质后，才允许恢复隔离机网络。Python 引用释放不等于可证明的物理内存擦除，因此 swap 禁用/加密、core dump 禁用、dumpability 关闭和隔离机退役/重启策略都必须按企业密钥介质制度执行。只把 attestation、签名和已在 prepare/challenge v2 中固定摘要的 attestation 公钥通过批准介质放回 root-only 验收目录。先 dry-run，再追加三个执行确认参数运行 `finalize`：

```bash
sudo /usr/bin/python3 -I scripts/legacy_offline_adoption.py finalize \
  --plan /srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json \
  --binding-key /etc/heyi-adoption/binding.key \
  --prepared-state /srv/heyi-knowledgebases-offline/backups/<run-id>/evidence/prepared-state.json \
  --ca-restore-attestation /etc/heyi-adoption/ca-restore-attestation.json \
  --ca-restore-attestation-signature /etc/heyi-adoption/ca-restore-attestation.sig \
  --ca-restore-attestation-public-key /etc/heyi-adoption/ca-restore-attestation.pub \
  --evidence-signing-key /run/heyi-adoption-signing/evidence-signing.key \
  --evidence-public-key /etc/heyi-adoption/trusted-evidence-public.pem
```

恢复演练只创建带固定 ownership/purpose 标签的内部 Docker 网络、临时 PostgreSQL 与 MinIO，不发布任何端口。它验证 schema head、每张表行数、每个对象大小和 SHA-256；完成后只删除本次 challenge 精确匹配的临时容器、网络和 scratch 目录。成功后生成兼容 `deploy/tencent/verify-upgrade-backup.py` 的 schema v3 签名证据，顶层以不可省略的 `operation_scope=legacy_adoption` 同时绑定迁移用途、`release_authorization_sha256` 与目标 manifest。调用方也必须固定传入 `--expected-operation-scope legacy_adoption`，证据不能把自己冒充为常规升级证据。新的 predictive/execute 接管必须在 24 小时新鲜度窗口内开始；只有同一旧栈退休意图、最终退役收据或接管事务日志已经持久化后，durable resume 才可忽略相对当前墙钟的过期，并仍使用原 contract 中的统一校验器复验签名、制品哈希、结构时序和固定发布授权。

### 4. `adopt-offline.sh` 预测性目标预检

只有签名证据仍在 24 小时有效期内，且 CA、数据库、MinIO 隔离恢复全部通过，才可运行预测性接管门禁。下面命令**不带 `--execute`**，只创建并验证目标 canonical contract，验签发布/Registry/备份证据，验证环境、镜像、Compose、主机隔离基线，运行旧栈 `retire` dry-run，并证明预期退役收据路径和旧状态收据可安全归档。它不会停止旧栈、启动目标栈或改变端口：

```bash
export TARGET_BUNDLE=/srv/heyi-knowledgebases-offline/artifacts/<release-id>/offline-registry-bundle
export TARGET_ENTRY=$TARGET_BUNDLE/release
export RUNTIME_ENV=/srv/heyi-knowledgebases-offline/shared/runtime.env
export TARGET_RELEASE_ENV=$TARGET_BUNDLE/release.env
export LEGACY_PLAN=/srv/heyi-knowledgebases-offline/state/legacy-adoption/plan.json
export BACKUP_RUN=/srv/heyi-knowledgebases-offline/backups/<run-id>

sudo sh "$TARGET_ENTRY/deploy/tencent/adopt-offline.sh" \
  --runtime-env "$RUNTIME_ENV" \
  --release-env "$TARGET_RELEASE_ENV" \
  --legacy-plan "$LEGACY_PLAN" \
  --legacy-binding-key /etc/heyi-adoption/binding.key \
  --backup-evidence "$BACKUP_RUN/evidence/upgrade-backup-evidence.json" \
  --backup-signature "$BACKUP_RUN/evidence/upgrade-backup-evidence.sig" \
  --retirement-receipt "$BACKUP_RUN/evidence/retirement/receipt.json" \
  --retirement-signature "$BACKUP_RUN/evidence/retirement/receipt.sig" \
  --host-isolation-baseline /srv/heyi-kb-evidence/host-isolation-before.json \
  --host-isolation-hmac-key /srv/heyi-kb-evidence/host-isolation.hmac \
  --confirm-project heyi-kb-offline \
  --confirm-plan-sha256 "<plan-sha256>" \
  --confirm-preserve-data PRESERVE_BIND_DATA_AND_NAMED_VOLUMES
```

`TARGET_BUNDLE` 是已验签运输 bundle，不是 materialized release。外部入口以 bundle 根的 `release.env` 和服务器 `runtime.env` 创建完整 canonical contract，并只把其中 `release/*` 控制面物化到 `/srv/heyi-knowledgebases-offline/releases/<contract-sha256>`；物化目录不含环境文件、Registry 或 SBOM。40 位 Git SHA 仅用于溯源，不能替代 64 位 contract SHA-256 或充当目录名。

预测成功的固定输出是 `adoption: predictive-only PASS; legacy project unchanged; execute=false`。它只说明本次输入与目标机当前状态满足切换前置条件，不是上线批准，也不延长用于发起新切换的 24 小时备份证据有效期。durable resume 例外只适用于已持久化的同一退役/接管事务，不能用来启动新事务或绕过固定发布授权。当前发布的 Schema head 为 `20260715_0021`；`offline_contract_files` 当前共有 42 个固定条目，其中 3 个是环境/镜像清单，39 个是 `release/` 发布控制面资产。数量或清单发生变化时必须重新构建、签名并导入整个发布包，不能手工补文件。

双人复核 predictive-only 输出、计划摘要和变更单后，使用**完全相同的参数**重新运行上面的命令，并在末尾追加 `--execute`。闭合事务在同一个 root-only 项目锁中按固定顺序执行：预测预检 → 准备隔离安装合同 → 精确退役 → 退役收据验签 → 主机零漂移复核 → 准备旧收据清单 → 写入 HMAC 绑定的接管事务日志 → 旧收据带 SHA-256 原子归档 → 目标安装 → 最终主机复核 → 签名完成收据。HMAC 日志必须在归档开始前完成持久化，使断电续跑能够先验证同一计划、合同、退役收据和预期归档清单，再继续或失败关闭；任何人都不得跳过入口而单独调用退役、安装或迁移命令。

目标安装会在执行迁移命令前先持久化 `migration_invoked`，该状态是不可逆边界。若目标安装在此之前失败，闭合入口会调用受签名发布约束的 `offline-pre-migration-abort.py`：先 dry-run，再只停止并删除与合同及事务精确绑定的 `api-preflight`、`clamav-db-preflight`、`llm-egress-preflight` 容器，删除精确 owner marker，恢复 reconcile service/timer 的“从未安装”基线，归档未提交的安装状态与切换意图，并再次证明目标容器、网络、项目卷、owner marker 均为零。它不删除 bind 数据、命名数据卷，不执行全局 Docker 操作，并生成状态为 `aborted_pre_migration`、边界为 `PRE_MIGRATION_ONLY` 的签名收据。

`adopt-offline.sh` 必须独立复验中止收据签名、事务日志摘要、计划/退役/合同身份、目标资源为零、reconcile 基线及主机零漂移，全部通过后才恢复已归档的旧收据并调用旧栈恢复。没有签名中止收据时，即使目标安装尚未创建容器，也不得恢复旧栈；入口必须失败关闭。若 `migration_invoked` 已持久化、目标安装已提交、清理不完整、收据或签名无效、身份不一致，或者是否执行过迁移无法证明，入口必须保持旧 API 关闭，进入维护入口并输出 `POST_MIGRATION_FORWARD_FIX_ONLY`；此后只能前向修复，禁止恢复旧 API 或执行 Alembic downgrade。

### 5. `reactivate PRE_MIGRATION_ONLY` 恢复契约

`reactivate` 不是数据库降级工具。它只接受签名退役收据、同一接管事务下的签名目标中止收据、未变化的发布状态绑定、通过 HMAC 的主机隔离基线、空闲的 `19443/19444`、精确保留的数据根/卷，以及与退役前一致的 PostgreSQL 17 Schema。下面的不带 `--execute` 命令仅用于复核恢复条件；只有闭合入口先验签目标 `PRE_MIGRATION_ONLY` 中止收据并再次证明目标资源与主机隔离基线一致，才可追加执行确认：

```bash
sudo /usr/bin/python3 -I "/srv/heyi-knowledgebases-offline/releases/<contract-sha256>/scripts/legacy_offline_adoption.py" reactivate \
  --plan "$LEGACY_PLAN" \
  --binding-key /etc/heyi-adoption/binding.key \
  --retirement-receipt "$BACKUP_RUN/evidence/retirement/receipt.json" \
  --retirement-signature "$BACKUP_RUN/evidence/retirement/receipt.sig" \
  --target-abort-receipt "/srv/heyi-knowledgebases-offline/state/legacy-adoption/transactions/<32位事务ID>/target-pre-migration-abort/receipt.json" \
  --target-abort-signature "/srv/heyi-knowledgebases-offline/state/legacy-adoption/transactions/<32位事务ID>/target-pre-migration-abort/receipt.sig" \
  --adoption-transaction "<32位事务ID>" \
  --evidence-public-key /etc/heyi-adoption/trusted-evidence-public.pem \
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
python -m ruff check scripts/legacy_offline_adoption.py scripts/offline_ca_restore_drill.py tests/test_legacy_offline_adoption.py tests/test_offline_ca_restore_drill.py
python -m mypy --strict scripts/legacy_offline_adoption.py scripts/offline_ca_restore_drill.py
python -m pytest tests/test_offline_ca_restore_drill.py tests/test_legacy_offline_adoption.py tests/test_offline_adoption_transaction.py tests/test_offline_pre_migration_abort.py tests/test_legacy_adoption_document_contract.py -q
python -m bandit -q -r scripts/legacy_offline_adoption.py scripts/offline_ca_restore_drill.py deploy/tencent/offline-pre-migration-abort.py
```

Windows 测试只验证纯逻辑和安全契约；Docker 生命周期、root 权限、目录 fsync、OpenSSL CMS、PostgreSQL/MinIO 全量恢复必须在与目标一致的 Linux 8 核/16 GiB/300 GiB SSD 预生产主机上执行。没有目标机签名证据时，结论必须保持 **NO-GO**。
