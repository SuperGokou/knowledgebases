# 国内云 Linux 隔离部署运行手册

本目录提供两套互不覆盖的编排：

- `compose.yml`：现有共享主机部署，数据层使用受管服务；
- `compose.offline.yml`：8 核 16G、300 GB SSD 的单机隔离环境，PostgreSQL、Redis 与 MinIO 全部部署在本机。默认 `KB_LLM_EGRESS_MODE=strict_offline`，不创建公网模型出口；只有完成数据出境、供应商、固定目的地、费用/配额和 L3/L4 出口审批后，才允许切换为 `controlled_gateway`。

离线企业方案必须先阅读[通用 Linux 8 核 16G 离线企业部署](../../docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md)。它使用独立项目名 `heyi-kb-offline`、独立端口 `19443/19444` 和独立数据目录，不会修改当前 `heyi-kb-prod` 或其他应用。固定发布公钥、Registry 回执、最高发布序列、纳管 plan 与备份授权的交叉绑定见[离线发布信任链](../../docs/OFFLINE_RELEASE_TRUST_CHAIN.zh-CN.md)；终端信任、根证书分发、严格验收和轮换操作见[内网 TLS 与 Caddy 内部 CA 运维手册](../../docs/TLS_INTERNAL_CA_OPERATIONS.zh-CN.md)。

> [!IMPORTANT]
> 目标发布的安装清理、升级和维护切换对业务写入者使用 150 秒优雅停机预算；旧栈 `prepare`、`retire` 与恢复使用 140 秒。两者都覆盖单次 45 秒模型调用及 95/105 秒端到端清算链，避免正常变更过早发送 `SIGKILL`，从而留下无法判定的模型用量。运维时不得使用 `docker kill`、`docker rm -f` 或缩短预算。

> [!WARNING]
> 自动化门禁通过不等于环境获准上线。磁盘静态加密或风险例外、共享主机资源余量、PostgreSQL/MinIO/CA 恢复演练、VPN/安全组和签名终验证据任一缺失时，结论仍为 **FAIL / NO-GO**。

`compose.yml` 用于保留的共享主机/受管数据层部署；`compose.offline.yml` 则把 Web、API、维护任务、反向代理、PostgreSQL、Redis、MinIO 与 ClamAV 全部纳入本机隔离项目。两套入口、环境文件和数据边界不能混用。

同一台服务器继续部署其他应用前，必须先阅读并填写[共享服务器应用部署基线](../../docs/TENCENT_SHARED_HOST_DEPLOYMENT_BASELINE.zh-CN.md)中的资源登记、预检与回滚清单。本应用已经占用 Compose 项目名 `heyi-kb-prod`、目录 `/srv/heyi-knowledgebases` 和 `18443/tcp`，其他应用不得复用。

## `compose.yml` 共享主机边界

- 固定使用独立 Compose 项目名 `heyi-kb-prod`。
- 仅公开高位 HTTPS 端口 `18443`，不占用宿主机 `80/443`。
- 网络、数据卷、镜像和日志均由 Compose 项目作用域隔离。
- 不修改 Docker 守护进程、系统代理或其他 Compose 项目。
- 环境变量文件位于发布目录之外，权限必须为 `0600`，且不得提交到 Git。

## `compose.yml` 目录约定

```text
/srv/heyi-knowledgebases/
├── releases/<git-sha>/
│   └── deploy.env
└── shared/
    ├── api.env
    └── web.env
```

`deploy.env` 随发布版本保存固定的 Git SHA 镜像引用和共享密钥文件路径。回滚时必须使用目标发布目录自己的 `deploy.env`，不得使用其他版本的镜像引用。

## `compose.yml` 常用操作

所有命令必须显式指定项目名、环境文件和编排文件：

```bash
sudo docker compose \
  --project-name heyi-kb-prod \
  --env-file /srv/heyi-knowledgebases/releases/<git-sha>/deploy.env \
  --file /srv/heyi-knowledgebases/releases/<git-sha>/deploy/tencent/compose.yml \
  ps
```

查看本项目日志时同样使用上述前缀并追加 `logs --tail=200 api web proxy maintenance`。禁止执行全局 `docker system prune`，也不要对不属于 `heyi-kb-prod` 的容器、网络或卷执行停止、删除操作。

首次在空机部署时可顺序构建 API 与 Web 镜像。共享主机开始承载其他应用后，应由 CI 构建带 Git SHA 的不可变镜像，服务器只执行 `pull` 和项目限定的 `up -d`，避免现场构建抢占其他应用的 CPU 与内存。

## `compose.offline.yml` 安装与接管入口

- 空项目首次安装：`install-offline.sh <runtime.env> <release.env>`；
- 常规升级入口（当前 **NO-GO / fail-closed**）：`deploy-offline.sh <runtime.env> <release.env>` 已实现事务编排，但在签名 active collector 与 source/target 交叉绑定完成并重新验收前禁止执行；
- 已存在旧 `heyi-kb-offline`：先完成[旧版离线栈安全接管与恢复证明](../../docs/LEGACY_OFFLINE_ADOPTION.zh-CN.md)，再运行目标发布的 `adopt-offline.sh`；禁止手工删除旧资源后伪装成首次安装。

`adopt-offline.sh` 不带 `--execute` 时会在一个项目锁内执行预测性目标预检和旧栈退役 dry-run，成功输出 `predictive-only PASS`，且旧栈保持不变。经双人复核后，以完全相同参数追加 `--execute` 才会进入闭合接管事务；不能拆成裸 `retire` 与 `install-offline.sh`。目标安装在持久化 `migration_invoked` 前失败时，入口只允许签名的 `PRE_MIGRATION_ONLY` 中止器精确回收本事务预检资源、归档未提交状态并签发 `aborted_pre_migration` 收据；入口独立验签并复核资源清零、reconcile 基线及主机零漂移后，才运行 `reactivate --confirm-restore-boundary PRE_MIGRATION_ONLY`。迁移已调用、清理/签名不完整或状态不明时只允许 `POST_MIGRATION_FORWARD_FIX_ONLY`。

当前 canonical contract 固定包含 42 个条目，其中 3 个环境/镜像清单、39 个 `release/` 发布控制面资产；当前发布 Schema head 是 `20260715_0021`。完整签名 bundle 还必须包含 `registry/` 与 9 个镜像的 `sbom/`，`SHA256SUMS` 精确枚举 `release/`、`registry/`、`sbom/` 下全部普通文件。构建器必须从代码中的 `offline_contract_files` 动态读取发布清单，文件总数按最终 bundle 动态枚举，不得在运维脚本或手册中另写一份易漂移清单。导入和安装/接管入口必须从 bundle 自带的 `release/` 控制面运行；入口验证 self-describing contract 后，会按 64 位 contract SHA-256 物化不可变发布目录，禁止把 40 位 Git SHA 手工当作 canonical 目录名。

默认保持 `KB_LLM_EGRESS_MODE=strict_offline`。切换 `controlled_gateway` 前必须取得数据出境、固定模型目的地、供应商、凭据、费用/配额、日志脱敏和主机 L3/L4 出口审批；审批缺失时不得为恢复生成式回答而放宽网络。

## Chat Safety 持久哨兵恢复

离线 API 固定为单 Uvicorn worker，`KB_CHAT_MAX_ACTIVE_REQUESTS=8`；第 9 个并发聊天在读取请求体和取得数据库连接前立即返回 503。85/94/95 秒是同一次请求的绝对栅栏：前 85 秒覆盖收体与完整路由，85–94 秒只允许取消后的连接释放、供应商用量与幂等终态封闭，94–95 秒只允许发送已完整缓冲且验证通过的唯一响应。终态或真实发送无法在该边界内得到证明时，API 会进入 sticky fail-closed，并在主机写入 `/srv/heyi-knowledgebases-offline/data/chat-safety/poison.json`。

该哨兵跨 API、Docker 与主机重启保留。恢复器还会在任何 API 自动启动前检查唯一受控 API 容器；任意非零退出码都会物化持久 hold，`78` 记录为哨兵持久化失败，其他非零码记录为 worker 异常退出。哨兵、退出状态、容器归属或镜像身份无法证明时都只允许 `maintenance-page`，不得自动重启 `api`、`proxy`、`maintenance` 或模型出口。

操作员必须先确认恢复器已静默全部敏感写入者，完成聊天幂等账本、供应商 token/费用和审计记录对账，再把严格 schema 证据以 `root:root 0600` 保存到固定路径：

```text
/srv/heyi-knowledgebases-offline/state/chat-safety-reconciliation.json
```

证据顶层必须且只能包含 14 个键：原有的 schema、哨兵摘要、时间、操作员/变更单、三项对账布尔值和两项非敏感引用，再加 `state_selection`、`state_operation`、`contract_sha256`、`transaction_id`。后四项必须与恢复器当前选定的 `intent` 或 `active` 状态完全一致；`active` 只能配 `none`，`intent` 只能配 `install`、`deploy` 或 `maintenance`。

随后从当前选定的 64 位 contract SHA-256 不可变发布目录执行摘要绑定清除：

```bash
export SELECTED_CONTRACT_SHA256='<选定 intent 或 active 状态中的 64 位 contract_sha256>'
export SELECTED_RELEASE="/srv/heyi-knowledgebases-offline/releases/${SELECTED_CONTRACT_SHA256}"
export EXPECTED_SENTINEL_SHA256='<chat-safety-sentinel.py verify 输出>'

sudo sh "$SELECTED_RELEASE/deploy/tencent/clear-chat-safety-poison.sh" \
  --expected-sha256 "$EXPECTED_SENTINEL_SHA256" \
  --evidence /srv/heyi-knowledgebases-offline/state/chat-safety-reconciliation.json
```

清除脚本会先归档对账证据并写入 `authorized` 审计，再持久化 `/srv/heyi-knowledgebases-offline/state/chat-safety-clear-pending.json`。非零 API exit witness 经归属和固定镜像复核后归档为 root-only `worker-exit-<code>-<container-id>.json` 并消费；选择 `active` 时还会用选定发布的固定镜像创建一个不启动、ExitCode=0 且身份完全匹配的 clean API handoff。脚本随后清除精确哨兵、写入 `cleared`，最后删除 pending 作为提交点。pending 存在期间，恢复、预检、首次安装和升级入口都不得开放业务。若中途崩溃，只能用同一状态、摘要、contract、transaction 和字节完全相同的证据重新执行命令并幂等续提。首次证据必须在 24 小时窗口内；既有 pending 的续提按证据摘要绑定，不会因合法恢复跨过该窗口而永久锁死。

禁止用 `rm` 删除哨兵或 pending、直接 `docker start` 业务容器或手工更新幂等表。清除成功后触发 `heyi-kb-offline-reconcile.service`，再验证 pending/哨兵均不存在、维护页退出、`/health/ready` 返回 200、一次带新 `Idempotency-Key` 的受控聊天返回合法来源，并保存 `/srv/heyi-knowledgebases-offline/state/chat-safety-audit/clear-events.jsonl` 中可按 sentinel/evidence/contract/transaction/state 关联的 `authorized` / `cleared` 事件。完整证据 schema、停服核验和命令见[运维手册：持久 Chat Safety Poison 哨兵与人工恢复](../../docs/OPERATIONS.zh-CN.md#91-持久-chat-safety-poison-哨兵与人工恢复)。

灾备不能从“未恢复到哨兵文件”推断系统清洁。签名备份证据 schema v3 必须包含调用方绑定的 `operation_scope`：旧栈接管只接受 `legacy_adoption`；常规升级只接受 `active_upgrade`，并必须同时绑定 control-state archive 与 manifest。内部 active profile 已将 `state/installed-<source-contract-sha256>.json` 作为第十一项 mandatory-present 控制状态，并要求源端/恢复端 SHA-256 一致；但在完整签名采集器和 source/target 状态语义交叉绑定完成前，生产入口仍显式禁用 `active_upgrade`，不得使用手写 JSON 或 durable resume 绕过。新主机先物化 Chat Safety maintenance hold，只启动数据服务与维护页；缺记录、不一致或人工对账未完成时，API 与业务边缘保持停止。

## 内网 TLS 说明

离线编排已经在 `19443/19444` 启用 Caddy 内部 CA 签发的 TLS；浏览器提示“不安全”可能来自根 CA 未受信任、SAN 不匹配、证书过期、终端时钟错误或访问了错误入口，不代表服务端仍在使用 HTTP。应先按运维手册诊断链路和 SAN，再决定是否安装根证书。内网部署可以继续使用独立高位端口和企业内部 CA，无须占用同机其他应用的 `80/443`。

当 `KB_DATA_ROOT=/srv/heyi-knowledgebases-offline/data` 时，Compose 将 `${KB_DATA_ROOT}/caddy-data` 挂载到 Caddy `/data`，因此唯一正确的 CA 主机目录是 `/srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local`。旧栈接管必须从已验证的 `/data` bind 自动推导该目录，不能由操作员随意指定另一个数据根子目录。

只允许通过受控渠道分发 `root.crt`。不得分发 `root.key`、`intermediate.key`、整个 `caddy-data` 目录或任何包含私钥的归档；导入前必须通过两个独立渠道核对 PEM 文件 SHA-256 与 X.509 证书 SHA-256 指纹。浏览器、`curl`、OpenSSL 和自动化验收均不得使用 `--insecure`、`-k`、`verify=False`、`ignoreHTTPSErrors` 或关闭主机名校验。

若企业基线要求 CRL/OCSP、集中吊销或正式内网域名，应由企业 PKI 签发包含实际 DNS/IP SAN 的服务器证书，并按变更窗口迁移。Caddy 内部 CA 不提供完整的企业吊销服务，不能以忽略证书错误作为替代方案。
