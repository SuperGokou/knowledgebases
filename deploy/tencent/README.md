# 国内云 Linux 隔离部署运行手册

本目录提供两套互不覆盖的编排：

- `compose.yml`：现有共享主机部署，数据层使用受管服务；
- `compose.offline.yml`：8 核 16G、300 GB SSD 的单机隔离环境，PostgreSQL、Redis 与 MinIO 全部部署在本机。默认 `KB_LLM_EGRESS_MODE=strict_offline`，不创建公网模型出口；只有完成数据出境、供应商、固定目的地、费用/配额和 L3/L4 出口审批后，才允许切换为 `controlled_gateway`。

离线企业方案必须先阅读[通用 Linux 8 核 16G 离线企业部署](../../docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md)。它使用独立项目名 `heyi-kb-offline`、独立端口 `19443/19444` 和独立数据目录，不会修改当前 `heyi-kb-prod` 或其他应用。终端信任、根证书分发、严格验收和轮换操作见[内网 TLS 与 Caddy 内部 CA 运维手册](../../docs/TLS_INTERNAL_CA_OPERATIONS.zh-CN.md)。

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
- 已验收部署升级：`deploy-offline.sh <runtime.env> <release.env>`；
- 已存在旧 `heyi-kb-offline`：先完成[旧版离线栈安全接管与恢复证明](../../docs/LEGACY_OFFLINE_ADOPTION.zh-CN.md)，再运行目标发布的 `adopt-offline.sh`；禁止手工删除旧资源后伪装成首次安装。

`adopt-offline.sh` 不带 `--execute` 时会在一个项目锁内执行预测性目标预检和旧栈退役 dry-run，成功输出 `predictive-only PASS`，且旧栈保持不变。经双人复核后，以完全相同参数追加 `--execute` 才会进入闭合接管事务；不能拆成裸 `retire` 与 `install-offline.sh`。目标安装在持久化 `migration_invoked` 前失败时，入口只允许签名的 `PRE_MIGRATION_ONLY` 中止器精确回收本事务预检资源、归档未提交状态并签发 `aborted_pre_migration` 收据；入口独立验签并复核资源清零、reconcile 基线及主机零漂移后，才运行 `reactivate --confirm-restore-boundary PRE_MIGRATION_ONLY`。迁移已调用、清理/签名不完整或状态不明时只允许 `POST_MIGRATION_FORWARD_FIX_ONLY`。

当前 canonical contract 固定包含 39 个条目，其中 3 个环境/镜像清单、36 个 `release/` 发布控制面资产；当前发布 Schema head 是 `20260715_0021`。构建器必须从代码中的 `offline_contract_files` 动态读取清单，Registry 造成的 `SHA256SUMS` 总行数按最终 bundle 动态枚举，不得在运维脚本或手册中另写一份易漂移清单。

默认保持 `KB_LLM_EGRESS_MODE=strict_offline`。切换 `controlled_gateway` 前必须取得数据出境、固定模型目的地、供应商、凭据、费用/配额、日志脱敏和主机 L3/L4 出口审批；审批缺失时不得为恢复生成式回答而放宽网络。

## 内网 TLS 说明

离线编排已经在 `19443/19444` 启用 Caddy 内部 CA 签发的 TLS；浏览器提示“不安全”可能来自根 CA 未受信任、SAN 不匹配、证书过期、终端时钟错误或访问了错误入口，不代表服务端仍在使用 HTTP。应先按运维手册诊断链路和 SAN，再决定是否安装根证书。内网部署可以继续使用独立高位端口和企业内部 CA，无须占用同机其他应用的 `80/443`。

当 `KB_DATA_ROOT=/srv/heyi-knowledgebases-offline/data` 时，Compose 将 `${KB_DATA_ROOT}/caddy-data` 挂载到 Caddy `/data`，因此唯一正确的 CA 主机目录是 `/srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local`。旧栈接管必须从已验证的 `/data` bind 自动推导该目录，不能由操作员随意指定另一个数据根子目录。

只允许通过受控渠道分发 `root.crt`。不得分发 `root.key`、`intermediate.key`、整个 `caddy-data` 目录或任何包含私钥的归档；导入前必须通过两个独立渠道核对 PEM 文件 SHA-256 与 X.509 证书 SHA-256 指纹。浏览器、`curl`、OpenSSL 和自动化验收均不得使用 `--insecure`、`-k`、`verify=False`、`ignoreHTTPSErrors` 或关闭主机名校验。

若企业基线要求 CRL/OCSP、集中吊销或正式内网域名，应由企业 PKI 签发包含实际 DNS/IP SAN 的服务器证书，并按变更窗口迁移。Caddy 内部 CA 不提供完整的企业吊销服务，不能以忽略证书错误作为替代方案。
