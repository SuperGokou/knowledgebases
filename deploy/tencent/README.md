# 腾讯云隔离部署运行手册

本目录提供两套互不覆盖的编排：

- `compose.yml`：现有共享主机部署，数据层使用受管服务；
- `compose.offline.yml`：8 核 16G、300 GB SSD 的单机离线模拟环境，PostgreSQL、Redis 与 MinIO 全部部署在本机，运行时禁止公网模型调用。

离线企业方案必须先阅读[腾讯云 8 核 16G 离线企业部署](../../docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md)。它使用独立项目名 `heyi-kb-offline`、独立端口 `19443/19444` 和独立数据目录，不会修改当前 `heyi-kb-prod` 或其他应用。终端信任、根证书分发、严格验收和轮换操作见[内网 TLS 与 Caddy 内部 CA 运维手册](../../docs/TLS_INTERNAL_CA_OPERATIONS.zh-CN.md)。

> [!IMPORTANT]
> 离线编排为 Web、API 和维护任务预留至少 120 秒优雅停机时间，为受控 LLM 出口预留 135 秒。该顺序覆盖单次 45 秒模型调用及 95/105 秒端到端清算预算，避免正常升级或重启过早发送 `SIGKILL`，从而留下无法判定的模型用量。运维时不得使用 `docker kill` 或缩短这些预算。

本目录用于将知识库部署到共享的腾讯云主机。生产编排只运行 Web、API、维护任务和反向代理；数据库、Redis 与对象存储继续使用受管服务。

同一台服务器继续部署其他应用前，必须先阅读并填写[腾讯云共享服务器应用部署基线](../../docs/TENCENT_SHARED_HOST_DEPLOYMENT_BASELINE.zh-CN.md)中的资源登记、预检与回滚清单。本应用已经占用 Compose 项目名 `heyi-kb-prod`、目录 `/srv/heyi-knowledgebases` 和 `18443/tcp`，其他应用不得复用。

## 隔离边界

- 固定使用独立 Compose 项目名 `heyi-kb-prod`。
- 仅公开高位 HTTPS 端口 `18443`，不占用宿主机 `80/443`。
- 网络、数据卷、镜像和日志均由 Compose 项目作用域隔离。
- 不修改 Docker 守护进程、系统代理或其他 Compose 项目。
- 环境变量文件位于发布目录之外，权限必须为 `0600`，且不得提交到 Git。

## 目录约定

```text
/srv/heyi-knowledgebases/
├── releases/<git-sha>/
│   └── deploy.env
└── shared/
    ├── api.env
    └── web.env
```

`deploy.env` 随发布版本保存固定的 Git SHA 镜像引用和共享密钥文件路径。回滚时必须使用目标发布目录自己的 `deploy.env`，不得使用其他版本的镜像引用。

## 常用操作

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

## 内网 TLS 说明

离线编排已经在 `19443/19444` 启用 Caddy 内部 CA 签发的 TLS；浏览器提示“不安全”可能来自根 CA 未受信任、SAN 不匹配、证书过期、终端时钟错误或访问了错误入口，不代表服务端仍在使用 HTTP。应先按运维手册诊断链路和 SAN，再决定是否安装根证书。内网部署可以继续使用独立高位端口和企业内部 CA，无须占用同机其他应用的 `80/443`。

只允许通过受控渠道分发 `root.crt`。不得分发 `root.key`、`intermediate.key`、整个 `caddy-data` 目录或任何包含私钥的归档；导入前必须通过两个独立渠道核对 PEM 文件 SHA-256 与 X.509 证书 SHA-256 指纹。浏览器、`curl`、OpenSSL 和自动化验收均不得使用 `--insecure`、`-k`、`verify=False`、`ignoreHTTPSErrors` 或关闭主机名校验。

若企业基线要求 CRL/OCSP、集中吊销或正式内网域名，应由企业 PKI 签发包含实际 DNS/IP SAN 的服务器证书，并按变更窗口迁移。Caddy 内部 CA 不提供完整的企业吊销服务，不能以忽略证书错误作为替代方案。
