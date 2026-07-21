# 腾讯云隔离部署运行手册

本目录提供两套互不覆盖的编排：

- `compose.yml`：现有共享主机部署，数据层使用受管服务；
- `compose.offline.yml`：8 核 16G、300 GB SSD 的单机离线模拟环境，PostgreSQL、Redis 与 MinIO 全部部署在本机，运行时禁止公网模型调用。
- `compose.llm-egress.yml`：可选受控模型出口 override；数据层仍在本机，API 与维护任务只能通过专用代理访问已批准的外部模型。

离线企业方案必须先阅读[腾讯云 8 核 16G 离线企业部署](../../docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md)。它使用独立项目名 `heyi-kb-offline`、独立端口 `19443/19444` 和独立数据目录，不会修改当前 `heyi-kb-prod` 或其他应用。

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

## 受控外部模型出口（可选）

`compose.llm-egress.yml` 不会改变 PostgreSQL、Redis、MinIO、ClamAV、Web 或反向代理的网络边界。`backend`、`frontend` 和新增的 `llm-client` 均为 `internal: true`。`api` 与 `maintenance` 只加入 `llm-client`，并通过 `KB_LLM_HTTPS_PROXY=http://llm-egress-proxy:8080` 显式使用模型代理。只有 `llm-egress-proxy` 同时连接 `llm-client` 和非 internal 的 `llm-egress`；API 与维护容器本身没有公网默认路由。

> 启用后不再属于“完全离线”运行。代理必须只允许官方主机的 HTTPS `CONNECT`，并拒绝私网、本机、云 metadata、IP 字面量、非 443 端口和未授权域名。还应由企业出口网关或针对 `br-kb-llme` 的主机策略提供第二层限制。该 override 不修改宿主机防火墙，以免影响同机其他应用。

已批准的默认主机为：

- `api.deepseek.com:443`；
- `dashscope.aliyuncs.com:443`；
- `dashscope-us.aliyuncs.com:443`；
- `dashscope-intl.aliyuncs.com:443`；
- `api.minimax.io:443`。

Qwen 专属工作空间域名必须单独评审，不得使用通配符。`KB_QWEN_ALLOWED_WORKSPACE_HOSTS` 使用 JSON 字符串数组；同一配置会同时注入应用层和出口代理，避免应用放行而代理误拒绝。

### 1. 只创建最小凭据文件

不得把工作区 `.env` 或整份部署环境上传到服务器。仅参照 `llm-egress.env.example` 在服务器上创建：

```text
/srv/heyi-knowledgebases-offline/shared/llm-egress.env
```

文件只应包含模型出口所需的供应商、模型与凭据配置：

```dotenv
KB_LLM_DEFAULT_PROVIDER=qwen
KB_DEEPSEEK_API_KEY=<secret>
KB_DEEPSEEK_BASE_URL=https://api.deepseek.com
KB_DEEPSEEK_MODEL=deepseek-v4-flash
KB_QWEN_API_KEY=<secret>
KB_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
KB_QWEN_MODEL=qwen-plus
KB_QWEN_ALLOWED_WORKSPACE_HOSTS=[]
KB_MINIMAX_API_KEY=
KB_MINIMAX_BASE_URL=https://api.minimax.io/v1
KB_MINIMAX_MODEL=MiniMax-M2.7
```

由于生成答案必须经过不同供应商的独立审核，至少两个供应商 Key 必须非空；管理后台还必须为生成模型和至少一个独立审核模型配置有效价格，并设置能够匹配二者的 Token/成本预算。仅有 API Key 不代表审核链路已就绪。凭据文件必须为 root 所有，且权限为 `0600` 或 `0400`：

```bash
sudo chown root:root /srv/heyi-knowledgebases-offline/shared/llm-egress.env
sudo chmod 0600 /srv/heyi-knowledgebases-offline/shared/llm-egress.env
```

### 2. 执行两层预检

先执行原离线基线预检，再校验最小凭据合同、独立网段和合成后的 Compose 边界：

```bash
sudo sh deploy/tencent/preflight-offline.sh \
  /srv/heyi-knowledgebases-offline/shared/offline.env

sudo sh deploy/tencent/preflight-llm-egress.sh \
  /srv/heyi-knowledgebases-offline/shared/offline.env \
  /srv/heyi-knowledgebases-offline/shared/llm-egress.env
```

预检不会打印 API Key，也不会将合成后含凭据的 Compose 文档写入磁盘。

### 3. 只重建 API 与维护任务

基础离线栈必须先处于健康状态。启用出口时使用两份 `--env-file` 和两层 `--file`，并以 `--no-deps` 限定变更范围：

```bash
sudo docker compose \
  --project-name heyi-kb-offline \
  --env-file /srv/heyi-knowledgebases-offline/shared/offline.env \
  --env-file /srv/heyi-knowledgebases-offline/shared/llm-egress.env \
  --file deploy/tencent/compose.offline.yml \
  --file deploy/tencent/compose.llm-egress.yml \
  up -d --pull never --no-build --no-deps llm-egress-proxy api maintenance
```

这一操作不会重建 PostgreSQL、Redis、MinIO、ClamAV、Web 或入口 Proxy。启用后应验证 API 和维护任务仅加入 `llm-client`，`llm-egress-proxy` 独占 `llm-egress`，且模型 API Key 没有进入代理容器。

### 4. 回滚

回滚时不执行 `down`，也不删除数据卷。只用原离线编排重建两个运行容器：

```bash
sudo docker compose \
  --project-name heyi-kb-offline \
  --env-file /srv/heyi-knowledgebases-offline/shared/offline.env \
  --file deploy/tencent/compose.offline.yml \
  up -d --pull never --no-build --no-deps --force-recreate api maintenance
```

确认 API 与维护容器已恢复离线配置后，仅删除专用模型代理容器：

```bash
sudo docker compose \
  --project-name heyi-kb-offline \
  --env-file /srv/heyi-knowledgebases-offline/shared/offline.env \
  --env-file /srv/heyi-knowledgebases-offline/shared/llm-egress.env \
  --file deploy/tencent/compose.offline.yml \
  --file deploy/tencent/compose.llm-egress.yml \
  rm --stop --force llm-egress-proxy
```

回滚后的回答应显示 `source_status.reason=deployment_external_llm_disabled`，而不应伪装成模型回答。

## HTTPS 说明

首次灰度使用 Caddy 内部 CA，为服务器 IP 提供加密访问，浏览器会显示证书未受公共机构信任。正式上线时应绑定企业域名，将本项目接入独立域名和公共 HTTPS 证书，再按变更窗口切换到 `443`。
