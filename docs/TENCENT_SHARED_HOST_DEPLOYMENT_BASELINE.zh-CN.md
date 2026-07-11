# 腾讯云共享服务器应用部署基线

本文用于在同一台腾讯云服务器上继续部署其他应用。目标是让每个应用可独立发布、回滚和排障，不覆盖现有端口、容器、网络、数据卷、环境变量或反向代理配置。

> [!IMPORTANT]
> 本文只记录资源名称和操作规范，不保存服务器密码、云 API 密钥、数据库密码、JWT 密钥、证书私钥或真实连接串。敏感值必须存放在服务器权限为 `0600` 的独立文件或合规的密钥管理服务中。

## 1. 当前资源登记

| 应用 | Compose 项目名 | 服务器目录 | 对外端口 | 域名 | 状态与说明 |
| --- | --- | --- | ---: | --- | --- |
| 和熠企业知识库 | `heyi-kb-prod` | `/srv/heyi-knowledgebases` | `18443/tcp` | 待绑定企业域名 | 受限灰度 HTTPS；不得被其他应用占用 |
| 共享入口 | 待规划 | 待规划 | `80/tcp`、`443/tcp` | 按应用分配 | 为后续统一反向代理预留，不得由单个新应用直接覆盖 |

部署新应用时，必须先在此表新增一行，登记应用名、唯一 Compose 项目名、目录、端口和域名。端口必须以服务器实时检查结果为准，不能仅依赖本文。

## 2. 每个应用必须拥有的隔离边界

- 唯一应用标识：例如 `<app-slug>`；只允许小写字母、数字和连字符。
- 唯一 Compose 项目名：例如 `<app-slug>-prod`；所有命令都显式传入 `--project-name`。
- 独立目录：`/srv/<app-slug>/releases/<git-sha>` 与 `/srv/<app-slug>/shared`。
- 独立网络、数据卷、镜像标签和日志；不要在 Compose 中使用全局 `container_name`。
- 独立运行时账号、数据库角色、Redis 命名空间或实例、对象存储前缀和云访问密钥。
- 独立 CPU、内存、进程数和日志大小限制，必须为同机其他应用保留余量。
- 只由反向代理容器发布必要的宿主机端口；API、Worker 和数据库端口留在项目内部网络。

建议目录：

```text
/srv/<app-slug>/
├── releases/
│   └── <git-sha>/
│       └── deploy.env
├── shared/
│   ├── api.env
│   └── web.env
└── current -> releases/<git-sha>
```

`deploy.env` 保存该版本的不可变镜像标签和共享环境文件路径。`current` 只能在健康检查通过后切换。

## 3. 部署前检查：先证明不会影响现有应用

在任何构建、启动或防火墙变更之前执行：

```bash
sudo docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}'
sudo docker compose ls
sudo ss -lntup
free -h
df -h
sudo docker system df
```

同时检查：

1. 记录所有既有容器 ID、状态和端口，部署结束后逐项复核。
2. 确认候选高位端口未被 `ss`、Docker 或腾讯云防火墙规则占用。
3. 读取现有 Nginx/Caddy/Traefik 配置；只追加新域名路由，不能覆盖共享配置。
4. 检查磁盘、内存和镜像空间，预留系统与其他应用的故障恢复余量。
5. 验证目标数据库项目、迁移版本和表结构，避免连接到同名但错误的云项目。
6. 记录变更前防火墙规则；发现目标端口已有宽泛放行时停止部署并查明归属。

禁止操作：

- `docker system prune`；
- 未限定项目名的 `docker compose down`；
- `docker compose down -v`；
- 重启 Docker 守护进程或修改全局 Docker 代理；
- 停止、重命名或删除不属于当前应用的容器、网络、数据卷和镜像；
- 在没有备份及验证方案时修改共享反向代理或云防火墙规则。

## 4. 国内服务器的构建与镜像策略

中国大陆服务器访问 PyPI、npm、Docker Hub 或 GHCR 时可能出现超时。共享服务器承载多个应用后，不应在生产机现场编译完整镜像：

1. 在 CI 或隔离构建机执行 lint、测试、类型检查和镜像构建。
2. 镜像使用 Git SHA 或内容摘要，例如 `registry.example.com/<app>:<git-sha>`，禁止使用 `latest`。
3. 优先推送到服务器网络稳定可达的镜像仓库；无法稳定拉取时使用 `docker save`/`docker load` 传输已验证镜像。
4. 生产服务器只执行限定项目的 `pull`、迁移检查和 `up -d`。
5. 发布前固定依赖锁文件，避免部署当天解析到不同依赖版本。

## 5. 环境变量与密钥

- 本地 `.env` 只允许 `KEY=value`，不要写成 `IP: value` 或包含说明文字。
- 使用变量白名单生成生产环境文件，禁止把完整本地 `.env` 上传到服务器。
- 服务器环境文件由 `root` 持有并设置 `chmod 600`；临时上传文件写入完成后立即删除。
- Compose 读取包含 `$` 的密码时应使用支持的原始格式，例如 `env_file: { path: ..., format: raw }`，防止二次插值。
- 每个应用单独生成 JWT、会话、BFF、加密和 webhook 密钥；不得复制其他应用的值。
- 云平台管理凭据只能用于部署控制面，不得注入业务容器。
- 日志、错误页、CI 输出和健康检查不得打印密钥、完整连接串、令牌或用户敏感数据。

## 6. Supabase / PostgreSQL 注意事项

腾讯云轻量服务器可能只有 IPv4，而 Supabase 直接数据库主机可能仅返回 IPv6。持久 VM 应优先使用 Supavisor 的 IPv4 Session 模式 `5432`；Transaction 模式 `6543` 更适合短连接或 Serverless，采用前必须验证 ORM 与连接池行为。

数据库权限规则：

- 每个应用创建独立登录角色并继承最小权限业务角色；禁止复用或轮换共享 `postgres` 密码。
- 运行时角色不得拥有 `SUPERUSER`、`CREATEDB`、`CREATEROLE`、`REPLICATION` 或 `BYPASSRLS`。
- 限制连接数，并使应用连接池上限小于数据库角色限制。
- 迁移身份与运行时身份分离；先检查 migration heads，再执行受控升级。
- 数据库迁移必须向后兼容当前与上一版本；回滚应用时不要盲目回滚数据库。
- 上线前核对 Supabase 项目引用、目标 schema、关键表数量和迁移版本，防止使用陈旧连接串。

本知识库当前使用独立运行时角色 `knowledge_vm_prod`，继承最小权限角色 `knowledge_app`，连接上限为 30。新应用不得复用这两个角色。

## 7. Upstash Redis

- 服务端 Redis 客户端使用 TLS 连接 `rediss://`，不要把 REST URL 当作 Redis 协议地址。
- 每个应用使用独立实例，或至少使用明确的键前缀和独立凭据。
- 启动 Web 前，readiness 必须同时验证数据库与 Redis；仅进程存活不能视为可服务。
- 限流、队列和锁要设置 TTL，避免永久键造成配额失真或存储持续增长。

## 8. 腾讯 COS 与 CAM

- 每个应用创建无控制台登录能力的 API 专用 CAM 子用户，并最后创建访问密钥。
- 权限应限制到指定 Bucket 和应用前缀，只授予业务需要的 Put/Get/Head/Delete 与必要 Multipart 操作。
- 禁止授予 `cos:*`、Bucket 策略/ACL/配置管理、CAM、CVM 或 Lighthouse 权限。
- 浏览器直传需要从用户浏览器访问 COS，不能简单用服务器 IP 条件限制 CAM 策略。
- 修改 CORS 时先读取现有规则并追加新 Origin，不能覆盖其他应用的规则。
- 通过通用 S3 API 调用腾讯 COS `PutBucketCors` 时需要正确的 `Content-MD5`。
- 密钥只写入目标服务器一次，不保存在仓库、本地部署日志或聊天记录中。

上线至少验证：单 PUT、Head、Copy、Range Get、Multipart 发起与中止、Delete，以及错误权限路径确实被拒绝。

## 9. 端口、TLS 与防火墙

灰度阶段可使用未占用高位端口，但必须在腾讯云防火墙中限制到管理员固定 `/32` 地址，不能开放为 `0.0.0.0/0`。正式生产应使用企业域名、公共可信证书和共享入口的 `443` 路由。

Caddy 使用 IP 地址和内部 CA 灰度时需注意：浏览器或客户端可能不发送 SNI，可通过 `default_sni {$APP_PUBLIC_HOST}` 为当前 IP 站点配置默认 SNI。内部 CA 只提供加密，不代表浏览器信任，也不适合对公众提供正式登录服务。

服务器命令行若配置了 HTTP(S) 代理，`curl --resolve` 仍可能走代理并误判本机服务；本机验证使用：

```bash
curl --noproxy '*' --resolve '<domain>:443:127.0.0.1' https://<domain>/health
```

防火墙变更顺序：应用内部健康检查通过 → 反向代理验证通过 → 添加精确端口/来源规则 → 外部冒烟测试。绝不删除或改写归属不明的既有规则。

## 10. 容器安全与资源限制

每个服务至少配置：

- 明确的 CPU、内存和 PID 限制；
- `restart` 策略、健康检查和有界超时；
- JSON 日志轮转大小与文件数量；
- 非 root 用户、`read_only` 根文件系统和必要的 `tmpfs`；
- `security_opt: no-new-privileges:true`；
- `cap_drop: [ALL]`，按实际需要逐项加回能力。

官方 Caddy 镜像中的二进制带有绑定低位端口的文件能力。若直接 `cap_drop: [ALL]` 后出现 `operation not permitted`，只加回 `NET_BIND_SERVICE`，或使用移除文件能力的自定义镜像；不要为了方便改成特权容器。

## 11. 安全发布顺序

```text
配置与密钥校验
  → 获取不可变镜像
  → 检查迁移版本并执行兼容迁移
  → 启动 API/Worker
  → API readiness 通过
  → 启动 Web
  → Web readiness 通过
  → 加入反向代理
  → 精确放行防火墙
  → 外部冒烟测试
  → 切换 current
```

所有 Compose 命令使用固定前缀：

```bash
sudo docker compose \
  --project-name <compose-project> \
  --env-file /srv/<app-slug>/releases/<git-sha>/deploy.env \
  --file /srv/<app-slug>/releases/<git-sha>/deploy/tencent/compose.yml \
  <command>
```

发布过程中先使用 `config` 校验合并后的编排，再执行 `pull` 和 `up -d`。不要依赖当前工作目录或默认项目名。

## 12. 上线验收清单

- [ ] CI 的 lint、单元测试、类型检查、构建和 Compose 配置校验全部通过。
- [ ] 镜像标签为 Git SHA/摘要，没有使用 `latest`。
- [ ] 数据库项目、迁移版本、运行时最小权限和连接数已复核。
- [ ] Redis 使用 TLS 且 readiness 能发现 Redis 故障。
- [ ] `/live` 与 `/ready` 含义分离，失败时返回非 2xx。
- [ ] 登录、角色跳转、退出、Secure/HttpOnly/SameSite Cookie 正常。
- [ ] 安全响应头、CORS、CSRF 和上传大小限制符合预期。
- [ ] COS 的上传、下载、分片与拒绝路径验证通过。
- [ ] 所有本项目容器健康，CPU、内存、PID 和日志限制生效。
- [ ] 变更前记录的其他应用容器仍在运行，端口、网络与卷未变化。
- [ ] 防火墙只开放已登记端口和预期来源。
- [ ] 外部冒烟测试通过后才切换正式域名或流量。

## 13. 回滚原则

1. 每个发布目录保存自己的 `deploy.env` 和不可变镜像引用。
2. 修改共享环境文件前创建权限受控的备份。
3. 回滚使用目标旧版本目录的 Compose 文件与 `deploy.env`，不能混用新版本镜像标签。
4. 只对指定 Compose 项目执行操作，永远不使用 `down -v`。
5. 数据库迁移采用 expand/contract 等兼容策略；先回滚应用，再根据经过评审的方案处理数据结构。
6. 回滚后重新执行健康检查、登录、核心业务路径和其他应用存活验证。

## 14. 新应用登记模板

部署下一个应用前复制并填写：

```text
应用名称：
应用标识 <app-slug>：
Compose 项目名：
服务器目录：/srv/<app-slug>
镜像仓库与不可变标签：
内部服务与端口：
对外端口（经 ss、防火墙复核）：
生产域名：
数据库项目与独立运行时角色：
Redis 实例/键前缀：
COS Bucket/前缀与 CAM 子用户：
CPU/内存/PID 预算：
健康检查地址：
回滚版本与负责人：
变更窗口：
```

登记完成、预检无冲突、回滚路径验证后，才进入正式部署。
