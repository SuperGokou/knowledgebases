# Vercel 部署手册

生产部署使用同一仓库的两个 Vercel Project：仓库根目录运行 FastAPI 控制面，`web/` 运行 Next.js 登录与管理工作台。文件字节仍由浏览器使用预签名 URL 直传腾讯 COS；PostgreSQL、Redis 和对象存储都必须是外部托管服务。Vercel 不运行 `docker-compose.yml`、MinIO、常驻 maintenance worker 或构建阶段数据库迁移。

```text
knowledgebases-api / Root=.       -> FastAPI、Cron、数据库、Redis、COS
knowledgebases     / Root=web/    -> Next.js、HttpOnly BFF、登录与管理 UI
```

两个项目必须拥有不同 Origin。`FASTAPI_URL` 必须指向 API Project，不能指向 Web Project 自身。

## 美国部署拓扑

当前 Web 与 API 两个 Vercel Project 均将默认 Function 区域设置为美国华盛顿特区 `iad1`，仓库中的 `vercel.json` 与 `web/vercel.json` 也显式固定该区域，确保后续 Production 与 Preview 部署保持一致。静态 HTML、CSS、JavaScript 等资源仍由 Vercel 全球 CDN 就近分发。

```text
中国大陆用户
    -> Vercel Web / BFF (iad1, Washington D.C., USA)
    -> Vercel FastAPI (iad1, Washington D.C., USA)
       -> Supabase PostgreSQL (建议 us-east-1 或邻近区域)
       -> Upstash Redis primary (建议 us-east-1 或邻近区域)

浏览器
    -> 腾讯 COS 私有 Bucket（预签名直传，文件字节不经过 Vercel）
```

同区部署原则：

- Vercel Web、BFF 与 FastAPI 固定为 `iad1`；
- Supabase 新项目优先选择美国东部或邻近区域，运行时使用该项目的 Transaction Pooler；
- Upstash 新数据库优先选择 `us-east-1` 或邻近主区域；
- 切换前保留旧数据库，完成 migration、数据校验、健康检查和登录回归后再决定是否下线；
- Supabase 已建项目不能原地修改区域，需要创建新项目后迁移；Upstash 主区域也不应通过删除/新增只读区域来伪装迁移。

> [!WARNING]
> Vercel `iad1` 是中国大陆以外的美国节点。Vercel 不提供中国大陆节点或 ICP 备案，因此大陆访问质量不能等同于境内部署。当前拓扑适合演示和海外 Serverless 服务；公司正式面向中国大陆生产时，应使用隔离的其他云 Linux 境内部署，并评估 ICP 备案、等保和数据跨境要求。Vercel Hobby 仅限非商业用途，企业正式生产应升级到适用的商业计划。

> [!IMPORTANT]
> 本次区域变更只作用于 Vercel Web/BFF 与 FastAPI Functions，不修改其他云 Linux 主机上的 Compose、镜像、端口、发布目录或运行中的容器。若现有 Supabase/Upstash 仍位于新加坡，函数迁到美国后会增加数据层往返延迟；数据库迁移必须单独规划、备份和验证，不能把删除旧实例作为本次发布步骤。

## 已完成的 Vercel 适配

- `pyproject.toml` 的 `[tool.vercel]` 指向 `app.main:app`；
- Vercel 自动通过 `VERCEL=1` 启用 Serverless 数据库模式；
- SQLAlchemy 使用 `NullPool`，避免每个 Function 实例保留连接池；
- asyncpg 禁用 statement cache，psycopg 禁用自动 prepared statements；
- `*.vercel.app` 已加入可信 Host；
- `/api/v1/internal/maintenance` 使用 `CRON_SECRET` Bearer 验证；
- `vercel.json` 每天 03:17 UTC 运行一次有界、幂等的过期上传清理；
- 根目录与 `web/` 的 Vercel 配置都固定 `regions: ["iad1"]`；
- `.vercelignore` 明确排除 `.env`、虚拟环境、测试、Docker 和本地脚本。
- Next.js BFF 使用 Host-only `Secure + HttpOnly + SameSite=Lax` Cookie，不把 JWT 暴露给浏览器脚本；
- BFF 用共享 HMAC 密钥签名 Vercel 提供的终端 IP，FastAPI 验证后再执行登录/刷新限流。

## API Project 环境变量

秘密必须写入 Vercel Project Environment Variables，不能提交 `.env`。

| Vercel 变量 | 来源/说明 |
|---|---|
| `KB_ENVIRONMENT` | 固定为 `production` |
| `KB_DATABASE_URL` | Supabase Transaction Pooler URL；必须使用 `postgresql+psycopg://...:6543/postgres?sslmode=verify-full` 强制服务器证书和主机名验证 |
| `KB_REDIS_URL` | 外部 TLS Redis URL，例如 `rediss://...`；Upstash REST URL 不能直接替代 |
| `KB_BFF_SHARED_SECRET` | 与 Web Project 相同的至少 32 字符随机密钥；验证 BFF 转发的终端 IP |
| `KB_JWT_SECRET` | 新生成的至少 64 字符随机值 |
| `CRON_SECRET` | 新生成的至少 16 字符随机值；Vercel Cron 会自动作为 Bearer Token 发送 |
| `KB_S3_ENDPOINT_URL` | `https://cos.<COS_REGION>.myqcloud.com` |
| `KB_S3_PUBLIC_ENDPOINT_URL` | 与上面相同，必须是公网 HTTPS |
| `KB_S3_REGION` | 来自 `COS_REGION` |
| `KB_S3_ACCESS_KEY` | 来自 `COS_SECRET_ID` |
| `KB_S3_SECRET_KEY` | 来自 `COS_SECRET_KEY` |
| `KB_S3_BUCKET` | `COS_BUCKET`；若尚未包含 `-COS_APPID`，需要追加 |
| `KB_S3_USE_SSL` | 固定为 `true` |
| `KB_S3_ADDRESSING_STYLE` | 腾讯 COS 固定为 `virtual`；本地 MinIO 保持 `path` |
| `KB_TRUSTED_HOSTS` | 可省略并使用安全默认值；覆盖时必须是严格 JSON，例如 `["*.vercel.app"]` |
| `KB_CORS_ORIGINS` | BFF 同源模式可为 `[]`；只有浏览器直连 API 时才加入精确 Web Origin |
| `KB_LLM_CREDENTIAL_ENCRYPTION_KEY` | 独立生成的至少 32 字符随机主密钥；用于加密后台录入的模型供应商凭据 |
| `KB_LLM_DEFAULT_PROVIDER` | `deepseek`、`qwen` 或 `minimax`；数据库尚未设置默认值时使用 |
| `KB_DEEPSEEK_API_KEY` | 可选的 DeepSeek 环境凭据；只配置在 API Project |
| `KB_QWEN_API_KEY` | 可选的 Qwen/Model Studio 环境凭据；只配置在 API Project |
| `KB_MINIMAX_API_KEY` | 可选的 MiniMax 环境凭据；只配置在 API Project |

当前应用不使用 `SUPABASE_SERVICE_ROLE_KEY` 和 `COS_ENABLE_CI`。Service Role Key 不能替代 PostgreSQL DSN，也绝不能暴露给浏览器。

## Web Project 环境变量

Web Project 的 Root Directory 必须设置为 `web/`。只配置服务端变量，不要添加 `NEXT_PUBLIC_` 前缀：

| Vercel 变量 | 来源/说明 |
|---|---|
| `FASTAPI_URL` | API Project 的 HTTPS Origin，例如 `https://knowledgebases-api.vercel.app` |
| `FASTAPI_BFF_SHARED_SECRET` | 与 API 的 `KB_BFF_SHARED_SECRET` 完全相同 |
| `SESSION_REFRESH_MAX_AGE_SECONDS` | 可选；默认 `604800`（7 天） |

生产缺少或使用短于 32 字符的 BFF 密钥时，登录和刷新会返回 `503`，不会降级成不可信转发。

## Upstash Redis

通过 Vercel Marketplace 创建 **Upstash for Redis / upstash-kv** 后，集成通常注入：

- `KV_URL`：Redis TLS 协议 URL，可映射为 API Project 的 `KB_REDIS_URL`；
- `KV_REST_API_URL` / `KV_REST_API_TOKEN`：REST SDK 变量，本 FastAPI 后端不使用它们。

不要把 REST URL 填入 `KB_REDIS_URL`。运行时连接必须是 `rediss://` 协议 URL，并在部署前用 `PING` 做一次脱敏连通性验证。

## Supabase 连接

在 Supabase Dashboard 的 **Connect** 页面复制两种连接串：

1. Runtime：Transaction Pooler，端口 `6543`，配置到 Vercel `KB_DATABASE_URL`；
2. Migration：Direct 或 Session Pooler，供本地 Alembic/bootstrap 一次性使用，不注入 Vercel Runtime。

把 Supabase 给出的 `postgresql://` scheme 改为 `postgresql+psycopg://`，并在查询参数中保留 `sslmode=verify-full`。密码中的特殊字符必须进行 URL 编码。迁移 `20260712_0013` 还会撤销 `PUBLIC`、`anon` 和 `authenticated` 对业务表与序列的直接权限；前端和 Data API 不得绕过 FastAPI 授权边界。

迁移会把 `pg_trgm` 安装或移动到 `extensions` schema，再创建 schema-qualified GIN 索引。如果项目已在 `public` 安装该扩展，执行迁移的角色必须拥有扩展；Supabase 环境应通过受控的管理迁移执行这一步，而不是给应用运行时角色授予扩展所有权。

首次上线前，在受信任机器执行：

```powershell
$env:KB_DATABASE_URL = 'postgresql+psycopg://迁移连接串'
$env:KB_BOOTSTRAP_ADMIN_EMAIL = 'admin@example.com'
$env:KB_BOOTSTRAP_ADMIN_PASSWORD = '一次性强密码'

.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe -m app.bootstrap

Remove-Item Env:KB_BOOTSTRAP_ADMIN_PASSWORD
```

不要把 bootstrap 管理员密码配置到 Vercel Runtime。

## 腾讯 COS

Bucket 名必须是 `BucketName-APPID`。COS 需要允许管理前端或上传客户端所在 Origin 执行 `PUT/GET/HEAD/POST`，允许上传所需请求头并暴露 `ETag`；否则浏览器 Multipart 无法把各分片 ETag 交给完成接口。

同时在 COS 配置：

- AbortIncompleteMultipartUpload 生命周期；
- `staging/` 临时对象过期；
- 最小权限 CAM 子账号，只允许指定 Bucket；
- 不要使用主账号永久密钥。

## Vercel 命令

先部署 API Project：

```powershell
npx --yes vercel@50.28.0 login
npx --yes vercel@50.28.0 link --yes --project knowledgebases-api
npx --yes vercel@50.28.0 env ls
npx --yes vercel@50.28.0 --prod
```

再从 `web/` 链接并部署独立 Web Project：

```powershell
Push-Location web
npx --yes vercel@50.28.0 link --yes --project knowledgebases
npx --yes vercel@50.28.0 env ls
npx --yes vercel@50.28.0 --prod
Pop-Location
```

部署后检查：

```powershell
Invoke-RestMethod https://knowledgebases-api.vercel.app/health/live
Invoke-RestMethod https://knowledgebases-api.vercel.app/health/ready
Invoke-WebRequest https://knowledgebases.vercel.app/login
npx --yes vercel@50.28.0 logs --since 1h --level error
```

## 平台边界

- Vercel Function 请求体有限制，所以文件内容不能经过 FastAPI；当前直传设计符合这一要求。
- Hobby 套餐 Cron 最多每天一次，因此当前配置使用每日调度。更高频清理需 Pro Cron 或外部 worker。
- Hobby 仅适用于非商业项目；公司正式生产部署必须选择适用的商业计划。
- 美国华盛顿特区 `iad1` 不是中国大陆区域，不能替代境内部署、ICP备案或数据合规评估。
- Alembic/bootstrap 必须在部署前单独执行，不能放在 Function 冷启动或 Vercel Build 中。
- 生产仍需 COS 病毒扫描/内容检测流水线；人工 `approve` 不是恶意软件扫描。

官方参考：

- [FastAPI on Vercel](https://vercel.com/docs/frameworks/backend/fastapi)
- [Vercel Regions](https://vercel.com/docs/regions)
- [Vercel Functions Region](https://vercel.com/docs/functions/configuring-functions/region)
- [Vercel 中国大陆访问说明](https://vercel.com/kb/guide/accessing-vercel-hosted-sites-from-mainland-china)
- [Vercel Cron Jobs](https://vercel.com/docs/cron-jobs/manage-cron-jobs)
- [Supabase 更改项目区域](https://supabase.com/docs/guides/troubleshooting/change-project-region-eWJo5Z)
- [Supabase Postgres connections](https://supabase.com/docs/guides/database/connecting-to-postgres)
- [Using SQLAlchemy with Supabase](https://supabase.com/docs/guides/troubleshooting/using-sqlalchemy-with-supabase-FUqebT)
- [Upstash Global Database](https://upstash.com/docs/redis/features/globaldatabase)
- [腾讯 COS S3 兼容配置](https://intl.cloud.tencent.com/zh/document/product/436/34688)
