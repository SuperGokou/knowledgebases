# Vercel 部署手册

该部署只把 FastAPI 控制面运行在 Vercel Functions。文件字节仍由客户端使用预签名 URL 直传腾讯 COS；PostgreSQL、Redis 和对象存储都必须是外部托管服务。Vercel 不运行 `docker-compose.yml`、MinIO、常驻 maintenance worker 或构建阶段数据库迁移。

## 已完成的 Vercel 适配

- `pyproject.toml` 的 `[tool.vercel]` 指向 `app.main:app`；
- Vercel 自动通过 `VERCEL=1` 启用 Serverless 数据库模式；
- SQLAlchemy 使用 `NullPool`，避免每个 Function 实例保留连接池；
- asyncpg 禁用 statement cache，psycopg 禁用自动 prepared statements；
- `*.vercel.app` 已加入可信 Host；
- `/api/v1/internal/maintenance` 使用 `CRON_SECRET` Bearer 验证；
- `vercel.json` 每天 03:17 UTC 运行一次有界、幂等的过期上传清理；
- `.vercelignore` 明确排除 `.env`、虚拟环境、测试、Docker 和本地脚本。

## 必需环境变量

秘密必须写入 Vercel Project Environment Variables，不能提交 `.env`。

| Vercel 变量 | 来源/说明 |
|---|---|
| `KB_ENVIRONMENT` | 固定为 `production` |
| `KB_DATABASE_URL` | Supabase Transaction Pooler URL；推荐 `postgresql+psycopg://...:6543/postgres` |
| `KB_REDIS_URL` | 外部 TLS Redis URL，例如 `rediss://...`；Upstash REST URL 不能直接替代 |
| `KB_JWT_SECRET` | 新生成的至少 64 字符随机值 |
| `CRON_SECRET` | 新生成的至少 16 字符随机值；Vercel Cron 会自动作为 Bearer Token 发送 |
| `KB_S3_ENDPOINT_URL` | `https://cos.<COS_REGION>.myqcloud.com` |
| `KB_S3_PUBLIC_ENDPOINT_URL` | 与上面相同，必须是公网 HTTPS |
| `KB_S3_REGION` | 来自 `COS_REGION` |
| `KB_S3_ACCESS_KEY` | 来自 `COS_SECRET_ID` |
| `KB_S3_SECRET_KEY` | 来自 `COS_SECRET_KEY` |
| `KB_S3_BUCKET` | `COS_BUCKET`；若尚未包含 `-COS_APPID`，需要追加 |
| `KB_S3_USE_SSL` | 固定为 `true` |
| `KB_TRUSTED_HOSTS` | JSON：`["*.vercel.app"]`，有自定义域名时一并加入 |
| `KB_CORS_ORIGINS` | 管理前端 Origin 的 JSON 数组；没有跨域前端时可为 `[]` |

当前应用不使用 `SUPABASE_SERVICE_ROLE_KEY` 和 `COS_ENABLE_CI`。Service Role Key 不能替代 PostgreSQL DSN，也绝不能暴露给浏览器。

## Supabase 连接

在 Supabase Dashboard 的 **Connect** 页面复制两种连接串：

1. Runtime：Transaction Pooler，端口 `6543`，配置到 Vercel `KB_DATABASE_URL`；
2. Migration：Direct 或 Session Pooler，供本地 Alembic/bootstrap 一次性使用，不注入 Vercel Runtime。

把 Supabase 给出的 `postgresql://` scheme 改为 `postgresql+psycopg://`。密码中的特殊字符必须进行 URL 编码。

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

```powershell
npx --yes vercel@50.28.0 login
npx --yes vercel@50.28.0 link --yes --project knowledgebases
npx --yes vercel@50.28.0 env ls
npx --yes vercel@50.28.0 --prod
```

部署后检查：

```powershell
Invoke-RestMethod https://<project>.vercel.app/health/live
Invoke-RestMethod https://<project>.vercel.app/health/ready
npx --yes vercel@50.28.0 logs --since 1h --level error
```

## 平台边界

- Vercel Function 请求体有限制，所以文件内容不能经过 FastAPI；当前直传设计符合这一要求。
- Hobby 套餐 Cron 最多每天一次，因此当前配置使用每日调度。更高频清理需 Pro Cron 或外部 worker。
- Alembic/bootstrap 必须在部署前单独执行，不能放在 Function 冷启动或 Vercel Build 中。
- 生产仍需 COS 病毒扫描/内容检测流水线；人工 `approve` 不是恶意软件扫描。

官方参考：

- [FastAPI on Vercel](https://vercel.com/docs/frameworks/backend/fastapi)
- [Vercel Cron Jobs](https://vercel.com/docs/cron-jobs/manage-cron-jobs)
- [Supabase Postgres connections](https://supabase.com/docs/guides/database/connecting-to-postgres)
- [Using SQLAlchemy with Supabase](https://supabase.com/docs/guides/troubleshooting/using-sqlalchemy-with-supabase-FUqebT)
- [腾讯 COS S3 兼容配置](https://intl.cloud.tencent.com/zh/document/product/436/34688)
