# 企业知识库后台

一个可直接运行的 FastAPI 后台骨架，面向 10 TB+ 文档存储。文件数据走 S3/MinIO 直传，PostgreSQL 保存元数据、动态 RBAC、持久配额和审计，Redis 负责分布式分钟级限流。

支持 `.txt`、`.doc`、`.docx`、`.xls`、`.xlsx`、`.csv`、`.pdf`、`.ppt`、`.pptx`。

## 已实现

- OAuth2 密码登录、Argon2 哈希、短期 JWT 与一次性刷新令牌轮换
- 管理员动态创建角色、组合固定权限目录、配置角色限额并分配用户
- 多角色权限取并集；同一限额取最大授权值；用户覆盖值最终生效；`NULL` 表示无限
- 角色优先级、系统角色、目标管理员层级和最后一个超级管理员保护
- 单文件预签名 PUT 与大文件 S3 Multipart，客户端不把文件流量压到 API
- 精确 `Content-Length` 签名、10,000 分片上限、不可复用最终对象键
- PostgreSQL 原子配额预留，覆盖单文件大小、每日上传字节、总存储、每日下载凭证
- Redis Lua 原子限流、登录 IP/账号双维度限制
- 上传状态机、幂等键、过期会话清理、`FINALIZING` 对象存储对账、审计日志和短时下载凭证
- 角色详情返回权限与限额，用户详情返回角色，并提供权限/限额目录
- Alembic、Docker Compose、MinIO、上传 CLI、中文架构与运维文档

## 本地启动

需要先启动 Docker Desktop。

```powershell
Copy-Item .env.example .env.kb
# 打开 .env.kb，至少更换 JWT、管理员、PostgreSQL、Redis、MinIO 密码
.\scripts\start.ps1 -EnvFile .env.kb
```

`start.ps1` 会构建镜像、启动 Compose 并显示状态；它也会自动规避 Windows 中文目录触发的 Docker Buildx 非 ASCII 路径问题。已有最新镜像时可加 `-SkipBuild`。

服务启动顺序是 PostgreSQL/Redis/MinIO → Alembic migration → 幂等 bootstrap → API。首次管理员来自 `.env.kb`：

```text
KB_BOOTSTRAP_ADMIN_EMAIL
KB_BOOTSTRAP_ADMIN_PASSWORD
```

启动后访问：

- Swagger UI: http://localhost:8000/docs
- OpenAPI: http://localhost:8000/openapi.json
- 存活检查: http://localhost:8000/health/live
- 就绪检查: http://localhost:8000/health/ready
- MinIO Console: http://localhost:9001

## 上传文件

上传脚本支持自动登录、单文件直传、并发分片、URL 刷新和断点续传：

```powershell
$env:KB_EMAIL='admin@example.com'
$env:KB_PASSWORD='你在 .env.kb 中设置的管理员密码'
.\.venv\Scripts\python.exe scripts\upload.py `
  --password-env KB_PASSWORD `
  --calculate-sha256 `
  'C:\data\manual.pdf'
```

上传完成后文件处于 `processing`，不会立即开放下载。接入杀毒/内容检测 Worker 后由 Worker 审批；开发环境也可由拥有 `file:approve` 权限的管理员调用：

```http
POST /api/v1/files/{file_id}/approve
Authorization: Bearer <access-token>
```

## 核心 API

| 能力 | 接口 |
|---|---|
| 登录/刷新 | `POST /api/v1/auth/token`, `POST /api/v1/auth/refresh` |
| 用户管理 | `GET/POST /api/v1/users`, `PUT /api/v1/users/{id}/roles` |
| 动态角色 | `GET/POST /api/v1/roles`, `GET /roles/{id}`, `PUT /roles/{id}/permissions`, `PUT /roles/{id}/limits` |
| 权限/限额目录 | `GET /api/v1/permissions`, `GET /api/v1/limits` |
| 发起上传 | `POST /api/v1/files/uploads` |
| 分片签名 | `POST /api/v1/files/uploads/{id}/parts` |
| 完成/中止 | `POST .../{id}/complete`, `DELETE .../{id}` |
| 文件列表 | `GET /api/v1/files` |
| 下载凭证 | `POST /api/v1/files/{id}/download` |

下载次数的精确定义是“签发下载凭证次数”。普通 S3 预签名 URL 在过期前可重复使用；若业务要求按真实下载次数或字节严格计费，应改用下载网关或 CDN 边缘鉴权。

## 开发验证

```powershell
uv sync --extra dev
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing -q
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe app scripts
```

## 生产边界

Compose 中的单节点 MinIO 和开发凭据仅供本机开发，不能作为 10 TB+ 生产部署。生产环境应使用 S3/云对象存储或多节点纠删码 MinIO、托管 PostgreSQL/Redis、企业 OIDC、TLS、独立扫描/解析 Worker、备份/PITR、对象生命周期和集中审计。应用、迁移与对象存储账号也应使用不同的最小权限身份。

详细设计见 [架构文档](docs/ARCHITECTURE.zh-CN.md)，部署、备份和排障见 [运维手册](docs/OPERATIONS.zh-CN.md)。

Vercel Functions 部署、Supabase Transaction Pooler、腾讯 COS 环境变量映射和 Cron 配置见 [Vercel 部署手册](docs/VERCEL_DEPLOYMENT.zh-CN.md)。
