# 企业知识库后台启动与运维手册

本文面向开发、测试和平台运维人员。默认工作目录是仓库根目录，示例使用 Windows PowerShell；Linux/macOS 可把环境变量写法替换为对应 shell 语法。

## 1. 先明确环境等级

仓库内 <code>docker-compose.yml</code> 是本地开发/验收环境：

- PostgreSQL、Redis、MinIO 与 API 端口只绑定 127.0.0.1；
- MinIO 是单节点单盘；
- HTTP 没有 TLS；
- 凭据来自单独的本地 <code>.env.kb</code>；
- 容器数据保存在 Docker named volumes。

它可以验证登录、动态 RBAC、限额、单 PUT、Multipart、审批和下载，但不能作为 10 TB 生产集群。生产要求见本文第 12 节和架构文档。

## 2. 本地快速启动

### 2.1 前置条件

- Docker Desktop 或 Docker Engine + Compose v2；
- 建议至少 4 CPU、8 GiB RAM 和足够的 Docker 数据盘空间；
- 若运行上传脚本或测试，需要 Python 3.12+；仓库推荐使用 uv；
- 端口 8000、5432、6379、9000、9001 未被占用，或在 <code>.env.kb</code> 中改端口。

### 2.2 首次配置

如果还没有 <code>.env.kb</code>：

~~~powershell
Copy-Item .env.example .env.kb
~~~

若 <code>.env.kb</code> 已存在但 Compose 报某个必填变量缺失，请把 <code>.env.example</code> 中缺少的 key 合并进去；不要直接覆盖已经保存的真实 secret。

打开 <code>.env.kb</code>，至少替换以下开发示例值：

- <code>KB_JWT_SECRET</code>：足够长的随机值；
- <code>KB_BOOTSTRAP_ADMIN_PASSWORD</code>：首个管理员密码；
- <code>POSTGRES_PASSWORD</code>；
- <code>REDIS_PASSWORD</code>；
- <code>MINIO_ROOT_USER</code> 与 <code>MINIO_ROOT_PASSWORD</code>。

不要提交 <code>.env.kb</code>。共享或生产环境使用 Secrets Manager/Vault/Kubernetes Secret 注入，不把 secret 放进镜像、Compose 文件、命令行参数或日志。

先验证 Compose 展开是否成功：

~~~powershell
docker compose --env-file .env.kb config --quiet
~~~

### 2.3 启动

~~~powershell
.\scripts\start.ps1 -EnvFile .env.kb
~~~

启动依赖顺序是：

1. PostgreSQL、Redis、MinIO 通过 healthcheck；
2. MinIO 初始化私有 bucket；
3. Alembic 升级数据库；
4. bootstrap 幂等写入权限目录、限额定义、system admin role 与首个 superuser；
5. API 启动；
6. maintenance worker 回收过期会话/配额，并对账崩溃后遗留的 `FINALIZING`；
7. Multipart GC 周期清理过旧的不完整 part 与 staging 对象。

检查 API：

~~~powershell
Invoke-RestMethod http://localhost:8000/health/live
Invoke-RestMethod http://localhost:8000/health/ready
~~~

- <code>/health/live</code> 只表示进程可响应；
- <code>/health/ready</code> 同时检查 PostgreSQL 与 Redis，失败返回 503；
- MinIO 控制台默认是 <http://localhost:9001>；
- OpenAPI UI 默认是 <http://localhost:8000/docs>。

查看启动问题：

~~~powershell
docker compose --env-file .env.kb logs --tail 200 migrate
docker compose --env-file .env.kb logs --tail 200 bootstrap
docker compose --env-file .env.kb logs --tail 200 app
docker compose --env-file .env.kb logs --tail 200 minio-init
~~~

bootstrap 是幂等的，不会因重启重复创建目录数据。管理员密码只应在首次创建前确定；修改环境变量不会自动轮换数据库中既有密码。既有用户必须使用受审计的自助改密或超级管理员重置接口，完成后旧密码、access token 与 refresh token 均失效；企业 IdP/OIDC 仍属于后续增强。

## 3. 登录验证

~~~powershell
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/auth/token -ContentType "application/x-www-form-urlencoded" -Body @{ username = $env:KB_EMAIL; password = $env:KB_PASSWORD }
$headers = @{ Authorization = "Bearer $($login.access_token)" }
Invoke-RestMethod -Headers $headers http://localhost:8000/api/v1/permissions
~~~

本地可设置：

~~~powershell
$env:KB_EMAIL = "admin@example.com"
$env:KB_PASSWORD = "你在 .env.kb 中设置的管理员密码"
~~~

用完后从当前 PowerShell 会话移除密码：

~~~powershell
Remove-Item Env:KB_PASSWORD
~~~

access token 默认 15 分钟；refresh token 默认 7 天且每次 refresh 都轮换，服务端只保存 fingerprint。refresh 重放会撤销整个令牌族，logout 同样撤销当前族；账户禁用、角色替换和密码更改等安全变化会提高 `token_version`，使旧 access token 失效。

## 4. 上传文件

### 4.1 基本命令

上传器只使用 Python 标准库：

~~~powershell
$env:KB_EMAIL = "admin@example.com"
$env:KB_PASSWORD = "你的密码"
.\.venv\Scripts\python.exe .\scripts\upload.py .\data\manual.pdf
~~~

也可使用系统 Python：

~~~powershell
python .\scripts\upload.py .\data\manual.pdf --email admin@example.com
~~~

支持扩展名：

<code>.txt .doc .docx .xls .xlsx .csv .pdf .ppt .pptx</code>

添加元数据：

~~~powershell
python .\scripts\upload.py .\data\manual.pdf --email admin@example.com --metadata-json '{"department":"quality","retention":"7y"}'
~~~

元数据也可来自文件：

~~~powershell
python .\scripts\upload.py .\data\manual.pdf --email admin@example.com --metadata-json "@.\metadata.json"
~~~

可选计算客户端声明的 SHA-256：

~~~powershell
python .\scripts\upload.py .\data\manual.pdf --email admin@example.com --calculate-sha256
~~~

该选项会完整扫描源文件，对超大文件耗时明显。当前后台完成阶段强制校验实际对象大小，SHA-256 尚未形成强制端到端验证；不要把该选项当作恶意篡改证明。

### 4.2 Multipart 并发与恢复

~~~powershell
python .\scripts\upload.py .\data\archive.pptx --email admin@example.com --workers 8 --url-batch-size 24
~~~

- workers 默认 4，允许 1–32；先测网络与对象存储再提高；
- 每批最多申请 100 个 URL，默认 16，减少 URL 等待过期；
- 每个 PUT 都发送服务端签名的精确 Content-Length；
- 429、5xx 和临时网络错误使用带 jitter 的指数退避；
- access token 将在需要控制面请求时自动 refresh；
- checkpoint 默认位于源文件旁，例如 <code>.archive.pptx.kb-upload.json</code>；
- checkpoint 不包含密码、JWT 或预签名 URL。

中断后运行同一命令即可恢复。客户端核对 API URL、绝对源路径、大小、mtime、内容类型、元数据、checksum 和服务端分片计划；不一致时拒绝混传。

源文件确实已更换时：

~~~powershell
python .\scripts\upload.py .\data\archive.pptx --email admin@example.com --restart
~~~

<code>--restart</code> 会先调用 DELETE 中止旧服务端会话、释放 HELD 配额，再用新幂等键开始。不要只删除 checkpoint；否则旧 Multipart 与预留会留到后台回收。

成功时脚本输出 File JSON，文件进入 <code>quarantined</code> 并等待恶意软件扫描，退出码为 0。失败退出码为 2，Ctrl+C 为 130；错误会给出 checkpoint 路径。上传器禁止 HTTP 重定向，避免 Authorization 或预签名请求跨 origin；远程 HTTP API/对象存储默认拒绝，本机 loopback 开发例外。

只有隔离开发网确有需要时，才使用：

~~~powershell
python .\scripts\upload.py .\data\manual.pdf --email admin@example.com --api-url http://dev-api.internal/api/v1 --allow-insecure-api --allow-insecure-storage
~~~

生产不要使用这两个 insecure 开关，应配置 HTTPS 和可信 CA；私有 CA 使用 <code>--ca-bundle</code>。

## 5. 审批与下载

上传完成不自动可下载。maintenance worker 先领取扫描租约；ClamAV 返回 `CLEAN` 后，文件进入 `processing` 并启动当前版本 OKF 转换。管理员在扫描和转换均完成后批准：

~~~powershell
$fileId = "上传脚本输出的 file id"
$approve = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/files/$fileId/approve" -Headers $headers
$approve.status
~~~

只有 <code>file:approve</code> 能执行该操作。审批同时要求恶意软件状态为 `CLEAN`，并且当前文件版本存在成功的 OKF 转换及草稿；随后草稿发布、文件进入 <code>available</code>。感染、扫描错误、解析失败或 OKF 未完成时均失败关闭并保持不可下载，人工 approve 不能绕过门禁。

申请下载 URL：

~~~powershell
$grant = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/files/$fileId/download" -Headers $headers
Invoke-WebRequest -Uri $grant.url -OutFile .\downloaded-file.pdf
~~~

URL 最长有效 300 秒。<code>daily_downloads</code> 在签发 grant 时计数，而不是传输结束时计数。

## 6. 创建角色与用户

### 6.1 查看目录

~~~powershell
$permissions = Invoke-RestMethod -Headers $headers http://localhost:8000/api/v1/permissions
$roles = Invoke-RestMethod -Headers $headers http://localhost:8000/api/v1/roles
$permissions | Select-Object code,name
~~~

### 6.2 创建受限上传角色

以下示例允许单文件最大 2 GiB、每日上传 20 GiB、总存储 200 GiB、每日 20 次下载和每分钟 120 个受保护请求。PowerShell 数字直接以字节传输：

~~~powershell
$rolePayload = @{
  code = "knowledge_uploader"
  name = "Knowledge Uploader"
  description = "Upload and read own approved files"
  priority = 10
  permission_codes = @("file:upload", "file:read")
  limits = @{
    max_upload_bytes = 2147483648
    daily_upload_bytes = 21474836480
    storage_bytes = 214748364800
    daily_downloads = 20
    requests_per_minute = 120
  }
} | ConvertTo-Json -Depth 5
$role = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/roles -Headers $headers -ContentType "application/json" -Body $rolePayload
~~~

SQL NULL 表示“不设角色额度”，0 表示禁止。多角色有限值取最大；任一角色为 NULL 则该 key 的角色合并结果为无限制；用户 override 最后覆盖。不要给普通角色设置 NULL，除非确实希望不设角额度。该语义不会绕过 2 GiB 单文件平台安全硬上限、clamd 扫描上限、180 GB 对象停止线或 70%/80%/90% 磁盘水位门禁。

### 6.3 创建用户

~~~powershell
$userPayload = @{
  email = "uploader@example.com"
  password = "Replace-With-A-Long-Random-Password"
  display_name = "Uploader"
  role_ids = @($role.id)
} | ConvertTo-Json -Depth 4
$user = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/users -Headers $headers -ContentType "application/json" -Body $userPayload
~~~

替换用户角色必须携带刚读取到的 `role_assignment_version`：

~~~powershell
$roleUpdatePayload = @{
  expected_version = $user.role_assignment_version
  role_ids = @($role.id)
} | ConvertTo-Json -Depth 4
$user = Invoke-RestMethod -Method Put -Uri "http://localhost:8000/api/v1/users/$($user.id)/roles" -Headers $headers -ContentType "application/json" -Body $roleUpdatePayload
~~~

该接口使用严格 CAS。实际角色变更会令 `role_assignment_version` 单调递增并使该用户已有 token 失效；提交相同角色集合不会递增版本、不会吊销 token，也不会写入“角色已替换”审计。旧快照返回 `409 stale_role_assignment`，`details.current_version` 给出当前版本；管理员客户端必须重新读取用户及角色集合后再确认，禁止仅替换版本号并盲目重试。非 superuser 不能创建高于自己 priority 的角色、修改 system role，或授予自己没有的权限/更宽限额。

修改角色元数据、优先级、权限、限额或组合策略时同样必须携带最近读取的 `RoleRead.policy_version`。例如组合策略请求为：

~~~powershell
$rolePolicyPayload = @{
  expected_version = $role.policy_version
  permission_codes = @("file:read", "file:upload")
  limits = @{ max_upload_bytes = 104857600 }
} | ConvertTo-Json -Depth 4
$role = Invoke-RestMethod -Method Put -Uri "http://localhost:8000/api/v1/roles/$($role.id)/policy" -Headers $headers -ContentType "application/json" -Body $rolePolicyPayload
~~~

`PATCH /roles/{id}`、`PUT /permissions`、`PUT /limits` 与 `PUT /policy` 共用一个单调递增的策略版本。旧快照返回 `409 stale_role_policy` 和 `details.current_version`；客户端必须立即废弃旧草稿，重新读取完整角色后由管理员再次确认，禁止只替换版本号自动重试。完全相同的提交是无副作用操作，不递增版本、不写成功审计，也不触发外部模型撤权门禁。

删除非系统角色时必须使用刚读取的策略版本：

~~~powershell
Invoke-RestMethod -Method Delete -Uri "http://localhost:8000/api/v1/roles/$($role.id)?expected_version=$($role.policy_version)" -Headers $headers
~~~

系统角色、高于操作者权限边界的角色和旧版本请求会被拒绝。角色仍被用户分配或知识库授权引用时返回 `409 role_in_use` 与引用计数；应先通过受审计 API 清理引用，再重新读取角色版本，禁止直接删数据库行。

### 6.4 修改或重置密码

当前用户修改密码必须提供当前密码：

~~~powershell
$passwordPayload = @{
  current_password = $env:KB_PASSWORD
  new_password = "Replace-With-A-New-Long-Random-Password"
} | ConvertTo-Json
Invoke-RestMethod -Method Put -Uri "http://localhost:8000/api/v1/users/me/password" -Headers $headers -ContentType "application/json" -Body $passwordPayload
~~~

超级管理员重置他人密码时调用 `PUT /api/v1/users/{user_id}/password`，只提交 `new_password`，不得收集或提交目标用户当前密码。两种操作都执行强密码校验、限流/权限检查、`token_version` 递增、refresh token 撤销与审计；成功后客户端必须清除本地会话并重新登录。

知识库授权替换也采用 CAS。管理员先从 `GET /api/v1/knowledge-bases/{id}` 或知识库列表读取 `role_grant_version`，再向 `PUT /api/v1/knowledge-bases/{id}/role-grants` 提交同值的 `expected_version`。旧快照返回 `409 stale_knowledge_grants`；客户端必须重新加载知识库版本和完整授权集合，禁止把旧授权集合自动重放。提交相同集合不会递增版本、不会触发数据外发撤权检查，也不会写成功变更审计。

## 7. 日常检查与告警

建议至少采集：

| 指标/事件 | 告警条件 |
|---|---|
| API readiness | 连续失败；区分 PostgreSQL 与 Redis |
| API 5xx、p95/p99 | 持续高于基线；按 route 和 error.code 聚合 |
| 401/403/429 | 异常突增；区分攻击、配置错误、请求限流和 quota_exceeded |
| PostgreSQL | 连接池饱和、复制延迟、WAL 归档失败、磁盘、长事务、锁等待 |
| Redis | 不可达、内存、eviction、延迟；不可达会令受保护 API 返回 503 |
| 对象存储 | 容量、节点/盘健康、5xx/503、PUT/GET 延迟、复制/纠删码健康 |
| Multipart | 不完整 part 容量、GC 失败、超过会话期限的上传数 |
| 配额 | HELD reservation 超期、reserved 长期不归零、异常大用量 |
| 文件状态 | processing/quarantined/failed 积压与最长等待时间 |
| 审计 | 登录失败、角色/权限变更、管理员批准、异常下载 grant |

本地查看：

~~~powershell
docker compose --env-file .env.kb ps
docker compose --env-file .env.kb logs --since 30m app
docker compose --env-file .env.kb logs --since 24h minio-multipart-gc
docker compose --env-file .env.kb stats
~~~

API 响应包含 <code>X-Request-ID</code>，报障时同时记录时间、route、用户、HTTP 状态、error.code 和 request_id；不要记录 Authorization、refresh token、密码或完整预签名 URL。

## 8. 常见故障

### 8.1 ready 返回 503

~~~powershell
docker compose --env-file .env.kb ps
docker compose --env-file .env.kb logs --tail 200 postgres
docker compose --env-file .env.kb logs --tail 200 redis
docker compose --env-file .env.kb logs --tail 200 app
~~~

检查 <code>KB_DATABASE_URL</code>、Redis 密码、容器 healthcheck 与磁盘。限流选择 fail closed，所以 Redis 故障会影响所有受保护业务请求。

### 8.2 401

- 检查客户端系统时间；
- access 过期应由 refresh 自动恢复；
- refresh 已轮换、已撤销或 token_version 改变时必须重新登录；
- 生产检查 issuer、audience、算法和 JWT secret 是否在滚动发布中不一致。

### 8.3 403

- <code>permission_denied</code>：用户没有所需 code；
- <code>role_escalation_denied</code>：尝试管理 system role 或高 priority role；
- 对象存储 403：通常是 URL 过期、host/scheme 被代理改写、签名头不一致或 Content-Length 不符。上传器会刷新 part URL；单 PUT 可重跑同一命令取得新 URL。

不要把对象存储 403 的完整 URL 粘贴到工单或聊天工具。

### 8.4 429

- <code>rate_limit_exceeded</code>：遵守 <code>Retry-After</code>；
- <code>quota_exceeded</code>：查看 details 中 limit、remaining、requested；等待 UTC 日窗口、降低大小或由管理员调整角色/override；
- 并发上传在发起时已预留 daily_upload_bytes 与 storage_bytes，因此即使尚未上传字节也可能暂时占额度。

### 8.5 SignatureDoesNotMatch

确认：

- <code>KB_S3_PUBLIC_ENDPOINT_URL</code> 是客户端真正能访问的 origin；
- 反向代理没有改 host、scheme、path 或 query；
- 客户端发送服务端返回的所有 required_headers；
- 单 PUT/part 的 Content-Length 与签名一致；
- MinIO/S3 与 API 时钟同步；
- 没有复用其他 part number 的 URL。

### 8.6 上传中断或过期

先重跑相同上传命令。若 API 返回 <code>upload_expired</code>，使用 <code>--restart</code> 中止旧会话。Compose 默认让 Multipart GC 清理超过 2 天的不完整 part，而应用会话默认 24 小时；GC 年龄不能小于会话窗口。

maintenance worker 会把过期 `INITIATED` 会话标记为 `EXPIRED`、释放 HELD reservation 并清理对象；对过期 `FINALIZING` 会先 HEAD 对账，实际对象完整时补偿提交，否则回收。它还会把超过 `KB_CHAT_IDEMPOTENCY_PROCESSING_TIMEOUT_SECONDS` 的聊天记录封闭为 `OUTCOME_UNKNOWN`，并在 `KB_CHAT_IDEMPOTENCY_TTL_SECONDS` 到期后删除 `COMPLETED` / `OUTCOME_UNKNOWN` / `INVALIDATED` 记录；处理中与过期终态使用独立批次配额，避免一类积压饿死另一类，处理中记录绝不能直接删除后重跑。生产仍需全量 reconciliation 覆盖无数据库记录的孤儿对象、跨区域复制和长期漂移。

### 8.7 quarantined / processing 长期积压

maintenance worker 使用数据库租约推进 ClamAV 扫描与 OKF 转换。`quarantined` 长期积压时检查 clamd readiness、病毒库兼容性、扫描租约与失败审计；`processing` 长期积压时检查解析器 `--require-all` 预检、OKF 作业租约、重试终态和当前版本草稿。感染或扫描错误必须保持隔离，禁止通过直接改表或跳过扫描强制批准。当前单机 worker 不是独立消息队列或高吞吐集群，生产仍需监控最老任务年龄、租约、重试与死信，并以目标机证据校准容量。

## 9. 数据库诊断

只读查看聊天幂等状态（表中没有问题正文、明文 Key 或明文主体标识）：

~~~sql
SELECT status, count(*) AS records, min(created_at) AS oldest
FROM chat_idempotency_records
GROUP BY status
ORDER BY status;
~~~

`PROCESSING` 超过配置超时应由 maintenance 封闭为 `OUTCOME_UNKNOWN`。不要手工删除
处理中记录，也不要通过清空表来“解决”客户端 `409`，否则可能重复检索、外发和计费。
`INVALIDATED` 表示知识库内容版本已经变化，旧压缩响应已被清空；它只能在 TTL 到期后由维护任务删除，不能改回 `PROCESSING`。默认 `KB_CHAT_IDEMPOTENCY_CLEANUP_BATCH_SIZE=1000`、`KB_CHAT_IDEMPOTENCY_CLEANUP_MAX_BATCHES=5`、循环间隔 60 秒：每轮分别最多处理 5,000 条超时处理中记录和 5,000 条过期终态。该数值只是理论上界，不是吞吐认证；同一 worker 还执行其他维护任务，必须用目标机 backlog、最老记录年龄和锁等待实测校准。

当前采用最保守的 fail-closed 异常策略：claim 建立后 operation 抛出的任何异常都会封闭为 `OUTCOME_UNKNOWN`，包括少数可以证明尚未外发的确定性错误。这可能牺牲可用性，但不会放宽为可能二次外发；运维不得手工改状态。将错误分类为“未开始/已知结果/未知结果”属于后续优化项，在完成故障注入验收前不能宣称已经解决。

聊天幂等表不保存问题正文、明文 Key 或明文主体 ID；响应先有界 zlib 压缩，再以 AES-256-GCM 加密。数据库保存密钥版本、12 字节随机 nonce、密文和原始大小，外置密钥环由 `KB_CHAT_REPLAY_ENCRYPTION_KEYS` 与 `KB_CHAT_REPLAY_ACTIVE_KEY_VERSION` 配置。旧密钥必须至少保留到相关记录超过 TTL；提前移除、AAD/密文篡改或解密失败会安全转为 `OUTCOME_UNKNOWN` 并清除密文，不会再次调用模型。完整轮换流程见[聊天幂等回放加密运维](./CHAT_REPLAY_ENCRYPTION.zh-CN.md)。

应用层 AEAD 不覆盖 PostgreSQL 其他元数据、对象文件、WAL、快照或备份。上述介质仍必须采用企业访问控制、静态加密、保留和销毁策略；若无法提供静态加密及恢复演练证据，敏感知识库部署必须判定为 `NO-GO`。SHA-256、压缩或 replay 字段加密都不能充当整库匿名化/加密证明。

容量按“保留期内逻辑问答数 × 实际压缩响应字节”核算，而不是按在线用户数核算。
在每天 50 亿 token 场景中，若平均每次问答消耗 1 万 token，则约有 50 万条记录/
日；即使采用默认 128 KiB 上限，理论响应体上界也超过 60 GiB/日，尚未计入表膨胀、
索引、WAL 与备份。因此单机 300 GiB 不能据此宣称容量通过：正式验收必须用实测平均/
P95 响应大小和请求数确定 TTL，并采用独立或分区 PostgreSQL、磁盘水位告警、WAL/
备份容量预算与可验证清理。不得通过缩短处理中超时或删除未决记录换取空间。

只读查看长期 HELD reservation：

~~~powershell
docker compose --env-file .env.kb exec postgres psql -U knowledge -d knowledge -c "SELECT id,user_id,upload_session_id,limit_key,amount,expires_at FROM quota_reservations WHERE status='HELD' ORDER BY expires_at;"
~~~

查看未结束上传：

~~~powershell
docker compose --env-file .env.kb exec postgres psql -U knowledge -d knowledge -c "SELECT id,user_id,file_id,status,expires_at,created_at FROM upload_sessions WHERE status IN ('INITIATED','FINALIZING') ORDER BY expires_at;"
~~~

查看文件状态积压：

~~~powershell
docker compose --env-file .env.kb exec postgres psql -U knowledge -d knowledge -c "SELECT status,count(*),min(created_at) AS oldest FROM files GROUP BY status ORDER BY status;"
~~~

若修改了 <code>POSTGRES_USER</code>/<code>POSTGRES_DB</code>，同步替换命令。不要手工 UPDATE quota 或上传状态；它们跨多个表并关联对象存储操作。优先使用 API 中止，或建设并运行受测试的 reconciliation job。

## 10. 备份、恢复与升级

### 10.1 备份

生产必须同时保护：

- PostgreSQL：定期 base backup + 连续 WAL 归档，满足明确 RPO/RTO；
- 对象存储：版本化、跨故障域复制，合规场景评估 Object Lock；
- 配置与密钥：可恢复但与数据备份隔离保管；
- 审计日志：写入独立、受限、防篡改的长期存储。

Redis 限流窗口可丢失并重建，不应成为业务恢复事实源。Compose 的 Redis AOF 只是开发便利。

只做备份不算完成：至少季度演练恢复 PostgreSQL 到指定时间，并抽样校验 file.object_key 对应对象、大小和状态。跨 PostgreSQL/S3 没有单一事务，需要记录恢复点并执行孤儿对账。

### 10.2 本地升级

先备份，再执行：

~~~powershell
docker compose --env-file .env.kb pull postgres redis minio
.\scripts\start.ps1 -EnvFile .env.kb
Invoke-RestMethod http://localhost:8000/health/ready
~~~

生产采用 expand/contract migration：

1. 先增加向后兼容 schema；
2. 发布兼容新旧 schema 的 API；
3. 后台回填；
4. 再删除旧列/约束。

不要在未验证备份与 downgrade 行为时直接执行 Alembic downgrade。大表 DDL 要评估锁、WAL、复制延迟和回滚窗口。

`20260714_0018` 建立内容版本快照与 API 凭据族，`20260714_0019` 收紧角色引用删除，`20260714_0020` 把聊天 replay 升级为外置密钥的 AES-256-GCM 并销毁历史可逆正文，`20260715_0021` 增加不可破坏的账号退休时间、执行人和原因约束。这些安全迁移是明确的 forward-only migration，`0020` 与 `0021` 均不可逆。回退必须在维护窗口恢复升级前的整库备份和匹配的旧应用，不能执行 Alembic downgrade、删除退休审计元数据或手工恢复旧明文列语义。

## 11. 停止与清理

停止但保留数据：

~~~powershell
docker compose --env-file .env.kb down
~~~

<code>docker compose --env-file .env.kb down -v</code> 会永久删除本地 PostgreSQL、Redis 和 MinIO volumes。只有确认不需要任何本地数据并已有必要备份时才可执行。

单独中止一个上传应优先调用：

~~~powershell
Invoke-RestMethod -Method Delete -Uri "http://localhost:8000/api/v1/files/uploads/$uploadSessionId" -Headers $headers
~~~

## 12. 从本地迁移到 10 TB+ 生产

上线清单：

- [ ] API 与对象存储全部 HTTPS；禁止 insecure 客户端开关；
- [ ] API 2–3 个以上跨故障域副本，配置 PodDisruptionBudget、readiness、优雅终止；
- [ ] 托管 PostgreSQL 多可用区或主备流复制，连接池、WAL/PITR 和恢复演练；
- [ ] Redis HA/TLS/私网，容量与延迟监控；
- [ ] 托管 S3，或 MinIO 多节点多盘纠删码；禁止单节点 Compose MinIO；
- [ ] bucket 私有、Block Public Access/等价策略、最小权限 service account、静态加密；
- [ ] 版本化/复制/保留策略和不完整 Multipart 生命周期；
- [ ] 自动扫描、MIME/魔数、解析沙箱、资源上限和审批策略；
- [ ] 过期会话、reservation、孤儿对象与 Multipart reconciliation；
- [ ] 文件删除、storage_bytes 退款、法律保全和审计流程；
- [ ] 统一 checksum 编码并签入 PUT，完成后强制校验；
- [ ] 结构化日志、指标、trace、告警、审计归档；
- [ ] 压测单 PUT、Multipart、并发 quota、Redis/PG 故障和对象存储 503；
- [ ] 安全测试覆盖 RBAC 提权、IDOR、JWT、预签名泄露、恶意文件和 SSRF。

MinIO 官方生产建议使用 Multi-Node Multi-Drive，并对纠删码、磁盘一致性、时间同步、负载均衡和容量余量进行专门规划。若没有对象存储运维团队，优先选择托管 S3。

## 13. 开发验证

安装开发依赖并运行：

~~~powershell
uv sync --extra dev
uv run pytest
uv run ruff check app tests scripts
uv run mypy app scripts/upload.py
~~~

涉及上传协议的改动至少验证：

- 单 PUT 的 Content-Type、会话 metadata 和 Content-Length；
- 首片、中间片、末片的精确 size_bytes；
- 10,000 part 上限规划；
- 同幂等键重试与冲突；
- 并发 reservation 不超额；
- URL 过期、403、429、5xx、网络中断和 checkpoint 恢复；
- 完成前源文件变化；
- 完成后 processing、审批后 available；
- 非 owner 与缺失权限不能下载。

架构依据、生产缺口与官方链接见 [ARCHITECTURE.zh-CN.md](./ARCHITECTURE.zh-CN.md)。
