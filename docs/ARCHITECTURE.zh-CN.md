# 企业知识库后台架构设计

本文描述当前仓库已经实现的后台、其安全与限额语义，以及从本地开发拓展到 10 TB 以上生产规模时应采用的目标架构。当前版本是可运行的管理与上传基础设施，不等同于已完成文档解析、全文检索或 RAG 的最终知识平台。

## 1. 结论与技术选型

核心选择是“元数据与文件字节分离”：

| 能力 | 当前实现 | 生产建议 | 选择理由 |
|---|---|---|---|
| API | Python 3.12、FastAPI、Pydantic | 多副本无状态容器 | 类型化契约、OpenAPI、异步数据库访问 |
| 元数据与策略 | PostgreSQL、SQLAlchemy、Alembic | 托管 PostgreSQL 或多可用区主备 | 用户、RBAC、配额和状态转换需要事务与唯一约束 |
| 文件字节 | S3 兼容对象存储；本地为 MinIO | AWS S3 或分布式 MinIO | 10 TB 以上不应由 API 本地磁盘或 PostgreSQL BLOB 承担 |
| 短时计数 | Redis + 原子 Lua | Redis Sentinel/Cluster 或托管 Redis | 所有 API 副本共享限流状态 |
| 上传数据面 | 短期预签名 PUT、S3 Multipart | 客户端直传对象存储 | API 不转发大文件，扩容主要处理控制面请求 |
| 认证 | 短期 JWT access token + 轮换 refresh token | TLS、外部密钥管理、可选企业 IdP | access token 只承载身份，动态权限每次从数据库解析 |
| 本地编排 | Docker Compose | Kubernetes/ECS/VM 编排 | Compose 只用于开发和单机验收，不具备生产冗余 |

对象存储比块存储更适合这里：对象以 key 访问、天然支持大对象分片、生命周期、版本化、跨区域复制和预签名访问。块存储仍适合作为 PostgreSQL 数据盘，但不应成为 10 TB 文档库的共享文件目录。

## 2. 系统边界与组件

~~~mermaid
flowchart LR
    U["浏览器 / scripts/upload.py"] -->|"TLS: 登录、元数据、RBAC 请求"| E["Ingress / WAF / API Gateway"]
    E --> A["FastAPI 无状态副本"]
    A -->|"事务、状态、审计"| P[("PostgreSQL")]
    A -->|"分布式限流"| R[("Redis")]
    A -->|"服务凭证：建分片会话、HEAD、签名"| O[("S3 / 分布式 MinIO")]
    U -->|"短期预签名 PUT/GET；不携带 JWT"| O
    A -.->|"待建设：可靠队列 / Outbox"| Q["扫描与解析 Worker"]
    Q -.->|"恶意软件、格式解析、索引结果"| O
    Q -.-> P
~~~

控制面是 FastAPI、PostgreSQL 和 Redis；数据面是客户端与对象存储。API 只返回具有限时、对象级权限的 URL，不接收 10 TB 文件字节。这使 API 副本能按请求数横向扩容，而非按文件吞吐扩容。

当前 Compose 包含 PostgreSQL、Redis、单节点 MinIO、迁移、幂等初始化、API 和不完整分片清理服务。单节点 MinIO 只能用于开发；MinIO 官方把多节点多盘拓扑列为生产推荐形态。

## 3. 上传与下载协议

### 3.1 上传顺序

~~~mermaid
sequenceDiagram
    participant C as "上传客户端"
    participant A as "FastAPI"
    participant D as "PostgreSQL"
    participant R as "Redis"
    participant S as "S3/MinIO"

    C->>A: POST /auth/token
    A-->>C: access + refresh token
    C->>A: POST /files/uploads（声明名称、大小、幂等键）
    A->>R: 用户级请求限流
    A->>D: 权限、有效限额、配额行锁与预留
    A->>S: 建立单 PUT 或 Multipart 会话
    A-->>C: 会话、分片计划、短期预签名 URL
    C->>S: PUT staging 单对象/Multipart 分片（精确 Content-Length）
    S-->>C: ETag
    C->>A: POST .../complete（全部 part_number + ETag）
    A->>S: CompleteMultipart 或 staging promote + HEAD
    A->>D: 校验大小；预留转已用；状态改为 processing
    A-->>C: FileRead(status=processing)
    Note over A,D: 只有 file:approve 可改为 available
~~~

具体规则：

1. <code>POST /api/v1/files/uploads</code> 先检查登录状态、<code>file:upload</code>、Redis 限流、允许的最终扩展名、单文件大小和配额。
2. 幂等键在“用户 + idempotency_key”上唯一；相同键和相同名称/大小返回原会话，不同参数返回 409。
3. 默认小于 100 MiB 使用单 PUT；达到阈值后使用 Multipart，默认目标分片 64 MiB。服务端会增大分片以保证不超过 10,000 片。
4. 单 PUT 先写不可下载的 <code>staging/</code> key，其签名包含 Content-Type、上传会话元数据和精确 Content-Length；大小验证后由服务端凭证复制到从未暴露写 URL 的 <code>objects/</code> key。Multipart 每个 URL 绑定 upload id、part number 和精确 Content-Length，part URL 响应同时返回 size_bytes 供客户端校验。
5. 客户端只按小批次申请 URL，避免大量 URL 在队列中等待到过期；并发 PUT 的 ETag 被原子写入本地 checkpoint。
6. 完成 Multipart 时必须提供从 1 到 part_count 的全部分片且恰好一次。服务端完成后用 HEAD 校验实际对象大小。
7. 上传完成只进入 <code>processing</code>。具有 <code>file:approve</code> 的管理员调用 <code>POST /files/{id}/approve</code> 后才进入 <code>available</code>。

AWS 官方规定 Multipart 最多 10,000 个 part，除最后一片外 part 为 5 MiB 到 5 GiB；当前规划器遵守 part 数上限。预签名 URL 是可重复使用至过期的 bearer capability，因此泄露 URL 等价于在有效期内泄露该对象操作能力。

### 3.2 恢复与失败

<code>scripts/upload.py</code> 将会话 ID、源文件大小/mtime、计划和已完成 ETag 写入源文件旁的 checkpoint，不保存密码、JWT 或预签名 URL。

- 网络中断：重跑相同命令，沿用幂等键并跳过 checkpoint 中已完成分片。
- URL 过期：当前运行会重新申请 URL；仍失败时保留 checkpoint 并清晰退出。
- 单 PUT：无法从字节偏移续传，失败时重传整个对象；相同对象 key 的 PUT 是可安全重试的会话内覆盖。
- 源文件变化：大小或 mtime 改变时拒绝完成，防止混合多个版本；使用 <code>--restart</code> 先 DELETE 旧会话、释放配额，再建新会话。
- 明确放弃：<code>DELETE /files/uploads/{upload_session_id}</code> 中止 Multipart/删除单对象并释放 HELD 配额。
- 后台还以对象存储不完整 Multipart 清理作为兜底；清理时间必须大于上传会话有效期。

### 3.3 下载

<code>POST /files/{file_id}/download</code> 依次检查：

1. <code>file:read</code>；
2. 文件属于当前用户，或用户拥有 <code>file:read:any</code>；
3. 文件状态是 <code>available</code>；
4. 原子消费一次 <code>daily_downloads</code>；
5. 返回最长 300 秒的 GET 预签名 URL。

当前“下载次数”语义是“成功签发下载 URL 的次数”，并非对象存储确认传输完成的次数；客户端未实际下载也会计数。这是刻意选择的可审计、可原子执行语义。

## 4. 状态机

~~~mermaid
stateDiagram-v2
    [*] --> uploading: "创建 File + UploadSession"
    uploading --> processing: "完成对象并验证实际大小"
    uploading --> failed: "大小不符 / 主动中止"
    processing --> available: "管理员批准"
    processing --> quarantined: "目标态：扫描不通过（待建设）"
    processing --> failed: "目标态：解析失败（待建设）"
    available --> deleted: "目标态：保留/删除流程（待建设）"
~~~

UploadSession 独立状态为 <code>initiated → finalizing → completed</code>（finalizing 主要保护 Multipart 完成重试），或进入 <code>failed / aborted / expired</code>。文件状态与上传会话分开是必要的：对象上传成功不代表内容安全、解析成功或可以下载。

## 5. 动态 RBAC

### 5.1 数据关系

~~~mermaid
erDiagram
    USERS ||--o{ USER_ROLES : assigned
    ROLES ||--o{ USER_ROLES : contains
    ROLES ||--o{ ROLE_PERMISSIONS : grants
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : catalog
    ROLES ||--o{ ROLE_LIMITS : configures
    LIMIT_DEFINITIONS ||--o{ ROLE_LIMITS : catalog
    USERS ||--o{ USER_LIMIT_OVERRIDES : overrides
    LIMIT_DEFINITIONS ||--o{ USER_LIMIT_OVERRIDES : catalog
    USERS ||--o{ FILES : owns
    FILES ||--|| UPLOAD_SESSIONS : uploaded_by
    UPLOAD_SESSIONS ||--o{ QUOTA_RESERVATIONS : holds
    USERS ||--o{ QUOTA_COUNTERS : consumes
    USERS ||--o{ REFRESH_TOKENS : rotates
    USERS ||--o{ AUDIT_LOGS : acts
~~~

权限不是写死在 token 中。每个受保护请求会从数据库解析当前用户的有效角色，因此角色删除、权限修改或带 expires_at 的分配到期可立即影响后续请求。

权限匹配语义：

- 精确权限，例如 <code>file:upload</code>；
- 资源通配，例如 <code>file:*</code> 可以满足任意 <code>file:...</code>；
- 全局 <code>*</code>；superuser 自动获得；
- 多角色权限取并集；
- 非 superuser 不能创建/修改高于自身 priority 的角色、系统角色，也不能授予自己没有的权限或更宽限额，防止权限提升。

当前权限目录至少覆盖文件读取/上传/批准、用户管理、角色读取/管理/分配等管理动作。目录由 bootstrap 幂等写入，角色 API 只能引用目录中存在的 code。

### 5.2 限额合并

多角色同一 limit key 的合并规则是：

1. 有限值取最大值；
2. 任一角色值为 SQL NULL，则结果为无限；
3. 用户级 override 最后覆盖角色结果，包括把无限改回有限或把有限改为无限；
4. 数值 0 表示禁止，不表示无限；
5. 缺失的上传/存储/下载限额在业务端点按 0 处理；缺失的 <code>requests_per_minute</code> 使用服务默认值。

| Limit key | 单位/窗口 | 执行点 | 当前语义 |
|---|---|---|---|
| max_upload_bytes | bytes / per_request | 发起上传 | 单个声明对象的最大字节数 |
| daily_upload_bytes | bytes / UTC day | 发起时预留，完成时消费 | 防止多个并发上传同时穿透日额度 |
| storage_bytes | bytes / lifetime | 发起时预留，完成时消费 | 当前累计成功上传量；MVP 尚无删除退款 |
| daily_downloads | count / UTC day | 签发下载 URL | 每次 grant 计 1 |
| requests_per_minute | requests / fixed minute | 每个受保护 API | Redis 原子固定窗口；超限 429 |

配额表使用“used + reserved”模型。发起上传时按固定 key 顺序锁定 counter 行并创建 reservation；完成后 reserved 转 used；中止或大小不符时释放。唯一约束 <code>(user_id, limit_key, window_start)</code> 与行锁共同防止双花。

Redis 不可用时受保护端点 fail closed，返回 503，而不是绕过限流。Redis 官方建议在多副本服务中用共享 Redis 与原子 Lua 完成 read-decide-update。

## 6. 数据库模式与约束

核心表如下：

| 表 | 关键字段/约束 |
|---|---|
| users | email 唯一；status；is_superuser；token_version |
| roles | code 唯一；priority；is_system |
| permissions | code 唯一的权限目录 |
| user_roles | user_id + role_id 唯一；assigned_by；expires_at |
| role_permissions | role_id + permission_id 唯一 |
| limit_definitions | key 唯一；unit；window |
| role_limits | role + definition 唯一；value 非负或 NULL |
| user_limit_overrides | user + definition 唯一；value 非负或 NULL |
| files | owner；私有 object_key 唯一；声明/实际大小；状态；自定义 JSON |
| upload_sessions | file 一对一；用户 + 幂等键唯一；storage upload id；计划和过期时间 |
| quota_counters | 用户 + key + window_start 唯一；used/reserved 非负 |
| quota_reservations | upload + key 唯一；HELD/CONSUMED/RELEASED/EXPIRED |
| refresh_tokens | 只存 token fingerprint；过期与撤销时间 |
| audit_logs | actor、action、resource、request_id、IP、details、时间 |

PostgreSQL 是授权与状态事实源。Redis 只保存可重建的短时限流计数，对象存储只保存不可查询的文件字节；不要从对象 key 推断权限。

生产中可在应用层检查之外增加 PostgreSQL Row-Level Security 作为纵深防御。启用 RLS 后若无匹配 policy 默认拒绝，但表 owner 通常绕过 RLS，因此应用数据库角色与迁移 owner 必须分离。

## 7. 安全边界

| 边界 | 已实现 | 生产强化 |
|---|---|---|
| 客户端 → API | JWT、issuer/audience/type/algorithm 校验；短 access；refresh 轮换；请求 ID | 仅 TLS、WAF、密钥管理、企业 OIDC、MFA |
| 客户端 → 对象存储 | 短期预签名、私有 bucket、精确 key/part/Content-Length；上传器禁重定向 | TLS、限制 source IP/VPC endpoint、严格 CORS、URL 日志脱敏 |
| API → PostgreSQL | 参数化 ORM、事务、唯一约束、行锁 | 独立最小权限角色、RLS、mTLS、PITR |
| API → Redis | 认证密码；原子 Lua；失败关闭 | TLS、网络隔离、HA、脚本与 key 容量监控 |
| 未信任文件 → 平台 | 扩展名 allowlist、文件名 basename、大小限制、processing 审批门 | 杀毒、MIME/魔数、解压炸弹限制、CDR、沙箱解析 |

JWT 校验必须固定允许算法并检查 issuer、audience 和 token 类型，不能信任 token 自带的算法选择；RFC 8725 给出了对应最佳实践。用户角色替换或账户状态变更会增加 token_version，使既有 token 失效；角色策略内容本身则因每次动态解析而立即生效。

上传文件名与 MIME 都不可信。OWASP 建议扩展名 allowlist、重命名、大小限制、内容验证、恶意软件扫描、存储在 webroot 之外并限制授权。当前版本只实现其中的基础边界；<code>processing → available</code> 的人工批准不是恶意软件扫描替代品。生产上线前必须接入扫描/解析 worker，只有扫描通过才能批准。

当前 SHA-256 字段采用 64 位十六进制“客户端声明值”。服务端完成阶段强制校验的是对象实际大小；尚未把该 hash 签入所有 PUT 并做端到端强制比对。S3 的 ChecksumSHA256 响应通常是 44 字符 base64，二者不得直接比较。需要强完整性时，应统一 canonical 编码、把校验头加入预签名请求，并在完成后严格比较。

## 8. 10 TB 以上部署

### 8.1 推荐拓扑

| 层 | 生产最小建议 |
|---|---|
| Ingress | 两个以上入口实例、TLS 1.2+、上传控制面限流 |
| API | 跨可用区至少 2–3 个副本；无本地持久数据；readiness 连接 PG/Redis |
| PostgreSQL | 托管多可用区或主库 + 流复制 standby；连接池；WAL 归档与 PITR |
| Redis | 托管 HA 或 Sentinel/Cluster；仅私网；持久化不是业务恢复的唯一依据 |
| 对象存储 | 托管 S3，或 MinIO 多节点多盘 + 纠删码 + 负载均衡；禁止单节点卷 |
| Worker | 独立伸缩的扫描、解析、缩略图和索引消费者；资源/网络沙箱 |
| 可观测性 | 指标、结构化日志、审计日志归档、分布式 trace、告警 |

10 TB 是容量门槛而不是特殊数据库门槛。对象元数据仍在 PostgreSQL，文件容量与 API 内存无关。容量规划至少包含：

- 可用容量 = 原始容量扣除纠删码/副本、版本、临时 Multipart 和安全余量；
- 保持足够增长余量，不到磁盘接近满时才扩容；
- 峰值吞吐约为“并发上传数 × 单上传目标吞吐”，据此测算网络、对象存储连接与客户端 workers；
- PostgreSQL 主要按文件数、审计量、配额写入和索引测算，而非按 TB 文件字节测算；
- Multipart 会占用未完成 part 的计费容量，必须有过期与清理；
- 大量对象列表使用游标分页；当前文件列表还是 offset，达到高对象数前应升级。

AWS S3 官方建议以多连接横向扩展吞吐、监控 503 并重试。Kubernetes HPA 可按 CPU、内存或自定义指标横向调整无状态 API；上传字节绕过 API 后，建议优先用请求速率、p95 延迟和 DB pool 饱和度而非网络字节作为 HPA 指标。

### 8.2 一致性与恢复

这里存在 PostgreSQL 与对象存储两个系统，不能假装存在跨系统 ACID：

- 发起时先在数据库创建记录/预留，再创建存储会话；数据库提交失败会尝试 abort。
- 完成时对象可能先成功组装，随后数据库提交失败；API 重试与 maintenance worker 会识别 `FINALIZING` 中“对象已存在但会话未完成”，通过 HEAD/大小对账后消费预留或回收失败会话。
- 生产仍应增加全量 outbox/reconciliation job，覆盖数据库记录之外的孤儿对象、跨区域复制状态和长期漂移；当前 worker 聚焦 UploadSession、HEAD、过期 reservation 和不完整 Multipart。
- PostgreSQL 备份与对象版本/复制应共享恢复点记录；灾难演练要验证“元数据有对象、对象有元数据”两类孤儿处理。

## 9. 后续处理流水线

为了支持 txt、Office、CSV、PDF 和 PowerPoint 的安全检索，建议按以下顺序建设：

1. 上传完成写 transactional outbox，不直接在请求内解析；
2. worker 拉取对象到隔离的临时目录，执行杀毒、魔数/MIME、压缩层级和资源限制；
3. 旧版二进制 Office 与现代 OOXML 分开解析；转换工具在无网络、只读根文件系统、CPU/内存/时限约束的沙箱运行；
4. 解析产物按文件版本保存，文本分块和 embedding 也绑定版本；
5. 只有扫描与必要解析成功，才允许 <code>processing → available</code>；
6. 全部状态转换、重试和人工覆盖写审计日志。

搜索层可从 PostgreSQL FTS 起步；文档数和向量规模增大后使用 OpenSearch 或专用向量数据库。原始对象、解析文本、索引都必须以 file_id + version 关联，避免覆盖后检索到旧内容。

## 10. 当前生产缺口

以下项目不是“以后优化”，而是正式对外部署前的门槛：

- 自动恶意软件扫描、内容类型/魔数校验、解析沙箱和审批策略；
- 全量孤儿对象扫描、transactional outbox 与跨区域/跨账户存储对账（过期 UploadSession、HELD reservation 和 `FINALIZING` 基础恢复已实现）；
- 文件删除、保留策略、storage_bytes 退款及法律保全流程；
- 用户级 limit override、带到期时间的角色分配、审计查询等完整管理 API（底层表与权限目录已预留）；
- 强制端到端 checksum 契约；
- PostgreSQL HA/PITR、对象版本/复制、Redis HA 与定期恢复演练；
- 指标、trace、集中日志、审计日志防篡改归档和告警；
- API 数据库最小权限与可选 RLS；
- 针对角色变更、配额竞争、预签名泄露、恶意文件和灾难恢复的安全测试。

## 11. 官方参考

- [Amazon S3 Multipart upload limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html)
- [Amazon S3 Multipart upload overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html)
- [Amazon S3 presigned URL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- [Amazon S3 abort incomplete Multipart](https://docs.aws.amazon.com/AmazonS3/latest/userguide/abort-mpu.html)
- [Amazon S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Amazon S3 performance guidelines](https://docs.aws.amazon.com/AmazonS3/latest/userguide/optimizing-performance-guidelines.html)
- [MinIO multi-node multi-drive deployment](https://min.io/docs/minio/linux/operations/install-deploy-manage/deploy-minio-multi-node-multi-drive.html)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL Continuous Archiving and PITR](https://www.postgresql.org/docs/current/continuous-archiving.html)
- [PostgreSQL warm standby](https://www.postgresql.org/docs/current/warm-standby.html)
- [Redis distributed rate limiter](https://redis.io/docs/latest/develop/use-cases/rate-limiter/)
- [Kubernetes Horizontal Pod Autoscaling](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/info/rfc8725/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
