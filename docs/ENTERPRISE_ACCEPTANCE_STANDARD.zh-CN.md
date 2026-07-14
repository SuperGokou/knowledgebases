# 企业知识库超级详细验收标准

本标准适用于江苏和熠光显有限公司企业知识中台的代码、Web 工作台、FastAPI 控制面、PostgreSQL、Redis、对象存储、OKF、知识问答、模型管理，以及通用云 Linux 离线部署。它是发布门禁，不是功能愿望清单；任何一项只有在产生可复核证据后才能判定通过。

## 1. 判定规则

| 等级 | 含义 | 发布规则 |
|---|---|---|
| P0 | 安全、数据正确性、核心业务或恢复能力的硬阻断 | 任一项失败或无法验证，结论为 `FAIL` |
| P1 | 企业正式生产必须具备的可靠性、运维与可用性 | P0 全过但任一 P1 失败/阻断，结论为 `CONDITIONAL` |
| P2 | 下一阶段体验、效率和规模优化 | 不改变 P0/P1 结论，但必须进入版本计划 |

最终结论只有三种：

- `PASS`：全部 P0、P1 通过；
- `CONDITIONAL`：全部 P0 通过，但存在失败或未验证的 P1；
- `FAIL`：至少一个 P0 失败/阻断，或者验收证据发生凭据、内部文档、预签名 URL 泄漏。

“代码存在”“文档写了”“开发者口头确认”“单元测试大部分通过”均不能单独作为验收通过依据。

## 2. 证据规范

每项证据必须包含：Gate ID、Git SHA、环境、开始/结束时间、执行命令或测试名称、退出码、关键断言、脱敏输出、执行人和复核人。禁止记录 `.env`、JWT、Refresh Token、API Key、数据库密码、模型密钥、完整公网 IP、企业文档正文、完整预签名 URL 或 Cookie。

| 证据类型 | 最低要求 |
|---|---|
| 自动测试 | 命令、版本、总数、失败数、退出码；失败截图不得含数据/密钥 |
| API 验收 | 请求方法、脱敏路径、状态码、业务错误码、`x-request-id` |
| 数据库验收 | 迁移 revision、断言 SQL、行数/约束结果；不输出连接串 |
| UI 验收 | 浏览器/分辨率、步骤、断言、脱敏截图；Trace 不记录表单密钥 |
| 性能验收 | 数据集、并发、持续时间、P50/P95/P99、错误率、资源曲线 |
| 恢复演练 | 备份 ID、恢复目标、RPO/RTO、哈希抽检、失败/重试记录 |
| 安全验收 | 测试授权范围、工具版本、发现/豁免、修复复测 |

## 3. 验收环境

| 环境 | 用途 | 数据要求 |
|---|---|---|
| 本地/CI | 单元、契约、静态、构建、Compose 解析 | 仅合成数据，不使用企业真实数据 |
| 集成环境 | PostgreSQL/Redis/MinIO、并发与故障注入 | 隔离测试账号和合成文件 |
| 浏览器 E2E | 登录、聊天、后台管理、权限、响应式 | 临时账号，执行后自动销毁 |
| 通用云 Linux 离线验收 | 8C16G/300GB、无外网、恢复、负载、升级回滚 | 批准的脱敏/合成数据集 |

通用云 Linux 离线验收的最低硬件为 8 个逻辑 CPU、15GB 可用内存、300GB 物理磁盘、初始至少 240GB 可用空间。规格不足时必须终止，不得降低门槛后继续；云厂商不是验收条件。

## 4. 代码、供应链与发布

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| REL-P0-001 | P0 | Git 工作区与发布制品可追溯 | 报告记录 SHA；发布镜像标签与 SHA 一致；工作树无未提交生产修改 |
| REL-P0-002 | P0 | Python/Node 锁文件严格生效 | `uv sync --frozen`、`npm ci` 均退出 0 |
| REL-P0-003 | P0 | 后端静态质量 | Ruff 0 错误；严格 MyPy 0 错误 |
| REL-P0-004 | P0 | 前端静态与构建 | ESLint 0 warning；TypeScript/Next production build 退出 0 |
| REL-P0-005 | P0 | 自动测试回归 | 后端、前端失败数均为 0；后端总覆盖率 ≥80% |
| REL-P0-006 | P0 | 数据库 revision 一致 | 运行库 `alembic current --check-heads` 退出 0，与仓库全部 head 完全一致 |
| REL-P0-007 | P0 | 依赖漏洞门禁 | 运行依赖 Critical=0、High=0；例外必须有负责人、到期日和补偿控制 |
| REL-P0-008 | P0 | 镜像不可变 | 所有离线镜像固定 digest/签名清单；目标架构全部为 `linux/amd64` |
| REL-P1-001 | P1 | SBOM 与离线包完整性 | API/Web/基础镜像都有 SBOM；离线 tar 有 SHA-256 与签名验证记录 |
| REL-P1-002 | P1 | CI 门禁不可绕过 | main 分支保护要求后端、前端、验收 Gate 全绿；普通开发者不能跳过 |

## 5. 认证、会话与滥用防护

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| AUTH-P0-001 | P0 | 密码安全 | Argon2 recommended；数据库无明文/可逆密码；错误密码与不存在用户返回同一状态和错误码 |
| AUTH-P0-002 | P0 | JWT 完整声明 | 强制校验 `iss/aud/exp/nbf/iat/jti/typ/sub/ver`；access/refresh 互换接受率 0% |
| AUTH-P0-003 | P0 | Token 生命周期 | access ≤60 分钟，refresh ≤90 天；生产默认 access ≤15 分钟 |
| AUTH-P0-004 | P0 | 即时撤销 | 禁用用户、角色/账号版本变化后，旧 access 在下一次受控请求立即失败 |
| AUTH-P0-005 | P0 | Refresh 单次使用 | 20 个并发请求复用同一 refresh，恰好 1 个成功 |
| AUTH-P0-006 | P0 | Refresh 重放响应 | 重放旧 refresh 后 replacement/family 全部撤销，后续使用返回 401 |
| AUTH-P0-007 | P0 | 登录限流 | IP 与账号双维度原子限流；超过阈值返回 429；Redis 故障时 fail closed 503 |
| AUTH-P0-008 | P0 | BFF Cookie | `HttpOnly; Secure; SameSite=Lax`；鉴权响应 `Cache-Control: no-store` |
| AUTH-P0-009 | P0 | CSRF/同源 | 所有变更型 BFF 请求校验同源；跨站请求 100% 返回 403 |
| AUTH-P0-010 | P0 | 登录入口与角色路由 | 单一 `/login`；用户不选择角色；登录落点由服务端实际权限决定 |
| AUTH-P1-001 | P1 | 管理员强认证 | 正式商用管理员启用 WebAuthn/TOTP；恢复码一次性且加密保存 |
| AUTH-P1-002 | P1 | 会话管理 | 可查询当前会话、撤销单会话、撤销全部会话，并记录审计 |

## 6. 动态 RBAC 与知识库 ACL

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| RBAC-P0-001 | P0 | 动态角色 | 新角色无需重启即可创建、修改、分配；系统角色不可编辑 |
| RBAC-P0-002 | P0 | 防权限提升 | 非超级用户不能授予自己没有的 permission、优先级或更高额度 |
| RBAC-P0-003 | P0 | 角色过期 | 过期角色在下一次请求不再生效 |
| RBAC-P0-004 | P0 | ACL 双门禁 | KB 操作必须同时满足全局 permission 与 `reader/editor/manager` 等级 |
| RBAC-P0-005 | P0 | 资源隐藏 | 无 KB grant 返回 404；已知资源但等级不足返回 403 |
| RBAC-P0-006 | P0 | Draft 隔离 | Draft 仅 manager 可见；reader/editor 搜索和 RAG 只能命中 published |
| RBAC-P0-007 | P0 | API Key 权限交集 | 有效权限=Key scope∩用户当前权限∩KB allowlist；任一撤销立即生效 |
| RBAC-P0-008 | P0 | 前后端一致 | 隐藏按钮不替代后端授权；伪造前端角色/Header/Cookie 成功率 0% |
| RBAC-P1-001 | P1 | 权限变化收敛 | 当前用户权限变化后，导航和当前页面在一次交互/请求内刷新或退出 |
| RBAC-P1-002 | P1 | 权限矩阵回归 | 无 grant/reader/editor/manager × 核心 API 全矩阵自动化覆盖 |

## 7. 文件、配额、审批与对象存储

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| FILE-P0-001 | P0 | 上传前校验 | 扩展名、规范文件名、非零大小、单文件/日上传/总存储额度在签 URL 前校验 |
| FILE-P0-002 | P0 | 并发额度 | 剩余100MiB时并发两个80MiB上传，只能一个预留成功；计数不超卖、不为负 |
| FILE-P0-003 | P0 | 单段完整性 | 签名绑定 Content-Length；完成时大小和 SHA-256 全部一致 |
| FILE-P0-004 | P0 | Multipart 完整性 | part 编号唯一完整；篡改单 part 但保持长度时最终摘要校验失败 |
| FILE-P0-005 | P0 | 私有暂存 | 上传只进入私有 `staging/`；未验证对象不能下载或审批 |
| FILE-P0-006 | P0 | 恶意文件门禁 | EICAR、伪扩展、宏 Office、PDF JS、加密/损坏文件、解压炸弹全部隔离；扫描故障 fail closed |
| FILE-P0-007 | P0 | 审批权限 | 只有 KB manager 且有 `file:approve` 才可发布 |
| FILE-P0-008 | P0 | 审批证据 | 保存 reviewer、时间、文件版本、哈希、扫描结论、OKF review/意见 |
| FILE-P0-009 | P0 | 下载门禁 | 非 AVAILABLE、越权、超额度均不得返回下载授权 |
| FILE-P0-010 | P0 | 下载额度语义 | 若按次数，同一 grant 第二次兑换失败；若按流量，存储事件计量误差≤1% |
| FILE-P0-011 | P0 | 失败补偿 | DB 提交/对象 COPY/完成接口失败后可重复收敛，不重复计费且无孤儿对象 |
| FILE-P0-012 | P0 | 文件删除闭环 | 具备权限、二次确认、软删除/保留审计；无权限 UI 不显示且 API 403 |
| FILE-P1-001 | P1 | 大文件恢复 | Multipart 中断后可恢复；重复完成幂等；过期分片按策略清理 |
| FILE-P1-002 | P1 | 容量熔断 | 磁盘70%告警、80%停止批量上传、90%拒绝新上传，均有自动化证据 |

## 8. PostgreSQL、Redis 与数据一致性

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| DATA-P0-001 | P0 | 运行身份最小权限 | runtime 的 `rolsuper/createdb/createrole/replication/bypassrls` 全 false |
| DATA-P0-002 | P0 | 迁移/运行分权 | owner/migrator/runtime 身份不同；runtime 无法 CREATE ROLE/DATABASE/EXTENSION/TABLE |
| DATA-P0-003 | P0 | 事务原子性 | quota、refresh、角色替换、默认模型、OKF claim 使用事务/行锁并通过真实 PG 并发测试 |
| DATA-P0-004 | P0 | Redis 原子限流 | Lua/事务原子执行；并发超发为0；`noeviction` 且 evicted_keys=0 |
| DATA-P0-005 | P0 | Redis 冷启动 | 全新数据目录首次启动 healthy；AOF 重启恢复；RestartCount=0 |
| DATA-P0-006 | P0 | Readiness 真值 | 检查 DB、Redis、MinIO、迁移 head；任一失败 `/health/ready` 返回 503 |
| DATA-P0-007 | P0 | Schema 安全默认 | 未来表/序列默认权限 fail closed；迁移有 advisory lock 和目标指纹 |
| DATA-P1-001 | P1 | 数据库超时 | 配置 statement/lock/idle transaction timeout；超时有 request ID 与告警 |
| DATA-P1-002 | P1 | 大表迁移 | 索引/回填对生产写入影响有基准；长锁超过批准阈值自动中止 |

## 9. OKF、检索、LLM 与防幻觉

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| AI-P0-001 | P0 | OKF 队列原子性 | 上传完成与 enqueue 同一事务；`file_id+version` 唯一 |
| AI-P0-002 | P0 | Worker 租约 | `SKIP LOCKED`+lease；过期 worker 不能发布；重复任务幂等 |
| AI-P0-003 | P0 | 外部处理同意 | KB manager 显式开启；真正发送前再次读取 consent；关闭竞态 provider 调用数=0 |
| AI-P0-004 | P0 | 离线不外发 | isolated 模式模型解析器 fail closed；API/maintenance/web 公网连接全部失败 |
| AI-P0-005 | P0 | 模型输出约束 | 严格 schema、额外字段拒绝、内容只进入 draft，不自动发布 |
| AI-P0-006 | P0 | 引用完整性 | 每个非空事实段引用有效 `[n]`；非法/遗漏引用立即降级确定性检索 |
| AI-P0-007 | P0 | 引用真实性 | 返回 citation 必须是正文/表格实际引用子集，并映射到 published entry |
| AI-P0-008 | P0 | 生成后审查 | review 超时、不可用、无效 JSON、未通过时 100% 降级检索，不返回模型草稿 |
| AI-P0-009 | P0 | 对抗评测 | ≥100例；虚构事实泄漏率0%；非法 citation 接受率0%；无结果时外部事实输出率0% |
| AI-P0-010 | P0 | 数据答案表格 | 标记为数据/比较/清单型时 table 必填；1–8列、1–50行、每格≤1000字且有引用 |
| AI-P1-001 | P1 | 独立审查 | reviewer 与 generator 隔离，或增加确定性 claim/evidence 校验；同模型自审不是唯一门禁 |
| AI-P1-002 | P1 | 检索质量 | 固定评测集 Recall@5≥90%、MRR≥0.80；ACL 泄漏率0% |
| AI-P1-003 | P1 | 模型审计 | 记录 provider/model/prompt版本/token/review reason，不记录敏感原文 |

## 10. API Key、模型配置与审计

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| API-P0-001 | P0 | Key 一次性明文 | 仅创建响应显示；DB只存高熵 Key SHA-256；刷新后全文不可恢复 |
| API-P0-002 | P0 | Key 状态 | revoke/expiry/用户禁用立即失效；Key和用户双层 RPM 原子执行 |
| API-P0-003 | P0 | 模型密钥 | 加密存储；读取接口永不回显；空值保存不覆盖旧密钥 |
| API-P0-004 | P0 | Provider SSRF 防护 | 仅批准 HTTPS host/443；禁止凭据、重定向、任意 workspace host |
| API-P0-005 | P0 | 单一默认模型 | 任意并发下恰好一个 default provider；切换有审计 |
| AUDIT-P0-001 | P0 | 关键事件覆盖 | 登录/refresh/logout、用户/角色/ACL、文件、Key、模型、OKF、下载全部记录结果 |
| AUDIT-P0-002 | P0 | 审计可查询 | `audit:read` 分页、时间/actor/action/resource/result过滤与受控导出 |
| AUDIT-P0-003 | P0 | 审计不可篡改 | 应用 runtime 执行 UPDATE/DELETE audit_logs 必须被 DB 拒绝 |
| AUDIT-P0-004 | P0 | 审计脱敏 | JWT、refresh、API/LLM key、密码、预签名参数命中数=0 |
| AUDIT-P1-001 | P1 | 留存与完整性 | 定义保留期、归档、hash/WORM校验、访问审批并季度抽查 |

## 11. Web、业务闭环与无障碍

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| WEB-P0-001 | P0 | 浏览器 E2E | Chromium桌面1440×900和移动390×844核心场景100%通过 |
| WEB-P0-002 | P0 | 无权直达 | 未登录/无权访问工作区时内容从未渲染，最终跳到安全落点 |
| WEB-P0-003 | P0 | 每答必有来源状态 | 有引用显示详情；无引用/失败也显示“无可核验来源”，不得省略来源区域 |
| WEB-P0-004 | P0 | 契约失败安全 | malformed citation/table 返回受控错误，不触发 React 崩溃 |
| WEB-P0-005 | P0 | 超时与取消 | 聊天70秒超时；新对话取消旧请求；迟到消息插入数=0 |
| WEB-P0-006 | P0 | 错误可恢复 | 聊天失败与知识库加载失败都有一键重试；重复点击只发一个请求 |
| WEB-P0-007 | P0 | 后台功能闭环 | 账号、角色/额度、文件、KB授权、API Key、模型切换均有成功/失败/无权限 E2E |
| WEB-P0-008 | P0 | 响应式 | 1440/768/390宽度页面级横向溢出=0；仅指定表格容器可滚动 |
| WEB-P1-001 | P1 | WCAG 2.2 AA | axe critical/serious=0；核心流程可仅键盘完成；焦点始终可见 |
| WEB-P1-002 | P1 | 动态播报 | loading=`status/live`、错误=`alert`、进度有ARIA数值、reduced-motion生效 |
| WEB-P1-003 | P1 | 中文一致性 | 用户文案为中文；技术英文有中文解释；`html lang=zh-CN` |
| WEB-P1-004 | P1 | 安全 Header | CSP、nosniff、DENY frame、严格 referrer、Permissions-Policy、HSTS全部存在 |
| WEB-P2-001 | P2 | 表格导出 | 支持复制表格/CSV与来源编号跳转，不复制隐藏敏感字段 |

## 12. 通用云 Linux 离线部署与网络

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| OPS-P0-001 | P0 | 项目隔离 | 仅操作 `heyi-kb-offline`；现有项目容器ID/端口/网络前后差异=0 |
| OPS-P0-002 | P0 | 内部网络 | backend/frontend 的 `Internal=true`；数据服务无宿主机端口 |
| OPS-P0-003 | P0 | 公网出口 | API/maintenance/web 访问公共IP、DNS及三家模型域名全部失败 |
| OPS-P0-004 | P0 | 内部连通 | API访问 postgres/redis/minio 成功；Web访问 API 成功 |
| OPS-P0-005 | P0 | 冷启动 | 全新空数据盘启动；长期服务 healthy；RestartCount=0 |
| OPS-P0-006 | P0 | 维护稳定 | `maintenance --once`退出0；30分钟≥10周期；重启数0 |
| OPS-P0-007 | P0 | TLS身份 | 企业CA验证成功、SAN匹配、剩余期≥30天；正式证据禁止 `--insecure` |
| OPS-P0-008 | P0 | 防火墙 | 仅批准VPN/办公CIDR访问19443/19444；SSH仅堡垒/管理网；出站默认拒绝 |
| OPS-P0-009 | P0 | 日志不泄密 | 上传/下载后所有日志搜索 `X-Amz-Signature/Credential/Token` 命中数=0 |
| OPS-P0-010 | P0 | 断网制品启动 | `--pull never --no-build`启动成功，期间外网依赖请求数=0 |
| OPS-P1-001 | P1 | 资源余量 | 常态容器CPU预算≤6.5核；宿主机保留≥1.5核和≥2GB内存 |
| OPS-P1-002 | P1 | 优雅停止 | PostgreSQL/MinIO/API有stop_grace_period；强杀次数=0 |

## 13. 性能、容量与稳定性

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| PERF-P0-001 | P0 | 基准数据集 | ≥10万published entry、150GB对象、1000用户、100角色 |
| PERF-P0-002 | P0 | 稳态负载 | 30分钟；20并发检索用户+8并发Multipart；5xx≤0.1% |
| PERF-P0-003 | P0 | 控制API延迟 | P95≤500ms、P99≤1.5s（不含对象字节传输） |
| PERF-P0-004 | P0 | 检索延迟 | 确定性检索 P95≤2s、P99≤5s |
| PERF-P0-005 | P0 | 资源稳定 | 无OOM/重启；CPU均值≤75%；内存≤85%；Redis eviction=0 |
| PERF-P0-006 | P0 | 数据库稳定 | 活跃连接<80；死锁=0；未批准长事务=0；锁等待符合阈值 |
| PERF-P1-001 | P1 | 容量预测 | 30/90/180天容量预测，误差≤20%；到80%前有扩容窗口 |
| PERF-P1-002 | P1 | 降级 | 本地模型/扫描/对象存储变慢时队列有界，控制面不级联崩溃 |

## 14. 备份、恢复、升级与灾难恢复

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| DR-P0-001 | P0 | 独立备份介质 | 备份不与数据盘同故障域；静态加密；访问最小权限 |
| DR-P0-002 | P0 | 元数据RPO | PostgreSQL/WAL 恢复点丢失≤15分钟 |
| DR-P0-003 | P0 | 整套RTO | 新的一次性主机恢复到可登录/检索/下载≤4小时 |
| DR-P0-004 | P0 | 对象完整性 | 恢复后抽检≥1000对象，大小和SHA-256一致率100% |
| DR-P0-005 | P0 | 配置/CA恢复 | Caddy CA、环境密钥、Compose清单恢复且权限正确，不写入报告 |
| DR-P0-006 | P0 | 恢复演练 | 首次上线前完成；以后每季度；失败必须创建整改项 |
| DR-P0-007 | P0 | 升级前置 | 升级前备份验证、迁移克隆演练、镜像摘要和回滚版本齐全 |
| DR-P0-008 | P0 | 回滚 | 15分钟内恢复旧版本；核心数据无丢失；其他Compose项目差异=0 |
| DR-P1-001 | P1 | Redis恢复 | AOF损坏/丢失场景有预期；安全限流状态恢复或fail closed |

## 15. 可观测性、运维与合规

| Gate ID | 级别 | 验收要求 | 方法与通过阈值 |
|---|---|---|---|
| OBS-P0-001 | P0 | 请求关联 | API错误、审计、代理日志可用同一 `x-request-id` 关联，格式受控 |
| OBS-P0-002 | P0 | 核心告警 | 服务down、迁移漂移、磁盘、备份失败、队列积压、5xx、登录攻击均有告警 |
| OBS-P0-003 | P0 | 告警送达 | 每类告警演练送达≤5分钟，有确认、升级和关闭记录 |
| OBS-P0-004 | P0 | 日志脱敏 | 自动扫描凭据/文档/预签名参数命中0；日志只保留批准字段 |
| OBS-P1-001 | P1 | 指标 | 主机/容器/PG/Redis/MinIO/API/队列指标有仪表盘和阈值 |
| OBS-P1-002 | P1 | 留存 | 业务/安全/审计日志保留期、容量、归档与删除责任人明确 |
| COMP-P0-001 | P0 | 数据驻留 | 离线部署运行时不调用外部DB/Redis/S3/LLM；数据跨境路径=0 |
| COMP-P0-002 | P0 | 账号与权限评审 | 上线前完成管理员、SSH、Docker、数据库、备份介质权限复核 |
| COMP-P1-001 | P1 | 制度评审 | ICP、等保、隐私、员工数据、商业计划和软件许可由负责人签署结论 |

## 16. 必须执行的业务场景

1. 超级管理员、聊天用户、知识编辑、文件上传、只读、无权限用户分别登录并验证唯一落点。
2. 无权限用户直接访问每个管理路由，确认页面内容从未短暂渲染。
3. 创建角色、设置有限/无限/未设置额度、分配用户、撤销角色并验证即时生效。
4. 建立两个知识库，执行 reader/editor/manager 全矩阵，确认跨库搜索和引用泄漏为0。
5. 单段和Multipart各上传一次；注入对象拒绝、缺ETag、分片篡改、DB提交失败和重复完成。
6. 审批 EICAR、伪扩展、宏Office、PDF JS、加密/损坏/高压缩比文件，全部必须阻断。
7. 提问有结果、无结果、数据比较、prompt injection、伪引用、review超时/无效JSON，检查来源和降级。
8. 创建/撤销 API Key；切换模型；确认旧密钥不回显且所有操作有审计。
9. 断开公网后重启所有离线服务，验证登录、检索、上传、审批、下载和本地维护。
10. 从独立备份恢复到一次性主机，执行业务抽样、哈希校验、性能冒烟和回滚。

## 17. 推荐自动化命令

```powershell
uv run python scripts/acceptance.py --profile local --report-dir artifacts/acceptance
uv run pytest --cov=app --cov-report=term-missing --cov-fail-under=80
uv run ruff check .
uv run mypy app scripts

Push-Location web
npm run lint
npm test
npm run build
Pop-Location

docker compose `
  --project-name heyi-kb-offline `
  --env-file deploy/tencent/offline.env.example `
  --file deploy/tencent/compose.offline.yml `
  --profile ops config --quiet
```

真实服务器命令、TLS/断网、备份恢复和负载步骤暂以[离线企业部署（历史文件名）](TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md)中的通用 Linux 步骤为准；其中厂商专属网络或对象存储内容不作为当前目标主机事实。未在真实 8C16G/300GB 环境执行的 Gate 必须标记 `blocked`，不得标记 `passed`。
