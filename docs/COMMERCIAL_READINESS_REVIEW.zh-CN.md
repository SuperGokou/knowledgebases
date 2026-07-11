# 商业版代码审计与交付报告

> 审计日期：2026-07-11<br>
> 审计范围：FastAPI、Next.js BFF/前端、PostgreSQL/Supabase、Redis/Upstash、S3/COS、Vercel 部署与工程化门禁<br>
> 结论：`DONE_WITH_CONCERNS`——可作为受控内部 Beta 运行；在下列 P1 门槛关闭前，不批准作为中国境内企业正式生产系统对外发布。

## 1. 执行摘要

仓库已经具备一套质量较好的企业知识库控制面基础：动态 RBAC、知识库级 ACL、配额预留、对象存储直传、API Key、模型供应商管理、OKF 草稿门禁和带结构化来源的问答都已形成可运行闭环。本轮确认并修复了导致“知识问答”页面崩溃的 React Effect 缺陷，同时补强了运行时 API 契约、请求超时/取消、错误关联、OKF 审批时序、生产配置校验和 CI 门禁。

系统仍有几项不能用文案或单元测试代替的正式上线工程：恶意文件扫描与隔离解析、对象版本一致性与故障对账、刷新令牌盗用检测、预认证滥用限流、近实时任务队列、跨区数据库迁移、备份恢复演练和集中可观测性。10 TB 是当前架构的容量目标，不是已经完成的容量或性能认证。

## 2. 发布判定

| 使用场景 | 判定 | 前提 |
|---|---|---|
| 本地开发 / 功能演示 | 通过 | 使用非生产数据和独立测试凭据 |
| 受控内部 Beta | 有条件通过 | 限定可信员工、禁止敏感文件、每日人工审计异常 |
| 公网客户 Demo | 有条件通过 | 使用脱敏示例数据；持续监控 Vercel 与 API 健康状态 |
| 中国境内企业正式生产 | 不通过 | 必须先关闭本文全部 P1，并完成 ICP/等保/数据跨境专项评估 |
| 10 TB 生产容量承诺 | 不通过 | 必须完成容量、并发、故障注入、恢复和成本基准测试 |

## 3. 本轮已关闭的问题

| 问题 | 风险 | 处置 |
|---|---|---|
| 聊天页 `TypeError: i is not a function` | 连续消息更新时整页进入错误边界 | Effect 改为显式 `void` 块体；隔离被浏览器扩展包装的 `scrollIntoView()` 返回值，并加入回归测试 |
| 成功响应仅做 TypeScript 强转 | 畸形/漂移的问答 JSON 可再次使 React 渲染崩溃 | 新增 `ChatReply` 运行时契约，非法响应以受控 502 失败关闭 |
| BFF 与聊天请求没有截止时间 | 上游挂起会占用函数、会话刷新和用户界面 | 为服务器回源和聊天请求增加有界超时、取消与新对话中止 |
| 错误无法跨层关联 | 用户只有笼统错误，日志难以定位 | 保留 `x-request-id`，错误边界记录脱敏摘要并向用户显示错误编号 |
| 无效 `FASTAPI_URL` 可使 Function 直接崩溃 | 产生 `FUNCTION_INVOCATION_FAILED` | BFF 将配置错误转换为受控 503，避免进程级异常 |
| 文件先审批、模型后转换可自动发布 | 模型派生内容绕过独立审核 | OKF 派生条目始终保存为草稿；转换中的文件禁止审批 |
| 生产可接受明文 Redis、示例对象存储凭据或通配 CORS | 中间人、错误部署或跨站访问风险 | 生产启动时 fail closed，强制 `rediss://`、精确 Origin 和非示例对象存储凭据 |
| Refresh Token 请求体无合理上限 | 匿名端点可被超长字符串消耗资源 | 限制为 4 KiB |
| 模型切换后仍显示“DeepSeek 自动转换” | 管理员可能误判数据外发目标 | 文案改为当前启用的外部模型，并明确 DeepSeek/Qwen/MiniMax |
| 中文整句被当成一个检索词 | 数据存在时仍错误返回“无结果” | 为阶段一 PostgreSQL/ILIKE 检索增加中文重叠二元词切分和真实搜索回归测试 |
| 仓库缺少自动发布门禁 | 回归可直接进入部署 | 新增前后端 CI：Lint、类型、测试、覆盖率、构建、依赖审计和迁移验证 |

## 4. 正向安全与架构能力

- 密码采用 Argon2 单向哈希；未知账号走 dummy hash，降低账号枚举时序差异。
- JWT 固定算法并校验 issuer、audience、token type、JTI、过期时间和 `token_version`。
- 权限在请求时动态解析；角色变更和知识库授权不依赖旧 Token 中的静态权限。
- API Key 使用高熵随机值，数据库只保存摘要；支持 scope、知识库范围、过期和撤销。
- 文件字节不经过 Serverless API；控制面只签发短期对象级 URL，元数据与对象存储分离。
- 上传配额使用 `used + reserved`、事务锁和幂等状态，防止常见的并发穿透。
- 外部模型密钥不进入浏览器；每个知识库默认禁止正文外发，需 Manager 显式开启。
- 在线数据库现有业务表已启用 RLS；匿名和普通认证 Data API 角色当前没有业务表权限。

## 5. P1：正式商用发布阻断项

### P1-01 文件安全门

当前主要验证扩展名、声明大小和部分摘要，没有 MIME/魔数、恶意软件、宏、PDF 活动内容、压缩炸弹或 CDR 门禁。正式发布必须增加隔离扫描 Worker，持久化 `scan_status`，且只有 `CLEAN` 文件可以审批、解析或下载。

验收：EICAR、伪造扩展名、带宏 Office、PDF JavaScript、加密/损坏文件和高压缩比文件均有自动化拒绝测试；扫描服务故障时 fail closed。

### P1-02 对象一致性与故障恢复

单 PUT 在 HEAD 校验与 COPY 之间缺少源对象 VersionId/ETag 绑定，且对象完成后、数据库提交前崩溃可能留下永久孤儿。必须启用对象版本化，按已校验版本复制，最终对象复验 SHA-256，并用持久化 `FINALIZING`/outbox 状态完成双向对账。

验收：校验后覆写、COPY 超时、数据库提交失败、重复完成和 Worker 重启的故障注入测试全部通过；孤儿对象和悬空数据库记录均能收敛。

### P1-03 身份与滥用防护

失败 JWT/API Key 认证在主体级限流之前发生，攻击者可在 401/403 路径制造数据库读取；刷新令牌没有 family/replay detection；管理员还缺少 MFA、密码重置、会话列表和全设备退出。

验收：预认证可信客户端 IP 限流覆盖随机 API Key、无效 JWT、`/auth/me`、连续 403 和 logout；旧 Refresh Token 重放会原子撤销整个 family；管理员强制 WebAuthn/TOTP。

### P1-04 任务吞吐与文档解析

当前 Vercel Hobby Cron 每日运行，默认 OKF 批量很小；只有 UTF-8 TXT/CSV 可以自动转换。必须改为事件队列 + 短事务租约 Worker + DLQ，Cron 只做漏单对账；PDF/Office 解析必须在有 CPU/内存/页数/解压比限制的沙箱中执行。

验收：上传后任务延迟、队列深度、失败重试、死信、积压恢复均有 SLO 和告警；所有声明支持的格式都有安全解析基准。

### P1-05 区域、数据驻留与中国大陆可用性

Vercel Function 当前位于新加坡，而现有 Supabase 数据库位于美国区域，控制面存在跨太平洋数据库往返。Supabase 项目不能原地改区，需创建新加坡项目后迁移和切换。Vercel 官方也明确不提供中国大陆基础设施或 ICP 支持，因此新加坡 Demo 不应被描述为中国大陆生产部署。

验收：数据库、Redis、函数和对象存储按批准的数据驻留方案同区；完成双写/停机迁移、回滚、延迟基准与合规评审。

### P1-06 可观测性、备份与灾难恢复

当前缺少统一错误跟踪、指标、Trace、日志保留策略和已演练的 RPO/RTO。正式发布前必须有登录失败、401/403/429、对象状态、队列年龄、LLM token/成本、慢 SQL 和 5xx 指标，并完成 PostgreSQL PITR、对象版本恢复和 Redis 降级演练。

验收：告警能关联 `x-request-id`；季度恢复演练有证据；RPO/RTO、日志留存和责任人经过业务批准。

### P1-07 数据规模与管理面

管理列表只读取前 50/100 条，深分页和本地搜索无法管理 10 TB 规模；检索虽已有 pg_trgm GIN 索引，但缺少相关性排序、文档分块、混合检索和大租户查询预算。

验收：游标分页和服务端搜索覆盖文件、用户、角色、API Key；百万级条目基准满足确定的 P95/P99；查询有 statement timeout 和租户级预算。

### P1-08 数据库迁移与未来对象权限

线上存在未纳入仓库的手工安全迁移；Alembic 默认读取通用 `.env` 数据库地址，存在误操作目标库风险。现有表权限较安全，但数据库 owner 的默认 ACL 仍可能让未来新表重新授予 Data API 角色权限。

验收：所有线上变更回填为版本化、可重放 migration；迁移使用独立 `KB_MIGRATION_DATABASE_URL`、目标指纹和 advisory lock；未来表/序列默认 ACL fail closed，并在 CI 中验证。

## 6. P2：下一版本必须规划

- “grounded” 当前只代表引用编号协议有效，不代表模型陈述已完成语义蕴含验证；需改名或增加 claim-evidence evaluator。
- 下载限额统计的是下载 URL 签发次数，不是真实下载次数或字节；计费场景需要一次性 ticket/下载网关。
- 角色策略和知识库授权采用整集合 PUT，多管理员并发会后写覆盖；应增加版本号、ETag 和 `If-Match`。
- `file:delete`、`quota:manage`、`audit:read` 等权限尚未形成 API/UI/测试完整闭环。
- CSP 仍包含 `unsafe-inline` 且连接范围偏宽；应切换 nonce/hash 并收窄对象存储域名。
- 管理页部分字号和颜色对比度不足；需要按 WCAG 2.2 AA 做自动化与人工无障碍验收。
- 来源卡片应提供受 RBAC 保护的“查看原文/下载源文件”，而不只是摘录和内部 ID。
- LLM 需要用户/API Key/知识库/供应商多维 token、金额和并发预算，防止合法凭据造成失控成本。

## 7. 数据库现状说明

只读线上核查显示，现有业务表已启用 RLS，匿名/普通认证角色没有业务表权限，数据库安全顾问当前没有活动告警；应用运行角色也不是超级用户，不能创建数据库、角色或绕过 RLS。这些是良好基础，但不能替代未来对象默认 ACL、迁移漂移和恢复演练的整改。

## 8. 推荐交付顺序

1. **立即（发布前）**：旋转已经在沟通渠道中暴露或强度不足的管理员凭据；关闭 Bootstrap Runtime 密码；部署本轮代码；启用错误监控。
2. **第 1–2 周**：预认证限流、Refresh Token family、对象版本化与最终校验、迁移目标保护和默认 ACL。
3. **第 2–4 周**：隔离扫描/解析 Worker、队列/DLQ、文件生命周期、管理员 MFA、审计读取与告警。
4. **第 4–8 周**：新加坡 Supabase 迁移、容量/并发/故障注入基准、PITR 与对象恢复演练。
5. **正式发布前**：中国大陆部署、ICP、等保、数据分类和跨境方案由法务/安全/业务共同签字；工程团队不能单方面替代该结论。

## 9. 验证记录

最终验证结果以本次交付提交及 CI 运行记录为准。最低门禁包括：

- Python 3.12：Ruff、mypy strict、pytest + branch coverage；
- Node.js：ESLint、Vitest、Next.js production build、npm audit；
- PostgreSQL：空库 Alembic upgrade 到 head；
- 浏览器：登录、知识问答、连续提问、来源展示、新对话取消和管理页冒烟；
- 线上：Web/API liveness/readiness、Vercel READY、错误日志扫描和真实浏览器控制台检查。

本轮本地最终结果：**131 项后端测试、142 项前端测试全部通过；Python branch coverage 84.48%；Ruff、mypy strict、ESLint、TypeScript 与 Next.js production build 全部通过；npm 与 Python 已锁定依赖均未发现已知漏洞。** PostgreSQL 17 + Redis 8 的 CI 演练已验证 Alembic 可以升级到唯一 head。

## 10. 依据与来源

- 本仓库：[架构设计](ARCHITECTURE.zh-CN.md)、[运维手册](OPERATIONS.zh-CN.md)、[Vercel 部署](VERCEL_DEPLOYMENT.zh-CN.md)、[知识编译与 OKF](KNOWLEDGE_PIPELINE.zh-CN.md)。
- [React `useEffect` 官方参考](https://react.dev/reference/react/useEffect)：Effect setup 只能返回清理函数或 `undefined`。
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)：文件类型/签名校验、恶意软件扫描、CDR、隔离存储和限额要求。
- [Vercel：中国大陆访问说明](https://vercel.com/kb/guide/accessing-vercel-hosted-sites-from-mainland-china)：Vercel 不提供中国大陆节点或 ICP 支持。
- [Supabase：可用区域](https://supabase.com/docs/guides/platform/regions) 与 [迁移项目区域](https://supabase.com/docs/guides/troubleshooting/change-project-region-eWJo5Z)：项目绑定区域，更换区域需要新建项目并迁移。
- [Upstash Redis Security](https://upstash.com/docs/redis/features/security)：生产连接使用 TLS，凭据保存在环境变量或秘密管理系统中。
