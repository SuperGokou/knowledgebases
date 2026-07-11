# 2026-07-11 企业验收本地自测报告

## 结论

**企业正式生产结论：`FAIL / NO-GO`。**

自动化可执行子集的结论为 `CONDITIONAL`：7 个本地/CI Gate 通过，真实 8C16G/300GB 腾讯云服务器 Gate 为 blocked。企业总标准还存在恶意文件扫描、不可篡改审计、Refresh Token family 重放处置、真实浏览器 E2E、备份恢复、性能容量和真实断网部署等 P0，因此不能把本地测试全绿解释为企业生产验收通过。

| 项目 | 值 |
|---|---|
| 验收标准 | [企业知识库超级详细验收标准](../ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md) |
| 测试 Git SHA | `d7038e17f8be2e2c656d9055a5763ed955728e70` |
| 分支 | `codex/enterprise-acceptance-hardening` |
| 自动化 Profile | `local` |
| 自动化 verdict | `CONDITIONAL` |
| 企业总体 verdict | `FAIL` |
| 报告敏感模式扫描 | 0 命中 |

## 自动化 Gate 结果

执行命令：

```powershell
uv run python scripts/acceptance.py `
  --profile local `
  --report-dir artifacts/acceptance
```

| Gate | 结果 | 耗时 | 证据摘要 |
|---|---|---:|---|
| `CODE-P0-001` | passed | 0.08s | Ruff 全仓库 0 错误 |
| `TYPE-P1-001` | passed | 0.45s | 严格 MyPy 0 错误 |
| `BACKEND-P0-001` | passed | 24.02s | 169 passed；总覆盖率 84.53%，要求≥80% |
| `FRONTEND-P0-001` | passed | 1.44s | 21个测试文件、149项测试通过 |
| `FRONTEND-P1-001` | passed | 3.49s | ESLint 0 warning |
| `BUILD-P0-001` | passed | 6.97s | Next.js production build通过，9个页面完成生成/编译 |
| `OFFLINE-P0-001` | passed | 0.12s | 离线 Compose + ops profile解析通过 |
| `SERVER-P1-001` | blocked | 0.00s | 未发现真实8C16G/300GB目标服务器 |

额外严格验证：

```powershell
uv run pytest -W error -q
uv run ruff check .
uv run mypy app scripts
docker compose --project-name heyi-kb-offline `
  --env-file deploy/tencent/offline.env.example `
  --file deploy/tencent/compose.offline.yml `
  --profile ops config --quiet
docker run --rm --env KB_PUBLIC_HOST=knowledge.internal `
  --volume "${PWD}/deploy/tencent/Caddyfile.offline:/etc/caddy/Caddyfile:ro" `
  caddy:2.10.2-alpine caddy validate --config /etc/caddy/Caddyfile
```

结果：测试、Ruff、MyPy、Compose 与 Caddy 均退出 0；`pytest -W error` 无 warning。

## 多 Agent 审查范围

| Agent | 独立审查面 | 核心结论 |
|---|---|---|
| Backend/Security Agent | 认证、RBAC、ACL、文件、OKF、RAG、审计、API Key | 代码基础较好，但迁移漂移、审计闭环、恶意文件扫描是生产阻断 |
| Frontend Agent | 登录路由、聊天来源、表格、管理后台、响应式、无障碍 | 149项单测通过，但缺少真实浏览器E2E，不能签署UI企业验收 |
| Offline/Ops Agent | 腾讯云离线网络、权限、冷启动、日志、备份、负载 | 本地配置隔离正确，但发现维护崩溃、Redis初始化、DB超级用户、URL日志等问题；真实服务器与DR仍blocked |

## 本轮已按 TDD 修复

### 1. 离线 maintenance 不再因 LLM 禁用崩溃

- 红灯：`tests/test_maintenance.py` 证明离线维护在清理后仍解析公网模型并抛异常；
- 修复：`KB_EXTERNAL_LLM_ENABLED=false` 时跳过外部转换，仅执行本地过期上传维护；
- 绿灯：维护专项与相邻集成测试通过。

状态：**代码修复通过；真实服务器连续30分钟/10周期验收仍 blocked。**

### 2. Redis 冷启动补回最小初始化 capabilities

- 红灯：Compose 解析证明 Redis `cap_drop: ALL` 后没有 `CHOWN/SETGID/SETUID`；
- 修复：只补回官方入口初始化数据目录需要的三个能力；
- 绿灯：Compose 安全契约测试通过，其他服务仍无宿主机端口。

状态：**静态契约通过；全新空数据盘冷启动仍需真机验收。**

### 3. PostgreSQL owner 与 runtime 身份分离

- 红灯：API 与迁移都使用 `POSTGRES_USER`；
- 修复：新增 `knowledge-runtime` 独立角色初始化，强制 `NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS`，只授予业务表 DML/序列权限；
- 预检：owner 与 runtime 相同会直接失败；
- 绿灯：Compose 与脚本契约测试通过。

状态：**代码和配置通过；真机还需执行 `pg_roles` 与禁止 CREATE 的运行时测试。**

### 4. 对象入口不再记录预签名请求 URI

- 红灯：对象端口 Caddy access log 会接收完整请求 URI；
- 修复：工作台保留 JSON access log，对象端口关闭 access log，保留进程错误日志；
- 绿灯：泄漏契约测试与 Caddy 官方配置验证通过。

状态：**配置通过；真机上传/下载后日志 grep 仍需执行。**

### 5. Readiness 拒绝过期数据库迁移

- 已发现环境：运行库 `20260709_0001`，仓库 head `20260710_0006`；旧实现仍返回 ready；
- 红灯：schema drift 测试证明健康检查没有 revision 门禁；
- 修复：应用保存期望 head，readiness 查询 `alembic_version`；不一致统一返回受控 503；
- CI：Alembic 图与应用期望 head 不一致时测试失败。

状态：**代码通过；旧环境必须真正升级到全部 head 后才能恢复 ready。**

### 6. 可复用验收运行器与 CI Gate

- 支持 P0/P1/P2 verdict、超时、跨平台命令解析、UTF-8容错、敏感信息脱敏、原子JSON/Markdown报告；
- 长输出保留尾部 TOTAL/coverage/测试结论；
- CI 在前后端 Gate 后独立执行 `ci` profile，并把脱敏报告写入 Job Summary。

## 当前 P0 阻断项

| Gate/领域 | 当前证据 | 必须完成的验收 |
|---|---|---|
| `REL-P0-006` 运行迁移 | 已发现运行库落后5个迁移 | 目标环境执行受控升级并通过 `alembic current --check-heads` |
| `REL-P0-008` 离线镜像 | 多个基础镜像仅固定tag，缺SBOM/签名闭包 | 全部digest、linux/amd64、签名、SBOM、Critical/High门禁、断网启动 |
| `AUTH-P0-006` Refresh重放 | 旧refresh重放只拒绝自身，未撤销family | family/parent链、并发测试、重放后replacement 401 |
| `FILE-P0-004` Multipart摘要 | 最终只强制大小，完整对象摘要不足 | 篡改单part但等长时完成必须失败并释放配额 |
| `FILE-P0-006` 恶意文件扫描 | 无AV/宏/PDF JS/压缩炸弹扫描状态机 | EICAR等全套拒绝；扫描服务故障fail closed |
| `FILE-P0-010` 下载额度 | 预签名URL在有效期内可重复使用 | 一次性grant或对象事件精确计量 |
| `AUDIT-P0-002/003` 审计 | 无审计查询API；应用角色可修改/删除审计表 | `audit:read`查询导出；DB append-only约束 |
| `AI-P0-009` 对抗评测 | 现有单测未形成≥100例固定评测集 | 幻觉/非法引用/无结果外部事实输出率全部0% |
| `WEB-P0-001` 浏览器E2E | 只有Node Vitest，无Playwright/Cypress | 桌面+移动核心流程100%通过，无console error/泄密trace |
| `WEB-P0-006` 错误恢复 | 聊天和知识库加载缺直接重试闭环 | 一键重试、重复点击单请求、迟到消息0 |
| `OPS-P0-005/007/008/010` 真机 | 当前`.env`目标仅4C4G/40GB | 正确8C16G/300GB，冷启动、可信TLS、防火墙、断网启动证据 |
| `PERF-P0-*` 性能容量 | 无150GB/10万条目30分钟负载证据 | 满足标准中的P95/P99、错误率、资源与无重启阈值 |
| `DR-P0-*` 备份恢复 | 无独立备份实现和恢复报告 | RPO≤15分钟、RTO≤4小时、1000对象哈希100%、季度演练 |

## 当前服务器事实

只读检查 `.env` 当前目标与腾讯云账号可见实例后，仅发现一台运行中的轻量服务器：4 CPU、约4GB内存、40GB系统盘；它不是要求的8C16G/300GB企业服务器。预检会拒绝该主机，本轮没有在其上创建目录、启动容器、修改端口或影响其他应用。

## 下一优先级

1. 新建/升级并正确填写8C16G/300GB服务器连接信息；
2. 先实现恶意文件扫描状态机和审计append-only/query API；
3. 补Refresh Token family与一次性下载grant；
4. 引入Playwright桌面/移动E2E及axe；
5. 建立独立加密备份介质、恢复脚本和负载数据集；
6. 关闭全部P0后重新执行本标准，届时才允许重新计算企业 verdict。

