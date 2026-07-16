# 2026-07-12 企业终验通过性自检报告

## Executive Summary

**最终结论：`FAIL / NO-GO`，不得按完整企业生产规格交付。** 当前代码的本地可执行质量门禁全部通过，并完成了刷新令牌族重放封锁、离线知识入库闭环、数据库/主机资源加固、LLM 连接复用、浏览器 E2E 和不安全 XML 解析等实质整改；但恶意文件扫描、50 亿 Token/日容量、10 TB 存储、Token 成本治理、容灾恢复、深度安全扫描、全格式解析、检索质量、审计不可篡改和法务授权仍存在 P0 证据缺口。

本报告不使用“零瑕疵”“绝对安全”或“零版权风险”等不可验证表述。当前可以证明的是：指定本地代码门禁通过；不能证明的是：完整企业生产目标已经达到。

## 1. 审计身份与范围

| 项目 | 值 |
|---|---|
| 项目 | 江苏和熠光显有限公司企业知识中台 |
| 审计分支 | `codex/enterprise-final-acceptance` |
| 自动验收 Git SHA | `311f7a341bf60cc8d3e5dd0b633a8265fc5d6971` |
| 审计起点 | `e5b8a93ff93204a6390d244dc97ef18c7df74cc8` |
| 最终标准 | [企业知识中台最终交付验收标准](../ENTERPRISE_FINAL_ACCEPTANCE_STANDARD.zh-CN.md) |
| 基础标准 | [企业知识库超级详细验收标准](../ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md) |
| 容量模型 | [性能与容量模型](../PERFORMANCE_CAPACITY_MODEL.zh-CN.md) |
| 威胁模型 | [企业知识库威胁模型](../THREAT_MODEL.zh-CN.md) |
| 许可证审计 | [依赖、许可证与 SBOM 审计](../DEPENDENCY_LICENSE_AUDIT.zh-CN.md) |
| 自动化 Profile | `final` |
| 自动化 verdict | `FAIL` |

审计覆盖 FastAPI、Next.js、PostgreSQL、Redis、S3/MinIO、动态 RBAC、知识库 ACL、文件上传/审批/下载、OKF、RAG、模型管理、API Key、Docker/Compose、供应链、许可证、浏览器 UI 和腾讯云离线设计。未读取或记录 `.env` 值，未连接或修改云端环境，未使用企业真实文档做测试。

## 2. 多 Agent 与 Skills 执行

本轮由三个独立审查面并行完成：

| 审查面 | 范围 | 独立结论 |
|---|---|---|
| 后端/数据/安全 | Auth、RBAC、ACL、quota、文件、OKF、审计、并发一致性 | `FAIL`；发现令牌族重放、恶意文件、Token 治理等阻断 |
| 性能/容量/基础设施 | 8C16G/300GB、10TB、50亿Token/日、Compose、DB/Redis/MinIO、DR | `FAIL`；目标存在物理冲突且没有真实压测/恢复证据 |
| 前端/RAG/供应链 | 登录、问答来源、E2E、检索质量、许可证、SBOM、素材权属 | `FAIL`；业务闭环、检索、法务和镜像供应链仍未闭环 |

执行方法遵循 TDD、系统化调试、并行审查、基准测量、威胁建模、依赖审计和完成前验证。Codex Security 深度扫描已创建任务并执行预检，但插件要求至少 6 个可用 worker；当前宿主只有 3 个可用子线程，因此该扫描合法地保持 `blocked`，本报告不冒充深扫结果。

## 3. 自动化 Gate 结果

执行命令：

```powershell
$env:UV_NO_SYNC = '1'
$env:PYTHONPATH = (Get-Location).Path
uv run --no-sync python scripts/acceptance.py `
  --profile final `
  --report-dir artifacts/acceptance/final
```

执行时间：2026-07-12T22:21:20Z。结果为 **8 passed、7 blocked、0 failed，最终 verdict 为 `FAIL`**。`blocked` 的 P0 按标准等同发布失败。

| Gate | 级别 | 结果 | 证据摘要 |
|---|---|---|---|
| `CODE-P0-001` | P0 | passed | Ruff 全仓库 0 错误 |
| `TYPE-P1-001` | P1 | passed | MyPy strict 检查 64 个源文件，0 错误 |
| `BACKEND-P0-001` | P0 | passed | 176 passed；总覆盖率 84.83%，阈值 80% |
| `FRONTEND-P0-001` | P0 | passed | 23 个测试文件、152 项测试通过 |
| `FRONTEND-P1-001` | P1 | passed | ESLint 0 warning |
| `BUILD-P0-001` | P0 | passed | Next.js 16.2.10 production build 通过，9 个页面完成生成 |
| `OFFLINE-P0-001` | P0 | passed | 离线 Compose + ops profile 解析通过 |
| `E2E-P0-001` | P0 | passed | Chromium 桌面/移动共 4 项登录页、响应式、axe、性能 smoke 通过 |
| `SERVER-P1-001` | P1 | blocked | 本轮未在真实 8C16G/300GB 腾讯云隔离主机执行 |
| `CAPACITY-P0-001` | P0 | blocked | 无 1,000 用户、50 亿 Token/日的可重复容量证据 |
| `STORAGE-P0-001` | P0 | blocked | 300GB 与 10TB 目标冲突，无获批外部存储容量证据 |
| `MALWARE-P0-001` | P0 | blocked | 上传到审批路径没有生产恶意文件扫描与 fail-closed 隔离 |
| `TOKEN-GOV-P0-001` | P0 | blocked | 无多级 Token/成本原子预留与实际 usage 结算 |
| `DR-P0-001` | P0 | blocked | 未执行带 RPO/RTO 和数据完整性证明的恢复演练 |
| `SECURITY-SCAN-P0-001` | P0 | blocked | Codex 深度安全扫描受宿主线程上限阻断，无完成产物 |

自动生成的脱敏原始证据位于本地 `artifacts/acceptance/final/acceptance.json` 和 `acceptance.md`。该目录默认不提交，以避免把本机路径和过量日志带入公开仓库。

## 4. 本轮已完成的代码整改

| Commit | 整改 | 验证 |
|---|---|---|
| `6d69b00` | Refresh Token 增加 family/parent/replacement；检测重放后封锁整个族并递增用户 token version | 重放后后继 refresh 与现有 access 均失效；迁移、测试、类型检查通过 |
| `ee7a6a7` | TXT/CSV 在完全离线时使用确定性本地 OKF 编译；PDF/Office 进入明确 unsupported；文件状态与知识状态分离 | 上传、转换、审批、检索相关回归通过；前端显示“已入知识库/转换失败/暂不支持解析” |
| `3640871` | 稳态容器 CPU 上限降至 5.9 核；DB pool 默认 8+4；加入 pool/statement/lock/idle transaction timeout；优雅停止 | 配置、Compose、Serverless 两驱动断言通过 |
| `838169c` | 同一问答流程复用并确定性关闭 Provider HTTP 连接池 | LLM、聊天、maintenance 回归通过 |
| `5298801` | 加入 Playwright、axe、桌面/移动响应式和登录页生产构建性能预算 | 4 项真实 Chromium E2E 通过；严重/致命 axe 问题为 0 |
| `e96ccf7` | 对象存储错误 XML 改用 `defusedxml`，拒绝实体展开 | TDD 首先复现实体扩展；修复后定向测试通过，Bandit Medium/High 为 0 |
| `311f7a3` | 新增 `final` 严格验收 Profile；任何 P0 缺证自动返回 `FAIL` | 14 项 runner 单测通过；即使所有可执行命令成功，P0 blocked 仍强制 FAIL |

完整回归曾发现 3 个 Serverless 数据库测试仍断言旧的 10+20 池配置。测试已改为精确验证 8+4、10 秒 pool wait 和三类数据库超时，随后全量 176 项通过。这一过程保留了“先发现失败、再修正、再全量复测”的证据链。

## 5. 性能与容量结论

### 5.1 50 亿 Token/日

建模结果：

- 24 小时平均：约 57,870 token/s；
- 8 小时业务窗平均：约 173,611 token/s；
- 5 倍峰值：约 868,056 token/s；
- 4k/8k/16k Token 每对话对应 5 倍峰值约 217/109/54 chat RPS；
- 当前每次 RAG 对话包含生成和审核两次调用，对应约 434/217/109 上游调用 RPS。

8C16G、无 GPU、完全断网主机的外部 LLM 能力为 0 Token/日。它只能模拟控制面和确定性检索；完整目标需要企业内网 GPU 推理集群或书面降低业务指标。

### 5.2 10 TB 与 300 GB

300GB 仅为 10TB 的 3%；按当前 180GB 对象停止线只有 1.8%。正式存储必须独立建模主存储、纠删码/副本、版本、增长、Multipart 暂存和不同故障域备份。8C16G/300GB 主机不能被描述为 10TB 生产存储。

### 5.3 本地浏览器实测边界

本地 production build 的登录页 smoke 实测：

| 视口 | TTFB | FCP | DOM complete | 请求数 | 总传输 | JS 传输 |
|---|---:|---:|---:|---:|---:|---:|
| Desktop Chromium | 16.0ms | 164ms | 194.6ms | 11 | 172,742 B | 155,525 B |
| Mobile Chromium | 47.4ms | 188ms | 209.6ms | 11 | 176,818 B | 155,525 B |

这些数字只证明本机登录页的构建性能预算，不是 1,000 用户系统压测，也不证明 API、检索、对象传输或 LLM 的生产 SLO。

## 6. 安全审计结果

| 检查 | 结果 | 边界 |
|---|---|---|
| Bandit | 修复前发现 1 个 Medium/High-confidence XML 实体问题；修复后 Medium=0、High=0 | 仍有 6 个 Low 级提示；未替代人工审计 |
| npm audit | 0 known vulnerabilities | 使用 npm 官方 registry；只覆盖 npm 已知公告 |
| pip-audit | 0 known vulnerabilities | 基于 `uv.lock` 导出的 51 个生产包；只覆盖 PyPI 已知公告 |
| 高信号凭据正则 | 0 命中 | gitleaks 未安装，不能等同完整 secret scan |
| Codex Security deep scan | blocked | 插件要求 6 个可用 worker，宿主只有 3 个；不得声称完成 |
| 容器漏洞扫描 | blocked | Trivy、Syft、Grype 未安装；已构建但没有 image vulnerability 结论 |

威胁模型已覆盖认证、RBAC、API Key、预签名 URL、恶意上传、提示注入/数据外传、资源耗尽、供应链、审计和备份。当前最高风险攻击链仍是“恶意文件未经扫描即批准/下载”“管理员或 API Key 批量导出”“提示注入经外部 Provider 外传”和“主数据与同故障域备份同时丢失”。

## 7. 供应链、SBOM 与版权

两份 CycloneDX 1.6 SBOM 已生成并通过 Schema 校验：

| 产物 | 组件/依赖节点 | SHA-256 |
|---|---:|---|
| `sbom-web.cdx.json` | 54 / 57 | `A90A51571435CA05986F976F9CAAADF2F5CF8F3435534D485272D7EFC0DEC5DF` |
| `sbom-python.cdx.json` | 52 / 53 | `6895E628CDE5244D3654749A9DC631C98E62139C92D928A034ABD84D164D97C9` |

许可证与权属 Gate 为 `FAIL`：

- Web 根包为 `UNLICENSED`，Python 根项目也未声明许可证；
- sharp/libvips、psycopg/psycopg-binary 涉及 LGPL；
- certifi 为 MPL-2.0；caniuse-lite 为 CC-BY-4.0；
- Logo 由用户提供，但没有公司签字的商标/Logo 商业授权书；
- 设计参考图和对比图没有完整来源/授权链；
- SBOM 尚未覆盖最终 Linux 镜像中的 OS 包。

因此不能生成或签署“零版权风险”的结论。必须由权利人和法务选择项目许可证、补齐第三方通知与素材授权，并对实际发布镜像复核。

## 8. 容器与离线部署证据

API 与 Web Linux/amd64 镜像均在本机成功构建，且运行用户非 root：

| 镜像 | 本地 manifest list ID | 用户 |
|---|---|---|
| API | `sha256:41998d8ac4dfecb1f1ae3e440e132cd57efd8e923365683be2419d3880f33e06` | `10001:10001` |
| Web | `sha256:6001b6fade66caaae292298eddf7b84f0cf79bd2a6f566fb9e488924efaff31f` | `node` |

这些是本地镜像 ID，不是已推送仓库的远程 digest，也没有签名或漏洞扫描。Compose 解析通过不等于真实腾讯云断网启动、运行、升级、回滚和与其他应用零干扰已经通过。

## 9. Critical Issues（发布 Blockers）

1. 没有恶意软件扫描、隔离解析和 fail-closed 文件安全链路；
2. 没有用户/知识库/租户/模型/供应商 Token 与成本原子账本；
3. 50 亿 Token/日没有真实推理资源、供应商配额、成本或负载证据；
4. 300GB 无法承载 10TB，且单节点 MinIO 没有正式冗余和扩容证明；
5. PDF/Office 可存储但不能进入当前本地知识解析闭环；
6. 文件审批仍会隐式发布模型草稿，缺少独立内容预览、差异与审核意见；
7. 检索仍以词项/中文 n-gram 和 `%ILIKE%` 为主，没有 10TB 混合检索、分块、重排与黄金集指标；
8. 同一模型自审不能作为唯一防幻觉门禁，表格也缺少逐行 claim/evidence 映射；
9. Multipart 缺少完整对象摘要；预签名下载计量的是授权次数，不是实际下载次数/字节；
10. 审计日志没有受控查询导出和数据库级不可更新/删除保证；
11. 关键并发语义没有真实 PostgreSQL/Redis 集成测试；
12. 没有 PostgreSQL PITR、对象版本/复制、独立介质和恢复演练；
13. 深度安全扫描、容器漏洞扫描、镜像签名和 image SBOM 未完成；
14. 项目许可证、第三方履约和 Logo/参考图授权未签署。

## 10. Non-Critical Suggestions

- 将登录页之外的完整业务流加入浏览器 E2E：多角色登录、上传、扫描、转换、内容审批、聊天来源、模型故障和退出；
- 将 Playwright 本地启动与 standalone Windows 原生依赖分开配置，减少 `next start` 的非阻断警告；
- 为 MinIO 加入 readiness 检查，为 maintenance 加入结构化日志、指标和队列年龄告警；
- 将 offset 分页改为稳定游标分页；
- 统一依赖 registry，GitHub Actions 与全部基础镜像使用不可变 SHA/digest；
- 为 refresh/quota/audit 等高增长表建立分区、保留和清理策略；
- 修正生成、审核、BFF 和浏览器之间的超时预算倒挂，并传递取消信号。

## 11. 重新验收顺序

1. 先建设恶意文件扫描、内容审批、全格式隔离解析；
2. 实现 Token/成本预留结算、全局并发/队列/熔断；
3. 采用可横向扩展的分块混合检索并建立中文黄金评测集；
4. 完成审计不可篡改、真实 PostgreSQL/Redis 并发测试；
5. 确定内网 GPU/外部 Provider 合规拓扑和独立 10TB 存储拓扑；
6. 建立 PITR、对象复制/版本和独立备份，完成全新主机恢复；
7. 在真实 8C16G/300GB 控制面执行 30 分钟稳态、8–24 小时长稳和故障注入；
8. 在具备至少 6 个可用 worker 的宿主完成 Codex 深扫，并运行容器/secret/许可证门禁；
9. 法务签署项目许可证、第三方义务和所有素材授权；
10. 重新运行 `final` Profile。只有全部 P0、P1 有证据通过时，结论才能改为 `PASS`。

## 12. 签署状态

| 角色 | 状态 |
|---|---|
| 技术负责人 | 待复核 |
| 安全负责人 | 待深扫与渗透测试后签署 |
| 运维负责人 | 待真实主机、负载与恢复演练后签署 |
| 数据/合规负责人 | 待模型出站与数据驻留审查后签署 |
| 法务/知识产权负责人 | 待许可证、第三方通知和素材授权后签署 |

当前发布决定：**拒绝完整企业生产交付；允许继续在隔离测试环境整改，不允许以本报告对外宣称已通过企业终验。**
