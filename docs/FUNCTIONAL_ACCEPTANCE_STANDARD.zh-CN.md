# 企业知识库功能验收标准

> 本标准定义“功能具备、自动化证据存在、真实运行证据充分”的统一判定方法。机器清单为 docs/functional_acceptance_manifest.json，执行器为 scripts/functional_acceptance.py。

## 1. 判定边界

| 层级 | 证明内容 | 通过条件 | 企业终验签字 |
|---|---|---|---|
| Source contract | 路由、源码、配置、文档和活动自动化测试逐项对应 | 14 项证据完整；声明的后端/前端测试全通过；关键命令无 skip | 不可 |
| Runtime-functional | 真实浏览器完整业务链与通用 Linux 目标机离线运行 | Source contract 与本次自动化命令通过，且两个外部证据文档全部通过 | 不可；仅代表功能运行层通过 |

现有 Playwright 企业档案固定为两个项目，每个项目执行 12 个业务场景和 1 个失败关闭预检，共 26 个测试实例，并生成 16 个证据检查 ID；只有 collection 或源码存在不等于真实业务链已通过。目标“其他云 Linux 8C16G300G”主机也未在本地会话中提供。因此缺少真实浏览器与目标机证据时，已实际运行自动化命令的 `source_verdict` 可以是 PASS，但 `runtime_functional_verdict` 必须是 BLOCKED。未使用 `--run-tests` 时，`source_verdict` 为 UNVERIFIED，不得显示 PASS。

本脚本不是企业交付终验器，也不覆盖容量、性能、容灾、安全扫描、供应链、真实 PostgreSQL 与恶意文件全链路等全部企业门禁。企业唯一正式 final 判定只能由 `scripts/acceptance.py --profile final` 产生；功能脚本不提供名为 `final` 的 profile 或 verdict 字段。

## 2. 严重度与阻断

| 级别 | 定义 | 门禁语义 |
|---|---|---|
| P0 | 身份、授权、数据隔离、文件安全、引用真实性、凭据、审计、就绪和正式离线部署核心能力 | 失败、缺证、skip 或外部运行未证实均阻断 |
| P1 | 不直接破坏数据边界，但会使企业用户无法可靠完成任务的状态与恢复能力 | 清单标记 blocking=true 时与 P0 一样阻断 |
| P2 | 不影响核心任务或安全边界的体验改进 | 可记录缺陷，不得伪装成已验证 |

检测器失败关闭：空需求、空测试命令、空外部证据、路径不存在、文字证据缺失、路径越界、任何 .env 路径、未知执行器、测试状态不是 active、非零退出或出现 skip 均失败。每个测试执行器还必须声明框架、完整测试节点集合和最低通过数量；命令选择的测试节点必须与清单完全一致，自动化证据文件也必须被对应节点实际选中。检测器不读取环境文件，也不输出测试进程原始日志。

## 3. 通用证据要求

每个阻断需求至少具备：

1. 一项可定位的路由、源码、配置或正式文档证据；
2. 一项状态为 active 的自动化测试证据；
3. 测试必须绑定清单执行器，执行器声明覆盖该需求并禁止 skip；执行命令、测试节点和最低通过数量三者必须同时匹配；
4. 证据位于仓库内、使用 UTF-8，并可确定性复核；
5. 浏览器和目标机结论必须来自真实运行证据，不得由源码存在性推断。

## 4. 功能验收用例

### FUNC-AUTH-001 统一登录、会话与按角色路由

- 严重度：P0，阻断。
- 前置条件：管理员、内容管理员、聊天用户和无可用权限账户均存在。
- 步骤：统一登录；读取服务端当前用户；请求授权页、无权页、安全 next 与外部/畸形 next；模拟 token 或当前用户响应畸形。
- 预期：落地页只由服务端 is_superuser 与 permission_codes 决定；客户端角色声明不可信；无权路径回落到有权页或待授权页；畸形会话失败关闭且不签发 Cookie。
- 证据：auth.py 的 token/me/refresh/logout；access-routing.ts；access-routing、login-route、workspace-guard 测试。

### FUNC-ACCOUNT-001 账户与会话全生命周期

- 严重度：P0，阻断。
- 前置条件：管理员已登录，系统角色和自定义角色已初始化。
- 步骤：创建账户并分配角色；修改账户；替换角色；刷新会话；退出并重放刷新令牌；尝试授予系统管理员角色。
- 预期：全部变更校验权限与层级；退出后刷新令牌失效，重放返回 401；系统管理员角色不可越权授予。
- 证据：users.py 创建/更新/角色替换；test_admin_role_user_and_refresh_workflow。

### FUNC-RBAC-001 动态 RBAC、层级约束与中文权限

- 严重度：P0，阻断。
- 前置条件：权限目录、角色目录和操作者有效权限已加载。
- 步骤：创建角色；替换权限、限额和完整策略；验证精确权限、资源通配符与全局通配符；尝试修改系统角色或越权授予；查看角色页。
- 预期：策略动态生效；系统角色不可修改；权限提升被拒绝；权限前缀不误匹配；当前全部权限及未知权限都有中文展示。
- 证据：roles.py；role-policy.ts；test_domain_access.py 与 role-policy.test.ts。

### FUNC-LIMIT-001 角色配额、限额与平台硬上限

- 严重度：P0，阻断。
- 前置条件：限额目录已初始化，账户至少有一个角色。
- 步骤：设置有限、未设置和 null 无限；合并多角色并应用用户覆盖；触发上传/存储/下载额度；让无限角色超过平台硬上限。
- 预期：三种状态不混淆；多角色使用最宽松合法值；用户覆盖最终生效；无限制仍受平台上传、扫描和存储水位硬上限约束；并发预留不超卖。
- 证据：角色限额路由；role-policy.ts；test_domain_quota.py、test_domain_access.py 和 role-policy.test.ts。

### FUNC-KB-ACL-001 知识库 ACL 与撤权

- 严重度：P0，阻断。
- 前置条件：知识库、条目、reader/editor/manager 与无授权角色存在。
- 步骤：授予角色访问；分别列表、读取、检索、聊天、上传和修改；使用无授权角色；撤权后重试。
- 预期：只返回有权知识库；操作同时满足 RBAC 与 ACL；越权资源以 404 隐藏；撤权立即移除文件、上传、检索和聊天访问。
- 证据：knowledge_bases.py；知识库 ACL 边界与撤权集成测试。

### FUNC-FILE-001 文件上传、扫描、OKF、审批与下载

- 严重度：P0，阻断。
- 前置条件：对象存储、扫描器和维护任务可用，账户具有对应权限。
- 步骤：小文件单次上传；大文件 Multipart 获取分片并完成/终止；模拟过期和重复完成；执行 clean/infected/error 扫描；执行 OKF 成功/失败/显式重试；审批并下载。
- 预期：上传方式按阈值选择；大小、分片、幂等键严格校验；扫描前保持隔离；infected/error 不可审批下载；审批只认最新 OKF；只有 clean + available 文件签发短期下载授权。
- 证据：files.py 全链路路由；上传、恶意软件和 OKF 自动测试。

### FUNC-CHAT-001 聊天检索、逐答引用、回答审计与数据表

- 严重度：P0，阻断。
- 前置条件：知识库有已发布条目，账户有 chat:query 和知识库访问权。
- 步骤：纯检索问答；模型返回合法引用、漏引、越界、伪造来源和部分引用；回答审计返回通过、拒绝、畸形或上游错误；返回来源化数据表。
- 预期：每答都有 citations 与 source_status；每个事实段有合法标记；漏引、越界、伪造或审计非明确通过时丢弃模型文本并回落确定性检索；不伪造来源；表格只引用已验证 citation 并语义化展示。
- 证据：chat.py 与聊天服务；chat answer review、presentation、contract、sources 和 data-table 测试。

### FUNC-MODEL-001 DeepSeek、Qwen、MiniMax 切换

- 严重度：P0，阻断。
- 前置条件：操作者有 llm:manage，服务端凭据加密有效。
- 步骤：列出供应商；配置模型、Base URL、价格与凭据；切默认供应商；尝试不支持主机和未配置供应商；执行聊天。
- 预期：只允许三家供应商及其主机白名单；凭据不由 GET 回显且密文保存；未配置供应商不可设默认；回答报告实际 provider/model；上游失败安全回落。
- 证据：llm.py；API 与模型管理文档；LLM provider、模型设置/生成和 model-settings 测试。

### FUNC-APIKEY-001 API Key 生成、文档、范围与撤销

- 严重度：P0，阻断。
- 前置条件：操作者有 api-key:manage，目标用户和知识库有效。
- 步骤：生成带权限与知识库范围的 Key；保存一次性明文；按文档调用公开接口；尝试提权、跨账户和跨知识库；触发限流；撤销/过期/禁用后重试。
- 预期：明文只返回一次，服务端只存摘要；有效权限为用户 RBAC、Key scope、KB scope 交集；越权签发被拒；撤销、过期、禁用或 ACL 撤销立即生效；文档示例与真实路径一致。
- 证据：api_keys.py；API 与模型管理文档；API Key 生命周期/隔离集成测试；api-usage-examples.test.ts。

### FUNC-AUDIT-001 审计记录、检索、脱敏与结果

- 严重度：P0，阻断。
- 前置条件：准备有/无 audit:read 的账户并产生成功、失败事件。
- 步骤：按动作、actor、资源、结果、时间查询；游标翻页；提交倒置或无时区范围；检查响应。
- 预期：无权限返回 403；过滤使用持久化 result；游标稳定；非法时间范围被拒；事件含 actor/action/resource/result/request_id；凭据和正文脱敏。
- 证据：audit_logs.py；test_audit_logs_api.py 与 test_audit_result_persistence.py。

### FUNC-UXSTATE-001 错误、加载、空态与连接状态

- 严重度：P1，阻断。
- 前置条件：可模拟加载、会话过期、后端超时、网络失败、渲染异常和无来源。
- 步骤：进入加载；后台刷新；模拟渲染错误与 502/503/504；模拟刷新失败；查看连接和来源状态。
- 预期：加载有占位；后台刷新不闪退；错误页可重试并给安全编号；日志不含消息、堆栈或敏感 digest；失败不误报成功。
- 证据：workspace loading/error；error-reporting、access-provider、BFF、chat-service-status 与 chat-sources 测试。

### FUNC-HEALTH-001 存活、就绪与依赖健康

- 严重度：P0，阻断。
- 前置条件：API 启动，数据库与 Redis 可模拟正常、失败和 schema 漂移。
- 步骤：调用 /health/live 与 /health/ready；模拟数据库/Redis 不可用和 schema 漂移。
- 预期：liveness 不依赖外部服务；readiness 只在数据库、Redis、schema 全部正常时 ready；异常返回非 2xx 且不暴露连接信息。
- 证据：app/api/health.py；test_api_contract.py 与 readiness 集成测试。

### FUNC-FORMAT-001 九类文档格式的隔离解析与 OKF 闭环

- 严重度：P0，阻断。
- 前置条件：解析运行时通过能力预检；`bwrap`、`prlimit`、`pdftotext` 与 `libreoffice` 由 root 所有且不可被非特权用户修改。
- 步骤：解析 TXT、DOC、DOCX、XLS、XLSX、CSV、PDF、PPT、PPTX 黄金样本；注入宏、外部关系、主动 PDF、加密包、压缩炸弹、错配扩展名与资源越界；将安全解析结果送入 OKF。
- 预期：内建 TXT/CSV/OOXML 保留稳定定位；PDF 与旧版 Office 只在断网沙箱和资源限制可用时启用；任一必需能力缺失均返回 `blocked`；来源定位持久化到 OKF 元数据。
- 证据：document_parser.py；test_document_parser.py、test_document_parser_preflight.py 与 test_okf_document_pipeline.py；正式运行时门禁为 `python -m app.document_parser_preflight --require-all`。

### FUNC-OFFLINE-001 其他云 Linux 服务器离线 8C16G300G

- 严重度：P0，阻断。
- 前置条件：其他云厂商提供的真实 Linux amd64/x86_64 目标机；至少 8 CPU、16 GB 级内存、300 GB 数据文件系统和 240 GB 可用；离线镜像与 ClamAV 库已校验。
- 步骤：运行只读主机预检；校验镜像、病毒库、Compose、私网依赖、非管理员数据库身份、只读文件系统、资源限制和存储水位；启动后执行 health/readiness 与文件、聊天、审计 smoke。
- 预期：规格不足或非目标环境失败/阻塞；无公网数据依赖；扫描器失败关闭；资源与停机策略有效；目标机业务 smoke 全通过并留证。
- 证据：云厂商无关的离线 Compose、现有部署文档、主机与 Compose 自动测试；`runtime-functional` 还必须有 EXT-LINUX-HOST-001。

## 5. 执行

只验证确定性映射：

~~~powershell
uv run python scripts/functional_acceptance.py --json
~~~

该命令只用于查看映射缺陷；由于没有实际执行测试，预期 `source_verdict=UNVERIFIED`、`verdict=UNVERIFIED` 并返回退出码 2，不能作为通过证据。

执行 source 功能门禁：

~~~powershell
uv run python scripts/functional_acceptance.py --run-tests --json
~~~

验证运行功能证据：

~~~powershell
uv run python scripts/functional_acceptance.py --profile runtime-functional --run-tests --json
~~~

退出码：0 为所选 profile 通过；1 为源码契约或测试失败；2 为未执行测试（UNVERIFIED）或运行功能证据不完整（BLOCKED）。`runtime-functional` 强制要求本次进程实际执行测试命令；即使外部证据齐全，省略 `--run-tests` 也只能得到 BLOCKED，不能利用空测试集合通过。源码契约或测试一旦失败，`runtime_functional_verdict` 与所选总 `verdict` 必须为 FAIL，不能降级成 BLOCKED。

## 6. 外部证据

浏览器与通用 Linux 主机证据分别为：

- artifacts/acceptance/functional/browser-e2e.json
- artifacts/acceptance/functional/linux-host.json

这些路径位于 Git 忽略的验收产物目录中，避免证据文件本身改变待验证的工作树指纹。正式结构遵循 `docs/schemas/functional-acceptance-evidence-v2.schema.json`；checks 的必需名称、采集器身份/版本与最大证据年龄由 manifest 定义。所有必需检查必须为 passed，且每项检查至少引用一个已校验的原始产物：

~~~json
{
  "schema_version": 2,
  "evidence_id": "EXT-LINUX-HOST-001",
  "status": "complete",
  "collector": {"id": "heyi-linux-host", "version": "1.0.0"},
  "target": {
    "git_head": "<40-char-git-revision>",
    "content_fingerprint": "<sha256>"
  },
  "collected_at": "2026-07-13T12:00:00Z",
  "artifacts": [
    {
      "id": "host-preflight",
      "path": "raw/host-preflight.json",
      "sha256": "<sha256>",
      "bytes": 1234
    }
  ],
  "checks": {
    "required_check_name": {
      "status": "passed",
      "artifact_ids": ["host-preflight"]
    }
  },
  "attestation": {
    "type": "sha256-chain-v1",
    "digest": "<canonical-evidence-chain-sha256>"
  }
}
~~~

检测器会重新计算当前 Git HEAD 与包含 tracked diff、未跟踪内容的工作树指纹，检查 UTC 采集时间窗，逐个读取非符号链接原始产物并核对大小和 SHA-256，最后复算规范化 JSON 哈希链。采集器身份/版本、工作树指纹、时效、原始产物或哈希链任一不匹配均为 BLOCKED。仅手写 `required_check_name: passed` 永远不能通过。证据不得包含密码、Cookie、Bearer Token、API Key、预签名查询串或环境文件内容。

## 7. 变更控制

功能变化时必须同步更新 manifest 的源码证据、活动测试证据和执行器覆盖范围。删除测试、标记 skip、改名导致证据消失或移动到仓库外，都会失败。运行功能报告必须同时列出 `source_verdict`、`runtime_functional_verdict` 与所选 `verdict`，禁止把它重命名或摘录为企业 final 结论。
