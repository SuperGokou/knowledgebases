<div align="center">
  <h1>企业浏览器验收套件</h1>
  <p><strong>面向真实预生产拓扑的双端业务闭环、故障韧性与可审计证据采集。</strong></p>
  <p>真实认证 · 动态 RBAC · 知识授权 · 文件处理 · 可溯源问答 · 审计导出 · 模型降级 · API Key 边界</p>
</div>

> [!IMPORTANT]
> 本套件采用 fail-closed 语义。缺少真实目标、故障控制面、凭据、必需场景或证据工件时，结果必须是 `BLOCKED` 或 `FAILED`，绝不能以跳过、浏览器拦截或 mock 响应生成“通过”证据。

## 验收边界

企业档案只验证已经部署的真实前端、BFF、后端、数据库、Redis、对象存储、异步处理器和模型出口。测试代码禁止使用 `page.route()`、请求拦截或内存假服务替代任何安全边界。

| 检查项 | 真实闭环 |
| --- | --- |
| `login_role_routing` | 统一登录、管理员/普通成员/无权限账号按角色落地 |
| `account_lifecycle` | 创建、重复冲突、角色撤销、停用、他人改密仅限超级管理员、自改验证当前密码并退出、旧凭据与旧会话失效、角色编辑/删除、占用保护、系统角色只读与并发版本冲突 |
| `knowledge_acl` | 知识库授权、可见性与撤权后即时拒绝 |
| `file_upload_scan_okf_approval_download` | 直传、扫描、OKF、可见审批按钮、可见下载按钮、对象源/文件名/字节数/SHA-256 校验 |
| `chat_citations_audit_table` | 引用来源、无答案、审核拒绝、数据表与表格来源 |
| `model_switch` | 已配置模型切换、真实调用、故障降级与恢复 |
| `model_deepseek_success` | DeepSeek 返回精确 provider/model、RAG、语义审核通过与有效引用 |
| `model_qwen_success` | Qwen 返回精确 provider/model、RAG、语义审核通过与有效引用 |
| `model_minimax_success` | MiniMax 返回精确 provider/model、RAG、语义审核通过与有效引用 |
| `api_key_lifecycle` | 一次性密钥、知识库 scope、限流、撤销后 401 |
| `audit_log_query_export` | 独立 55 条数据集筛选、50/5 游标分页与回退、UI CSV 下载、BOM/RFC 4180/8 列/脱敏、>5,000 条 422、撤权后的导航/路由/UI/HTTP 拒绝 |
| `error_loading_states` | loading、401、403、409、429、5xx、超时；401/403/5xx/超时必须在页面显示错误与重试入口 |
| `tls_ca_trust` | Node 系统信任链严格验证，禁止跳过 CA 校验 |
| `tls_san_identity` | Web、API 与对象存储证书必须含匹配目标主机的 SAN |
| `tls_validity_and_renewal` | 三个入口叶证书必须处于有效窗口、`notBefore` 时钟偏差不超过 5 分钟、剩余不少于 1 小时、完整生命周期与签发链合理；Caddy CA 持久化及自动证书管理/续期健康必须由 `EXT-LINUX-HOST-001` 正式主机证据单独证明 |
| `tls_strict_client` | 仅允许协商 TLS 1.2 或 TLS 1.3；独立硬墙钟超时不受滴流活动重置，错误脱敏且 socket 只关闭一次 |

上表是 **16 个证据检查 ID**，不是 Playwright 的测试实例数量。正式 collection 固定为每个项目 13 个实例（12 个业务场景 + 1 个失败关闭预检），在 `enterprise-desktop` 与 `enterprise-mobile` 两个项目中合计 **26 个实例**。每个检查 ID 必须从真实实例结果生成截图、可访问性结果、控制台与网络异常摘要；任一项目、实例或必需工件缺失，证据采集器不会签发 `passed`。

## 运行档案

默认 `npm run test:e2e` 仍是本地 smoke，不连接企业数据。真实验收必须显式选择企业档案：

```powershell
$env:KB_E2E_PROFILE = "enterprise"
$env:KB_E2E_BASE_URL = "https://<preproduction-host>"
$env:KB_E2E_PUBLIC_API_ORIGIN = "https://<public-api-host>"
$env:KB_E2E_OBJECTS_ORIGIN = "https://<objects-host>"
$env:KB_E2E_ADMIN_EMAIL = "<synthetic-admin>"
$env:KB_E2E_ADMIN_PASSWORD = "<secret>"
$env:KB_E2E_FAULT_CONTROL_ORIGIN = "https://<private-fault-controller>"
$env:KB_E2E_FAULT_CONTROL_TOKEN = "<secret>"
$env:KB_E2E_SEEDED_KNOWLEDGE_BASE_ID = "<approved-synthetic-kb-id>"
$env:KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID = "<different-synthetic-kb-id>"
$env:KB_E2E_MULTIPART_BYTES = "104857600"
$env:KB_E2E_DOCUMENT_FIXTURE_ROOT = "C:\\acceptance\\document-fixtures"
$env:KB_E2E_DOCUMENT_FIXTURE_MANIFEST = "C:\\acceptance\\document-fixtures\\document-fixtures-v1.json"
$env:KB_E2E_SIGNING_KEY_PATH = "/etc/heyi-acceptance/private/browser-e2e-ed25519.pem"
$env:KB_E2E_CHALLENGE_PATH = "/var/lib/heyi-acceptance/challenges/<challenge-id>.json"
$env:KB_E2E_RUN_ID = "acceptance-20260714-a001"
$env:KB_E2E_AUDIT_PAGE_ACTION = "e2e.acceptance.audit.page.<run-tag>"
$env:KB_E2E_AUDIT_OVERSIZED_ACTION = "e2e.acceptance.audit.oversized.<run-tag>"
$env:KB_E2E_AUDIT_REDACTION_SENTINEL = "E2E_REDACT_<run-tag>"

npm run test:e2e
```

`KB_E2E_OBJECTS_ORIGIN` 为必填项，必须配置为唯一且纯净的绝对 HTTPS 源（origin），不得包含用户名、密码、路径、查询参数或片段。所有签名下载 URL 的源必须与其精确一致，并且测试会拒绝任何重定向。

补充变量：

| 变量 | 说明 |
| --- | --- |
| `KB_E2E_JOB_TIMEOUT_MS` | 扫描与 OKF 作业等待上限，最低 30 秒，默认 180 秒 |
| `KB_E2E_TEST_TIMEOUT_MS` | Playwright 单项企业测试上限，最低 60 秒，默认 30 分钟 |
| `KB_E2E_SUITE_TIMEOUT_MS` | 正式验收器执行整套企业 E2E 的上限，默认 2 小时；允许 30 分钟至 12 小时，且不得短于单项测试上限 |
| `KB_E2E_RUN_ID` | **必填**。8–80 位字母、数字、`_`、`-`，用于隔离并追踪所有合成数据；缺失或格式错误时 fail-closed |
| `KB_E2E_AUDIT_PAGE_ACTION` | **必填**。本次运行专用且只对应 55 条审计事件的动作名；必须与其他验收运行隔离 |
| `KB_E2E_AUDIT_OVERSIZED_ACTION` | **必填**。本次运行专用且对应超过 5,000 条审计事件的动作名；与分页动作名相同会 fail-closed |
| `KB_E2E_AUDIT_REDACTION_SENTINEL` | **必填**。预置在审计详情/IP 等禁止导出字段中的无敏感哨兵；页面和 CSV 出现该值即失败 |
| `KB_E2E_MULTIPART_BYTES` | 真实 Multipart 载荷字节数，必须为 100 MiB–512 MiB，并且必须达到目标拓扑的 Multipart 阈值 |
| `KB_E2E_DOCUMENT_FIXTURE_ROOT` | 九格式黄金样本的绝对专用目录；不得指向生产上传目录 |
| `KB_E2E_DOCUMENT_FIXTURE_MANIFEST` | 由离线生成器产生并通过 SHA-256 验证的 v1 清单绝对路径 |
| `KB_E2E_SIGNING_KEY_PATH` | **必填**。仓库外的 Ed25519 PKCS#8 PEM 私钥绝对路径；必须是 Linux root 所有、`0400/0600` 的常规非符号链接文件 |
| `KB_E2E_CHALLENGE_PATH` | **必填**。仓库外的一次性 challenge JSON 绝对路径；文件名必须为 `<challenge_id>.json`，并满足相同的 root/类型/权限门禁 |
| `KB_E2E_EVIDENCE_PATH` | 正式证据 JSON 输出路径，默认 `artifacts/acceptance/functional/browser-e2e.json` |

`KB_E2E_SUITE_TIMEOUT_MS` 由正式 `scripts/acceptance.py --run-browser-e2e` 路径执行；直接运行 `npm run test:e2e` 时仍由 Playwright 的单项超时负责。非法整数、越界值或整套上限短于 `KB_E2E_TEST_TIMEOUT_MS` 时，验收器会在启动 npm 前以 `BLOCKED` 结束。外层 Gate 会在整套上限之外保留 60 秒退出与证据收尾时间，避免父进程先于 Playwright 的受控超时终止。

> [!CAUTION]
> 不要把任何真实员工账号、生产密钥或企业文档用于此套件。目标环境必须是一次性或可清理的预生产数据集；Playwright 企业档案关闭 trace 与 video，避免把一次性 API Key 写入工件。

### 审计专用数据集

验收操作员必须在运行前用受控离线工具预置两个与 `KB_E2E_RUN_ID` 唯一绑定的数据集：`KB_E2E_AUDIT_PAGE_ACTION` 精确对应 55 条可导出事件，`KB_E2E_AUDIT_OVERSIZED_ACTION` 对应至少 5,001 条事件。55 条数据集用于证明第一页 50 条、第二页 5 条及返回上一页；大数据集必须让真实导出接口返回 `422 / audit_export_too_large`。`KB_E2E_AUDIT_REDACTION_SENTINEL` 只能写入详情、来源 IP 等禁止展示/导出字段。

任一动作不存在、数量不精确、数据串入其他运行、超大数据集未触发 422，测试都会产生 `E2E_BLOCKED`。套件不会临时生成、复制或截断数据来伪造边界条件。

## 合成数据生命周期

企业场景仅面向独立验收栈，允许在断开外网的局域网中运行，不依赖 GitHub、Vercel 或公网模型服务。所有新建角色、成员、知识库、API Key 和 Multipart 对象均绑定 `KB_E2E_RUN_ID`：角色/成员名称带完整 `run_id`，知识库写入 `custom_metadata.e2e_run_id`，文件通过所属知识库追溯到同一运行批次。

`KB_E2E_RUN_ID` 同时写入一次性 challenge 与正式证据的 `target.run_id`；它会参与 canonical evidence digest 和 Ed25519 签名。challenge、运行环境与证据三者的 `run_id` 任一不一致，reporter 必须 fail-closed，不能生成 `complete` 证据。

- 一次性 API Key 在场景结束前撤销；可安全删除且未被引用的合成角色会删除。
- 产品没有成员硬删除接口。密码与角色生命周期场景会对其合成成员解除角色并停用；其他业务闭环可能保留仍可追踪的合成成员，因此不得笼统描述为“已清理”。
- 文件、知识库和成员等需要保留的记录必须按 `run_id` 归档或由验收环境管理员在取证完成后执行受控数据集销毁。
- 每次正式验收使用新的 `run_id`；同一套件重复运行依靠唯一后缀避免冲突，但不能复用旧数据冒充本次结果。
- 若场景中途失败，可能留下仍带 `run_id` 的合成记录；验收环境必须禁止真实用户访问，并按该标识完成复核与处置。

## 故障控制面契约

故障控制面必须位于受控测试网络，并在真实反向代理或模型出口上实施故障；它不是浏览器 mock，也不能存在于生产环境。建议契约：

```http
POST /v1/runs/{run_id}/mode
Authorization: Bearer <token>
Content-Type: application/json

{"mode":"provider_5xx"}
```

允许模式：`normal`、`provider_5xx`、`provider_timeout`、`review_reject`、`table_response`、`backend_5xx`、`backend_timeout`。其中后台 5xx/超时模式必须作用于已登录页面的知识空间查询，测试会确认错误文案与重试按钮可见，再恢复 `normal` 并通过同一按钮验证请求恢复。控制面还应提供只含计数、状态与时间的脱敏证据，不得返回提示词、文档正文、凭据或完整内部 URL；测试异常也不会转述底层连接错误。

故障控制令牌只允许放在 `Authorization: Bearer` 请求头。非 loopback 控制面必须使用 HTTPS；只有显式 `localhost`、`127.0.0.0/8` 或 `::1` 可在本机验收时使用 HTTP，私网 IP 也不能绕过此规则。

## TLS 短期证书与续期证据

Caddy `tls internal` 使用短期叶证书并自动管理续期，因此不能用“剩余 30 天”作为通过条件。浏览器套件只证明当前三个入口的严格信任、SAN、协议、有效窗口、1 小时安全余量、合理完整生命周期及签发链；附件中的 `assertion_source` 固定为 `formal_host_evidence_not_socket_probe`。

自动续期不是一次 TLS 握手能够证明的事实。正式结论还必须同时具备 `EXT-LINUX-HOST-001`，由目标 Linux 主机采集器验证 Caddy `/data` 使用持久绑定、内部 CA 跨重启保持一致、自动证书管理已启用且续期健康。该主机证据缺失或失败时，整体运行时验收仍为 `BLOCKED`，即使浏览器 TLS 探针通过也不能宣称续期已验收。

## 证据与判定

`evidence-reporter.ts` 从 Playwright 的实际结果生成 functional evidence schema v2，不接受手工填写的通过状态。只有桌面端和移动端全部场景、质量工件及 Git/content fingerprint 齐全时，才生成 `EXT-BROWSER-E2E-001` 正式证据。collector 固定为 `heyi-browser-e2e@1.0.0`，key ID 固定为 `browser-e2e-ed25519`；采集器使用 Node.js Ed25519 对 Python 验收器定义的 canonical payload 签名，attestation 类型为 `ed25519-challenge-v1`。

challenge 必须由验收方预先签发，并精确绑定本次 `EXT-BROWSER-E2E-001`、不可预测 nonce、签发/过期时间以及目标 Git HEAD/content fingerprint：

```json
{
  "schema_version": 1,
  "challenge_id": "browser-acceptance-<unique-id>",
  "evidence_id": "EXT-BROWSER-E2E-001",
  "nonce": "<32-256位base64url随机值>",
  "issued_at": "<RFC3339 UTC>",
  "expires_at": "<RFC3339 UTC，不超过签发后24小时>",
  "status": "issued",
  "target": {
    "git_head": "<40-64位Git HEAD>",
    "content_fingerprint": "<64位内容指纹>",
    "run_id": "acceptance-20260714-a001"
  }
}
```

私钥、challenge 内容和签名输入不会写入日志或测试工件。私钥不允许放入仓库、镜像或 `.env`；这里只通过 `KB_E2E_SIGNING_KEY_PATH` 传递文件路径。正式验证成功后由 Python 验收器原子消费 challenge，第二次提交相同证据会被判定为重放。

失败或缺少拓扑、私钥、challenge、root 所有权、文件权限、有效期或目标指纹时，采集器会删除可能存在的正式证据，仅生成 `browser-e2e.blocked.json` 诊断文件。因此 `runtime-functional` 必须保持 `BLOCKED`，不会复用旧的“通过”文件。

企业场景同时覆盖内容管理员登录落地、真实 Multipart、聊天窗口中的来源/审核拒绝/语义表格、DeepSeek/Qwen/MiniMax 逐一切换、API Key 使用说明、次级页面质量监听与移动端横向溢出；所有故障模式和默认模型都通过 `finally` 恢复。

诊断结果只有三种：

- `passed`：26 个 Playwright 实例（13 个场景 × 桌面/移动）全部通过，16 个证据检查 ID 及质量工件齐全，代码身份可计算，并成功生成受信 Ed25519 challenge 签名；TLS 自动续期仍需配套 `EXT-LINUX-HOST-001` 正式主机证据。
- `failed`：真实场景、断言、可访问性、控制台或网络检查失败。
- `blocked`：配置/拓扑缺失、场景未收集、项目/工件缺失、代码身份不可得或工作树不干净。

默认工件目录 `web/test-results/` 已被忽略，不参与产品代码提交。证据可证明某次测试对应的代码身份和结果，但不能替代容量压测、灾备演练、渗透测试或生产变更审批。

## 当前状态

企业档案与验收场景属于验收基础设施；只有在完整预生产拓扑实际运行后才能声明通过。未运行、缺故障控制面或只完成本地 collection 时，项目交付状态仍应记录为 `BLOCKED`，不得写成“全部通过”。
