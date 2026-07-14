<div align="center">
  <h1>企业浏览器验收套件</h1>
  <p><strong>面向真实预生产拓扑的双端业务闭环、故障韧性与可审计证据采集。</strong></p>
  <p>真实认证 · 动态 RBAC · 知识授权 · 文件处理 · 可溯源问答 · 模型降级 · API Key 边界</p>
</div>

> [!IMPORTANT]
> 本套件采用 fail-closed 语义。缺少真实目标、故障控制面、凭据、必需场景或证据工件时，结果必须是 `BLOCKED` 或 `FAILED`，绝不能以跳过、浏览器拦截或 mock 响应生成“通过”证据。

## 验收边界

企业档案只验证已经部署的真实前端、BFF、后端、数据库、Redis、对象存储、异步处理器和模型出口。测试代码禁止使用 `page.route()`、请求拦截或内存假服务替代任何安全边界。

| 检查项 | 真实闭环 |
| --- | --- |
| `login_role_routing` | 统一登录、管理员/普通成员/无权限账号按角色落地 |
| `account_lifecycle` | 创建、重复冲突、角色撤销、停用与会话失效 |
| `knowledge_acl` | 知识库授权、可见性与撤权后即时拒绝 |
| `file_upload_scan_okf_approval_download` | 直传、扫描、OKF、审批、下载内容校验 |
| `chat_citations_audit_table` | 引用来源、无答案、审核拒绝、数据表与表格来源 |
| `model_switch` | 已配置模型切换、真实调用、故障降级与恢复 |
| `api_key_lifecycle` | 一次性密钥、知识库 scope、限流、撤销后 401 |
| `error_loading_states` | loading、401、403、409、429、5xx、超时 |

每项必须在 `enterprise-desktop` 与 `enterprise-mobile` 两个项目中完成，同时产出截图、可访问性结果、控制台与网络异常摘要。任一项目或工件缺失，证据采集器不会签发 `passed`。

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

npm run test:e2e
```

`KB_E2E_OBJECTS_ORIGIN` 为必填项，必须配置为唯一且纯净的绝对 HTTP(S) 源（origin），不得包含用户名、密码、路径、查询参数或片段。所有签名下载 URL 的源必须与其精确一致，并且测试会拒绝任何重定向。

补充变量：

| 变量 | 说明 |
| --- | --- |
| `KB_E2E_JOB_TIMEOUT_MS` | 扫描与 OKF 作业等待上限，最低 30 秒，默认 180 秒 |
| `KB_E2E_RUN_ID` | 8–80 位字母、数字、`_`、`-`，用于隔离合成数据 |
| `KB_E2E_MULTIPART_BYTES` | 真实 Multipart 载荷字节数，必须为 100 MiB–512 MiB，并且必须达到目标拓扑的 Multipart 阈值 |
| `KB_E2E_DOCUMENT_FIXTURE_ROOT` | 九格式黄金样本的绝对专用目录；不得指向生产上传目录 |
| `KB_E2E_DOCUMENT_FIXTURE_MANIFEST` | 由离线生成器产生并通过 SHA-256 验证的 v1 清单绝对路径 |
| `KB_E2E_SIGNING_KEY_PATH` | **必填**。仓库外的 Ed25519 PKCS#8 PEM 私钥绝对路径；必须是 Linux root 所有、`0400/0600` 的常规非符号链接文件 |
| `KB_E2E_CHALLENGE_PATH` | **必填**。仓库外的一次性 challenge JSON 绝对路径；文件名必须为 `<challenge_id>.json`，并满足相同的 root/类型/权限门禁 |
| `KB_E2E_EVIDENCE_PATH` | 正式证据 JSON 输出路径，默认 `artifacts/acceptance/functional/browser-e2e.json` |

> [!CAUTION]
> 不要把任何真实员工账号、生产密钥或企业文档用于此套件。目标环境必须是一次性或可清理的预生产数据集；Playwright 企业档案关闭 trace 与 video，避免把一次性 API Key 写入工件。

## 故障控制面契约

故障控制面必须位于受控测试网络，并在真实反向代理或模型出口上实施故障；它不是浏览器 mock，也不能存在于生产环境。建议契约：

```http
POST /v1/runs/{run_id}/mode
Authorization: Bearer <token>
Content-Type: application/json

{"mode":"provider_5xx"}
```

允许模式：`normal`、`provider_5xx`、`provider_timeout`、`review_reject`、`table_response`、`backend_5xx`、`backend_timeout`。控制面还应提供只含计数、状态与时间的脱敏证据，不得返回提示词、文档正文、凭据或完整内部 URL。

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
    "content_fingerprint": "<64位内容指纹>"
  }
}
```

私钥、challenge 内容和签名输入不会写入日志或测试工件。私钥不允许放入仓库、镜像或 `.env`；这里只通过 `KB_E2E_SIGNING_KEY_PATH` 传递文件路径。正式验证成功后由 Python 验收器原子消费 challenge，第二次提交相同证据会被判定为重放。

失败或缺少拓扑、私钥、challenge、root 所有权、文件权限、有效期或目标指纹时，采集器会删除可能存在的正式证据，仅生成 `browser-e2e.blocked.json` 诊断文件。因此 `runtime-functional` 必须保持 `BLOCKED`，不会复用旧的“通过”文件。

企业场景同时覆盖内容管理员登录落地、真实 Multipart、聊天窗口中的来源/审核拒绝/语义表格、DeepSeek/Qwen/MiniMax 逐一切换、API Key 使用说明、次级页面质量监听与移动端横向溢出；所有故障模式和默认模型都通过 `finally` 恢复。

诊断结果只有三种：

- `passed`：8 项检查在桌面与移动端全部通过，质量工件齐全，代码身份可计算，并成功生成受信 Ed25519 challenge 签名。
- `failed`：真实场景、断言、可访问性、控制台或网络检查失败。
- `blocked`：配置/拓扑缺失、场景未收集、项目/工件缺失、代码身份不可得或工作树不干净。

默认工件目录 `web/test-results/` 已被忽略，不参与产品代码提交。证据可证明某次测试对应的代码身份和结果，但不能替代容量压测、灾备演练、渗透测试或生产变更审批。

## 当前状态

企业档案与验收场景属于验收基础设施；只有在完整预生产拓扑实际运行后才能声明通过。未运行、缺故障控制面或只完成本地 collection 时，项目交付状态仍应记录为 `BLOCKED`，不得写成“全部通过”。
