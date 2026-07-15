# API 与模型管理手册

本文说明如何在管理后台创建服务端 API Key、调用知识检索/问答接口，以及切换 DeepSeek、Qwen 和 MiniMax 模型供应商。

## 安全边界

- 外部 API Key 只用于服务器到服务器调用，不得写入浏览器代码、移动端包、Git 或公开日志。
- 明文 Key 只在创建或原子轮换成功时返回一次；平台仅保存不可逆摘要、可识别前缀、权限范围、稳定凭据族 ID 和审计信息。
- 每个 Key 都绑定一个有效用户，最终权限是“用户当前 RBAC 权限 ∩ Key 权限范围 ∩ 知识库范围”。禁用用户或撤销知识库授权会立即影响该 Key。
- 每个 Key 独立配置过期时间和每分钟请求数；达到限制返回 `429` 和 `Retry-After`。
- 模型供应商 API Key 只在 FastAPI 服务端使用。数据库中的供应商凭据使用独立主密钥加密，管理端 GET 接口永不返回明文。
- 供应商 Base URL 仅允许官方 HTTPS 域名，HTTP 重定向默认关闭，避免把企业数据发送到非授权主机。

## 管理后台

具有 `api-key:manage` 或 `llm:manage` 权限的管理员可打开：

```text
https://<KB_PUBLIC_HOST>:<KB_HTTPS_PORT>/admin/api-models
```

页面包含：

1. API Key 创建、列表、状态、最近使用时间、原子轮换和撤销操作；
2. DeepSeek / Qwen / MiniMax 凭据状态、模型名、Base URL 和默认供应商切换；
3. cURL、Python 与 Node.js 的可复制调用示例；
4. 密钥一次性展示、服务端保存和泄露处置提醒。

角色管理接口使用资源级 CAS，避免多个管理员同时编辑时由旧页面恢复已撤销权限。`RoleRead` 必须包含正整数 `policy_version`；修改角色名称、描述、优先级、权限、限额或组合策略时，分别向对应 PATCH/PUT 请求提交 `expected_version`。成功的实际变更返回递增后的版本；相同内容保持无副作用。旧快照返回 `409 stale_role_policy` 与 `details.current_version`，客户端必须关闭旧草稿并重新读取完整角色，严禁自动重试全量策略。

账号与角色生命周期接口：

| 能力 | 接口 | 关键约束 |
|---|---|---|
| 当前用户修改密码 | `PUT /api/v1/users/me/password` | 必须验证当前密码并经过限流；成功后撤销现有会话 |
| 管理员重置密码 | `PUT /api/v1/users/{user_id}/password` | 重置他人密码仅允许仍有效的超级管理员；不得提交目标用户旧密码 |
| 删除角色 | `DELETE /api/v1/roles/{role_id}?expected_version=N` | 严格 CAS；系统角色、高优先级越权或仍被用户/知识库引用时失败关闭 |

两条密码路径都应用统一强密码策略，并在同一事务中提升 `token_version`、撤销 refresh token 和写入审计。角色存在引用时返回 `409 role_in_use`，`details.references` 只包含用户分配与知识库授权计数；清理引用后必须重新读取最新 `policy_version` 再决定是否删除。

## 服务端公共 API

生产 API Origin 由当前部署决定。内网部署应使用同一台知识库服务器，不依赖
GitHub、Vercel 或外部 CDN：

```bash
export KNOWLEDGEBASES_API_ORIGIN="https://<KB_PUBLIC_HOST>:<KB_HTTPS_PORT>"
```

局域网业务系统直接通过 Caddy 进入 FastAPI，不需要浏览器登录 Cookie，也不依赖
Web 页面、GitHub 或 Vercel。所有调用都必须携带：

```http
X-API-Key: kb_live_<one-time-secret>
Content-Type: application/json
```

知识问答端点还强制要求 `Idempotency-Key`。键长为 1～160 个字符，首字符必须是
ASCII 字母或数字，其余字符仅允许 ASCII 字母、数字、`.`、`_`、`:`、`-`。首次
发起一条逻辑问答时生成新键；网络超时后重试同一请求时复用原键；修改问题、切换
知识库或开始新对话时必须换新键。缺失或格式非法时返回 `422 validation_error`，
服务端不会再以请求追踪 ID 静默代替业务幂等键。

幂等命名空间按调用主体隔离：登录端点使用用户 ID，公开端点使用稳定的 API 凭据族 ID。轮换前后的 Key 属于同一凭据族，不能借轮换绕过幂等或每分钟限流；审计和用量记录仍保存实际使用的 Key ID。同一主体、同一 Key 与同一规范化 `ChatQueryRequest` 在保留期内会原样重放最终 `ChatQueryResponse`，不会再次执行知识检索、模型调用、审核或 token 计费。

服务端只持久化主体、Key 和请求的 SHA-256，不保存问题正文；最终响应先进行有界 zlib JSON 压缩，再使用 AES-256-GCM 加密。数据库只保存密钥版本、12 字节随机 nonce、密文和原始大小，密钥环位于数据库与备份之外。每次重放前仍会在与撤权相同的锁域内重新检查当前用户、实际 Key、RBAC 与知识库授权，并比较知识库内容版本；撤权后不能读取旧响应，内容被新增、修改、撤稿或删除后旧响应会被清空并封闭，绝不自动再次调用模型。密钥缺失、密文/AAD 篡改或解密失败时记录转为 `OUTCOME_UNKNOWN` 并清除密文，不会重新调用模型。

> [!WARNING]
> 迁移 `20260714_0020` 是不可逆安全迁移：历史 `zlib-json-v1` 的 `COMPLETED` 记录会转为 `OUTCOME_UNKNOWN` 并永久清除正文。应用层 AEAD 只覆盖聊天重放字段；生产环境仍必须对 PostgreSQL 数据卷、WAL、快照与备份启用并验证静态加密。密钥生成、轮换、AAD 与回退边界见[聊天幂等回放加密运维](./CHAT_REPLAY_ENCRYPTION.zh-CN.md)。

| 场景 | HTTP / `error.code` | 客户端行为 |
|---|---|---|
| 相同请求已完成 | `200` | 直接使用原样重放的响应 |
| 同 Key 对应不同请求 | `409 idempotency_conflict` | 生成新 Key；不得覆盖或重试旧请求 |
| 原请求仍在处理 | `409 idempotency_in_progress` | 保持相同请求和 Key，遵循 `Retry-After` 后重试 |
| 结果无法安全确认 | `409 idempotency_outcome_unknown` | 停止自动重试和人工重复提交，按请求 ID 交由运维核对 |
| 知识库内容版本已变化 | `409 idempotency_resource_changed` | 停止重放旧答案；由用户发起新逻辑请求并生成新 Key，不得把旧 Key 自动改写后重试 |

> [!CAUTION]
> `idempotency_outcome_unknown` 是防重复计费和防二次外发的终态，不会伪装成
> `200 duplicate_request` 检索降级。客户端不得换 Key 自动补发同一业务问题。

### API Key 原子轮换

```http
POST /api/v1/api-keys/{api_key_id}/rotate
Authorization: Bearer <access-token>
```

轮换在一个数据库事务内撤销旧 Key、创建同一 `credential_family_id` 的替代 Key，并迁移 Key 级预算绑定。响应以 `201` 返回一次性明文新 Key，同时带 `Cache-Control: no-store`；旧 Key 随即返回 `401`。替代 Key 继承原权限、知识库范围、每分钟限额和有效期。客户端必须保留原逻辑请求的 `Idempotency-Key`，这样响应丢失后可跨轮换安全重放；不要用“撤销后新建无关 Key”代替轮换，因为新建 Key 属于不同凭据族。

部署使用企业内部 CA 时，应先把根证书安装到操作系统或应用运行时的信任库。无法
修改系统信任库的受控客户端，可使用 cURL `--cacert <ROOT_CA.pem>`、Python/httpx
`verify=<ROOT_CA.pem>` 或 Node.js `NODE_EXTRA_CA_CERTS=<ROOT_CA.pem>`；禁止使用
`--insecure`、`verify=False` 或关闭 TLS 主机名校验。

无需公网资源的机器可读契约与健康探针为：

```text
GET /openapi.json
GET /health/live
GET /health/ready
```

离线入口不发布依赖公共 CDN 的 FastAPI 默认 `/docs` 与 `/redoc`。`/openapi.json`
包含完整控制面结构，只允许在 VPN/企业可信网段内使用；直接 API 调用范围仍限于
`/api/v1/public/*`。

### 知识问答

```http
POST /api/v1/public/chat/query
```

```json
{
  "knowledge_base_id": "00000000-0000-0000-0000-000000000000",
  "message": "请总结该知识库中的产品质检流程",
  "limit": 5
}
```

cURL：

```bash
curl "${KNOWLEDGEBASES_API_ORIGIN}/api/v1/public/chat/query" \
  --connect-timeout 10 \
  --max-time 115 \
  -H "X-API-Key: $KNOWLEDGEBASES_API_KEY" \
  -H "Idempotency-Key: $KNOWLEDGEBASES_IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "knowledge_base_id": "00000000-0000-0000-0000-000000000000",
    "message": "请总结该知识库中的产品质检流程",
    "limit": 5
  }'
```

Python：

```python
import os
import uuid
import httpx

api_origin = os.environ["KNOWLEDGEBASES_API_ORIGIN"].rstrip("/")
idempotency_key = f"chat-{uuid.uuid4()}"
response = httpx.post(
    f"{api_origin}/api/v1/public/chat/query",
    headers={
        "X-API-Key": os.environ["KNOWLEDGEBASES_API_KEY"],
        "Idempotency-Key": idempotency_key,
    },
    json={
        "knowledge_base_id": "00000000-0000-0000-0000-000000000000",
        "message": "请总结该知识库中的产品质检流程",
        "limit": 5,
    },
    timeout=httpx.Timeout(115.0, connect=10.0),
)
response.raise_for_status()
print(response.json())
```

Node.js：

```javascript
const apiOrigin = process.env.KNOWLEDGEBASES_API_ORIGIN?.replace(/\/+$/, "");
if (!apiOrigin) throw new Error("KNOWLEDGEBASES_API_ORIGIN is required");
const idempotencyKey = `chat-${crypto.randomUUID()}`;

const response = await fetch(
  `${apiOrigin}/api/v1/public/chat/query`,
  {
    method: "POST",
    headers: {
      "X-API-Key": process.env.KNOWLEDGEBASES_API_KEY,
      "Idempotency-Key": idempotencyKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      knowledge_base_id: "00000000-0000-0000-0000-000000000000",
      message: "请总结该知识库中的产品质检流程",
      limit: 5,
    }),
    signal: AbortSignal.timeout(115000),
  },
);
if (!response.ok) throw new Error(`Knowledge API failed: ${response.status}`);
console.log(await response.json());
```

每个成功的问答响应都包含服务端生成的来源脚注、结构化引用、来源状态、执行模式，以及实际使用的供应商和模型：

```json
{
  "knowledge_base_id": "00000000-0000-0000-0000-000000000000",
  "answer": "质检异常必须先登记并提交复核。[1]\n\n答案来源（知识库）：\n[1] 质检流程（entry:11111111-1111-1111-1111-111111111111 · path:policies/quality.md）",
  "mode": "rag",
  "provider": "qwen",
  "model": "qwen-plus",
  "citations": [
    {
      "entry_id": "11111111-1111-1111-1111-111111111111",
      "source_file_id": "22222222-2222-2222-2222-222222222222",
      "title": "质检流程",
      "excerpt": "发现异常后登记批次并提交质量负责人复核。",
      "source_path": "policies/quality.md",
      "format_version": "0.1",
      "citation_number": 1,
      "marker": "[1]"
    }
  ],
  "source_status": {
    "status": "grounded",
    "strategy": "rag",
    "reason": "llm_generated",
    "citation_count": 1
  }
}
```

`citation_number` 与 `marker` 由服务端分配，稳定 `entry_id` 是核验来源身份的主定位符，`title` 与 `source_path` 只用于可读展示。模型回答缺少合法引用、任一事实段漏引、出现越界编号或自行生成 `Sources` / `References` /“答案来源”区块时，平台会丢弃该模型文本，返回 `200` 的确定性检索结果，并把 `source_status.strategy` 标为 `retrieval_fallback`。供应商未配置、配置错误，以及明确未外发或已取得完整计量结果的失败也使用同一安全降级路径，不会伪造模型回答；网络中断、未知计量或重复用量占位等无法证明上游结果的场景返回 `409 idempotency_outcome_unknown`，不会伪装为成功降级。

未检索到匹配内容时，`citations` 为空，`source_status.status` 为 `no_results`，`answer` 会明确注明“当前知识库未检索到可引用内容”。生成回答与语义审核使用独立客户端；只有 `answer_review.status=passed` 且理由为 `semantic_verified` 时才返回模型文本。独立审核客户端不可用、拒绝、超时或引用校验失败时，平台丢弃生成文本并返回确定性检索结果。`grounded` 和自动审核通过仍不等于逐句业务事实认证；高风险结论必须打开来源并由授权人员人工核验，文档不得承诺“零幻觉”。

| `source_status.reason` | 含义 |
|---|---|
| `llm_generated` | 模型回答通过服务端引用结构校验 |
| `external_processing_disabled` | 知识库未授权外部模型，直接返回本地检索回答 |
| `provider_unconfigured` | 当前供应商未配置，已降级到本地检索 |
| `provider_configuration_error` | 供应商配置不可用，已降级到本地检索 |
| `provider_unavailable` | 上游模型调用失败，已降级到本地检索 |
| `missing_model_citations` | 模型漏引，模型文本已丢弃 |
| `invalid_model_citations` | 模型引用越界或伪造来源区块，模型文本已丢弃 |
| `no_matching_content` | 当前授权知识库没有可引用的匹配条目 |

### 纯知识检索

```http
POST /api/v1/public/knowledge-bases/{knowledge_base_id}/search
```

```json
{
  "query": "质检异常处理",
  "limit": 10
}
```

该接口仅返回当前 Key 有权访问且已发布的知识条目，不调用生成式模型。

## 状态码

| 状态码 | 含义 | 处理建议 |
|---|---|---|
| `200` | 请求成功；聊天也可能是安全检索降级 | 同时读取 `answer`、`citations` 与 `source_status`，不要只依赖 `mode` |
| `401` | Key 缺失、格式错误、过期或已撤销 | 替换 Key；不要自动无限重试 |
| `403` | Key 权限或知识库范围不足 | 由管理员调整 Key 范围或用户 RBAC |
| `404` | 资源不存在或为防止枚举而隐藏 | 检查知识库 ID 与授权 |
| `409` | 聊天幂等冲突、处理中或结果未知 | 按 `error.code` 执行上表策略；只有 `idempotency_in_progress` 可使用原 Key 退避重试 |
| `422` | 请求字段或聊天 `Idempotency-Key` 缺失/不合法 | 根据 `error.details` 修正参数；同一逻辑请求重试时复用原键 |
| `429` | 超过 Key 请求频率 | 遵循 `Retry-After` 并使用指数退避 |
| `502` | 非聊天接口的上游服务返回异常 | 短暂退避后重试，保留请求 ID；聊天 Provider 异常通常返回带来源的检索降级结果 |
| `503` | 数据库、Redis 或其他必需基础依赖不可用 | 检查 `/health/ready` 与服务配置；聊天 Provider 配置异常通常不会触发 503 |

所有错误均使用统一结构：

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Safe error message"
  },
  "request_id": "request-correlation-id"
}
```

## 模型供应商

| 供应商 | 推荐 Base URL | 示例模型 | 环境变量 |
|---|---|---|---|
| DeepSeek | `https://api.deepseek.com` | `deepseek-v4-flash` / `deepseek-v4-pro` | `KB_DEEPSEEK_API_KEY` |
| Qwen（中国北京） | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` | `KB_QWEN_API_KEY` |
| Qwen（其他区域） | 工作空间专属 `https://{workspace}.{region}.maas.aliyuncs.com/compatible-mode/v1` | 以该区域模型列表为准 | `KB_QWEN_API_KEY` |
| MiniMax | `https://api.minimax.io/v1` | `MiniMax-M2.7` | `KB_MINIMAX_API_KEY` |

三家均通过 OpenAI-compatible Chat Completions 接口接入，但平台会按供应商处理不兼容的扩展字段，避免把 DeepSeek 专属参数发送给 Qwen 或 MiniMax。

Qwen 工作空间专属地址必须额外配置精确主机白名单，例如：

```dotenv
KB_QWEN_ALLOWED_WORKSPACE_HOSTS=["workspace-id.cn-beijing.maas.aliyuncs.com"]
```

平台拒绝通配符、协议、路径与端口；内置的公共区域域名不需要加入该数组。

官方参考：

- [DeepSeek 首次调用 API](https://api-docs.deepseek.com/)
- [Alibaba Cloud Model Studio OpenAI-compatible API](https://www.alibabacloud.com/help/en/model-studio/qwen-api-reference/)
- [MiniMax Compatible OpenAI API](https://platform.minimax.io/docs/api-reference/text-openai-api)

## 生产配置

FastAPI 服务端至少需要：

```dotenv
KB_LLM_CREDENTIAL_ENCRYPTION_KEY=<独立生成且至少 32 字符的随机主密钥>
KB_LLM_DEFAULT_PROVIDER=deepseek
KB_LLM_EGRESS_MODE=strict_offline
KB_LLM_EGRESS_GATEWAY_URL=
KB_LLM_EGRESS_APPROVED_PROVIDERS=
KB_DEEPSEEK_API_KEY=<optional environment credential>
KB_QWEN_API_KEY=<optional environment credential>
KB_QWEN_ALLOWED_WORKSPACE_HOSTS=[]
KB_MINIMAX_API_KEY=<optional environment credential>
KB_CHAT_IDEMPOTENCY_TTL_SECONDS=86400
KB_CHAT_IDEMPOTENCY_PROCESSING_TIMEOUT_SECONDS=300
KB_CHAT_IDEMPOTENCY_RESPONSE_MAX_BYTES=131072
KB_CHAT_IDEMPOTENCY_CLEANUP_BATCH_SIZE=1000
KB_CHAT_IDEMPOTENCY_CLEANUP_MAX_BATCHES=5
KB_CHAT_REPLAY_ENCRYPTION_KEYS={"1":"<32-byte-base64url-key>"}
KB_CHAT_REPLAY_ACTIVE_KEY_VERSION=1
```

`KB_CHAT_IDEMPOTENCY_TTL_SECONDS` 决定已完成/结果未知记录的保留期；处理中超时必须
覆盖一次完整检索、生成与独立审核的最长允许时间，不能为了快速回收而缩短。响应上限
同时约束规范化 JSON 与压缩体，超过边界会封闭为 `idempotency_outcome_unknown`，
不会返回一个之后无法重放的成功响应。

环境变量凭据适合平台统一管理；后台录入的凭据适合运行期轮换。无论哪种方式，明文都不会通过管理 GET 接口返回。更换加密主密钥前必须先规划供应商凭据重新加密或重新录入，不能直接覆盖旧主密钥。

模型出口采用显式三态策略：

| 模式 | 语义 |
|---|---|
| `strict_offline` | 默认值；网关 URL 与供应商白名单必须为空，不创建模型出口，问答确定性降级 |
| `controlled_gateway` | 仅经审批时启用；URL 必须精确为 `http://llm-egress:8080`，白名单必须是按 `deepseek,qwen,minimax` 规范顺序排列的非空子集 |
| `direct` | 只允许经独立安全评审的非隔离部署；`deployment_profile=isolated` 会在启动阶段拒绝该模式 |

DeepSeek、Qwen 与 MiniMax 不是局域网检索、来源回答、权限、限额或审计的运行依赖。受控网关也不允许访问 GitHub、Vercel、外部数据库、对象存储、公共 Registry、npm 或 PyPI；完全离线的生成式回答需要另行部署并验收企业内网模型服务。废弃变量 `KB_EXTERNAL_LLM_ENABLED` 会被配置校验拒绝，不得继续写入环境文件或操作手册。

## 运维建议

- 一个调用方使用一个 Key，不要让多个系统共享同一凭据；
- 使用 30～90 天有效期，并在到期前调用原子轮换端点；不得以创建不同凭据族的新 Key 代替正常轮换；
- 监控 `401`、`403`、`429`、模型 `5xx`、响应时间和 token 使用量；
- 审计日志只记录 Key ID、用户、知识库、供应商、模型、结果和请求 ID，不记录 API Key、模型供应商密钥、问题正文或知识正文；
- 怀疑泄露时调用原子轮换立即撤销旧 Key，妥善保存一次性返回的新 Key，再按旧/新实际 Key ID 与共同凭据族 ID 调查审计日志；
- 知识库未启用外部 LLM 处理时，即使配置了默认模型，也不能把该知识库正文发送到第三方供应商。
