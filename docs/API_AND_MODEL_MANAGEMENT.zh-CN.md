# API 与模型管理手册

本文说明如何在管理后台创建服务端 API Key、调用知识检索/问答接口，以及切换 DeepSeek、Qwen 和 MiniMax 模型供应商。

## 安全边界

- 外部 API Key 只用于服务器到服务器调用，不得写入浏览器代码、移动端包、Git 或公开日志。
- 明文 Key 只在创建成功时返回一次；平台仅保存不可逆摘要、可识别前缀、权限范围和审计信息。
- 每个 Key 都绑定一个有效用户，最终权限是“用户当前 RBAC 权限 ∩ Key 权限范围 ∩ 知识库范围”。禁用用户或撤销知识库授权会立即影响该 Key。
- 每个 Key 独立配置过期时间和每分钟请求数；达到限制返回 `429` 和 `Retry-After`。
- 模型供应商 API Key 只在 FastAPI 服务端使用。数据库中的供应商凭据使用独立主密钥加密，管理端 GET 接口永不返回明文。
- 供应商 Base URL 仅允许官方 HTTPS 域名，HTTP 重定向默认关闭，避免把企业数据发送到非授权主机。

## 管理后台

具有 `api-key:manage` 或 `llm:manage` 权限的管理员可打开：

```text
https://knowledgebases.vercel.app/admin/api-models
```

页面包含：

1. API Key 创建、列表、状态、最近使用时间和撤销操作；
2. DeepSeek / Qwen / MiniMax 凭据状态、模型名、Base URL 和默认供应商切换；
3. cURL、Python 与 Node.js 的可复制调用示例；
4. 密钥一次性展示、服务端保存和泄露处置提醒。

## 外部 API

生产 API Origin：

```text
https://knowledgebases-api.vercel.app
```

所有外部调用都必须携带：

```http
X-API-Key: kb_live_<one-time-secret>
Content-Type: application/json
```

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
curl "https://knowledgebases-api.vercel.app/api/v1/public/chat/query" \
  -H "X-API-Key: $KNOWLEDGEBASES_API_KEY" \
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
import httpx

response = httpx.post(
    "https://knowledgebases-api.vercel.app/api/v1/public/chat/query",
    headers={"X-API-Key": os.environ["KNOWLEDGEBASES_API_KEY"]},
    json={
        "knowledge_base_id": "00000000-0000-0000-0000-000000000000",
        "message": "请总结该知识库中的产品质检流程",
        "limit": 5,
    },
    timeout=60,
)
response.raise_for_status()
print(response.json())
```

Node.js：

```javascript
const response = await fetch(
  "https://knowledgebases-api.vercel.app/api/v1/public/chat/query",
  {
    method: "POST",
    headers: {
      "X-API-Key": process.env.KNOWLEDGEBASES_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      knowledge_base_id: "00000000-0000-0000-0000-000000000000",
      message: "请总结该知识库中的产品质检流程",
      limit: 5,
    }),
  },
);
if (!response.ok) throw new Error(`Knowledge API failed: ${response.status}`);
console.log(await response.json());
```

问答响应包含答案、检索引用、执行模式，以及实际使用的供应商和模型。供应商不可用时接口返回明确的 `502` 或 `503`，不会伪造模型回答。

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
| `200` | 请求成功 | 读取响应中的 `answer`、`items` 或 `citations` |
| `401` | Key 缺失、格式错误、过期或已撤销 | 替换 Key；不要自动无限重试 |
| `403` | Key 权限或知识库范围不足 | 由管理员调整 Key 范围或用户 RBAC |
| `404` | 资源不存在或为防止枚举而隐藏 | 检查知识库 ID 与授权 |
| `422` | 请求字段不合法 | 根据 `error.details` 修正参数 |
| `429` | 超过 Key 请求频率 | 遵循 `Retry-After` 并使用指数退避 |
| `502` | 模型供应商返回异常 | 短暂退避后重试，保留请求 ID |
| `503` | 数据库、Redis、模型凭据或上游暂不可用 | 检查 `/health/ready` 与服务配置 |

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

API Project 至少需要：

```dotenv
KB_LLM_CREDENTIAL_ENCRYPTION_KEY=<独立生成且至少 32 字符的随机主密钥>
KB_LLM_DEFAULT_PROVIDER=deepseek
KB_DEEPSEEK_API_KEY=<optional environment credential>
KB_QWEN_API_KEY=<optional environment credential>
KB_QWEN_ALLOWED_WORKSPACE_HOSTS=[]
KB_MINIMAX_API_KEY=<optional environment credential>
```

环境变量凭据适合平台统一管理；后台录入的凭据适合运行期轮换。无论哪种方式，明文都不会通过管理 GET 接口返回。更换加密主密钥前必须先规划供应商凭据重新加密或重新录入，不能直接覆盖旧主密钥。

## 运维建议

- 一个调用方使用一个 Key，不要让多个系统共享同一凭据；
- 使用 30～90 天有效期，并在到期前并行创建新 Key 完成无中断轮换；
- 监控 `401`、`403`、`429`、模型 `5xx`、响应时间和 token 使用量；
- 审计日志只记录 Key ID、用户、知识库、供应商、模型、结果和请求 ID，不记录 API Key、模型供应商密钥、问题正文或知识正文；
- 怀疑泄露时先撤销旧 Key，再调查日志并生成新 Key；
- 知识库未启用外部 LLM 处理时，即使配置了默认模型，也不能把该知识库正文发送到第三方供应商。
