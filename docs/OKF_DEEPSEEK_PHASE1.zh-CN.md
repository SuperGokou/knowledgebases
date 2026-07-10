# OKF 第一阶段：DeepSeek 自动知识编译

本阶段把“文件上传完成”与“外部模型处理”拆成两个可恢复的事务。上传接口只创建持久化转换任务；定时 Worker 领取带 UUID 租约的任务，再调用 DeepSeek。Worker 崩溃后租约会过期并被重新领取，旧 Worker 无权覆盖新租约的结果。

## 当前能力边界

- 仅把不超过 `KB_OKF_SOURCE_MAX_BYTES` 的 UTF-8 `.txt` / `.csv` 发送给 DeepSeek。
- `.pdf`、Word、Excel、PowerPoint 等二进制格式标记为 `unsupported / parser_required`，等待后续隔离解析器；系统不会把二进制内容伪装成“已解析”。
- 每个知识库默认禁止外部 LLM 处理。知识库 Manager 必须明确设置 `external_llm_processing_enabled=true`；关闭后，未领取任务不会向第三方发送正文。
- 模型输出先经过严格 Pydantic Schema 校验，禁止未知字段；空输出、截断输出和无效 JSON 都会重试。
- 生成的 OKF 条目状态为 `draft`，普通读者、搜索与聊天均不可见。管理员批准源文件后，关联草稿才发布为 `published`。
- 原始文件保持在 S3/COS；PostgreSQL 保存任务状态、租约、重试时间、模型/提示版本、输出条目和审计事件。

## OKF v0.1 映射

生成条目遵循 OKF v0.1 的最小约定：

- `entry_type` → frontmatter `type`（必填）
- `title` → `title`
- `custom_metadata.description` → `description`
- `custom_metadata.resource` → 稳定的内部 `kb-file://<uuid>` URI
- `custom_metadata.tags` → `tags`
- `custom_metadata.timestamp` → ISO 8601 `timestamp`
- `content` → Markdown body
- `format_version` → `okf/0.1`

当前数据库记录是可导出的 OKF 概念投影，并不声称已经形成完整 Bundle。`index.md`、`log.md`、Bundle 导入/导出和交叉链接属于后续阶段。

## DeepSeek 配置

```dotenv
KB_DEEPSEEK_API_KEY=<server-side-secret>
KB_DEEPSEEK_BASE_URL=https://api.deepseek.com
KB_DEEPSEEK_MODEL=deepseek-v4-flash
KB_OKF_SOURCE_MAX_BYTES=1000000
KB_OKF_CONVERSION_MAX_ATTEMPTS=4
KB_OKF_CONVERSION_BATCH_SIZE=5
KB_OKF_CONVERSION_TIME_BUDGET_SECONDS=50
```

API Key 只允许配置在后端/Worker 环境，不能使用 `NEXT_PUBLIC_` 前缀。没有 Key 时 Worker 不领取任务，上传功能不受影响。

实现使用 DeepSeek 的 OpenAI 兼容 `POST /chat/completions`，启用 `response_format={"type":"json_object"}`，并在提示中明确要求 JSON。默认采用官方当前模型 `deepseek-v4-flash`；未使用即将弃用的 `deepseek-chat` / `deepseek-reasoner` 名称。

## 状态和运维

任务状态：`pending → processing → succeeded`，可重试错误进入 `retry_wait`，超过次数进入 `failed`，缺少解析器或文本不合格进入 `unsupported`。

当前 Hobby 兼容配置每天调用一次 `/api/v1/internal/maintenance` 做漏单对账。每次调用受批量上限与时间预算双重限制；单任务的意外异常会被隔离、审计并退避重试，不会使整个批次返回 500。

> 每分钟 Cron 需要 Vercel Pro/Enterprise。Hobby 计划只允许每天一次；若需要“上传后尽快转换”，请使用 Upstash QStash、Vercel Queue 或独立 Worker 触发消费，保留当前每日 Cron 仅用于漏单对账。

管理 API：

- `GET /api/v1/files/{file_id}/okf-conversion`：查看任务状态。
- `POST /api/v1/files/{file_id}/okf-conversion/retry`：Manager 对终态失败任务手动重试。
- `POST /api/v1/files/{file_id}/approve`：批准文件，并发布关联的 OKF 草稿。

参考：[DeepSeek JSON Output](https://api-docs.deepseek.com/guides/json_mode)、[DeepSeek Error Codes](https://api-docs.deepseek.com/quick_start/error_codes)、[OKF v0.1 Specification](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)。
