# 聊天幂等回放加密运维

聊天最终响应会先进行有界压缩，再使用 AES-256-GCM 加密后写入 PostgreSQL。数据库仅保存密钥版本、12 字节随机 nonce、密文和原始响应大小；密钥必须保存在数据库及备份之外。

## 初始配置

为每个版本生成独立的 32 字节随机密钥：

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

通过受保护的运行时环境文件或密钥管理系统注入：

```dotenv
KB_CHAT_REPLAY_ENCRYPTION_KEYS={"1":"<生成的 base64url 密钥>"}
KB_CHAT_REPLAY_ACTIVE_KEY_VERSION=1
```

生产环境缺少密钥环、密钥长度错误、活动版本不存在时，应用必须在启动阶段失败。非生产环境即使能够启动，聊天执行也会在创建幂等记录和调用模型前失败，不会降级为明文保存。

## 密钥轮换

1. 在密钥管理系统中新增版本，但保留所有仍可能被回放记录引用的旧版本。
2. 将新版本写入 `KB_CHAT_REPLAY_ENCRYPTION_KEYS`，并把 `KB_CHAT_REPLAY_ACTIVE_KEY_VERSION` 切换为新版本。
3. 重启 API 与维护进程，验证旧响应仍可回放、新响应仅写入新版本。
4. 至少等待 `KB_CHAT_IDEMPOTENCY_TTL_SECONDS`，确认旧版本记录已过期并被维护任务清理，再删除旧密钥。

若提前移除旧密钥，相关记录会安全转为 `OUTCOME_UNKNOWN` 并清除密文；系统不会重新调用模型。密文、nonce、密钥版本或 AAD 绑定字段遭到篡改时采用相同的 fail-closed 行为。

## AAD 与迁移边界

AEAD 附加认证数据绑定记录 ID、主体指纹、请求摘要、知识库 ID、知识库内容版本和密钥版本，防止密文被复制到其他记录或资源快照后继续回放。

`20260714_0020` 是不可逆安全迁移：历史 `zlib-json-v1` 的 `COMPLETED` 记录会转为 `OUTCOME_UNKNOWN`，并永久清除可逆响应正文。回滚必须恢复迁移前的整库备份和匹配的旧应用，不得执行降级迁移恢复明文列语义。
