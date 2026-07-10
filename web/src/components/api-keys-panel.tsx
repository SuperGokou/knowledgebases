"use client";

import { useCallback, useEffect, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { apiRequest, readableError } from "@/lib/api-client";
import type { KnowledgeBase, ManagedApiKey } from "@/lib/types";

type ApiKeyListResponse = ManagedApiKey[] | { items: ManagedApiKey[] };
type ApiKeyCreationResponse = ManagedApiKey & {
  key?: string;
  api_key?: string;
  secret?: string;
  plaintext_key?: string;
  item?: ManagedApiKey;
};

function listItems(response: ApiKeyListResponse): ManagedApiKey[] {
  return Array.isArray(response) ? response : response.items;
}

function createdSecret(response: ApiKeyCreationResponse): string {
  return response.key ?? response.api_key ?? response.secret ?? response.plaintext_key ?? "";
}

function createdItem(response: ApiKeyCreationResponse): ManagedApiKey {
  if (response.item) return response.item;
  return {
    id: response.id,
    user_id: response.user_id,
    created_by: response.created_by,
    name: response.name,
    key_prefix: response.key_prefix,
    permission_codes: response.permission_codes,
    knowledge_base_ids: response.knowledge_base_ids,
    requests_per_minute: response.requests_per_minute,
    expires_at: response.expires_at,
    revoked_at: response.revoked_at,
    last_used_at: response.last_used_at,
    created_at: response.created_at,
  };
}

function displayDate(value: string | null): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function ApiKeysPanel() {
  const { can, canAny, loading: accessLoading } = useAccess();
  const [keys, setKeys] = useState<ManagedApiKey[] | null>(null);
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [name, setName] = useState("");
  const [knowledgeBaseIds, setKnowledgeBaseIds] = useState<string[]>([]);
  const [permissionCodes, setPermissionCodes] = useState<string[]>([]);
  const [requestsPerMinute, setRequestsPerMinute] = useState("60");
  const [expiresAt, setExpiresAt] = useState("");
  const [issuedKey, setIssuedKey] = useState("");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  const load = useCallback(async () => {
    if (accessLoading) return;
    if (!can("api-key:manage")) {
      setKeys([]);
      return;
    }
    setError("");
    try {
      const canListKnowledge = canAny(["knowledge:read", "chat:query", "file:upload"]);
      const [keyResponse, knowledgeResponse] = await Promise.all([
        apiRequest<ApiKeyListResponse>("/api/v1/api-keys"),
        canListKnowledge
          ? apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases?limit=100&offset=0")
          : Promise.resolve([]),
      ]);
      setKeys(listItems(keyResponse));
      setKnowledgeBases(knowledgeResponse);
      const availablePermissions = ["chat:query", "knowledge:read"].filter((permission) => can(permission));
      setPermissionCodes((current) => {
        const retained = current.filter((permission) => availablePermissions.includes(permission));
        return retained.length ? retained : availablePermissions;
      });
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can, canAny]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  async function generateKey(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    setCopyState("idle");
    try {
      const created = await apiRequest<ApiKeyCreationResponse>("/api/v1/api-keys", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          permission_codes: permissionCodes,
          knowledge_base_ids: knowledgeBaseIds,
          requests_per_minute: Number(requestsPerMinute),
          expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        }),
      });
      const secret = createdSecret(created);
      if (!secret) throw new Error("后台没有返回一次性 API Key，请撤销该凭证后重试。");
      const item = createdItem(created);
      setIssuedKey(secret);
      setName("");
      setKnowledgeBaseIds([]);
      setExpiresAt("");
      setKeys((current) => current ? [item, ...current.filter((key) => key.id !== item.id)] : [item]);
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  function toggleValue(value: string, current: string[], update: (items: string[]) => void) {
    update(current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  }

  async function copyIssuedKey() {
    try {
      await navigator.clipboard.writeText(issuedKey);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  async function revokeKey(key: ManagedApiKey) {
    if (!window.confirm(`确定撤销“${key.name}”吗？使用该 Key 的系统将立即无法调用 API。`)) return;
    setPending(true);
    setError("");
    try {
      await apiRequest<null>(`/api/v1/api-keys/${key.id}`, { method: "DELETE" });
      setKeys((current) => current?.filter((item) => item.id !== key.id) ?? current);
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  if (!accessLoading && !can("api-key:manage")) {
    return <EmptyState compact icon="lock" title="没有 API Key 管理权限" description="当前角色不包含 api-key:manage；FastAPI 会在服务端再次校验权限。" />;
  }

  return (
    <section className="panel api-keys-panel">
      <div className="panel-header">
        <div><h2>API Key</h2><p>为内部系统生成独立凭证，并按应用执行撤销和轮换</p></div>
        <button className="button ghost small" type="button" disabled={pending} onClick={() => void load()}><Icon name="refresh" />刷新</button>
      </div>
      {error ? <div className="panel-inline-state"><ErrorState message={error} onRetry={() => void load()} /></div> : null}
      <form className="api-key-create" onSubmit={generateKey}>
        <div className="api-key-form-grid">
          <label htmlFor="api-key-name">凭证名称<input id="api-key-name" value={name} maxLength={200} onChange={(event) => setName(event.target.value)} placeholder="例如：ERP 生产环境" required /></label>
          <label htmlFor="api-key-rate">每分钟请求上限<input id="api-key-rate" type="number" min="1" max="10000" value={requestsPerMinute} onChange={(event) => setRequestsPerMinute(event.target.value)} required /></label>
          <label htmlFor="api-key-expiry">过期时间（可选）<input id="api-key-expiry" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
          <fieldset className="fieldset api-scope-fieldset">
            <legend>接口权限</legend>
            <div className="api-scope-options">
              {can("chat:query") ? <label className="check-option"><input type="checkbox" checked={permissionCodes.includes("chat:query")} onChange={() => toggleValue("chat:query", permissionCodes, setPermissionCodes)} /><span>知识问答<small>chat:query</small></span></label> : null}
              {can("knowledge:read") ? <label className="check-option"><input type="checkbox" checked={permissionCodes.includes("knowledge:read")} onChange={() => toggleValue("knowledge:read", permissionCodes, setPermissionCodes)} /><span>知识检索<small>knowledge:read</small></span></label> : null}
            </div>
          </fieldset>
          <fieldset className="fieldset api-knowledge-fieldset">
            <legend>允许访问的知识库</legend>
            {knowledgeBases === null ? <p className="field-hint">正在加载知识库…</p> : null}
            {knowledgeBases?.length === 0 ? <p className="field-hint">当前账号没有可授权的知识库。请先创建知识库或授予访问权限。</p> : null}
            {knowledgeBases?.length ? <div className="api-knowledge-options">{knowledgeBases.map((knowledgeBase) => <label className="check-option" key={knowledgeBase.id}><input type="checkbox" checked={knowledgeBaseIds.includes(knowledgeBase.id)} onChange={() => toggleValue(knowledgeBase.id, knowledgeBaseIds, setKnowledgeBaseIds)} /><span>{knowledgeBase.name}<small>{knowledgeBase.access_level} · {knowledgeBase.id.slice(0, 8)}</small></span></label>)}</div> : null}
          </fieldset>
        </div>
        <div className="api-key-create-footer">
          <p>按“系统 + 环境”隔离凭证，并只勾选业务必需的知识库与接口。</p>
          <button className="button primary" type="submit" disabled={pending || !name.trim() || permissionCodes.length === 0 || knowledgeBaseIds.length === 0}><Icon name="plus" />{pending ? "正在生成…" : "生成 API Key"}</button>
        </div>
      </form>

      {issuedKey ? (
        <div className="issued-key" role="status" aria-live="polite">
          <div className="issued-key-heading">
            <span><Icon name="warning" /></span>
            <div><strong>请立即复制并安全保存</strong><p>这是 API Key 唯一一次明文展示。关闭后无法恢复，只能撤销并重新生成。</p></div>
          </div>
          <div className="secret-copy-row">
            <code>{issuedKey}</code>
            <button className="button secondary" type="button" onClick={() => void copyIssuedKey()}><Icon name={copyState === "copied" ? "check" : "file"} />{copyState === "copied" ? "已复制" : copyState === "failed" ? "复制失败" : "复制"}</button>
          </div>
          <button className="issued-dismiss" type="button" onClick={() => { setIssuedKey(""); setCopyState("idle"); }}>我已保存，关闭明文</button>
        </div>
      ) : null}

      {keys === null && !error ? <LoadingRows count={3} /> : null}
      {keys?.length === 0 && !error ? <EmptyState compact icon="lock" title="还没有 API Key" description="为第一个服务端应用创建独立凭证。明文只会展示一次。" /> : null}
      {keys?.length ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>名称</th><th>Key 标识</th><th>状态</th><th>最近使用</th><th>创建时间</th><th>操作</th></tr></thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id}>
                  <td><div className="primary-cell"><span className="key-icon"><Icon name="lock" /></span><span><strong>{key.name}</strong><small>{key.permission_codes.join(" · ")} · {key.knowledge_base_ids.length} 个知识库</small></span></div></td>
                  <td><code className="mono">{key.key_prefix}••••••••</code></td>
                  <td>{key.expires_at && new Date(key.expires_at) <= new Date() ? <StatusBadge tone="danger">已过期</StatusBadge> : <StatusBadge tone="success">有效 · {key.requests_per_minute}/min</StatusBadge>}</td>
                  <td>{displayDate(key.last_used_at)}</td>
                  <td>{displayDate(key.created_at)}</td>
                  <td><button className="button danger small" type="button" disabled={pending} onClick={() => void revokeKey(key)}>撤销</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
