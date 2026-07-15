"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import {
  apiKeyPagePath,
  knowledgeBasePagePath,
  mergeAdminPage,
  replaceRotatedApiKey,
  splitAdminPage,
} from "@/lib/api-key-administration";
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

type IssuedCredential = {
  keyId: string;
  name: string;
  operation: "created" | "rotated";
  secret: string;
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
    credential_family_id: response.credential_family_id,
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
  const [keysHasMore, setKeysHasMore] = useState(false);
  const [keysLoading, setKeysLoading] = useState(false);
  const [keysError, setKeysError] = useState("");
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [knowledgeHasMore, setKnowledgeHasMore] = useState(false);
  const [knowledgeLoading, setKnowledgeLoading] = useState(false);
  const [knowledgeError, setKnowledgeError] = useState("");
  const [knowledgeQuery, setKnowledgeQuery] = useState("");
  const [debouncedKnowledgeQuery, setDebouncedKnowledgeQuery] = useState("");
  const [name, setName] = useState("");
  const [knowledgeBaseIds, setKnowledgeBaseIds] = useState<string[]>([]);
  const [permissionCodes, setPermissionCodes] = useState<string[]>([]);
  const [requestsPerMinute, setRequestsPerMinute] = useState("60");
  const [expiresAt, setExpiresAt] = useState("");
  const [issuedCredential, setIssuedCredential] = useState<IssuedCredential | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [actionError, setActionError] = useState("");
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const keysRequestId = useRef(0);
  const knowledgeRequestId = useRef(0);

  const loadKeys = useCallback(async (offset: number, replace: boolean) => {
    if (accessLoading) return;
    if (!can("api-key:manage")) {
      setKeys([]);
      setKeysHasMore(false);
      return;
    }
    const requestId = ++keysRequestId.current;
    setKeysLoading(true);
    setKeysError("");
    try {
      const response = await apiRequest<ApiKeyListResponse>(apiKeyPagePath(offset));
      if (requestId !== keysRequestId.current) return;
      const page = splitAdminPage(listItems(response));
      setKeys((current) => mergeAdminPage(current ?? [], page.items, replace));
      setKeysHasMore(page.hasMore);
    } catch (reason) {
      if (requestId === keysRequestId.current) setKeysError(readableError(reason));
    } finally {
      if (requestId === keysRequestId.current) setKeysLoading(false);
    }
  }, [accessLoading, can]);

  const loadKnowledgeBases = useCallback(async (
    query: string,
    offset: number,
    replace: boolean,
  ) => {
    if (accessLoading) return;
    if (!canAny(["knowledge:read", "chat:query", "file:upload"])) {
      setKnowledgeBases([]);
      setKnowledgeHasMore(false);
      return;
    }
    const requestId = ++knowledgeRequestId.current;
    setKnowledgeLoading(true);
    setKnowledgeError("");
    try {
      const response = await apiRequest<KnowledgeBase[]>(knowledgeBasePagePath({
        offset,
        query,
      }));
      if (requestId !== knowledgeRequestId.current) return;
      const page = splitAdminPage(response);
      setKnowledgeBases((current) => mergeAdminPage(current ?? [], page.items, replace));
      setKnowledgeHasMore(page.hasMore);
    } catch (reason) {
      if (requestId === knowledgeRequestId.current) {
        setKnowledgeError(readableError(reason));
      }
    } finally {
      if (requestId === knowledgeRequestId.current) setKnowledgeLoading(false);
    }
  }, [accessLoading, canAny]);

  useEffect(() => {
    if (accessLoading) return;
    const timeout = window.setTimeout(() => {
      const availablePermissions = ["chat:query", "knowledge:read"].filter((permission) => can(permission));
      setPermissionCodes((current) => {
        const retained = current.filter((permission) => availablePermissions.includes(permission));
        return retained.length ? retained : availablePermissions;
      });
      void loadKeys(0, true);
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [accessLoading, can, loadKeys]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => setDebouncedKnowledgeQuery(knowledgeQuery.trim()),
      300,
    );
    return () => window.clearTimeout(timeout);
  }, [knowledgeQuery]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => void loadKnowledgeBases(debouncedKnowledgeQuery, 0, true),
      0,
    );
    return () => window.clearTimeout(timeout);
  }, [debouncedKnowledgeQuery, loadKnowledgeBases]);

  function clearIssuedCredential() {
    setIssuedCredential(null);
    setCopyState("idle");
  }

  async function generateKey(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (issuedCredential) {
      setActionError("请先安全保存并关闭当前明文，再生成新凭证。");
      return;
    }
    setPendingAction("create");
    setActionError("");
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
      const item = createdItem(created);
      if (!secret) {
        void loadKeys(0, true);
        throw new Error("后台没有返回一次性 API Key，请立即刷新列表并撤销该凭证。");
      }
      setIssuedCredential({ keyId: item.id, name: item.name, operation: "created", secret });
      setName("");
      setKnowledgeBaseIds([]);
      setExpiresAt("");
      setKeys((current) => replaceRotatedApiKey(current ?? [], item.id, item));
    } catch (reason) {
      setActionError(readableError(reason));
    } finally {
      setPendingAction(null);
    }
  }

  function toggleValue(value: string, current: string[], update: (items: string[]) => void) {
    update(current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  }

  async function copyIssuedKey() {
    if (!issuedCredential) return;
    try {
      await navigator.clipboard.writeText(issuedCredential.secret);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  async function rotateKey(key: ManagedApiKey) {
    if (issuedCredential) {
      setActionError("请先安全保存并关闭当前明文，再轮换其他凭证。");
      return;
    }
    if (!window.confirm(`确定轮换“${key.name}”吗？旧 Key 将立即失效。`)) return;
    setPendingAction(`rotate:${key.id}`);
    setActionError("");
    try {
      const created = await apiRequest<ApiKeyCreationResponse>(
        `/api/v1/api-keys/${key.id}/rotate`,
        { method: "POST" },
      );
      const secret = createdSecret(created);
      const item = createdItem(created);
      if (!secret) {
        void loadKeys(0, true);
        throw new Error("轮换已提交，但后台未返回一次性明文。请立即刷新列表并撤销新凭证。");
      }
      setIssuedCredential({ keyId: item.id, name: item.name, operation: "rotated", secret });
      setCopyState("idle");
      setKeys((current) => replaceRotatedApiKey(current ?? [], key.id, item));
    } catch (reason) {
      setActionError(readableError(reason));
    } finally {
      setPendingAction(null);
    }
  }

  async function revokeKey(key: ManagedApiKey) {
    if (!window.confirm(`确定撤销“${key.name}”吗？使用该 Key 的系统将立即无法调用 API。`)) return;
    setPendingAction(`revoke:${key.id}`);
    setActionError("");
    try {
      await apiRequest<null>(`/api/v1/api-keys/${key.id}`, { method: "DELETE" });
      if (issuedCredential?.keyId === key.id) clearIssuedCredential();
      setKeys((current) => current?.filter((item) => item.id !== key.id) ?? current);
      void loadKeys(0, true);
    } catch (reason) {
      setActionError(readableError(reason));
    } finally {
      setPendingAction(null);
    }
  }

  if (!accessLoading && !can("api-key:manage")) {
    return <EmptyState compact icon="lock" title="没有 API Key 管理权限" description="当前角色不包含 api-key:manage；FastAPI 会在服务端再次校验权限。" />;
  }

  const mutationPending = pendingAction !== null;
  const visibleKnowledgeIds = new Set(knowledgeBases?.map((item) => item.id) ?? []);
  const hiddenSelectionCount = knowledgeBaseIds.filter((id) => !visibleKnowledgeIds.has(id)).length;

  return (
    <section className="panel api-keys-panel">
      <div className="panel-header">
        <div><h2>API Key</h2><p>为内部系统生成独立凭证，并按应用执行撤销和轮换</p></div>
        <button
          className="button ghost small"
          type="button"
          disabled={mutationPending || keysLoading || knowledgeLoading}
          onClick={() => {
            void loadKeys(0, true);
            void loadKnowledgeBases(debouncedKnowledgeQuery, 0, true);
          }}
        ><Icon name="refresh" />刷新</button>
      </div>

      {actionError ? <div className="panel-inline-state"><ErrorState message={actionError} /></div> : null}
      {keysError ? <div className="panel-inline-state"><ErrorState message={keysError} onRetry={() => void loadKeys(0, true)} /></div> : null}

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
          <fieldset className="fieldset api-knowledge-fieldset" aria-busy={knowledgeLoading}>
            <legend>允许访问的知识库</legend>
            <label htmlFor="api-key-knowledge-search">搜索知识库<input id="api-key-knowledge-search" type="search" maxLength={200} value={knowledgeQuery} onChange={(event) => setKnowledgeQuery(event.target.value)} placeholder="输入知识库名称" /></label>
            {knowledgeBaseIds.length ? <p className="field-hint">已选择 {knowledgeBaseIds.length} 个知识库；搜索和翻页不会清除已选范围。{hiddenSelectionCount ? ` 当前搜索外 ${hiddenSelectionCount} 个。` : ""}</p> : null}
            {knowledgeError ? <ErrorState message={knowledgeError} onRetry={() => void loadKnowledgeBases(debouncedKnowledgeQuery, 0, true)} /> : null}
            {knowledgeBases === null && knowledgeLoading ? <p className="field-hint">正在加载知识库…</p> : null}
            {knowledgeBases?.length === 0 && !knowledgeLoading && !knowledgeError ? <p className="field-hint">没有找到可授权的知识库。请调整搜索，或先创建知识库并授予访问权限。</p> : null}
            {knowledgeBases?.length ? <div className="api-knowledge-options">{knowledgeBases.map((knowledgeBase) => <label className="check-option" key={knowledgeBase.id}><input type="checkbox" checked={knowledgeBaseIds.includes(knowledgeBase.id)} onChange={() => toggleValue(knowledgeBase.id, knowledgeBaseIds, setKnowledgeBaseIds)} /><span>{knowledgeBase.name}<small>{knowledgeBase.access_level} · {knowledgeBase.id.slice(0, 8)}</small></span></label>)}</div> : null}
            {knowledgeHasMore ? <button className="button secondary small" type="button" disabled={knowledgeLoading} onClick={() => void loadKnowledgeBases(debouncedKnowledgeQuery, knowledgeBases?.length ?? 0, false)}>{knowledgeLoading ? "正在加载…" : "加载更多知识库"}</button> : null}
          </fieldset>
        </div>
        <div className="api-key-create-footer">
          <p>按“系统 + 环境”隔离凭证，并只勾选业务必需的知识库与接口。</p>
          <button className="button primary" type="submit" disabled={mutationPending || Boolean(issuedCredential) || !name.trim() || permissionCodes.length === 0 || knowledgeBaseIds.length === 0}><Icon name="plus" />{pendingAction === "create" ? "正在生成…" : "生成 API Key"}</button>
        </div>
      </form>

      {issuedCredential ? (
        <div className="issued-key" role="status" aria-live="polite" data-sensitive="true">
          <div className="issued-key-heading">
            <span><Icon name="warning" /></span>
            <div><strong>{issuedCredential.operation === "rotated" ? "轮换完成，请立即保存新 Key" : "请立即复制并安全保存"}</strong><p>“{issuedCredential.name}”的 API Key 只有这一次明文展示。关闭后无法恢复，只能再次轮换或撤销。</p></div>
          </div>
          <div className="secret-copy-row">
            <code>{issuedCredential.secret}</code>
            <button className="button secondary" type="button" onClick={() => void copyIssuedKey()}><Icon name={copyState === "copied" ? "check" : "file"} />{copyState === "copied" ? "已复制" : copyState === "failed" ? "复制失败" : "复制"}</button>
          </div>
          <button className="issued-dismiss" type="button" onClick={clearIssuedCredential}>我已保存，关闭明文</button>
        </div>
      ) : null}

      {keys === null && keysLoading && !keysError ? <LoadingRows count={3} /> : null}
      {keys?.length === 0 && !keysLoading && !keysError ? <EmptyState compact icon="lock" title="还没有 API Key" description="为第一个服务端应用创建独立凭证。明文只会展示一次。" /> : null}
      {keys?.length ? (
        <div className="table-wrap" aria-busy={keysLoading}>
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
                  <td>
                    <div className="form-actions">
                      <button className="button secondary small" type="button" aria-label={`轮换 ${key.name}`} disabled={mutationPending || Boolean(issuedCredential)} onClick={() => void rotateKey(key)}>{pendingAction === `rotate:${key.id}` ? "轮换中…" : "轮换"}</button>
                      <button className="button danger small" type="button" aria-label={`撤销 ${key.name}`} disabled={mutationPending} onClick={() => void revokeKey(key)}>{pendingAction === `revoke:${key.id}` ? "撤销中…" : "撤销"}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {keysHasMore ? <div className="panel-footer"><button className="button secondary" type="button" disabled={keysLoading || mutationPending} onClick={() => void loadKeys(keys.length, false)}>{keysLoading ? "正在加载…" : "加载更多 API Key"}</button></div> : null}
        </div>
      ) : null}
    </section>
  );
}
