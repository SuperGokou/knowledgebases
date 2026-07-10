"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { apiRequest, readableError } from "@/lib/api-client";
import type { KnowledgeAccessLevel, KnowledgeBase, KnowledgeBaseRoleGrant, Role } from "@/lib/types";

type GrantChoice = KnowledgeAccessLevel | "none";

export function KnowledgeGrantsPanel() {
  const { can, loading: accessLoading } = useAccess();
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [knowledgeBaseId, setKnowledgeBaseId] = useState("");
  const [choices, setChoices] = useState<Record<string, GrantChoice>>({});
  const [grantsLoading, setGrantsLoading] = useState(false);
  const [grantsReady, setGrantsReady] = useState(false);
  const [grantsRevision, setGrantsRevision] = useState(0);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const grantsRequestId = useRef(0);

  const selectKnowledgeBase = useCallback((nextId: string) => {
    grantsRequestId.current += 1;
    setChoices({});
    setGrantsReady(false);
    setError("");
    setGrantsLoading(Boolean(nextId));
    setKnowledgeBaseId(nextId);
    setGrantsRevision((current) => current + 1);
  }, []);

  const loadCatalog = useCallback(async () => {
    if (accessLoading || !can("knowledge:grant") || !can("role:read")) return;
    setError("");
    try {
      const [bases, roleItems] = await Promise.all([
        apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases"),
        apiRequest<Role[]>("/api/v1/roles"),
      ]);
      const manageable = bases.filter((item) => item.access_level === "manager");
      setKnowledgeBases(manageable);
      setRoles(roleItems);
      selectKnowledgeBase(manageable[0]?.id || "");
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can, selectKnowledgeBase]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void loadCatalog(), 0);
    return () => window.clearTimeout(timeout);
  }, [loadCatalog]);

  useEffect(() => {
    if (!knowledgeBaseId) {
      return;
    }
    const requestId = ++grantsRequestId.current;
    let active = true;
    async function loadGrants() {
      try {
        const grants = await apiRequest<KnowledgeBaseRoleGrant[]>(`/api/v1/knowledge-bases/${knowledgeBaseId}/role-grants`);
        if (!active || grantsRequestId.current !== requestId) return;
        setChoices(Object.fromEntries(grants.map((grant) => [grant.role_id, grant.access_level])));
        setGrantsReady(true);
      } catch (reason) {
        if (active && grantsRequestId.current === requestId) setError(readableError(reason));
      } finally {
        if (active && grantsRequestId.current === requestId) setGrantsLoading(false);
      }
    }
    void loadGrants();
    return () => { active = false; };
  }, [grantsRevision, knowledgeBaseId]);

  const selectedName = useMemo(() => knowledgeBases?.find((item) => item.id === knowledgeBaseId)?.name, [knowledgeBaseId, knowledgeBases]);

  async function save() {
    if (!knowledgeBaseId || grantsLoading || !grantsReady) return;
    setPending(true);
    setError("");
    try {
      await apiRequest<KnowledgeBaseRoleGrant[]>(`/api/v1/knowledge-bases/${knowledgeBaseId}/role-grants`, {
        method: "PUT",
        body: JSON.stringify({
          grants: Object.entries(choices)
            .filter((entry): entry is [string, KnowledgeAccessLevel] => entry[1] !== "none")
            .map(([role_id, access_level]) => ({ role_id, access_level })),
        }),
      });
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  if (accessLoading || !can("knowledge:grant")) return null;
  if (!can("role:read")) {
    return <section className="panel"><EmptyState compact icon="lock" title="缺少角色目录权限" description="管理知识库授权还需要 role:read，当前账号无法安全选择角色。" /></section>;
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div><h2>知识库角色授权</h2><p>为角色设置 Reader、Editor 或 Manager；数据库授权是唯一可信来源</p></div>
        <select aria-label="选择要授权的知识库" value={knowledgeBaseId} onChange={(event) => selectKnowledgeBase(event.target.value)} disabled={!knowledgeBases?.length || pending}>
          {!knowledgeBases?.length ? <option value="">没有可管理的知识库</option> : null}
          {knowledgeBases?.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
        </select>
      </div>
      {error ? <div className="panel-body"><ErrorState message={error} onRetry={() => void loadCatalog()} /></div> : null}
      {knowledgeBases === null && !error ? <LoadingRows count={3} /> : null}
      {knowledgeBases?.length === 0 ? <EmptyState compact icon="layers" title="没有 Manager 级知识库" description="只有知识库 Manager 可以修改角色授权。" /> : null}
      {knowledgeBaseId && roles.length ? (
        <div className="table-wrap" aria-busy={grantsLoading}>
          {grantsLoading ? <p className="field-hint" aria-live="polite">正在读取当前知识库授权…</p> : null}
          <table>
            <thead><tr><th>角色</th><th>角色代码</th><th>访问等级</th></tr></thead>
            <tbody>
              {roles.map((role) => (
                <tr key={role.id}>
                  <td><strong>{role.name}</strong></td>
                  <td><code>{role.code}</code></td>
                  <td>
                    <select aria-label={`${role.name} 在 ${selectedName ?? "知识库"} 的访问等级`} value={choices[role.id] ?? "none"} onChange={(event) => setChoices((current) => ({ ...current, [role.id]: event.target.value as GrantChoice }))} disabled={pending || grantsLoading || !grantsReady}>
                      <option value="none">无访问</option>
                      <option value="reader">Reader · 只读检索</option>
                      <option value="editor">Editor · 编辑内容</option>
                      <option value="manager">Manager · 管理授权</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="panel-footer"><button className="button primary" type="button" disabled={pending || grantsLoading || !grantsReady} onClick={() => void save()}>{pending ? "正在保存…" : grantsLoading ? "正在载入…" : "保存访问等级"}</button></div>
        </div>
      ) : null}
    </section>
  );
}
