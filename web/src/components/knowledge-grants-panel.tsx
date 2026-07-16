"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { apiRequest, readableError } from "@/lib/api-client";
import {
  candidatesWithSelection,
  knowledgeCandidatePagePath,
  mergeKnowledgeCandidates,
  splitKnowledgeCandidatePage,
} from "@/lib/knowledge-base-catalog";
import {
  openKnowledgeGrantEditor,
  saveKnowledgeGrantAssignment,
  STALE_KNOWLEDGE_GRANTS_MESSAGE,
  type KnowledgeGrantEditor,
  type KnowledgeGrantReloadReason,
} from "@/lib/knowledge-grant-assignment";
import {
  mergeRoleCatalogItems,
  roleCatalogPagePath,
  splitRoleCatalogPage,
} from "@/lib/role-catalog";
import type { KnowledgeAccessLevel, KnowledgeBase, KnowledgeBaseRoleGrant, Role } from "@/lib/types";

type GrantChoice = KnowledgeAccessLevel | "none";

export function KnowledgeGrantsPanel() {
  const { can, loading: accessLoading } = useAccess();
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [knowledgeBaseId, setKnowledgeBaseId] = useState("");
  const [selectedKnowledgeBase, setSelectedKnowledgeBase] = useState<KnowledgeBase | null>(null);
  const [knowledgeQuery, setKnowledgeQuery] = useState("");
  const [debouncedKnowledgeQuery, setDebouncedKnowledgeQuery] = useState("");
  const [knowledgeHasMore, setKnowledgeHasMore] = useState(false);
  const [knowledgeCatalogLoading, setKnowledgeCatalogLoading] = useState(false);
  const [knowledgeCatalogError, setKnowledgeCatalogError] = useState("");
  const [roleQuery, setRoleQuery] = useState("");
  const [debouncedRoleQuery, setDebouncedRoleQuery] = useState("");
  const [roleHasMore, setRoleHasMore] = useState(false);
  const [roleCatalogLoading, setRoleCatalogLoading] = useState(false);
  const [roleCatalogError, setRoleCatalogError] = useState("");
  const [choices, setChoices] = useState<Record<string, GrantChoice>>({});
  const [grantsLoading, setGrantsLoading] = useState(false);
  const [grantsReady, setGrantsReady] = useState(false);
  const [grantsRevision, setGrantsRevision] = useState(0);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [editor, setEditor] = useState<KnowledgeGrantEditor | null>(null);
  const grantsRequestId = useRef(0);
  const knowledgeCatalogRequestId = useRef(0);
  const roleCatalogRequestId = useRef(0);
  const selectedSnapshot = useRef<KnowledgeBase | null>(null);

  const selectKnowledgeBase = useCallback((next: KnowledgeBase | null) => {
    grantsRequestId.current += 1;
    selectedSnapshot.current = next;
    setSelectedKnowledgeBase(next);
    setChoices({});
    setEditor(null);
    setGrantsReady(false);
    setError("");
    setGrantsLoading(Boolean(next));
    setKnowledgeBaseId(next?.id ?? "");
    setGrantsRevision((current) => current + 1);
  }, []);

  const loadKnowledgeCatalog = useCallback(async (
    query: string,
    offset: number,
    replace: boolean,
  ) => {
    if (accessLoading || !can("knowledge:grant")) return;
    const requestId = ++knowledgeCatalogRequestId.current;
    setKnowledgeCatalogLoading(true);
    setKnowledgeCatalogError("");
    try {
      const bases = await apiRequest<KnowledgeBase[]>(knowledgeCandidatePagePath({
        offset,
        query,
        minimumAccessLevel: "manager",
      }));
      if (requestId !== knowledgeCatalogRequestId.current) return;
      const page = splitKnowledgeCandidatePage(bases);
      setKnowledgeBases((current) => mergeKnowledgeCandidates(current ?? [], page.items, replace));
      setKnowledgeHasMore(page.hasMore);
      if (!selectedSnapshot.current && page.items[0]) selectKnowledgeBase(page.items[0]);
    } catch (reason) {
      if (requestId === knowledgeCatalogRequestId.current) {
        setKnowledgeCatalogError(readableError(reason));
      }
    } finally {
      if (requestId === knowledgeCatalogRequestId.current) setKnowledgeCatalogLoading(false);
    }
  }, [accessLoading, can, selectKnowledgeBase]);

  const loadRoleCatalog = useCallback(async (
    query: string,
    offset: number,
    replace: boolean,
  ) => {
    if (accessLoading || !can("knowledge:grant") || !can("role:read")) return;
    const requestId = ++roleCatalogRequestId.current;
    setRoleCatalogLoading(true);
    setRoleCatalogError("");
    try {
      const roleItems = await apiRequest<Role[]>(roleCatalogPagePath({ offset, query }));
      if (requestId !== roleCatalogRequestId.current) return;
      const page = splitRoleCatalogPage(roleItems);
      setRoles((current) => mergeRoleCatalogItems(current, page.items, replace));
      setRoleHasMore(page.hasMore);
    } catch (reason) {
      if (requestId === roleCatalogRequestId.current) {
        setRoleCatalogError(readableError(reason));
      }
    } finally {
      if (requestId === roleCatalogRequestId.current) setRoleCatalogLoading(false);
    }
  }, [accessLoading, can]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => setDebouncedKnowledgeQuery(knowledgeQuery.trim()),
      300,
    );
    return () => window.clearTimeout(timeout);
  }, [knowledgeQuery]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => setDebouncedRoleQuery(roleQuery.trim()),
      300,
    );
    return () => window.clearTimeout(timeout);
  }, [roleQuery]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => void loadKnowledgeCatalog(debouncedKnowledgeQuery, 0, true),
      0,
    );
    return () => window.clearTimeout(timeout);
  }, [debouncedKnowledgeQuery, loadKnowledgeCatalog]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => void loadRoleCatalog(debouncedRoleQuery, 0, true),
      0,
    );
    return () => window.clearTimeout(timeout);
  }, [debouncedRoleQuery, loadRoleCatalog]);

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
        const snapshot = selectedSnapshot.current;
        if (!snapshot || snapshot.id !== knowledgeBaseId) return;
        setChoices(Object.fromEntries(grants.map((grant) => [grant.role_id, grant.access_level])));
        setEditor(openKnowledgeGrantEditor(snapshot));
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

  const reloadSelectedSnapshot = useCallback(async (
    reason: KnowledgeGrantReloadReason,
  ) => {
    const selectedId = knowledgeBaseId;
    const requestId = ++grantsRequestId.current;
    selectedSnapshot.current = null;
    setEditor(null);
    setChoices({});
    setGrantsReady(false);
    setGrantsLoading(Boolean(selectedId));

    try {
      const candidate = await apiRequest<KnowledgeBase>(`/api/v1/knowledge-bases/${selectedId}`);
      const latest = candidate.access_level === "manager" ? candidate : null;
      if (grantsRequestId.current !== requestId) return;
      if (latest) {
        setKnowledgeBases((current) => mergeKnowledgeCandidates(current ?? [], [latest], false));
      }
      selectedSnapshot.current = latest;
      setSelectedKnowledgeBase(latest);
      if (!latest) {
        setKnowledgeBaseId("");
        return;
      }

      const grants = await apiRequest<KnowledgeBaseRoleGrant[]>(
        `/api/v1/knowledge-bases/${latest.id}/role-grants`,
      );
      if (grantsRequestId.current !== requestId) return;
      setChoices(Object.fromEntries(grants.map((grant) => [grant.role_id, grant.access_level])));
      setEditor(reason === "saved" ? openKnowledgeGrantEditor(latest) : null);
      setGrantsReady(true);
    } finally {
      if (grantsRequestId.current === requestId) {
        setGrantsLoading(false);
      }
    }
  }, [knowledgeBaseId]);

  const selectedName = useMemo(
    () => selectedKnowledgeBase?.name
      ?? knowledgeBases?.find((item) => item.id === knowledgeBaseId)?.name,
    [knowledgeBaseId, knowledgeBases, selectedKnowledgeBase],
  );
  const selectableKnowledgeBases = candidatesWithSelection(
    knowledgeBases ?? [],
    selectedKnowledgeBase,
  );
  const hiddenChoiceCount = Object.keys(choices).filter(
    (roleId) => !roles.some((role) => role.id === roleId) && choices[roleId] !== "none",
  ).length;

  async function save() {
    if (
      !editor
      || editor.knowledgeBaseId !== knowledgeBaseId
      || grantsLoading
      || !grantsReady
    ) return;
    setPending(true);
    setError("");
    try {
      const result = await saveKnowledgeGrantAssignment(
        editor,
        Object.entries(choices)
          .filter((entry): entry is [string, KnowledgeAccessLevel] => entry[1] !== "none")
          .map(([role_id, access_level]) => ({ role_id, access_level })),
        { reloadLatest: reloadSelectedSnapshot },
      );
      if (result.status === "stale") {
        setError(STALE_KNOWLEDGE_GRANTS_MESSAGE);
      }
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
        <div className="catalog-selector">
          <label>搜索可管理知识库
            <input type="search" maxLength={200} value={knowledgeQuery} onChange={(event) => setKnowledgeQuery(event.target.value)} placeholder="输入知识库名称" />
          </label>
          <select aria-label="选择要授权的知识库" value={knowledgeBaseId} onChange={(event) => selectKnowledgeBase(selectableKnowledgeBases.find((item) => item.id === event.target.value) ?? null)} disabled={!selectableKnowledgeBases.length || pending}>
            {!selectableKnowledgeBases.length ? <option value="">没有可管理的知识库</option> : null}
            {selectableKnowledgeBases.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
          </select>
          {knowledgeHasMore ? <button className="button secondary small" type="button" disabled={knowledgeCatalogLoading || pending} onClick={() => void loadKnowledgeCatalog(debouncedKnowledgeQuery, knowledgeBases?.length ?? 0, false)}>{knowledgeCatalogLoading ? "正在加载…" : "加载更多知识库"}</button> : null}
        </div>
      </div>
      {knowledgeCatalogError ? <div className="panel-body"><ErrorState message={knowledgeCatalogError} onRetry={() => void loadKnowledgeCatalog(debouncedKnowledgeQuery, 0, true)} /></div> : null}
      {roleCatalogError ? <div className="panel-body"><ErrorState message={roleCatalogError} onRetry={() => void loadRoleCatalog(debouncedRoleQuery, 0, true)} /></div> : null}
      {error ? <div className="panel-body"><ErrorState message={error} /></div> : null}
      {knowledgeBases === null && knowledgeCatalogLoading ? <LoadingRows count={3} /> : null}
      {knowledgeBases?.length === 0 && !selectableKnowledgeBases.length ? <EmptyState compact icon="layers" title="没有 Manager 级知识库" description="只有知识库 Manager 可以修改角色授权。" /> : null}
      {knowledgeBaseId ? (
        <div className="table-wrap" aria-busy={grantsLoading || roleCatalogLoading}>
          {grantsLoading ? <p className="field-hint" aria-live="polite">正在读取当前知识库授权…</p> : null}
          <div className="catalog-toolbar">
            <label>搜索角色
              <input type="search" maxLength={200} value={roleQuery} onChange={(event) => setRoleQuery(event.target.value)} placeholder="输入角色名称或代码" />
            </label>
            {roleHasMore ? <button className="button secondary small" type="button" disabled={roleCatalogLoading || pending} onClick={() => void loadRoleCatalog(debouncedRoleQuery, roles.length, false)}>{roleCatalogLoading ? "正在加载…" : "加载更多角色"}</button> : null}
            {roleCatalogLoading ? <p className="field-hint" aria-live="polite">正在加载角色候选…</p> : null}
            {hiddenChoiceCount ? <p className="field-hint">当前搜索外仍保留 {hiddenChoiceCount} 项已授权角色；保存不会丢失。</p> : null}
          </div>
          {!roles.length && !roleCatalogLoading ? <EmptyState compact icon="search" title="没有匹配角色" description="调整角色名称或代码；已存在的隐藏授权仍会保留。" /> : null}
          <table>
            <thead><tr><th>角色</th><th>角色代码</th><th>访问等级</th></tr></thead>
            <tbody>
              {roles.map((role) => (
                <tr key={role.id}>
                  <td><strong>{role.name}</strong></td>
                  <td><code>{role.code}</code></td>
                  <td>
                    <select aria-label={`${role.name} 在 ${selectedName ?? "知识库"} 的访问等级`} value={choices[role.id] ?? "none"} onChange={(event) => setChoices((current) => ({ ...current, [role.id]: event.target.value as GrantChoice }))} disabled={pending || grantsLoading || !grantsReady || !editor}>
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
          <div className="panel-footer">
            {!editor && grantsReady && !grantsLoading ? (
              <button
                className="button secondary"
                type="button"
                disabled={pending}
                onClick={() => {
                  const latest = selectedSnapshot.current;
                  if (latest) {
                    setEditor(openKnowledgeGrantEditor(latest));
                    setError("");
                  }
                }}
              >
                重新编辑授权
              </button>
            ) : (
              <button className="button primary" type="button" disabled={pending || grantsLoading || !grantsReady || !editor} onClick={() => void save()}>{pending ? "正在保存…" : grantsLoading ? "正在载入…" : "保存访问等级"}</button>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
