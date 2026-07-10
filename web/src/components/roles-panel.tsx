"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { apiRequest, formatBytes, readableError } from "@/lib/api-client";
import type { LimitDefinition, Permission, Role } from "@/lib/types";

function displayLimit(key: string, value: number | null): string {
  if (value === null) return "不限";
  return key.includes("bytes") ? formatBytes(value) : new Intl.NumberFormat("zh-CN").format(value);
}

export function RolesPanel() {
  const { can, me, loading: accessLoading } = useAccess();
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [definitions, setDefinitions] = useState<LimitDefinition[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [permissionCodes, setPermissionCodes] = useState<string[]>([]);
  const [limitValues, setLimitValues] = useState<Record<string, string>>({});
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyReady, setPolicyReady] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("0");
  const selectedIdRef = useRef("");
  const policyRequestId = useRef(0);

  const selectRole = useCallback((roleId: string) => {
    selectedIdRef.current = roleId;
    const requestId = ++policyRequestId.current;
    setSelectedId(roleId);
    setPermissionCodes([]);
    setLimitValues({});
    setPolicyReady(false);
    setPolicyLoading(Boolean(roleId));
    setError("");
    if (!roleId) return;
    void (async () => {
      try {
        const role = await apiRequest<Role>(`/api/v1/roles/${roleId}`);
        if (policyRequestId.current !== requestId) return;
        setRoles((current) => current?.map((item) => item.id === role.id ? role : item) ?? current);
        setPermissionCodes(role.permission_codes);
        setLimitValues(Object.fromEntries(Object.entries(role.limits).map(([key, value]) => [key, value === null ? "unlimited" : String(value)])));
        setPolicyReady(true);
      } catch (reason) {
        if (policyRequestId.current === requestId) setError(readableError(reason));
      } finally {
        if (policyRequestId.current === requestId) setPolicyLoading(false);
      }
    })();
  }, []);

  const load = useCallback(async () => {
    if (accessLoading) return;
    if (!can("role:read")) {
      setRoles([]);
      return;
    }
    setError("");
    try {
      const [roleItems, permissionItems, limitItems] = await Promise.all([
        apiRequest<Role[]>("/api/v1/roles"),
        apiRequest<Permission[]>("/api/v1/permissions"),
        apiRequest<LimitDefinition[]>("/api/v1/limits"),
      ]);
      setRoles(roleItems);
      setPermissions(permissionItems);
      setDefinitions(limitItems);
      const currentId = selectedIdRef.current;
      selectRole(roleItems.some((item) => item.id === currentId) ? currentId : roleItems[0]?.id || "");
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can, selectRole]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  const selected = useMemo(() => roles?.find((role) => role.id === selectedId) ?? null, [roles, selectedId]);

  const mutable = Boolean(selected && can("role:manage") && (!selected.is_system || me?.is_superuser));

  function togglePermission(permissionCode: string) {
    setPermissionCodes((current) => current.includes(permissionCode) ? current.filter((item) => item !== permissionCode) : [...current, permissionCode]);
  }

  async function createRole(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const created = await apiRequest<Role>("/api/v1/roles", {
        method: "POST",
        body: JSON.stringify({ code: code.trim(), name: name.trim(), description: description.trim() || null, priority: Number(priority), permission_codes: [], limits: {} }),
      });
      setCode("");
      setName("");
      setDescription("");
      setPriority("0");
      await load();
      selectRole(created.id);
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  async function savePolicy() {
    if (!selected || !mutable || !policyReady || policyLoading) return;
    const limits: Record<string, number | null> = {};
    for (const definition of definitions) {
      const raw = limitValues[definition.key]?.trim().toLowerCase();
      if (!raw) continue;
      if (raw === "unlimited" || raw === "不限") limits[definition.key] = null;
      else {
        const value = Number(raw);
        if (!Number.isSafeInteger(value) || value < 0) {
          setError(`${definition.name} 必须是 0 到 ${Number.MAX_SAFE_INTEGER} 之间的安全整数，或填写 unlimited。`);
          return;
        }
        limits[definition.key] = value;
      }
    }
    setPending(true);
    setError("");
    try {
      const updated = await apiRequest<Role>(`/api/v1/roles/${selected.id}/policy`, {
        method: "PUT",
        body: JSON.stringify({ permission_codes: permissionCodes, limits }),
      });
      setRoles((current) => current?.map((item) => item.id === updated.id ? updated : item) ?? current);
      setPermissionCodes(updated.permission_codes);
      setLimitValues(Object.fromEntries(Object.entries(updated.limits).map(([key, value]) => [key, value === null ? "unlimited" : String(value)])));
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  if (!accessLoading && !can("role:read")) {
    return <EmptyState icon="lock" title="没有角色查看权限" description="当前角色不包含 role:read。角色菜单已隐藏，直接访问也会由 FastAPI 拒绝。" />;
  }

  return (
    <div className="page-stack">
      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      <section className="panel">
        {roles === null && !error ? <LoadingRows count={5} /> : null}
        {roles?.length === 0 ? <EmptyState compact icon="shield" title="还没有角色" description="创建第一个自定义角色，再配置权限与资源限额。" /> : null}
        {roles?.length ? (
          <div className="role-layout">
            <aside className="role-list">
              {roles.map((role) => (
                <button className={`role-item${role.id === selectedId ? " active" : ""}`} type="button" onClick={() => selectRole(role.id)} disabled={pending} key={role.id}>
                  <span className="role-symbol">{role.name.slice(0, 1).toUpperCase()}</span>
                  <span><strong>{role.name}</strong><small>{role.code}{role.is_system ? " · 系统" : ""}</small></span>
                  <span className="role-priority">P{role.priority}</span>
                </button>
              ))}
            </aside>
            {selected ? (
              <div className="role-detail" aria-busy={policyLoading}>
                <div className="detail-heading">
                  <div><h2>{selected.name}</h2><p>{selected.description || "暂无角色说明。"}</p></div>
                  <StatusBadge tone={selected.is_system ? "info" : "neutral"}>{selected.is_system ? "系统角色" : `优先级 ${selected.priority}`}</StatusBadge>
                </div>
                <section className="detail-section">
                  <h3>权限能力</h3>
                  {policyLoading ? <p className="field-hint" aria-live="polite">正在载入角色策略…</p> : null}
                  <div className="checkbox-grid">
                    {permissions.map((permission) => (
                      <label className="check-option" key={permission.code}>
                        <input type="checkbox" disabled={!mutable || pending || policyLoading || !policyReady} checked={permissionCodes.includes(permission.code)} onChange={() => togglePermission(permission.code)} />
                        <span>{permission.name}<small>{permission.code} · {permission.description || ""}</small></span>
                      </label>
                    ))}
                  </div>
                </section>
                <section className="detail-section">
                  <h3>资源与访问限额</h3>
                  <div className="limit-grid">
                    {definitions.map((definition) => (
                      <label className="limit-card" key={definition.key}>
                        <span>{definition.name}<small>{definition.window} · {definition.unit}</small></span>
                        {mutable ? <input value={limitValues[definition.key] ?? ""} onChange={(event) => setLimitValues((current) => ({ ...current, [definition.key]: event.target.value }))} placeholder="未设置" disabled={pending || policyLoading || !policyReady} /> : <strong>{selected.limits[definition.key] === undefined ? "未设置" : displayLimit(definition.key, selected.limits[definition.key])}</strong>}
                      </label>
                    ))}
                  </div>
                  {mutable ? <p className="field-hint">留空表示该角色不设置此限额；填写 unlimited 表示不限。非超级管理员不能授予高于自己的额度。</p> : null}
                </section>
                {mutable ? <div className="form-actions"><button className="button primary" type="button" disabled={pending || policyLoading || !policyReady} onClick={() => void savePolicy()}>{pending ? "正在保存…" : policyLoading ? "正在载入…" : "保存权限与限额"}</button></div> : <p className="field-hint">系统角色或高于自身优先级的角色可能只读；后台会阻止权限提升。</p>}
              </div>
            ) : null}
          </div>
        ) : null}
        {can("role:manage") ? (
          <details className="drawer-form">
            <summary>＋ 新建自定义角色</summary>
            <form className="form-grid" onSubmit={createRole}>
              <label>角色代码<input pattern="[a-z][a-z0-9_-]{1,99}" value={code} onChange={(event) => setCode(event.target.value)} placeholder="knowledge_editor" required /></label>
              <label>角色名称<input value={name} onChange={(event) => setName(event.target.value)} placeholder="知识编辑" required /></label>
              <label>优先级<input type="number" min={-10000} max={10000} value={priority} onChange={(event) => setPriority(event.target.value)} required /></label>
              <label>描述<input value={description} onChange={(event) => setDescription(event.target.value)} /></label>
              <div className="form-actions full"><button className="button primary" type="submit" disabled={pending}>{pending ? "正在创建…" : "创建角色"}</button></div>
            </form>
          </details>
        ) : null}
      </section>
    </div>
  );
}
