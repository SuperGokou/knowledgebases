"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import {
  displayLimit,
  generateRoleCode,
  isValidRoleCode,
  limitCopy,
  limitMode,
  normalizeRoleCode,
  permissionCopy,
  roleCopy,
  type LimitMode,
} from "@/lib/role-policy";
import type { LimitDefinition, Permission, Role } from "@/lib/types";

function roleCreateError(error: unknown): string {
  if (error instanceof ApiClientError) {
    if (error.code === "role_exists") return "角色标识已经存在，请更换后再试。";
    if (error.status === 422 && Array.isArray(error.details)) {
      const first = error.details.find((item) => typeof item === "object" && item !== null) as { loc?: unknown } | undefined;
      const location = Array.isArray(first?.loc) ? first.loc.at(-1) : undefined;
      if (location === "code") return "角色标识格式不正确。请使用小写英文字母开头，并仅包含字母、数字、下划线或短横线。";
      if (location === "name") return "角色名称不能为空，且不能超过 200 个字符。";
      if (location === "priority") return "优先级必须是 -10000 到 10000 之间的整数。";
      return "角色信息不符合要求，请检查名称、角色标识和优先级。";
    }
  }
  return readableError(error);
}

export function RolesPanel() {
  const { can, loading: accessLoading } = useAccess();
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [definitions, setDefinitions] = useState<LimitDefinition[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [permissionCodes, setPermissionCodes] = useState<string[]>([]);
  const [limitValues, setLimitValues] = useState<Record<string, string>>({});
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyReady, setPolicyReady] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
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
  const selectedCopy = selected ? roleCopy(selected) : null;

  const mutable = Boolean(selected && can("role:manage") && !selected.is_system);

  function togglePermission(permissionCode: string) {
    setPermissionCodes((current) => current.includes(permissionCode) ? current.filter((item) => item !== permissionCode) : [...current, permissionCode]);
  }

  function changeLimitMode(key: string, mode: LimitMode) {
    setLimitValues((current) => {
      if (mode === "unset") return { ...current, [key]: "" };
      if (mode === "unlimited") return { ...current, [key]: "unlimited" };
      return { ...current, [key]: limitMode(current[key]) === "limited" ? current[key] : "1" };
    });
  }

  async function createRole(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const roleName = name.trim();
    const normalizedCode = normalizeRoleCode(code);
    const submittedCode = normalizedCode || generateRoleCode(`${Date.now().toString(36)}${Math.random().toString(36).slice(2, 9)}`);
    const parsedPriority = Number(priority);
    if (!roleName) {
      setError("请输入角色名称。");
      return;
    }
    if (!isValidRoleCode(submittedCode)) {
      setError("角色标识格式不正确。请使用英文字母开头，并仅包含字母、数字、下划线或短横线。");
      return;
    }
    if (!Number.isInteger(parsedPriority) || parsedPriority < -10_000 || parsedPriority > 10_000) {
      setError("优先级必须是 -10000 到 10000 之间的整数。");
      return;
    }
    setPending(true);
    setError("");
    setSuccess("");
    try {
      const created = await apiRequest<Role>("/api/v1/roles", {
        method: "POST",
        body: JSON.stringify({ code: submittedCode, name: roleName, description: description.trim() || null, priority: parsedPriority, permission_codes: [], limits: {} }),
      });
      setCode("");
      setName("");
      setDescription("");
      setPriority("0");
      await load();
      selectRole(created.id);
      setSuccess(`角色“${created.name}”已创建，接下来可以配置权限能力和资源限额。`);
    } catch (reason) {
      setError(roleCreateError(reason));
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
    setSuccess("");
    try {
      const updated = await apiRequest<Role>(`/api/v1/roles/${selected.id}/policy`, {
        method: "PUT",
        body: JSON.stringify({ permission_codes: permissionCodes, limits }),
      });
      setRoles((current) => current?.map((item) => item.id === updated.id ? updated : item) ?? current);
      setPermissionCodes(updated.permission_codes);
      setLimitValues(Object.fromEntries(Object.entries(updated.limits).map(([key, value]) => [key, value === null ? "unlimited" : String(value)])));
      setSuccess(`角色“${updated.name}”的权限与限额已保存。`);
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
      {error ? <ErrorState title="操作未完成" message={error} onRetry={() => void load()} /> : null}
      {success ? <div className="notice role-success" role="status"><Icon name="check" /><div><strong>设置已生效</strong><p>{success}</p></div></div> : null}
      <section className="panel">
        {roles === null && !error ? <LoadingRows count={5} /> : null}
        {roles?.length === 0 ? <EmptyState compact icon="shield" title="还没有角色" description="创建第一个自定义角色，再配置权限与资源限额。" /> : null}
        {roles?.length ? (
          <div className="role-layout">
            <aside className="role-list">
              {roles.map((role) => {
                const copy = roleCopy(role);
                return (
                  <button className={`role-item${role.id === selectedId ? " active" : ""}`} type="button" onClick={() => selectRole(role.id)} disabled={pending} key={role.id}>
                    <span className="role-symbol">{copy.name.slice(0, 1).toUpperCase()}</span>
                    <span><strong>{copy.name}</strong><small>{role.code}{role.is_system ? " · 系统" : ""}</small></span>
                    <span className="role-priority">P{role.priority}</span>
                  </button>
                );
              })}
            </aside>
            {selected ? (
              <div className="role-detail" aria-busy={policyLoading}>
                <div className="detail-heading">
                  <div><h2>{selectedCopy?.name}</h2><p>{selectedCopy?.description}</p></div>
                  <StatusBadge tone={selected.is_system ? "info" : "neutral"}>{selected.is_system ? "系统角色" : `优先级 ${selected.priority}`}</StatusBadge>
                </div>
                <section className="detail-section">
                  <h3>权限能力</h3>
                  <p className="section-intro">权限名称与用途均使用中文；技术标识仅用于 API 配置、排障和审计追踪。</p>
                  {policyLoading ? <p className="field-hint" aria-live="polite">正在载入角色策略…</p> : null}
                  <div className="checkbox-grid">
                    {permissions.map((permission) => {
                      const copy = permissionCopy(permission);
                      return (
                        <label className="check-option" key={permission.code}>
                          <input type="checkbox" disabled={!mutable || pending || policyLoading || !policyReady} checked={permissionCodes.includes(permission.code)} onChange={() => togglePermission(permission.code)} />
                          <span><strong>{copy.name}</strong><small>{copy.description}</small><code>技术标识：{permission.code}</code></span>
                        </label>
                      );
                    })}
                  </div>
                </section>
                <section className="detail-section">
                  <h3>资源与访问限额</h3>
                  <div className="limit-legend">
                    <span><b>未设置</b><small>该角色不参与此项额度合并</small></span>
                    <span><b>有限制</b><small>按填写的数字限制；0 表示禁止</small></span>
                    <span><b>无限制</b><small>该角色不为此项设置上限</small></span>
                  </div>
                  <div className="limit-grid">
                    {definitions.map((definition) => {
                      const copy = limitCopy(definition);
                      const mode = limitMode(limitValues[definition.key]);
                      const storedValue = selected.limits[definition.key];
                      return (
                        <article className="limit-card" key={definition.key}>
                          <div className="limit-copy"><strong>{copy.name}</strong><p>{copy.description}</p><small>{copy.window} · {copy.unit}</small></div>
                          {mutable ? (
                            <div className="limit-editor">
                              <select aria-label={`${copy.name}设置方式`} value={mode} onChange={(event) => changeLimitMode(definition.key, event.target.value as LimitMode)} disabled={pending || policyLoading || !policyReady}>
                                <option value="unset">未设置</option>
                                <option value="limited">有限制</option>
                                <option value="unlimited">无限制</option>
                              </select>
                              {mode === "limited" ? <input aria-label={`${copy.name}数值`} type="number" min="0" max={Number.MAX_SAFE_INTEGER} step="1" value={limitValues[definition.key] ?? ""} onChange={(event) => setLimitValues((current) => ({ ...current, [definition.key]: event.target.value }))} disabled={pending || policyLoading || !policyReady} /> : <small className={`limit-mode-note ${mode}`}>{mode === "unlimited" ? "此角色不设置上限" : "不参与角色额度合并"}</small>}
                            </div>
                          ) : (
                            <div className="limit-readout"><strong>{displayLimit(definition, storedValue)}</strong><small>{storedValue === undefined ? "该角色未配置" : storedValue === null ? "此角色不设置上限" : "该角色的数值上限"}</small></div>
                          )}
                        </article>
                      );
                    })}
                  </div>
                  <div className="limit-policy-note"><strong>最终额度如何计算</strong><p>用户拥有多个角色时，数值取最大值；任一角色为“无限制”，角色合并结果就是无限制；用户级覆盖值最后生效。若所有角色都未设置，请求频率使用系统默认值，其余上传、累计存储写入与下载额度按 0 处理。每日限额按 UTC 00:00 重置。</p></div>
                  {mutable ? <p className="field-hint">容量类限额请输入原始字节数，保存后会自动换算为 KB、MB、GB 或 TB 显示。非超级管理员不能授予高于自身的额度。</p> : null}
                </section>
                {mutable ? <div className="form-actions"><button className="button primary" type="button" disabled={pending || policyLoading || !policyReady} onClick={() => void savePolicy()}>{pending ? "正在保存…" : policyLoading ? "正在载入…" : "保存权限与限额"}</button></div> : <p className="field-hint">系统角色始终只读；其他角色也不能被授予高于当前管理员自身的权限或额度。</p>}
              </div>
            ) : null}
          </div>
        ) : null}
        {can("role:manage") ? (
          <details className="drawer-form">
            <summary>＋ 新建自定义角色</summary>
            <form className="form-grid" onSubmit={createRole}>
              <label>角色标识（可选）<input value={code} onChange={(event) => setCode(event.target.value)} onBlur={() => setCode(normalizeRoleCode(code))} placeholder="例如 knowledge_editor" maxLength={100} /><small className="input-help">留空将自动生成；可输入英文字母、数字、下划线或短横线。</small></label>
              <label>角色名称<input value={name} onChange={(event) => setName(event.target.value)} placeholder="知识编辑" maxLength={200} required /></label>
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
