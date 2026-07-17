"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { useActionFeedback } from "@/components/action-feedback";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { createActionLock } from "@/lib/action-lock";
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
import {
  createLatestRolePolicyRequestController,
  loadRoleCatalogAndDetail,
  openRolePolicyEditor,
  SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE,
  saveRolePolicy,
  STALE_ROLE_POLICY_MESSAGE,
  STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE,
  type RolePolicyDraftInvalidationReason,
  type LatestRolePolicyRequestOutcome,
} from "@/lib/role-policy-assignment";
import {
  deleteRole,
  openRoleMetadataEditor,
  saveRoleMetadata,
  type RoleAdministrationInvalidationReason,
  type RoleDeleteEditor,
  type RoleMetadataEditor,
} from "@/lib/role-administration";
import {
  mergeRoleCatalogItems,
  roleCatalogPagePath,
  roleOptionsForSelection,
  splitRoleCatalogPage,
} from "@/lib/role-catalog";
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

function roleAdministrationError(error: unknown): string {
  if (error instanceof ApiClientError && error.code === "role_in_use") {
    const details = error.details && typeof error.details === "object"
      ? error.details as { references?: unknown }
      : null;
    const references = details?.references && typeof details.references === "object"
      ? details.references as { user_assignments?: unknown; knowledge_base_grants?: unknown }
      : null;
    const users = typeof references?.user_assignments === "number" ? references.user_assignments : 0;
    const grants = typeof references?.knowledge_base_grants === "number" ? references.knowledge_base_grants : 0;
    return `角色仍被 ${users} 个成员账号和 ${grants} 项知识库授权引用。请先解除全部引用，再删除角色。`;
  }
  return roleCreateError(error);
}

const ROLE_REFRESH_SUPERSEDED_MESSAGE = "角色刷新被更新的操作取代，不能把当前页面视为已刷新。";
const DELETED_ROLE_REFRESH_FAILED_MESSAGE = "角色已删除，但最新角色列表刷新失败；刷新成功前请勿继续管理角色。";

export function RolesPanel() {
  const { can, loading: accessLoading } = useAccess();
  const feedback = useActionFeedback();
  const actionLock = useMemo(() => createActionLock(), []);
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [roleQuery, setRoleQuery] = useState("");
  const [activeRoleQuery, setActiveRoleQuery] = useState("");
  const [roleHasMore, setRoleHasMore] = useState(false);
  const [roleCatalogLoading, setRoleCatalogLoading] = useState(false);
  const [roleCatalogError, setRoleCatalogError] = useState("");
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [definitions, setDefinitions] = useState<LimitDefinition[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [permissionCodes, setPermissionCodes] = useState<string[]>([]);
  const [limitValues, setLimitValues] = useState<Record<string, string>>({});
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyReady, setPolicyReady] = useState(false);
  const [policyVersion, setPolicyVersion] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pendingAction, setPendingAction] = useState<"create" | "policy" | "metadata" | "delete" | null>(null);
  const pending = pendingAction !== null;
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("0");
  const [metadataEditor, setMetadataEditor] = useState<RoleMetadataEditor | null>(null);
  const [deleteEditor, setDeleteEditor] = useState<RoleDeleteEditor | null>(null);
  const metadataNameInputRef = useRef<HTMLInputElement>(null);
  const deleteConfirmationInputRef = useRef<HTMLInputElement>(null);
  const selectedIdRef = useRef("");
  const activeRoleQueryRef = useRef("");
  const roleCandidatesRef = useRef<Role[]>([]);
  const knownRolesRef = useRef<Role[]>([]);
  const catalogLoadController = useMemo(() => createLatestRolePolicyRequestController(), []);
  const policyLoadController = useMemo(() => createLatestRolePolicyRequestController(), []);

  function focusRoleSelection(roleId?: string) {
    window.requestAnimationFrame(() => {
      const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-role-select-id]"));
      const target = roleId
        ? buttons.find((button) => button.dataset.roleSelectId === roleId)
        : buttons[0];
      target?.focus();
    });
  }

  const selectRole = useCallback(async (
    roleId: string,
    { propagateError = false }: { propagateError?: boolean } = {},
  ): Promise<LatestRolePolicyRequestOutcome> => {
    selectedIdRef.current = roleId;
    setSelectedId(roleId);
    setMetadataEditor(null);
    setDeleteEditor(null);
    setPermissionCodes([]);
    setLimitValues({});
    setPolicyVersion(null);
    setPolicyReady(false);
    setPolicyLoading(Boolean(roleId));
    setError("");
    if (!roleId) {
      policyLoadController.invalidate();
      setPolicyLoading(false);
      return "applied";
    }
    try {
      const outcome = await policyLoadController.run(
        () => apiRequest<Role>(`/api/v1/roles/${roleId}`),
        (role) => {
          knownRolesRef.current = mergeRoleCatalogItems(knownRolesRef.current, [role], false);
          setRoles(roleOptionsForSelection(
            roleCandidatesRef.current,
            knownRolesRef.current,
            [role.id],
          ));
          setPermissionCodes(role.permission_codes);
          setLimitValues(Object.fromEntries(Object.entries(role.limits).map(([key, value]) => [key, value === null ? "unlimited" : String(value)])));
          setPolicyVersion(openRolePolicyEditor(role).expectedVersion);
          setPolicyReady(true);
        },
      );
      if (outcome === "applied") setPolicyLoading(false);
      return outcome;
    } catch (reason) {
      setError(readableError(reason));
      setPolicyLoading(false);
      if (propagateError) throw reason;
      return "superseded";
    }
  }, [policyLoadController]);

  const loadRoleCandidates = useCallback(async ({
    query,
    offset,
    replace,
  }: {
    query: string;
    offset: number;
    replace: boolean;
  }) => {
    if (accessLoading || !can("role:read")) return;
    setRoleCatalogLoading(true);
    setRoleCatalogError("");
    let nextSelectedId = selectedIdRef.current;
    try {
      const outcome = await catalogLoadController.run(
        () => apiRequest<Role[]>(roleCatalogPagePath({ offset, query })),
        (roleItems) => {
          const page = splitRoleCatalogPage(roleItems);
          roleCandidatesRef.current = mergeRoleCatalogItems(
            roleCandidatesRef.current,
            page.items,
            replace,
          );
          knownRolesRef.current = mergeRoleCatalogItems(
            knownRolesRef.current,
            page.items,
            false,
          );
          const knownIds = new Set(knownRolesRef.current.map((role) => role.id));
          if (!nextSelectedId || !knownIds.has(nextSelectedId)) {
            nextSelectedId = roleCandidatesRef.current[0]?.id ?? "";
          }
          setRoles(roleOptionsForSelection(
            roleCandidatesRef.current,
            knownRolesRef.current,
            nextSelectedId ? [nextSelectedId] : [],
          ));
          setRoleHasMore(page.hasMore);
        },
      );
      if (outcome === "applied" && nextSelectedId !== selectedIdRef.current) {
        await selectRole(nextSelectedId);
      }
    } catch (reason) {
      setRoleCatalogError(readableError(reason));
    } finally {
      setRoleCatalogLoading(false);
    }
  }, [accessLoading, can, catalogLoadController, selectRole]);

  const load = useCallback(async (
    { propagateError = false }: { propagateError?: boolean } = {},
  ) => {
    if (accessLoading) {
      catalogLoadController.invalidate();
      policyLoadController.invalidate();
      return;
    }
    if (!can("role:read")) {
      catalogLoadController.invalidate();
      policyLoadController.invalidate();
      setRoles([]);
      return;
    }
    setError("");
    setRoleCatalogLoading(true);
    setRoleCatalogError("");
    try {
      const outcome = await loadRoleCatalogAndDetail({
        catalogController: catalogLoadController,
        requestCatalog: () => Promise.all([
          apiRequest<Role[]>(roleCatalogPagePath({ offset: 0, query: activeRoleQueryRef.current })),
          apiRequest<Permission[]>("/api/v1/permissions"),
          apiRequest<LimitDefinition[]>("/api/v1/limits"),
        ]),
        applyCatalog: ([roleItems, permissionItems, limitItems]) => {
          const page = splitRoleCatalogPage(roleItems);
          roleCandidatesRef.current = [...page.items];
          knownRolesRef.current = mergeRoleCatalogItems(
            knownRolesRef.current,
            page.items,
            false,
          );
          setPermissions(permissionItems);
          setDefinitions(limitItems);
          setRoleHasMore(page.hasMore);
          const currentId = selectedIdRef.current;
          const nextSelectedId = currentId
            && knownRolesRef.current.some((item) => item.id === currentId)
            ? currentId
            : page.items[0]?.id ?? "";
          setRoles(roleOptionsForSelection(
            roleCandidatesRef.current,
            knownRolesRef.current,
            nextSelectedId ? [nextSelectedId] : [],
          ));
          return nextSelectedId;
        },
        requestDetail: (roleId) => selectRole(roleId, { propagateError: true }),
      });
      if (outcome === "superseded" && propagateError) {
        throw new Error(ROLE_REFRESH_SUPERSEDED_MESSAGE);
      }
    } catch (reason) {
      setError(readableError(reason));
      if (propagateError) throw reason;
    } finally {
      setRoleCatalogLoading(false);
    }
  }, [accessLoading, can, catalogLoadController, policyLoadController, selectRole]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => {
      window.clearTimeout(timeout);
      catalogLoadController.invalidate();
      policyLoadController.invalidate();
    };
  }, [catalogLoadController, load, policyLoadController]);

  useEffect(() => {
    if (metadataEditor) metadataNameInputRef.current?.focus();
    else if (deleteEditor) deleteConfirmationInputRef.current?.focus();
  }, [deleteEditor, metadataEditor]);

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
    if (!actionLock.acquire()) return;
    let createdRole: Role | null = null;
    setPendingAction("create");
    setError("");
    setNotice("");
    feedback.dismiss();
    try {
      const created = await apiRequest<Role>("/api/v1/roles", {
        method: "POST",
        body: JSON.stringify({ code: submittedCode, name: roleName, description: description.trim() || null, priority: parsedPriority, permission_codes: [], limits: {} }),
      });
      createdRole = created;
      setCode("");
      setName("");
      setDescription("");
      setPriority("0");
      knownRolesRef.current = mergeRoleCatalogItems(knownRolesRef.current, [created], false);
      selectedIdRef.current = created.id;
      await load({ propagateError: true });
      feedback.success(`角色“${created.name}”已创建，接下来可以配置权限能力和资源限额。`, "角色创建成功");
    } catch (reason) {
      const detail = roleCreateError(reason);
      const message = createdRole
        ? `角色“${createdRole.name}”已创建，但角色列表刷新失败。请手动刷新确认，请勿重复创建。错误详情：${detail}`
        : detail;
      setError(message);
      feedback.error(message, createdRole ? "已创建，但刷新失败" : "角色创建失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
      if (createdRole) focusRoleSelection(createdRole.id);
    }
  }

  async function savePolicy() {
    if (
      !selected
      || !mutable
      || !policyReady
      || policyLoading
      || policyVersion === null
    ) return;
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
    if (!actionLock.acquire()) return;
    setPendingAction("policy");
    setError("");
    setNotice("");
    feedback.dismiss();
    let draftInvalidatedFor: RolePolicyDraftInvalidationReason | null = null;
    try {
      const result = await saveRolePolicy({
        roleId: selected.id,
        expectedVersion: policyVersion,
        permissionCodes: [...permissionCodes],
        limits: { ...limits },
      }, {
        invalidateDraft: (reason) => {
          draftInvalidatedFor = reason;
          invalidateRoleWorkspace(reason);
        },
        reloadLatest: () => load({ propagateError: true }),
      });
      if (result.status === "stale") {
        setNotice(STALE_ROLE_POLICY_MESSAGE);
        feedback.info(STALE_ROLE_POLICY_MESSAGE, "检测到并发更新");
        return;
      }
      feedback.success(`角色“${result.role.name}”的权限与限额已保存，角色策略已刷新。`, "权限与限额已保存");
    } catch (reason) {
      setNotice("");
      const message = draftInvalidatedFor === "saved"
        ? SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE
        : STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE;
      const errorMessage = draftInvalidatedFor
        ? `${message} ${readableError(reason)}`
        : readableError(reason);
      setError(errorMessage);
      feedback.error(errorMessage, draftInvalidatedFor === "saved" ? "已保存，但刷新失败" : "角色策略保存失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
      if (draftInvalidatedFor) focusRoleSelection(selected.id);
    }
  }

  function invalidateRoleWorkspace(reason: RoleAdministrationInvalidationReason) {
    catalogLoadController.invalidate();
    policyLoadController.invalidate();
    if (reason === "deleted") selectedIdRef.current = "";
    setRoles(null);
    setPermissionCodes([]);
    setLimitValues({});
    setPolicyVersion(null);
    setPolicyReady(false);
    setPolicyLoading(false);
    setMetadataEditor(null);
    setDeleteEditor(null);
  }

  async function saveMetadata() {
    if (!metadataEditor || pending || !actionLock.acquire()) return;
    const editorSnapshot = { ...metadataEditor };
    let draftInvalidatedFor: RoleAdministrationInvalidationReason | null = null;
    setPendingAction("metadata");
    setError("");
    setNotice("");
    feedback.dismiss();
    try {
      const result = await saveRoleMetadata(editorSnapshot, {
        invalidateDraft: (reason) => {
          draftInvalidatedFor = reason;
          invalidateRoleWorkspace(reason);
        },
        reloadLatest: () => load({ propagateError: true }),
      });
      if (result.status === "stale") {
        setNotice(STALE_ROLE_POLICY_MESSAGE);
        feedback.info(STALE_ROLE_POLICY_MESSAGE, "检测到并发更新");
        return;
      }
      feedback.success(`角色“${editorSnapshot.name.trim()}”的名称、描述和优先级已保存。`, "角色资料已保存");
    } catch (reason) {
      setNotice("");
      const message = draftInvalidatedFor === "saved"
        ? SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE
        : STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE;
      const errorMessage = draftInvalidatedFor
        ? `${message} ${readableError(reason)}`
        : roleAdministrationError(reason);
      setError(errorMessage);
      feedback.error(errorMessage, draftInvalidatedFor === "saved" ? "已保存，但刷新失败" : "角色资料保存失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
      if (draftInvalidatedFor) focusRoleSelection(editorSnapshot.roleId);
    }
  }

  async function deleteSelectedRole() {
    if (!deleteEditor || pending || !actionLock.acquire()) return;
    const editorSnapshot = { ...deleteEditor };
    let draftInvalidatedFor: RoleAdministrationInvalidationReason | null = null;
    setPendingAction("delete");
    setError("");
    setNotice("");
    feedback.dismiss();
    try {
      const result = await deleteRole(editorSnapshot, {
        invalidateDraft: (reason) => {
          draftInvalidatedFor = reason;
          invalidateRoleWorkspace(reason);
        },
        reloadLatest: () => load({ propagateError: true }),
      });
      if (result.status === "stale") {
        setNotice(STALE_ROLE_POLICY_MESSAGE);
        feedback.info(STALE_ROLE_POLICY_MESSAGE, "检测到并发更新");
        return;
      }
      feedback.success(`角色“${editorSnapshot.roleName}”已删除，角色列表已刷新。`, "角色已删除");
    } catch (reason) {
      setNotice("");
      const refreshMessage = draftInvalidatedFor === "deleted"
        ? DELETED_ROLE_REFRESH_FAILED_MESSAGE
        : STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE;
      const errorMessage = draftInvalidatedFor
        ? `${refreshMessage} ${readableError(reason)}`
        : roleAdministrationError(reason);
      setError(errorMessage);
      feedback.error(errorMessage, draftInvalidatedFor === "deleted" ? "已删除，但刷新失败" : "角色删除失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
      if (draftInvalidatedFor) focusRoleSelection();
    }
  }

  if (!accessLoading && !can("role:read")) {
    return <EmptyState icon="lock" title="没有角色查看权限" description="当前角色不包含 role:read。角色菜单已隐藏，直接访问也会由 FastAPI 拒绝。" />;
  }

  return (
    <div className="page-stack">
      {error ? <ErrorState title="操作未完成" message={error} onRetry={() => void load()} /> : null}
      {notice ? <div className="notice info-notice"><Icon name="refresh" /><div><strong>角色数据已同步</strong><p>{notice}</p></div></div> : null}
      <section className="panel">
        {roleCatalogError ? (
          <div className="panel-body">
            <ErrorState
              title="角色目录暂时不可用"
              message={`${roleCatalogError}。当前已打开的角色策略仍可查看和管理。`}
              onRetry={() => void loadRoleCandidates({
                query: activeRoleQuery,
                offset: 0,
                replace: true,
              })}
            />
          </div>
        ) : null}
        {roles === null && !error ? <LoadingRows count={5} /> : null}
        {roles?.length === 0 ? <EmptyState compact icon="shield" title="还没有角色" description="创建第一个自定义角色，再配置权限与资源限额。" /> : null}
        {roles?.length ? (
          <div className="role-layout">
            <aside className="role-list">
              <form className="role-catalog-toolbar" role="search" onSubmit={(event) => {
                event.preventDefault();
                const query = roleQuery.trim();
                activeRoleQueryRef.current = query;
                setActiveRoleQuery(query);
                void loadRoleCandidates({ query, offset: 0, replace: true });
              }}>
                <input aria-label="搜索角色目录" type="search" maxLength={200} value={roleQuery} onChange={(event) => setRoleQuery(event.target.value)} placeholder="搜索名称或代码" />
                <button className="button secondary small" type="submit" disabled={roleCatalogLoading}>{roleCatalogLoading ? "搜索中…" : "搜索"}</button>
              </form>
              <div className="role-list-items">
                {roles.map((role) => {
                  const copy = roleCopy(role);
                  return (
                    <button className={`role-item${role.id === selectedId ? " active" : ""}`} type="button" data-role-select-id={role.id} onClick={() => void selectRole(role.id)} disabled={pending} key={role.id}>
                      <span className="role-symbol">{copy.name.slice(0, 1).toUpperCase()}</span>
                      <span><strong>{copy.name}</strong><small>{role.code}{role.is_system ? " · 系统" : ""}</small></span>
                      <span className="role-priority">P{role.priority}</span>
                    </button>
                  );
                })}
              </div>
              {roleHasMore ? (
                <button className="button secondary role-load-more" type="button" disabled={roleCatalogLoading} onClick={() => void loadRoleCandidates({
                  query: activeRoleQuery,
                  offset: roleCandidatesRef.current.length,
                  replace: false,
                })}>
                  {roleCatalogLoading ? "正在加载…" : "加载更多角色"}
                </button>
              ) : null}
            </aside>
            {selected ? (
              <div className="role-detail" aria-busy={policyLoading}>
                <div className="detail-heading">
                  <div><h2>{selectedCopy?.name}</h2><p>{selectedCopy?.description}</p></div>
                  <div className="button-row">
                    <StatusBadge tone={selected.is_system ? "info" : "neutral"}>{selected.is_system ? "系统角色" : `优先级 ${selected.priority}`}</StatusBadge>
                    {mutable && policyReady ? <button className="button secondary small" type="button" aria-haspopup="dialog" aria-controls="role-metadata-editor" disabled={pending || policyLoading} onClick={() => { setDeleteEditor(null); setMetadataEditor(openRoleMetadataEditor(selected)); }}>编辑角色</button> : null}
                    {mutable && policyReady ? <button className="button danger small" type="button" aria-haspopup="dialog" aria-controls="role-delete-editor" disabled={pending || policyLoading} onClick={() => { setMetadataEditor(null); setDeleteEditor({ roleId: selected.id, roleName: selected.name, isSystem: selected.is_system, expectedVersion: selected.policy_version, confirmation: "" }); }}>删除角色</button> : null}
                  </div>
                </div>
                {metadataEditor ? (
                  <form id="role-metadata-editor" className="inline-editor" role="dialog" aria-modal="false" aria-labelledby="role-metadata-editor-title" onSubmit={(event) => { event.preventDefault(); void saveMetadata(); }}>
                    <div><strong id="role-metadata-editor-title">编辑角色资料</strong><p>名称、描述和优先级与权限策略共享同一版本，保存时会检查其他管理员是否已经修改。</p></div>
                    <div className="form-grid">
                      <label>角色名称<input ref={metadataNameInputRef} value={metadataEditor.name} maxLength={200} required disabled={pending} onChange={(event) => setMetadataEditor((current) => current ? { ...current, name: event.target.value } : current)} /></label>
                      <label>优先级<input type="number" min={-10000} max={10000} step="1" value={metadataEditor.priority} required disabled={pending} onChange={(event) => setMetadataEditor((current) => current ? { ...current, priority: Number(event.target.value) } : current)} /></label>
                      <label className="full">描述<input value={metadataEditor.description ?? ""} maxLength={2000} disabled={pending} onChange={(event) => setMetadataEditor((current) => current ? { ...current, description: event.target.value || null } : current)} /></label>
                    </div>
                    <div className="form-actions"><button className="button ghost" type="button" disabled={pending} onClick={() => setMetadataEditor(null)}>取消</button><button className="button primary" type="submit" disabled={pending} aria-busy={pendingAction === "metadata"}>{pendingAction === "metadata" ? <><span className="spinner" />正在保存…</> : "保存角色资料"}</button></div>
                  </form>
                ) : null}
                {deleteEditor ? (
                  <form id="role-delete-editor" className="inline-editor" role="dialog" aria-modal="false" aria-labelledby="role-delete-editor-title" onSubmit={(event) => { event.preventDefault(); void deleteSelectedRole(); }}>
                    <div><strong id="role-delete-editor-title">删除自定义角色</strong><p>仅未分配给成员、且未用于知识库授权的角色可以删除。删除后无法恢复。</p></div>
                    <label className="full">请输入角色名称“{deleteEditor.roleName}”确认<input ref={deleteConfirmationInputRef} value={deleteEditor.confirmation} autoComplete="off" disabled={pending} onChange={(event) => setDeleteEditor((current) => current ? { ...current, confirmation: event.target.value } : current)} /></label>
                    <div className="form-actions"><button className="button ghost" type="button" disabled={pending} onClick={() => setDeleteEditor(null)}>取消</button><button className="button danger" type="submit" disabled={pending || deleteEditor.confirmation !== deleteEditor.roleName} aria-busy={pendingAction === "delete"}>{pendingAction === "delete" ? <><span className="spinner" />正在删除…</> : "永久删除角色"}</button></div>
                  </form>
                ) : null}
                <details className="detail-section policy-disclosure" key={`permissions-${selected.id}`}>
                  <summary className="policy-disclosure-summary">
                    <span className="policy-disclosure-title"><strong>权限能力</strong><small>{policyLoading ? "正在载入角色策略…" : `${permissionCodes.length} 项已启用 · 共 ${permissions.length} 项`}</small></span>
                    <span className="policy-disclosure-action" aria-hidden="true"><span className="when-closed">展开配置</span><span className="when-open">收起配置</span><Icon name="arrow" /></span>
                  </summary>
                  <div className="policy-disclosure-body">
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
                  </div>
                </details>
                <details className="detail-section policy-disclosure" key={`limits-${selected.id}`}>
                  <summary className="policy-disclosure-summary">
                    <span className="policy-disclosure-title"><strong>资源与访问限额</strong><small>{policyLoading ? "正在载入角色策略…" : `${Object.keys(selected.limits).length} 项已配置 · 共 ${definitions.length} 项`}</small></span>
                    <span className="policy-disclosure-action" aria-hidden="true"><span className="when-closed">展开配置</span><span className="when-open">收起配置</span><Icon name="arrow" /></span>
                  </summary>
                  <div className="policy-disclosure-body">
                    <div className="limit-legend">
                      <span><b>未设置</b><small>该角色不参与此项额度合并</small></span>
                      <span><b>有限制</b><small>按填写的数字限制；0 表示禁止</small></span>
                      <span><b>无限制</b><small>仅不设角色额度；仍受平台安全硬上限</small></span>
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
                                {mode === "limited" ? <input aria-label={`${copy.name}数值`} type="number" min="0" max={Number.MAX_SAFE_INTEGER} step="1" value={limitValues[definition.key] ?? ""} onChange={(event) => setLimitValues((current) => ({ ...current, [definition.key]: event.target.value }))} disabled={pending || policyLoading || !policyReady} /> : <small className={`limit-mode-note ${mode}`}>{mode === "unlimited" ? "不设角色额度，仍受平台安全限制" : "不参与角色额度合并"}</small>}
                              </div>
                            ) : (
                              <div className="limit-readout"><strong>{displayLimit(definition, storedValue)}</strong><small>{storedValue === undefined ? "该角色未配置" : storedValue === null ? "此角色不设置上限" : "该角色的数值上限"}</small></div>
                            )}
                          </article>
                        );
                      })}
                    </div>
                    <div className="limit-policy-note"><strong>最终额度如何计算</strong><p>用户拥有多个角色时，数值取最大值；任一角色为“无限制”，角色合并结果就是无限制；用户级覆盖值最后生效。若所有角色都未设置，请求频率使用系统默认值，其余上传、累计存储写入与下载额度按 0 处理。每日限额按 UTC 00:00 重置。“无限制”永远不会绕过单文件平台安全硬上限、恶意软件扫描上限或磁盘水位门禁。</p></div>
                    {mutable ? <p className="field-hint">容量类限额请输入原始字节数，保存后会自动换算为 KB、MB、GB 或 TB 显示。非超级管理员不能授予高于自身的额度。</p> : null}
                  </div>
                </details>
                {mutable ? <div className="form-actions"><button className="button primary" type="button" disabled={pending || policyLoading || !policyReady} aria-busy={pendingAction === "policy"} onClick={() => void savePolicy()}>{pendingAction === "policy" ? <><span className="spinner" />正在保存…</> : policyLoading ? "正在载入…" : "保存权限与限额"}</button></div> : <p className="field-hint">系统角色始终只读；其他角色也不能被授予高于当前管理员自身的权限或额度。</p>}
              </div>
            ) : null}
          </div>
        ) : null}
        {can("role:manage") ? (
          <details className="drawer-form role-create-drawer">
            <summary>＋ 新建自定义角色</summary>
            <form className="form-grid" onSubmit={createRole}>
              <label>角色标识（可选）<input value={code} onChange={(event) => setCode(event.target.value)} onBlur={() => setCode(normalizeRoleCode(code))} placeholder="例如 knowledge_editor" maxLength={100} /><small className="input-help">留空将自动生成；可输入英文字母、数字、下划线或短横线。</small></label>
              <label>角色名称<input value={name} onChange={(event) => setName(event.target.value)} placeholder="知识编辑" maxLength={200} required /></label>
              <label>优先级<input type="number" min={-10000} max={10000} value={priority} onChange={(event) => setPriority(event.target.value)} required /></label>
              <label>描述<input value={description} maxLength={2000} onChange={(event) => setDescription(event.target.value)} /></label>
              <div className="form-actions full"><button className="button primary" type="submit" disabled={pending} aria-busy={pendingAction === "create"}>{pendingAction === "create" ? <><span className="spinner" />正在创建…</> : "创建角色"}</button></div>
            </form>
          </details>
        ) : null}
      </section>
    </div>
  );
}
