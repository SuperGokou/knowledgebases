"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { apiRequest, readableError } from "@/lib/api-client";
import {
  ADMIN_LIST_PAGE_SIZE,
  buildOffsetListPath,
  offsetPageNumber,
  previousOffset,
  splitOffsetPage,
} from "@/lib/offset-pagination";
import {
  mergeRoleCatalogItems,
  missingSelectedRoleCount,
  ROLE_CATALOG_PAGE_SIZE,
  roleCatalogPagePath,
  roleOptionsForSelection,
  splitRoleCatalogPage,
} from "@/lib/role-catalog";
import type { Role, User, UserStatus } from "@/lib/types";
import {
  createLatestRequestController,
  openRoleAssignmentEditor,
  SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE,
  saveUserRoleAssignment,
  STALE_ROLE_ASSIGNMENT_MESSAGE,
  STALE_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE,
  type RoleAssignmentDraftInvalidationReason,
  type RoleAssignmentEditor,
} from "@/lib/user-role-assignment";
import {
  canResetUserPassword,
  passwordResetRevokesCurrentSession,
  readablePasswordResetError,
  resetUserPassword,
  validateStrongPassword,
  type UserPasswordResetEditor,
} from "@/lib/user-password-reset";

const statusLabel: Record<UserStatus, string> = { active: "正常", disabled: "已停用", locked: "已锁定" };
const statusTone: Record<UserStatus, "success" | "neutral" | "danger"> = { active: "success", disabled: "neutral", locked: "danger" };

export function UsersPanel() {
  const { can, loading: accessLoading, me, reload: reloadAccess } = useAccess();
  const [users, setUsers] = useState<User[] | null>(null);
  const [knownRoles, setKnownRoles] = useState<Role[]>([]);
  const [roleCandidates, setRoleCandidates] = useState<Role[]>([]);
  const [roleSearchDraft, setRoleSearchDraft] = useState("");
  const [activeRoleSearch, setActiveRoleSearch] = useState("");
  const [roleOffset, setRoleOffset] = useState(0);
  const [hasMoreRoles, setHasMoreRoles] = useState(false);
  const [roleCatalogLoading, setRoleCatalogLoading] = useState(false);
  const [roleCatalogError, setRoleCatalogError] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pending, setPending] = useState(false);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [newRoleIds, setNewRoleIds] = useState<string[]>([]);
  const [searchDraft, setSearchDraft] = useState("");
  const [activeSearch, setActiveSearch] = useState("");
  const [userOffset, setUserOffset] = useState(0);
  const [hasNextUsers, setHasNextUsers] = useState(false);
  const [roleEditor, setRoleEditor] = useState<RoleAssignmentEditor | null>(null);
  const [passwordEditor, setPasswordEditor] = useState<UserPasswordResetEditor | null>(null);
  const loadController = useMemo(() => createLatestRequestController(), []);
  const roleLoadController = useMemo(() => createLatestRequestController(), []);

  const load = useCallback(async ({
    propagateError = false,
    offset = userOffset,
    search = activeSearch,
  }: { propagateError?: boolean; offset?: number; search?: string } = {}) => {
    if (accessLoading) {
      loadController.invalidate();
      return;
    }
    if (!can("user:manage")) {
      loadController.invalidate();
      setUsers([]);
      setHasNextUsers(false);
      return;
    }
    setError("");
    try {
      await loadController.run(
        () => apiRequest<User[]>(buildOffsetListPath("/api/v1/users", { offset, search })),
        (userItems) => {
          const page = splitOffsetPage(userItems);
          setUsers(page.items);
          setHasNextUsers(page.hasNext);
        },
      );
    } catch (reason) {
      setError(readableError(reason));
      if (propagateError) throw reason;
    }
  }, [accessLoading, activeSearch, can, loadController, userOffset]);

  const loadRoleCandidates = useCallback(async ({
    offset = 0,
    query = "",
    replace = offset === 0,
  }: { offset?: number; query?: string; replace?: boolean } = {}) => {
    if (accessLoading) {
      roleLoadController.invalidate();
      setRoleCatalogLoading(false);
      return;
    }
    if (!can("user:manage") || !can("role:read") || !can("role:assign")) {
      roleLoadController.invalidate();
      setRoleCandidates([]);
      setKnownRoles([]);
      setHasMoreRoles(false);
      setRoleCatalogLoading(false);
      return;
    }
    if (replace) {
      setRoleOffset(offset);
      setHasMoreRoles(false);
    }
    setRoleCatalogLoading(true);
    setRoleCatalogError("");
    try {
      const outcome = await roleLoadController.run(
        () => apiRequest<Role[]>(roleCatalogPagePath({ offset, query, assignable: true })),
        (items) => {
          const page = splitRoleCatalogPage(items);
          setRoleCandidates((current) => mergeRoleCatalogItems(current, page.items, replace));
          setKnownRoles((current) => mergeRoleCatalogItems(current, page.items, false));
          setRoleOffset(offset);
          setHasMoreRoles(page.hasMore);
        },
      );
      if (outcome === "applied") setRoleCatalogLoading(false);
    } catch (reason) {
      setRoleCatalogError(readableError(reason));
      setRoleCatalogLoading(false);
    }
  }, [accessLoading, can, roleLoadController]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => {
      window.clearTimeout(timeout);
      loadController.invalidate();
    };
  }, [load, loadController]);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => void loadRoleCandidates({ offset: 0, query: activeRoleSearch, replace: true }),
      0,
    );
    return () => {
      window.clearTimeout(timeout);
      roleLoadController.invalidate();
    };
  }, [activeRoleSearch, loadRoleCandidates, roleLoadController]);

  const roleById = useMemo(
    () => new Map(knownRoles.map((role) => [role.id, role.name])),
    [knownRoles],
  );
  const assignmentRoleOptions = useMemo(
    () => roleOptionsForSelection(roleCandidates, knownRoles, roleEditor?.roleIds ?? []),
    [knownRoles, roleCandidates, roleEditor?.roleIds],
  );
  const newUserRoleOptions = useMemo(
    () => roleOptionsForSelection(roleCandidates, knownRoles, newRoleIds),
    [knownRoles, newRoleIds, roleCandidates],
  );
  const missingAssignmentRoles = useMemo(
    () => missingSelectedRoleCount(knownRoles, roleEditor?.roleIds ?? []),
    [knownRoles, roleEditor?.roleIds],
  );
  const missingNewUserRoles = useMemo(
    () => missingSelectedRoleCount(knownRoles, newRoleIds),
    [knownRoles, newRoleIds],
  );
  const roleEditorUser = roleEditor ? users?.find((user) => user.id === roleEditor.userId) : null;
  const passwordEditorUser = passwordEditor ? users?.find((user) => user.id === passwordEditor.userId) : null;

  function closeMemberEditors() {
    setRoleEditor(null);
    setPasswordEditor(null);
  }

  function moveToUserOffset(offset: number) {
    closeMemberEditors();
    setUserOffset(offset);
  }

  function searchRoleCandidates(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = roleSearchDraft.trim();
    setRoleOffset(0);
    setHasMoreRoles(false);
    setRoleCandidates([]);
    if (query === activeRoleSearch) {
      void loadRoleCandidates({ offset: 0, query, replace: true });
    } else {
      setRoleCatalogLoading(true);
      setActiveRoleSearch(query);
    }
  }

  function loadMoreRoleCandidates() {
    void loadRoleCandidates({
      offset: roleOffset + ROLE_CATALOG_PAGE_SIZE,
      query: activeRoleSearch,
      replace: false,
    });
  }

  function toggleRole(id: string, selected: string[], update: (ids: string[]) => void) {
    update(selected.includes(id) ? selected.filter((item) => item !== id) : [...selected, id]);
  }

  async function createUser(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    setNotice("");
    setNotice("");
    try {
      validateStrongPassword(password);
      await apiRequest<User>("/api/v1/users", {
        method: "POST",
        body: JSON.stringify({
          email: email.trim(),
          password,
          display_name: displayName.trim() || null,
          role_ids: can("role:assign") ? newRoleIds : [],
        }),
      });
      setEmail("");
      setPassword("");
      setDisplayName("");
      setNewRoleIds([]);
      setSearchDraft("");
      setActiveSearch("");
      setUserOffset(0);
      await load({ offset: 0, search: "" });
      setNotice("成员账号已创建，列表已刷新。请按最小权限原则分配角色。");
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  async function setStatus(user: User, status: UserStatus) {
    setPending(true);
    setError("");
    try {
      await apiRequest<User>(`/api/v1/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ status }) });
      await load();
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
    }
  }

  async function saveRoles() {
    if (!roleEditor) return;
    const editorSnapshot = roleEditor;
    let draftInvalidatedFor: RoleAssignmentDraftInvalidationReason | null = null;
    setPending(true);
    setError("");
    setNotice("");
    try {
      const result = await saveUserRoleAssignment(editorSnapshot, {
        invalidateDraft: (reason) => {
          draftInvalidatedFor = reason;
          loadController.invalidate();
          setRoleEditor(null);
          setUsers(null);
        },
        reloadLatest: () => load({ propagateError: true }),
      });
      if (result.status === "stale") {
        setNotice(STALE_ROLE_ASSIGNMENT_MESSAGE);
      } else {
        setNotice("成员角色已保存，成员列表已刷新为最新版本。");
      }
    } catch (reason) {
      setNotice("");
      const message = draftInvalidatedFor === "saved"
        ? SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE
        : STALE_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE;
      setError(draftInvalidatedFor
        ? `${message} ${readableError(reason)}`
        : readableError(reason));
    } finally {
      setPending(false);
    }
  }

  async function resetPassword() {
    if (!passwordEditor || pending) return;
    const editorSnapshot = { ...passwordEditor };
    setPending(true);
    setError("");
    setNotice("");
    try {
      await resetUserPassword(editorSnapshot);
      setPasswordEditor(null);
      if (passwordResetRevokesCurrentSession(editorSnapshot.userId, me?.id)) {
        setNotice("当前管理员密码已重置，所有旧会话均已撤销，正在安全退出并返回登录页。请使用新密码重新登录。");
        await reloadAccess();
        return;
      }
      setNotice("管理员密码重置已完成。目标账号的全部旧会话已撤销，成员必须使用新密码重新登录。系统从不显示或读取旧密码。");
    } catch (reason) {
      setError(readablePasswordResetError(reason));
    } finally {
      setPending(false);
    }
  }

  if (!accessLoading && !can("user:manage")) {
    return <EmptyState icon="lock" title="没有账号管理权限" description="当前角色不包含 user:manage。管理入口已从导航隐藏，FastAPI 仍会执行最终权限校验。" />;
  }

  return (
    <div className="page-stack">
      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      {notice ? <div className="notice info-notice" role="status"><Icon name="refresh" /><div><strong>成员数据已同步</strong><p>{notice}</p></div></div> : null}
      <section className="panel">
        <div className="panel-header">
          <div><h2>成员账号</h2><p>创建账号、调整状态，并按角色授予能力</p></div>
          <form className="toolbar" role="search" onSubmit={(event) => {
            event.preventDefault();
            closeMemberEditors();
            setUserOffset(0);
            setActiveSearch(searchDraft.trim());
          }}>
            <div className="search-box"><Icon name="search" /><input aria-label="搜索成员" maxLength={200} placeholder="搜索邮箱或显示名称" value={searchDraft} onChange={(event) => setSearchDraft(event.target.value)} /></div>
            <button className="button secondary small" type="submit" disabled={pending}>搜索</button>
            <button className="button ghost small" type="button" disabled={pending} onClick={() => { closeMemberEditors(); setNotice(""); void load(); }}><Icon name="refresh" />刷新</button>
          </form>
        </div>
        {can("role:read") && can("role:assign") ? (
          <div className="inline-editor" aria-label="角色候选目录">
            <div>
              <strong>角色候选</strong>
              <p>候选目录由服务端按可分配范围过滤，搜索和加载更多不会清除已选角色。</p>
            </div>
            <form className="toolbar" role="search" onSubmit={searchRoleCandidates}>
              <div className="search-box"><Icon name="search" /><input aria-label="搜索角色候选" maxLength={200} placeholder="搜索角色名称或编码" value={roleSearchDraft} onChange={(event) => setRoleSearchDraft(event.target.value)} /></div>
              <button className="button secondary small" type="submit" disabled={roleCatalogLoading}>{roleCatalogLoading ? "搜索中…" : "搜索角色"}</button>
              <button className="button ghost small" type="button" disabled={roleCatalogLoading} onClick={() => {
                setRoleSearchDraft("");
                setRoleOffset(0);
                setHasMoreRoles(false);
                setRoleCandidates([]);
                if (activeRoleSearch) {
                  setRoleCatalogLoading(true);
                  setActiveRoleSearch("");
                } else {
                  void loadRoleCandidates({ offset: 0, query: "", replace: true });
                }
              }}>重置</button>
            </form>
            {roleCatalogError ? (
              <div className="notice error-notice" role="alert">
                <Icon name="warning" />
                <div><strong>角色候选暂时不可用</strong><p>{roleCatalogError}。成员停启用和密码操作仍可继续。</p></div>
                <button className="button ghost small" type="button" disabled={roleCatalogLoading} onClick={() => void loadRoleCandidates({ offset: 0, query: activeRoleSearch, replace: true })}>重试角色目录</button>
              </div>
            ) : null}
            <div className="pagination-bar">
              <span>已加载 {roleCandidates.length} 个候选{activeRoleSearch ? ` · 搜索“${activeRoleSearch}”` : ""}</span>
              <button className="button ghost small" type="button" disabled={roleCatalogLoading || !hasMoreRoles} onClick={loadMoreRoleCandidates}>{roleCatalogLoading ? "正在加载…" : "加载更多角色"}</button>
            </div>
          </div>
        ) : null}
        {users === null && !error ? <LoadingRows count={5} /> : null}
        {users?.length === 0 ? <EmptyState compact icon="users" title="还没有成员" description="创建第一个成员账号并分配最小必要角色。" /> : null}
        {users?.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>成员</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td><div className="primary-cell"><span className="file-icon"><Icon name="users" /></span><span><strong>{user.display_name || user.email}</strong><small>{user.email}{user.is_superuser ? " · 超级管理员" : ""}</small></span></div></td>
                    <td>{user.role_ids.length ? user.role_ids.map((id) => roleById.get(id) || id.slice(0, 8)).join("、") : "未分配"}</td>
                    <td><StatusBadge tone={statusTone[user.status]}>{statusLabel[user.status]}</StatusBadge></td>
                    <td>{new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "short", day: "numeric" }).format(new Date(user.created_at))}</td>
                    <td><div className="button-row">
                      <button className="button ghost small" type="button" aria-label={`${user.status === "active" ? "停用" : "启用"} ${user.email}`} disabled={pending} onClick={() => void setStatus(user, user.status === "active" ? "disabled" : "active")}>{user.status === "active" ? "停用" : "启用"}</button>
                      {canResetUserPassword(user.id, me?.id, Boolean(me?.is_superuser)) ? (
                        <button className="button ghost small" type="button" aria-label={`修改密码 ${user.email}`} disabled={pending} onClick={() => {
                          setRoleEditor(null);
                          setPasswordEditor({
                            userId: user.id,
                            isSelf: user.id === me?.id,
                            currentPassword: "",
                            newPassword: "",
                            confirmation: "",
                          });
                        }}>修改密码</button>
                      ) : null}
                      {can("role:assign") && can("role:read") ? <button className="button secondary small" type="button" aria-label={`分配角色 ${user.email}`} disabled={pending} onClick={() => { setPasswordEditor(null); setRoleEditor(openRoleAssignmentEditor(user)); }}>分配角色</button> : null}
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <nav className="pagination-bar" aria-label="成员列表分页">
              <span>第 {offsetPageNumber(userOffset)} 页 · 本页 {users.length} 项</span>
              <div className="button-row">
                <button className="button ghost small" type="button" disabled={pending || userOffset === 0} onClick={() => moveToUserOffset(previousOffset(userOffset))}>上一页</button>
                <button className="button ghost small" type="button" disabled={pending || !hasNextUsers} onClick={() => moveToUserOffset(userOffset + ADMIN_LIST_PAGE_SIZE)}>下一页</button>
              </div>
            </nav>
          </div>
        ) : null}
        {roleEditor ? (
          <div className="inline-editor" role="dialog" aria-labelledby="role-assignment-editor-title">
            <div><strong id="role-assignment-editor-title">分配角色：{roleEditorUser?.display_name || roleEditorUser?.email || roleEditor.userId}</strong><p>保存后立即影响该成员的有效权限与限额。</p></div>
            {missingAssignmentRoles ? <p className="inline-error">已保留 {missingAssignmentRoles} 个尚未加载详情的已选角色；不会在搜索或分页时丢失。</p> : null}
            {assignmentRoleOptions.length ? <div className="checkbox-grid">
              {assignmentRoleOptions.map((role) => (
                <label className="check-option" key={role.id}>
                  <input
                    type="checkbox"
                    checked={roleEditor.roleIds.includes(role.id)}
                    disabled={pending}
                    onChange={() => setRoleEditor((current) => current ? {
                      ...current,
                      roleIds: current.roleIds.includes(role.id)
                        ? current.roleIds.filter((id) => id !== role.id)
                        : [...current.roleIds, role.id],
                    } : current)}
                  />
                  <span>{role.name}<small>{role.code}</small></span>
                </label>
              ))}
            </div> : <p>当前检索没有可分配角色。可以重试目录或更换搜索条件。</p>}
            <div className="form-actions"><button className="button ghost" type="button" disabled={pending} onClick={() => setRoleEditor(null)}>取消</button><button className="button primary" type="button" disabled={pending} onClick={() => void saveRoles()}>保存角色</button></div>
          </div>
        ) : null}
        {passwordEditor ? (
          <form className="inline-editor" role="dialog" aria-labelledby="password-reset-editor-title" onSubmit={(event) => { event.preventDefault(); void resetPassword(); }}>
            <div>
              <strong id="password-reset-editor-title">{passwordEditor.isSelf ? "修改自己的密码" : `重置成员密码：${passwordEditorUser?.display_name || passwordEditorUser?.email || passwordEditor.userId}`}</strong>
              <p>{passwordEditor.isSelf
                ? "为验证当前身份，请输入现用密码。修改成功后会安全退出并撤销全部旧会话。"
                : "仅超级管理员可执行此操作，且无需读取目标成员的旧密码。保存后会撤销该账号的全部旧会话。"}</p>
            </div>
            <div className="form-grid">
              {passwordEditor.isSelf ? (
                <label className="full">当前密码<input type="password" minLength={1} maxLength={256} autoComplete="current-password" value={passwordEditor.currentPassword} disabled={pending} onChange={(event) => setPasswordEditor((current) => current ? { ...current, currentPassword: event.target.value } : current)} required /></label>
              ) : null}
              <label className="full">新密码<input type="password" minLength={12} maxLength={256} autoComplete="new-password" value={passwordEditor.newPassword} disabled={pending} onChange={(event) => setPasswordEditor((current) => current ? { ...current, newPassword: event.target.value } : current)} placeholder="12–256 位可打印 ASCII，包含大小写字母、数字和符号" required /></label>
              <label className="full">确认新密码<input type="password" minLength={12} maxLength={256} autoComplete="new-password" value={passwordEditor.confirmation} disabled={pending} onChange={(event) => setPasswordEditor((current) => current ? { ...current, confirmation: event.target.value } : current)} required /></label>
            </div>
            <div className="form-actions"><button className="button ghost" type="button" disabled={pending} onClick={() => setPasswordEditor(null)}>取消</button><button className="button primary" type="submit" disabled={pending}>{pending ? "正在修改…" : "确认修改并撤销旧会话"}</button></div>
          </form>
        ) : null}
        <details className="drawer-form">
          <summary>＋ 新建成员账号</summary>
          <form className="form-grid" onSubmit={createUser}>
            <label>邮箱<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
            <label>显示名称<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label>
            <label className="full">初始密码<input type="password" minLength={12} maxLength={256} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="12–256 位可打印 ASCII，包含大小写字母、数字和符号" required /></label>
            {can("role:assign") && can("role:read") ? <fieldset className="full fieldset"><legend>初始角色</legend>{missingNewUserRoles ? <p className="inline-error">已保留 {missingNewUserRoles} 个尚未加载详情的已选角色。</p> : null}<div className="checkbox-grid">{newUserRoleOptions.map((role) => <label className="check-option" key={role.id}><input type="checkbox" checked={newRoleIds.includes(role.id)} onChange={() => toggleRole(role.id, newRoleIds, setNewRoleIds)} /><span>{role.name}<small>{role.code}</small></span></label>)}</div>{newUserRoleOptions.length === 0 ? <p>当前检索没有可分配角色。</p> : null}</fieldset> : null}
            <div className="form-actions full"><button className="button primary" type="submit" disabled={pending}>{pending ? "正在创建…" : "创建账号"}</button></div>
          </form>
        </details>
      </section>
    </div>
  );
}
