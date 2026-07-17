"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { useActionFeedback } from "@/components/action-feedback";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { createActionLock } from "@/lib/action-lock";
import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import type { Role, User, UserStatus } from "@/lib/types";
import { canDeleteUser, deleteUser } from "@/lib/user-deletion";

const statusLabel: Record<UserStatus, string> = { active: "正常", disabled: "已停用", locked: "已锁定" };
const statusTone: Record<UserStatus, "success" | "neutral" | "danger"> = { active: "success", disabled: "neutral", locked: "danger" };
type PendingAction =
  | { type: "create" }
  | { type: "status"; userId: string; status: UserStatus }
  | { type: "roles"; userId: string }
  | { type: "password"; userId: string }
  | { type: "delete"; userId: string }
  | null;

export function UsersPanel() {
  const { can, loading: accessLoading, me } = useAccess();
  const feedback = useActionFeedback();
  const actionLock = useRef(createActionLock()).current;
  const [users, setUsers] = useState<User[] | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [error, setError] = useState("");
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const pending = pendingAction !== null;
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [newRoleIds, setNewRoleIds] = useState<string[]>([]);
  const [editingUserId, setEditingUserId] = useState("");
  const [editingRoleIds, setEditingRoleIds] = useState<string[]>([]);
  const [passwordUserId, setPasswordUserId] = useState("");
  const [resetPassword, setResetPassword] = useState("");
  const [resetPasswordConfirm, setResetPasswordConfirm] = useState("");

  const load = useCallback(async () => {
    if (accessLoading) return;
    if (!can("user:manage")) {
      setUsers([]);
      return;
    }
    setError("");
    try {
      const [userItems, roleItems] = await Promise.all([
        apiRequest<User[]>("/api/v1/users?limit=100&offset=0"),
        can("role:read") ? apiRequest<Role[]>("/api/v1/roles?limit=100&offset=0") : Promise.resolve([]),
      ]);
      setUsers(userItems);
      setRoles(roleItems);
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  const roleById = useMemo(() => new Map(roles.map((role) => [role.id, role.name])), [roles]);

  function toggleRole(id: string, selected: string[], update: (ids: string[]) => void) {
    update(selected.includes(id) ? selected.filter((item) => item !== id) : [...selected, id]);
  }

  async function createUser(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!actionLock.acquire()) return;
    feedback.dismiss();
    setPendingAction({ type: "create" });
    setError("");
    try {
      const created = await apiRequest<User>("/api/v1/users", {
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
      await load();
      feedback.success(`成员“${created.display_name || created.email}”已创建并可使用已分配的角色登录。`, "成员账号已创建");
    } catch (reason) {
      const message = readableError(reason);
      setError(message);
      feedback.error(message, "成员账号创建失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
    }
  }

  async function setStatus(user: User, status: UserStatus) {
    if (!actionLock.acquire()) return;
    feedback.dismiss();
    setPendingAction({ type: "status", userId: user.id, status });
    setError("");
    try {
      await apiRequest<User>(`/api/v1/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ status }) });
      await load();
      const actionLabel = status === "active" ? "启用" : "停用";
      feedback.success(`成员“${user.display_name || user.email}”已${actionLabel}。`, `账号已${actionLabel}`);
    } catch (reason) {
      const message = readableError(reason);
      setError(message);
      feedback.error(message, status === "active" ? "账号启用失败" : "账号停用失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
    }
  }

  async function saveRoles(userId: string) {
    if (!actionLock.acquire()) return;
    feedback.dismiss();
    setPendingAction({ type: "roles", userId });
    setError("");
    try {
      await apiRequest<User>(`/api/v1/users/${userId}/roles`, { method: "PUT", body: JSON.stringify({ role_ids: editingRoleIds }) });
      const userName = users?.find((user) => user.id === userId)?.display_name
        || users?.find((user) => user.id === userId)?.email
        || "当前成员";
      setEditingUserId("");
      await load();
      feedback.success(`成员“${userName}”的角色与对应权限已更新。`, "成员角色已保存");
    } catch (reason) {
      const message = readableError(reason);
      setError(message);
      feedback.error(message, "成员角色保存失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
    }
  }

  async function removeUser(user: User) {
    const userName = user.display_name || user.email;
    if (!window.confirm(`确定永久删除账号“${userName}”吗？此操作无法撤销。`)) return;
    if (!actionLock.acquire()) return;
    feedback.dismiss();
    setPendingAction({ type: "delete", userId: user.id });
    setError("");
    try {
      await deleteUser(user.id, (path, init) => apiRequest<void>(path, init));
      if (editingUserId === user.id) setEditingUserId("");
      if (passwordUserId === user.id) setPasswordUserId("");
      await load();
      feedback.success(`账号“${userName}”已永久删除。`, "账号已删除");
    } catch (reason) {
      const message = reason instanceof ApiClientError && reason.code === "user_owns_resources"
        ? "该账号仍拥有文件或知识库，请先处理这些资源后再删除账号。"
        : readableError(reason);
      setError(message);
      feedback.error(message, "账号删除失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
    }
  }

  async function savePassword(userId: string) {
    const user = users?.find((item) => item.id === userId);
    const userName = user?.display_name || user?.email || "当前成员";
    if (resetPassword.length < 12) {
      const message = "新密码至少需要 12 位。";
      setError(message);
      feedback.error(message, "密码修改失败");
      return;
    }
    if (resetPassword !== resetPasswordConfirm) {
      const message = "两次输入的密码不一致。";
      setError(message);
      feedback.error(message, "密码修改失败");
      return;
    }
    if (!actionLock.acquire()) return;
    feedback.dismiss();
    setPendingAction({ type: "password", userId });
    setError("");
    try {
      await apiRequest<void>(`/api/v1/users/${userId}/password`, {
        method: "PUT",
        body: JSON.stringify({ password: resetPassword }),
      });
      setPasswordUserId("");
      setResetPassword("");
      setResetPasswordConfirm("");
      feedback.success(`成员“${userName}”的密码已修改，旧登录会话已失效。`, "密码修改成功");
    } catch (reason) {
      const message = readableError(reason);
      setError(message);
      feedback.error(message, "密码修改失败");
    } finally {
      actionLock.release();
      setPendingAction(null);
    }
  }

  if (!accessLoading && !can("user:manage")) {
    return <EmptyState icon="lock" title="没有账号管理权限" description="当前角色不包含 user:manage。管理入口已从导航隐藏，FastAPI 仍会执行最终权限校验。" />;
  }

  return (
    <div className="page-stack">
      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      <section className="panel">
        <div className="panel-header">
          <div><h2>成员账号</h2><p>创建账号、调整状态，并按角色授予能力</p></div>
          <button className="button ghost small" type="button" disabled={pending} onClick={() => void load()}><Icon name="refresh" />刷新</button>
        </div>
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
                      <button className="button ghost small" type="button" disabled={pending} aria-busy={pendingAction?.type === "status" && pendingAction.userId === user.id} onClick={() => void setStatus(user, user.status === "active" ? "disabled" : "active")}>
                        {pendingAction?.type === "status" && pendingAction.userId === user.id
                          ? <><span className="spinner" />{pendingAction.status === "active" ? "正在启用…" : "正在停用…"}</>
                          : user.status === "active" ? "停用" : "启用"}
                      </button>
                      {can("role:assign") && roles.length ? <button className="button secondary small" type="button" disabled={pending} onClick={() => { setPasswordUserId(""); setEditingUserId(user.id); setEditingRoleIds(user.role_ids); }}>分配角色</button> : null}
                      {me?.is_superuser ? (
                        <button className="button secondary small" type="button" disabled={pending} onClick={() => { setEditingUserId(""); setPasswordUserId(user.id); setResetPassword(""); setResetPasswordConfirm(""); }}>修改密码</button>
                      ) : null}
                      {canDeleteUser(me, user) ? (
                        <button className="button danger small" type="button" disabled={pending} aria-busy={pendingAction?.type === "delete" && pendingAction.userId === user.id} onClick={() => void removeUser(user)}>
                          {pendingAction?.type === "delete" && pendingAction.userId === user.id ? <><span className="spinner" />正在删除…</> : "删除"}
                        </button>
                      ) : null}
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {passwordUserId ? (
          <div className="inline-editor">
            <div><strong>修改账号密码</strong><p>新密码至少 12 位；保存后该账号的旧登录会话会立即失效。</p></div>
            <div className="form-grid">
              <label>新密码<input type="password" minLength={12} maxLength={256} value={resetPassword} onChange={(event) => setResetPassword(event.target.value)} autoComplete="new-password" /></label>
              <label>确认新密码<input type="password" minLength={12} maxLength={256} value={resetPasswordConfirm} onChange={(event) => setResetPasswordConfirm(event.target.value)} autoComplete="new-password" /></label>
            </div>
            <div className="form-actions">
              <button className="button ghost" type="button" disabled={pending} onClick={() => { setPasswordUserId(""); setResetPassword(""); setResetPasswordConfirm(""); }}>取消</button>
              <button className="button primary" type="button" disabled={pending || resetPassword.length < 12 || resetPassword !== resetPasswordConfirm} aria-busy={pendingAction?.type === "password" && pendingAction.userId === passwordUserId} onClick={() => void savePassword(passwordUserId)}>
                {pendingAction?.type === "password" && pendingAction.userId === passwordUserId ? <><span className="spinner" />正在保存密码…</> : "保存新密码"}
              </button>
            </div>
          </div>
        ) : null}
        {editingUserId ? (
          <div className="inline-editor">
            <div><strong>分配角色</strong><p>保存后立即影响该成员的有效权限与限额。</p></div>
            <div className="checkbox-grid">
              {roles.map((role) => (
                <label className="check-option" key={role.id}>
                  <input type="checkbox" checked={editingRoleIds.includes(role.id)} onChange={() => toggleRole(role.id, editingRoleIds, setEditingRoleIds)} />
                  <span>{role.name}<small>{role.code}</small></span>
                </label>
              ))}
            </div>
            <div className="form-actions"><button className="button ghost" type="button" disabled={pending} onClick={() => setEditingUserId("")}>取消</button><button className="button primary" type="button" disabled={pending} aria-busy={pendingAction?.type === "roles" && pendingAction.userId === editingUserId} onClick={() => void saveRoles(editingUserId)}>{pendingAction?.type === "roles" && pendingAction.userId === editingUserId ? <><span className="spinner" />正在保存角色…</> : "保存角色"}</button></div>
          </div>
        ) : null}
        <details className="drawer-form">
          <summary>＋ 新建成员账号</summary>
          <form className="form-grid" onSubmit={createUser}>
            <label>邮箱<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
            <label>显示名称<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label>
            <label className="full">初始密码<input type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="至少 12 位" required /></label>
            {can("role:assign") && roles.length ? <fieldset className="full fieldset"><legend>初始角色</legend><div className="checkbox-grid">{roles.map((role) => <label className="check-option" key={role.id}><input type="checkbox" checked={newRoleIds.includes(role.id)} onChange={() => toggleRole(role.id, newRoleIds, setNewRoleIds)} /><span>{role.name}<small>{role.code}</small></span></label>)}</div></fieldset> : null}
            <div className="form-actions full"><button className="button primary" type="submit" disabled={pending} aria-busy={pendingAction?.type === "create"}>{pendingAction?.type === "create" ? <><span className="spinner" />正在创建账号…</> : "创建账号"}</button></div>
          </form>
        </details>
      </section>
    </div>
  );
}
