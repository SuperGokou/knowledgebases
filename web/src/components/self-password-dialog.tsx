"use client";

import { type FormEvent, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import {
  readablePasswordResetError,
  resetUserPassword,
} from "@/lib/user-password-reset";

export function SelfPasswordDialog() {
  const { me } = useAccess();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  function clearSecrets() {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmation("");
  }

  function openDialog() {
    if (!me || pending) return;
    setError("");
    clearSecrets();
    dialogRef.current?.showModal();
  }

  function closeDialog() {
    if (pending) return;
    dialogRef.current?.close();
    setError("");
    clearSecrets();
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!me || pending) return;
    setPending(true);
    setError("");
    try {
      await resetUserPassword({
        userId: me.id,
        isSelf: true,
        currentPassword,
        newPassword,
        confirmation,
      });
      clearSecrets();
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          cache: "no-store",
          credentials: "same-origin",
        });
      } finally {
        // The backend has already revoked every refresh token. A full
        // navigation also removes the browser's now-stale session cookies.
        window.location.replace("/login");
      }
    } catch (reason) {
      setError(readablePasswordResetError(reason));
      setPending(false);
    }
  }

  return (
    <>
      <button
        className="account-password-button"
        type="button"
        aria-label="修改登录密码"
        title={me ? "修改登录密码" : "正在加载账户信息"}
        disabled={!me || pending}
        onClick={openDialog}
      >
        <Icon name="lock" />
        <span>修改密码</span>
      </button>
      <dialog
        ref={dialogRef}
        className="self-password-dialog"
        aria-labelledby="self-password-title"
        onCancel={(event) => {
          if (pending) event.preventDefault();
        }}
        onClose={() => {
          if (!pending) clearSecrets();
        }}
      >
        <form className="self-password-card" onSubmit={changePassword}>
          <header>
            <span className="self-password-icon"><Icon name="lock" /></span>
            <div>
              <strong id="self-password-title">修改登录密码</strong>
              <p>验证当前密码后更新。成功后系统会撤销全部旧会话并返回登录页。</p>
            </div>
          </header>
          {error ? <div className="notice error-notice" role="alert">{error}</div> : null}
          <div className="form-grid">
            <label className="full">
              当前密码
              <input
                type="password"
                minLength={1}
                maxLength={256}
                autoComplete="current-password"
                value={currentPassword}
                disabled={pending}
                onChange={(event) => setCurrentPassword(event.target.value)}
                required
                autoFocus
              />
            </label>
            <label className="full">
              新密码
              <input
                type="password"
                minLength={12}
                maxLength={256}
                autoComplete="new-password"
                value={newPassword}
                disabled={pending}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="12–256 位可打印 ASCII，含大小写字母、数字和符号"
                required
              />
            </label>
            <label className="full">
              确认新密码
              <input
                type="password"
                minLength={12}
                maxLength={256}
                autoComplete="new-password"
                value={confirmation}
                disabled={pending}
                onChange={(event) => setConfirmation(event.target.value)}
                required
              />
            </label>
          </div>
          <div className="form-actions">
            <button className="button ghost" type="button" disabled={pending} onClick={closeDialog}>
              取消
            </button>
            <button className="button primary" type="submit" disabled={pending || !me} aria-busy={pending}>
              {pending ? <><span className="spinner" />正在安全更新…</> : "确认修改"}
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}
