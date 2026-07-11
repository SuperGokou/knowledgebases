"use client";

import { useState } from "react";

import { Icon } from "@/components/icon";

export function LogoutButton() {
  const [pending, setPending] = useState(false);

  async function logout() {
    setPending(true);
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
      });
    } finally {
      // A full navigation guarantees that Set-Cookie deletions are committed
      // before the workspace proxy evaluates the next request.
      window.location.replace("/login");
    }
  }

  return (
    <button className="logout-button" type="button" aria-label="退出登录" onClick={logout} disabled={pending}>
      <Icon name="logout" />
      <span>{pending ? "正在退出" : "退出登录"}</span>
    </button>
  );
}
