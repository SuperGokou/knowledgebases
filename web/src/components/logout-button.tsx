"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Icon } from "@/components/icon";

export function LogoutButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function logout() {
    setPending(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }

  return (
    <button className="logout-button" type="button" aria-label="退出登录" onClick={logout} disabled={pending}>
      <Icon name="logout" />
      <span>{pending ? "正在退出" : "退出登录"}</span>
    </button>
  );
}
