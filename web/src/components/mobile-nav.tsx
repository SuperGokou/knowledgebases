"use client";

import Link from "next/link";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";

export function MobileNav() {
  const { can, canAny, loading } = useAccess();
  if (loading) return null;
  const hasAdmin = canAny(["knowledge:read", "file:read", "user:manage", "role:read"]);
  return (
    <nav className="mobile-nav" aria-label="移动导航">
      {can("chat:query") ? <Link href="/chat"><Icon name="chat" /><span>问答</span></Link> : null}
      {can("file:read") ? <Link href="/admin/files"><Icon name="file" /><span>文件</span></Link> : null}
      {hasAdmin ? <Link href="/admin"><Icon name="grid" /><span>管理</span></Link> : null}
    </nav>
  );
}
