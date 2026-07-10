"use client";

import Link from "next/link";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { canAccessPath } from "@/lib/access-routing";

export function MobileNav() {
  const { me, loading } = useAccess();
  if (loading || !me) return null;
  return (
    <nav className="mobile-nav" aria-label="移动导航">
      {canAccessPath("/chat", me) ? <Link href="/chat"><Icon name="chat" /><span>问答</span></Link> : null}
      {canAccessPath("/admin/knowledge", me) ? <Link href="/admin/knowledge"><Icon name="book" /><span>知识库</span></Link> : null}
      {canAccessPath("/admin/files", me) ? <Link href="/admin/files"><Icon name="file" /><span>文件</span></Link> : null}
      {canAccessPath("/admin", me) ? <Link href="/admin"><Icon name="grid" /><span>管理</span></Link> : null}
    </nav>
  );
}
