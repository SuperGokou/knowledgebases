import Link from "next/link";
import type { ReactNode } from "react";

import { AccessProvider } from "@/components/access-provider";
import { BrandIdentity } from "@/components/brand-identity";
import { Icon } from "@/components/icon";
import { LogoutButton } from "@/components/logout-button";
import { MobileNav } from "@/components/mobile-nav";
import { SideNav } from "@/components/side-nav";
import { WorkspaceAccessBoundary } from "@/components/workspace-access-boundary";

export function AppShell({ children, email }: { children: ReactNode; email?: string }) {
  const initial = (email?.[0] ?? "K").toUpperCase();
  return (
    <AccessProvider>
      <div className="app-shell">
      <aside className="sidebar">
        <Link className="brand" href="/">
          <BrandIdentity />
        </Link>
        <SideNav />
        <div className="sidebar-foot">
          <div className="secure-chip"><Icon name="lock" /><span>HttpOnly 安全会话</span></div>
          <div className="account-card">
            <span className="avatar">{initial}</span>
            <span className="account-copy">
              <strong>{email ?? "已登录账号"}</strong>
              <small>企业工作区</small>
            </span>
            <LogoutButton />
          </div>
        </div>
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <div className="mobile-brand"><BrandIdentity variant="mobile" /></div>
          <div className="topbar-status"><span className="pulse" /> API 通过安全 BFF 连接</div>
          <div className="topbar-help"><kbd>⌘</kbd><kbd>K</kbd><span>快速搜索</span></div>
        </header>
        <main className="content"><WorkspaceAccessBoundary>{children}</WorkspaceAccessBoundary></main>
        <MobileNav />
      </div>
      </div>
    </AccessProvider>
  );
}
