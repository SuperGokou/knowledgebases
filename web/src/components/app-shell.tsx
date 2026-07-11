import Link from "next/link";
import type { ReactNode } from "react";

import { AccessProvider } from "@/components/access-provider";
import { BrandIdentity } from "@/components/brand-identity";
import { Icon } from "@/components/icon";
import { LogoutButton } from "@/components/logout-button";
import { MobileNav } from "@/components/mobile-nav";
import { SideNav } from "@/components/side-nav";
import { ThemeSelector } from "@/components/theme-selector";
import { WorkspaceAccessBoundary } from "@/components/workspace-access-boundary";

export function AppShell({ children, email }: { children: ReactNode; email?: string }) {
  const initial = (email?.[0] ?? "K").toUpperCase();
  return (
    <AccessProvider>
      <div className="app-shell">
      <aside className="sidebar">
        <SideNav />
        <div className="sidebar-foot">
          <div className="secure-chip"><Icon name="lock" /><span>安全会话</span></div>
        </div>
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <Link className="topbar-brand" href="/">
            <BrandIdentity variant="workspace" priority />
          </Link>
          <ThemeSelector />
          <div className="topbar-actions">
            <div className="topbar-status"><span className="pulse" /> 安全连接</div>
            <div className="topbar-account">
              <span className="avatar">{initial}</span>
              <span className="account-copy">
                <strong>{email ?? "已登录账号"}</strong>
                <small>企业工作区</small>
              </span>
              <LogoutButton />
            </div>
          </div>
        </header>
        <main className="content"><WorkspaceAccessBoundary>{children}</WorkspaceAccessBoundary></main>
        <MobileNav />
      </div>
      </div>
    </AccessProvider>
  );
}
