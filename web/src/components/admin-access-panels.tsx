"use client";

import Link from "next/link";

import { useAccess } from "@/components/access-provider";
import { Icon, type IconName } from "@/components/icon";
import { EmptyState, StatusBadge } from "@/components/ui";

const features: Array<{ href: string; icon: IconName; title: string; detail: string; permissions: string[] }> = [
  { href: "/admin/knowledge", icon: "book", title: "知识库", detail: "组织业务域与检索范围", permissions: ["knowledge:read"] },
  { href: "/admin/files", icon: "file", title: "文件中心", detail: "直传、审核与状态追踪", permissions: ["file:read"] },
  { href: "/admin/users", icon: "users", title: "账号管理", detail: "成员状态与角色分配", permissions: ["user:manage"] },
  { href: "/admin/roles", icon: "shield", title: "角色与权限", detail: "动态 RBAC 与资源限额", permissions: ["role:read"] },
  { href: "/admin/api-models", icon: "spark", title: "API 与模型", detail: "生成调用凭证并切换大模型", permissions: ["api-key:manage", "llm:manage"] },
];

export function AdminFeatureList() {
  const { canAny, loading } = useAccess();
  if (loading) return null;
  const visible = features.filter((feature) => canAny(feature.permissions));
  if (!visible.length) return <EmptyState compact icon="lock" title="没有管理模块" description="当前账号只拥有工作区能力。" />;
  return (
    <div className="panel-body feature-list">
      {visible.map((item) => (
        <Link className="feature-link" href={item.href} key={item.href}>
          <span><Icon name={item.icon} /></span><span><strong>{item.title}</strong><small>{item.detail}</small></span><Icon name="arrow" />
        </Link>
      ))}
    </div>
  );
}

export function AdminBoundaryList() {
  const { canAny, loading } = useAccess();
  if (loading) return null;
  return (
    <div className="panel-body">
      <div className="system-line"><span><Icon name="shield" />FastAPI 权限校验</span><StatusBadge tone="success">已实现</StatusBadge></div>
      {canAny(["file:read", "file:upload"]) ? <div className="system-line"><span><Icon name="upload" />对象存储直传</span><StatusBadge tone="success">已实现</StatusBadge></div> : null}
      {canAny(["chat:query"]) ? <div className="system-line"><span><Icon name="chat" />知识问答检索</span><StatusBadge tone="success">已接入</StatusBadge></div> : null}
      {canAny(["knowledge:read", "knowledge:update"]) ? <div className="system-line"><span><Icon name="book" />内容解析与扫描</span><StatusBadge tone="neutral">待接入 Worker</StatusBadge></div> : null}
    </div>
  );
}
