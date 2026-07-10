"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAccess } from "@/components/access-provider";
import { Icon, type IconName } from "@/components/icon";

const groups: Array<{
  label: string;
  items: Array<{
    href: string;
    label: string;
    icon: IconName;
    exact?: boolean;
    permissions: string[];
  }>;
}> = [
  {
    label: "工作空间",
    items: [{ href: "/chat", label: "知识问答", icon: "chat", permissions: ["chat:query"] }],
  },
  {
    label: "管理控制台",
    items: [
      {
        href: "/admin",
        label: "总览",
        icon: "grid",
        exact: true,
        permissions: ["knowledge:read", "file:read", "user:manage", "role:read"],
      },
      { href: "/admin/knowledge", label: "知识库", icon: "book", permissions: ["knowledge:read"] },
      { href: "/admin/files", label: "文件中心", icon: "file", permissions: ["file:read"] },
      { href: "/admin/users", label: "账号管理", icon: "users", permissions: ["user:manage"] },
      { href: "/admin/roles", label: "角色与权限", icon: "shield", permissions: ["role:read"] },
    ],
  },
];

export function SideNav() {
  const pathname = usePathname();
  const { canAny, loading } = useAccess();
  return (
    <nav className="side-nav" aria-label="主要导航">
      {groups.map((group) => {
        const items = loading ? [] : group.items.filter((item) => canAny(item.permissions));
        if (!items.length) return null;
        return (
          <div className="nav-group" key={group.label}>
            <p>{group.label}</p>
            {items.map((item) => {
            const active = item.exact ? pathname === item.href : pathname.startsWith(item.href);
            return (
              <Link className={active ? "active" : ""} href={item.href} key={item.href}>
                <Icon name={item.icon} />
                <span>{item.label}</span>
                {active ? <i /> : null}
              </Link>
            );
            })}
          </div>
        );
      })}
    </nav>
  );
}
