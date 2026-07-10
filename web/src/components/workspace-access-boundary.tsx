"use client";

import { useEffect, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";

import { useAccess } from "@/components/access-provider";
import { ErrorState, LoadingRows } from "@/components/ui";
import { canAccessPath, defaultLandingPath } from "@/lib/access-routing";

export function WorkspaceAccessBoundary({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { me, loading, error, reload } = useAccess();
  const landingPath = me ? defaultLandingPath(me) : "/access-pending";
  const shouldLeavePending = pathname === "/access-pending" && landingPath !== pathname;
  const allowed = me ? canAccessPath(pathname, me) : false;
  const redirectPath = shouldLeavePending || !allowed ? landingPath : null;

  useEffect(() => {
    if (!loading && me && redirectPath) router.replace(redirectPath);
  }, [loading, me, redirectPath, router]);

  if (loading || (me && redirectPath)) {
    return (
      <section className="panel" aria-label="正在载入账号工作区">
        <LoadingRows count={3} />
      </section>
    );
  }
  if (error || !me) {
    return <ErrorState message={error || "无法确认当前账号的访问权限。"} onRetry={() => void reload()} />;
  }
  return children;
}
