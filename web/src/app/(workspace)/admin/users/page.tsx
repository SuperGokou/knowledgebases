import { PageHeader } from "@/components/ui";
import { UsersPanel } from "@/components/users-panel";

export const metadata = { title: "账号管理" };

export default function UsersPage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="IDENTITY" title="账号管理" description="管理成员状态与角色分配。权限变更由 FastAPI 动态计算并记录审计事件。" />
      <UsersPanel />
    </div>
  );
}
