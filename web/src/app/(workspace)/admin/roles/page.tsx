import { RolesPanel } from "@/components/roles-panel";
import { PageHeader } from "@/components/ui";

export const metadata = { title: "角色与权限" };

export default function RolesPage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="RBAC" title="角色与权限" description="动态创建角色，并组合权限能力、请求频率、上传大小、存储与下载额度。" />
      <RolesPanel />
    </div>
  );
}
