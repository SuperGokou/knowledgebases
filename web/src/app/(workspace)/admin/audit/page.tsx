import { AuditLogsPanel } from "@/components/audit-logs-panel";
import { PageHeader } from "@/components/ui";

export const metadata = { title: "审计日志" };

export default function AuditLogsPage() {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="安全与合规"
        title="审计日志"
        description="按权限查询并导出关键操作记录，支持稳定游标分页与脱敏展示。"
      />
      <AuditLogsPanel />
    </div>
  );
}
