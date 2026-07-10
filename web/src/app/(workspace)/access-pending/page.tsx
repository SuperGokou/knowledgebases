import { EmptyState, PageHeader } from "@/components/ui";

export const metadata = { title: "等待授权" };

export default function AccessPendingPage() {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="ACCESS CONTROL"
        title="账号已登录，正在等待授权"
        description="身份验证已经完成，但当前账号还没有可进入的工作区。"
      />
      <section className="panel">
        <EmptyState
          icon="lock"
          title="尚未分配可用工作区"
          description="当前角色尚未包含可打开的问答或管理模块。请联系系统管理员补充权限；角色生效后刷新页面，系统会自动进入对应工作区。"
        />
      </section>
    </div>
  );
}
