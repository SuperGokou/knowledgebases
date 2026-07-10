import { AdminBoundaryList, AdminFeatureList } from "@/components/admin-access-panels";
import { Icon } from "@/components/icon";
import { PageHeader, StatCard } from "@/components/ui";

export const metadata = { title: "管理总览" };

export default function AdminOverviewPage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="ADMIN CONSOLE" title="管理控制台" description="统一管理知识、文件、成员与访问策略。所有数据请求都由 FastAPI 执行最终权限校验。" />
      <section className="stat-grid">
        <StatCard label="存储架构" value="10 TB+" detail="S3 / COS 预签名直传" icon="database" tone="blue" />
        <StatCard label="权限模型" value="动态 RBAC" detail="角色、权限与用户覆盖" icon="shield" tone="violet" />
        <StatCard label="会话安全" value="HttpOnly" detail="Token 不进入浏览器脚本" icon="lock" tone="green" />
        <StatCard label="上传状态" value="可恢复" detail="单文件与 Multipart" icon="upload" tone="amber" />
      </section>
      <section className="panel-grid">
        <article className="panel span-7">
          <div className="panel-header"><div><h2>管理入口</h2><p>按工作流进入对应模块</p></div></div>
          <AdminFeatureList />
        </article>
        <article className="panel span-5">
          <div className="panel-header"><div><h2>平台边界</h2><p>当前运行能力与责任范围</p></div></div>
          <AdminBoundaryList />
        </article>
        <article className="panel span-12">
          <div className="panel-header"><div><h2>上线准备</h2><p>从基础设施到知识服务的交付路径</p></div></div>
          <div className="panel-body roadmap">
            <div className="roadmap-item done"><span className="roadmap-dot"><Icon name="check" /></span><div><strong>安全登录与动态权限</strong><p>JWT 轮换、HttpOnly BFF、RBAC 与限额策略已接线。</p></div></div>
            <div className="roadmap-item done"><span className="roadmap-dot"><Icon name="check" /></span><div><strong>文件摄取与对象存储</strong><p>浏览器使用预签名 URL 直接上传，应用层不承载文件字节。</p></div></div>
            <div className="roadmap-item"><span className="roadmap-dot"><Icon name="clock" /></span><div><strong>解析、扫描与索引 Worker</strong><p>生产环境仍需内容安全扫描、文本抽取和检索索引流水线。</p></div></div>
          </div>
        </article>
      </section>
    </div>
  );
}
