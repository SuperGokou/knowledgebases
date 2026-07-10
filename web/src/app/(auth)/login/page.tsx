import { Suspense } from "react";
import { redirect } from "next/navigation";

import { BrandIdentity } from "@/components/brand-identity";
import { Icon } from "@/components/icon";
import { LoginForm } from "@/components/login-form";
import { sessionView } from "@/lib/server/session";

export const metadata = { title: "登录" };

export default async function LoginPage() {
  const session = await sessionView();
  if (session.authenticated) redirect("/");
  return (
    <main className="login-page">
      <section className="login-story">
        <div className="brand light"><BrandIdentity variant="login" priority /></div>
        <div className="story-copy">
          <p className="eyebrow light-text">KNOWLEDGE, WITH CONTROL.</p>
          <h2>让组织知识可发现，<br />更让每一次访问可控。</h2>
          <p>统一管理文档、账号、角色和访问等级，为团队提供可信的知识入口。</p>
        </div>
        <div className="story-points">
          <span><Icon name="database" /><b>10 TB+</b><small>对象存储架构</small></span>
          <span><Icon name="shield" /><b>动态 RBAC</b><small>细粒度权限</small></span>
          <span><Icon name="lock" /><b>零令牌暴露</b><small>HttpOnly 会话</small></span>
        </div>
        <p className="story-foot">江苏和熠光显有限公司 · Enterprise knowledge infrastructure · v0.1</p>
      </section>
      <section className="login-panel">
        <Suspense fallback={<div className="login-form"><span className="skeleton wide" /></div>}>
          <LoginForm />
        </Suspense>
      </section>
    </main>
  );
}
