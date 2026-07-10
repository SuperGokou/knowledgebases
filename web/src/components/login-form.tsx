"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Icon } from "@/components/icon";
import { safeNextPath } from "@/lib/safe-next-path";
import type { ApiProblem } from "@/lib/types";

type LoginResponse = {
  authenticated: true;
  landing_path: string;
};

export function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, next: search.get("next") }),
      });
      const result = (await response.json().catch(() => null)) as (ApiProblem & Partial<LoginResponse>) | null;
      if (!response.ok) {
        throw new Error(result?.error?.message ?? "登录失败，请检查邮箱和密码。");
      }
      if (!result?.authenticated || typeof result.landing_path !== "string") {
        throw new Error("登录服务返回了无效响应，请稍后再试。");
      }
      router.replace(safeNextPath(result.landing_path, window.location.origin));
      router.refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "登录失败，请稍后再试。");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="login-form" onSubmit={submit}>
      <div className="form-heading">
        <p className="eyebrow">江苏和熠光显有限公司</p>
        <h1>登录知识工作台</h1>
        <p>使用企业账号继续；系统会依据角色自动进入问答工作台或管理后台。</p>
      </div>
      {error ? <div className="inline-error" role="alert"><Icon name="warning" />{error}</div> : null}
      <label>
        <span>工作邮箱</span>
        <input
          type="email"
          name="email"
          autoComplete="username"
          placeholder="name@company.com"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
      </label>
      <label>
        <span>密码</span>
        <input
          type="password"
          name="password"
          autoComplete="current-password"
          placeholder="至少 12 位"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
      </label>
      <button className="button primary login-submit" type="submit" disabled={pending}>
        {pending ? <span className="spinner" /> : <Icon name="arrow" />}
        {pending ? "正在验证…" : "安全登录"}
      </button>
      <p className="form-note"><Icon name="shield" /> 无需选择入口 · 服务端 RBAC 会持续校验权限</p>
    </form>
  );
}
