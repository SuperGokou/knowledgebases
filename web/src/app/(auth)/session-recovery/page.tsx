"use client";

import { useCallback, useEffect, useState } from "react";

import { BrandIdentity } from "@/components/brand-identity";

const RETRY_DELAY_MS = 900;

function recoveryTarget(): string {
  const candidate = new URLSearchParams(window.location.search).get("next") ?? "/";
  return candidate.startsWith("/") && !candidate.startsWith("//")
    ? candidate
    : "/";
}

export default function SessionRecoveryPage() {
  const [retrying, setRetrying] = useState(false);
  const retry = useCallback(() => {
    if (retrying) return;
    setRetrying(true);
    window.location.replace(recoveryTarget());
  }, [retrying]);

  useEffect(() => {
    const timer = window.setTimeout(retry, RETRY_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [retry]);

  return (
    <main className="login-panel" style={{ minHeight: "100vh" }}>
      <section className="login-form" aria-live="polite" aria-busy="true">
        <BrandIdentity variant="login" priority />
        <p className="eyebrow">SECURE SESSION</p>
        <h1>正在恢复安全会话</h1>
        <p className="muted">
          检测到同一页面正在并发更新登录凭据，系统会自动完成验证并返回原页面。
        </p>
        <button
          className="button primary login-submit"
          type="button"
          onClick={retry}
          disabled={retrying}
        >
          {retrying ? "正在返回…" : "立即返回"}
        </button>
      </section>
    </main>
  );
}
