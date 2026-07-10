import { NextRequest, NextResponse } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { BffSigningConfigurationError, signedClientIpHeaders } from "@/lib/server/client-ip";
import { hasSameOrigin, setSessionCookies, type TokenPair } from "@/lib/server/session";

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!hasSameOrigin(request)) {
    return NextResponse.json(
      { error: { code: "invalid_origin", message: "请求来源无效。" } },
      { status: 403 },
    );
  }

  const payload = (await request.json().catch(() => null)) as
    | { email?: unknown; password?: unknown }
    | null;
  const email = typeof payload?.email === "string" ? payload.email.trim().toLowerCase() : "";
  const password = typeof payload?.password === "string" ? payload.password : "";
  if (!email || !password) {
    return NextResponse.json(
      { error: { code: "invalid_login", message: "请输入邮箱和密码。" } },
      { status: 422 },
    );
  }

  const form = new URLSearchParams({ username: email, password });
  let signedHeaders: Record<string, string>;
  try {
    signedHeaders = signedClientIpHeaders(request);
  } catch (error) {
    if (!(error instanceof BffSigningConfigurationError)) throw error;
    return NextResponse.json(
      { error: { code: "bff_signing_misconfigured", message: "登录服务缺少有效的 BFF 签名密钥。" } },
      { status: 503 },
    );
  }
  const backend = await safeBackendFetch(backendUrl("/api/v1/auth/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...signedHeaders },
    body: form,
  });
  const body = await backend.arrayBuffer();
  if (!backend.ok) {
    return new NextResponse(body, {
      status: backend.status,
      headers: { "Content-Type": backend.headers.get("content-type") ?? "application/json" },
    });
  }

  const pair = JSON.parse(new TextDecoder().decode(body)) as TokenPair;
  const response = NextResponse.json({ authenticated: true, email });
  setSessionCookies(response, pair, email, { resetFence: true });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
