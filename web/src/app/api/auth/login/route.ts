import { NextRequest, NextResponse } from "next/server";

import { resolveLandingPath } from "@/lib/access-routing";
import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { readBoundedBody, RequestBodyTooLargeError } from "@/lib/server/bounded-body";
import { BffSigningConfigurationError, signedClientIpHeaders } from "@/lib/server/client-ip";
import { hasSameOrigin, setSessionCookies, type TokenPair } from "@/lib/server/session";
import type { AuthMe } from "@/lib/types";

type LoginPayload = {
  email?: unknown;
  password?: unknown;
  next?: unknown;
};

const MAX_LOGIN_BODY_BYTES = 4096;
const MAX_LOGIN_EMAIL_CHARACTERS = 320;
const MAX_LOGIN_PASSWORD_CHARACTERS = 256;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isTokenPair(value: unknown): value is TokenPair {
  if (!isRecord(value)) return false;
  return (
    typeof value.access_token === "string"
    && value.access_token.length > 0
    && typeof value.refresh_token === "string"
    && value.refresh_token.length > 0
    && value.token_type === "bearer"
    && typeof value.expires_in === "number"
    && Number.isInteger(value.expires_in)
    && value.expires_in > 0
  );
}

function isAuthMe(value: unknown): value is AuthMe {
  if (!isRecord(value) || !isRecord(value.limits)) return false;
  const validStatus = value.status === "active" || value.status === "disabled" || value.status === "locked";
  const validLimits = Object.values(value.limits).every(
    (limit) => limit === null || (typeof limit === "number" && Number.isInteger(limit)),
  );
  return (
    typeof value.id === "string"
    && value.id.length > 0
    && typeof value.email === "string"
    && value.email.length > 0
    && (value.display_name === null || typeof value.display_name === "string")
    && validStatus
    && typeof value.is_superuser === "boolean"
    && isStringArray(value.permission_codes)
    && isStringArray(value.role_ids)
    && validLimits
  );
}

async function revokeRefreshToken(pair: TokenPair): Promise<void> {
  try {
    await safeBackendFetch(backendUrl("/api/v1/auth/logout"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: pair.refresh_token }),
    });
  } catch {
    // Best effort only: no session Cookie has been issued at this point.
  }
}

function loginInitializationFailure(status: 502 | 503): NextResponse {
  return NextResponse.json(
    {
      error: {
        code: "login_initialization_failed",
        message: "登录服务暂时无法完成会话初始化，请稍后重试。",
      },
    },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!hasSameOrigin(request)) {
    return NextResponse.json(
      { error: { code: "invalid_origin", message: "请求来源无效。" } },
      { status: 403, headers: { "Cache-Control": "no-store" } },
    );
  }

  let rawPayload: ArrayBuffer | undefined;
  try {
    rawPayload = await readBoundedBody(request, MAX_LOGIN_BODY_BYTES);
  } catch (error) {
    if (!(error instanceof RequestBodyTooLargeError)) throw error;
    return NextResponse.json(
      {
        error: {
          code: "request_body_too_large",
          message: "登录请求不得超过 4 KiB。",
        },
      },
      { status: 413, headers: { "Cache-Control": "no-store" } },
    );
  }
  const payload = (() => {
    try {
      const text = new TextDecoder().decode(rawPayload ?? new ArrayBuffer(0));
      return (text ? JSON.parse(text) : null) as LoginPayload | null;
    } catch {
      return null;
    }
  })();
  const email = typeof payload?.email === "string" ? payload.email.trim().toLowerCase() : "";
  const password = typeof payload?.password === "string" ? payload.password : "";
  const requestedNext = typeof payload?.next === "string" && payload.next.length <= 2_048
    ? payload.next
    : null;
  if (
    !email
    || !password
    || email.length > MAX_LOGIN_EMAIL_CHARACTERS
    || password.length > MAX_LOGIN_PASSWORD_CHARACTERS
  ) {
    return NextResponse.json(
      { error: { code: "invalid_login", message: "请输入邮箱和密码。" } },
      { status: 422, headers: { "Cache-Control": "no-store" } },
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
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
  let backend: Response;
  try {
    backend = await safeBackendFetch(backendUrl("/api/v1/auth/token"), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...signedHeaders },
      body: form,
    });
  } catch {
    return loginInitializationFailure(503);
  }
  const body = await backend.arrayBuffer();
  if (!backend.ok) {
    return new NextResponse(body, {
      status: backend.status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": backend.headers.get("content-type") ?? "application/json",
      },
    });
  }

  let pairValue: unknown;
  try {
    pairValue = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return loginInitializationFailure(502);
  }
  if (!isTokenPair(pairValue)) return loginInitializationFailure(502);
  const pair = pairValue;

  let meResponse: Response;
  try {
    meResponse = await safeBackendFetch(backendUrl("/api/v1/auth/me"), {
      method: "GET",
      headers: { Authorization: `Bearer ${pair.access_token}` },
    });
  } catch {
    await revokeRefreshToken(pair);
    return loginInitializationFailure(503);
  }
  if (!meResponse.ok) {
    await revokeRefreshToken(pair);
    return loginInitializationFailure(meResponse.status >= 500 ? 503 : 502);
  }

  const meValue = await meResponse.json().catch(() => null);
  if (!isAuthMe(meValue) || meValue.status !== "active") {
    await revokeRefreshToken(pair);
    return loginInitializationFailure(502);
  }

  const landingPath = resolveLandingPath(meValue, requestedNext, request.nextUrl.origin);
  const response = NextResponse.json({ authenticated: true, landing_path: landingPath });
  setSessionCookies(response, pair, meValue.email, { resetFence: true });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
