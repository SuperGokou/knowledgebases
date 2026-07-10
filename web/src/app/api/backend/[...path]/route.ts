import { createHash } from "node:crypto";

import { NextRequest, NextResponse } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { isAllowedBackendPath } from "@/lib/server/backend-path";
import { readBoundedBody, RequestBodyTooLargeError } from "@/lib/server/bounded-body";
import { BffSigningConfigurationError, signedClientIpHeaders } from "@/lib/server/client-ip";
import {
  hasSameOrigin,
  requestTokens,
  setSessionCookies,
  type TokenPair,
} from "@/lib/server/session";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const MAX_CONTROL_PLANE_BODY_BYTES = 1024 * 1024;
type RefreshOutcome =
  | { kind: "refreshed"; pair: TokenPair }
  | { kind: "expired" }
  | { kind: "unavailable"; status: number };
const refreshFlights = new Map<string, Promise<RefreshOutcome>>();

async function refreshSession(refreshToken: string, request: NextRequest): Promise<RefreshOutcome> {
  const response = await safeBackendFetch(backendUrl("/api/v1/auth/refresh"), {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", ...signedClientIpHeaders(request) },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (response.ok) return { kind: "refreshed", pair: (await response.json()) as TokenPair };
  if (response.status === 401) return { kind: "expired" };
  return { kind: "unavailable", status: response.status };
}

function refreshSessionOnce(refreshToken: string, request: NextRequest): Promise<RefreshOutcome> {
  const fingerprint = createHash("sha256").update(refreshToken).digest("hex");
  const current = refreshFlights.get(fingerprint);
  if (current) return current;
  const pending = refreshSession(refreshToken, request).finally(() => {
    if (refreshFlights.get(fingerprint) === pending) refreshFlights.delete(fingerprint);
  });
  refreshFlights.set(fingerprint, pending);
  return pending;
}

async function handler(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
): Promise<NextResponse> {
  const { path } = await context.params;
  if (!isAllowedBackendPath(path, request.method, request.nextUrl.pathname)) {
    return NextResponse.json(
      { error: { code: "route_not_allowed", message: "该后台路径未开放给 Web BFF。" } },
      { status: 404 },
    );
  }
  if (MUTATING.has(request.method) && !hasSameOrigin(request)) {
    return NextResponse.json(
      { error: { code: "invalid_origin", message: "请求来源无效。" } },
      { status: 403 },
    );
  }

  const tokens = requestTokens(request);
  if (tokens.fenced) {
    return NextResponse.json(
      {
        error: {
          code: "session_expired",
          message: "登录状态已失效，请重新登录。",
          details: { session_marker: tokens.marker ?? null },
        },
      },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }
  if (!tokens.access && !tokens.refresh) {
    return NextResponse.json(
      { error: { code: "not_authenticated", message: "请先登录。" } },
      { status: 401 },
    );
  }

  let body: ArrayBuffer | undefined;
  try {
    body = await readBoundedBody(request, MAX_CONTROL_PLANE_BODY_BYTES);
  } catch (error) {
    if (!(error instanceof RequestBodyTooLargeError)) throw error;
    return NextResponse.json(
      {
        error: {
          code: "request_body_too_large",
          message: "控制面请求不得超过 1 MiB；文件内容请使用对象存储直传。",
        },
      },
      { status: 413 },
    );
  }
  const forward = async (access: string | undefined): Promise<Response> => {
    const headers = new Headers({ Accept: "application/json" });
    const contentType = request.headers.get("content-type");
    const idempotencyKey = request.headers.get("idempotency-key");
    if (contentType) headers.set("Content-Type", contentType);
    if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);
    if (access) headers.set("Authorization", `Bearer ${access}`);
    const target = backendUrl(`/${path.join("/")}`, request.nextUrl.search);
    if (target.pathname !== `/${path.join("/")}`) {
      return new Response(JSON.stringify({ error: { code: "route_not_allowed", message: "后台路径不是规范路径。" } }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }
    return safeBackendFetch(target, {
      method: request.method,
      headers,
      body,
    });
  };

  let backend = await forward(tokens.access);
  let replacement: TokenPair | null = null;
  let refreshExpired = false;
  if (backend.status === 401 && tokens.refresh) {
    try {
      const outcome = await refreshSessionOnce(tokens.refresh, request);
      if (outcome.kind === "refreshed") replacement = outcome.pair;
      else if (outcome.kind === "expired") refreshExpired = true;
      else {
        return NextResponse.json(
          { error: { code: "session_refresh_unavailable", message: "会话刷新服务暂时不可用，请稍后重试。" } },
          { status: outcome.status >= 500 ? 503 : outcome.status },
        );
      }
    } catch (error) {
      if (!(error instanceof BffSigningConfigurationError)) throw error;
      return NextResponse.json(
        { error: { code: "bff_signing_misconfigured", message: "会话刷新服务缺少有效的 BFF 签名密钥。" } },
        { status: 503 },
      );
    }
    if (replacement) backend = await forward(replacement.access_token);
  }

  if (refreshExpired && !replacement) {
    const response = NextResponse.json(
      {
        error: {
          code: "session_expired",
          message: "登录状态已失效，请重新登录。",
          details: { session_marker: tokens.marker ?? null },
        },
      },
      { status: 401 },
    );
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  const responseBody = backend.status === 204 ? null : await backend.arrayBuffer();
  const response = new NextResponse(responseBody, { status: backend.status });
  for (const name of [
    "content-type",
    "x-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
  ]) {
    const value = backend.headers.get(name);
    if (value) response.headers.set(name, value);
  }
  response.headers.set("Cache-Control", "no-store");

  if (replacement) setSessionCookies(response, replacement, tokens.email);
  return response;
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
