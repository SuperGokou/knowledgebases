import { NextRequest, NextResponse } from "next/server";

import {
  BackendConfigurationError,
  backendUrl,
  safeBackendFetch,
} from "@/lib/server/backend";
import { isAllowedBackendPath } from "@/lib/server/backend-path";
import { readBoundedBody, RequestBodyTooLargeError } from "@/lib/server/bounded-body";
import {
  BackendResponseTooLargeError,
  readBoundedResponseBody,
} from "@/lib/server/bounded-response";
import {
  BffSigningConfigurationError,
  signedClientIpHeaders,
} from "@/lib/server/client-ip";
import { isValidIdempotencyKey } from "@/lib/chat-idempotency";
import { refreshSessionOnce } from "@/lib/server/session-refresh";
import {
  hasSameOrigin,
  requestTokens,
  setSessionCookies,
  type TokenPair,
} from "@/lib/server/session";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const MAX_CONTROL_PLANE_BODY_BYTES = 1024 * 1024;
const MAX_BACKEND_RESPONSE_BYTES = 16 * 1024 * 1024;

async function handleBackendRequest(
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

  const idempotencyKey = request.headers.get("idempotency-key");
  if (idempotencyKey !== null && !isValidIdempotencyKey(idempotencyKey)) {
    return NextResponse.json(
      {
        error: {
          code: "invalid_idempotency_key",
          message: "幂等键格式无效。",
        },
      },
      { status: 400, headers: { "Cache-Control": "no-store" } },
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
    if (contentType) headers.set("Content-Type", contentType);
    if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);
    if (access) headers.set("Authorization", `Bearer ${access}`);
    for (const [name, value] of Object.entries(signedClientIpHeaders(request))) {
      headers.set(name, value);
    }
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
      signal: request.signal,
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

  let responseBody: ArrayBuffer | null;
  try {
    responseBody = backend.status === 204
      ? null
      : await readBoundedResponseBody(backend, MAX_BACKEND_RESPONSE_BYTES);
  } catch (error) {
    if (!(error instanceof BackendResponseTooLargeError)) throw error;
    const response = NextResponse.json(
      {
        error: {
          code: "backend_response_too_large",
          message: "后台响应超过安全大小限制，请缩小查询范围后重试。",
        },
      },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
    if (replacement) setSessionCookies(response, replacement, tokens.email);
    return response;
  }
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

async function handler(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
): Promise<NextResponse> {
  try {
    return await handleBackendRequest(request, context);
  } catch (error) {
    const diagnostic = {
      method: request.method,
      request_path: request.nextUrl.pathname,
      error_name: error instanceof Error ? error.name : "UnknownError",
    };
    if (error instanceof BackendConfigurationError) {
      console.error("[bff_configuration]", {
        event: "bff_backend_configuration_error",
        ...diagnostic,
      });
      return NextResponse.json(
        {
          error: {
            code: "backend_configuration_error",
            message: "后台服务配置暂不可用，请联系系统管理员。",
          },
        },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (error instanceof BffSigningConfigurationError) {
      console.error("[bff_configuration]", {
        event: "bff_signing_configuration_error",
        ...diagnostic,
      });
      return NextResponse.json(
        {
          error: {
            code: "bff_signing_misconfigured",
            message: "请求签名服务配置暂不可用，请联系系统管理员。",
          },
        },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }
    throw error;
  }
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
