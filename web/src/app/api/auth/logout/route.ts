import { NextRequest, NextResponse } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { readBoundedBody, RequestBodyTooLargeError } from "@/lib/server/bounded-body";
import { signedClientIpHeaders } from "@/lib/server/client-ip";
import {
  clearSessionCookies,
  hasSameOrigin,
  requestTokens,
  SESSION_MARKER_COOKIE,
} from "@/lib/server/session";

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!hasSameOrigin(request)) {
    return NextResponse.json(
      { error: { code: "invalid_origin", message: "请求来源无效。" } },
      { status: 403 },
    );
  }
  let rawPayload: ArrayBuffer | undefined;
  try {
    rawPayload = await readBoundedBody(request, 4096);
  } catch (error) {
    if (!(error instanceof RequestBodyTooLargeError)) throw error;
    return NextResponse.json(
      { error: { code: "request_body_too_large", message: "退出请求格式无效。" } },
      { status: 413 },
    );
  }
  const payload = (() => {
    try {
      const text = new TextDecoder().decode(rawPayload ?? new ArrayBuffer(0));
      return (text ? JSON.parse(text) : null) as { session_marker?: unknown } | null;
    } catch {
      return null;
    }
  })();
  const conditional = Boolean(payload && Object.hasOwn(payload, "session_marker"));
  const expectedMarker = typeof payload?.session_marker === "string" ? payload.session_marker : null;
  const currentMarker = request.cookies.get(SESSION_MARKER_COOKIE)?.value ?? null;
  if (conditional && expectedMarker !== currentMarker) {
    const response = NextResponse.json({ authenticated: true, stale: true });
    response.headers.set("Cache-Control", "no-store");
    return response;
  }
  const { refresh } = requestTokens(request);
  let revocationConfirmed = !refresh;
  if (refresh) {
    try {
      const backend = await safeBackendFetch(backendUrl("/api/v1/auth/logout"), {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          ...signedClientIpHeaders(request),
        },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      revocationConfirmed = backend.status === 204;
    } catch {
      revocationConfirmed = false;
    }
  }
  const response = NextResponse.json(
    { authenticated: false, revocation_confirmed: revocationConfirmed },
    { status: revocationConfirmed ? 200 : 202 },
  );
  clearSessionCookies(response);
  response.headers.set("Cache-Control", "no-store");
  return response;
}
