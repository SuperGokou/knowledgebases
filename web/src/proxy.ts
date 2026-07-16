import { NextRequest, NextResponse } from "next/server";

import { canAccessPath, defaultLandingPath } from "@/lib/access-routing";
import { clearSessionCookies } from "@/lib/server/session";
import {
  authorizedWorkspaceHeaders,
  persistReplacementSession,
  persistWorkspaceSession,
  resolveWorkspaceSession,
} from "@/lib/server/workspace-guard";

function requestedPath(request: NextRequest): string {
  return `${request.nextUrl.pathname}${request.nextUrl.search}`;
}

function redirectToLogin(request: NextRequest): NextResponse {
  const login = new URL("/login", request.url);
  login.searchParams.set("next", requestedPath(request));
  const response = NextResponse.redirect(login);
  clearSessionCookies(response);
  response.headers.set("Cache-Control", "no-store");
  return response;
}

function unavailableResponse(status: 502 | 503): NextResponse {
  return NextResponse.json(
    {
      error: {
        code: "workspace_session_unavailable",
        message: "工作区会话验证暂时不可用，请稍后重试。",
      },
    },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const session = await resolveWorkspaceSession(request);
  if (session.kind === "unauthenticated") return redirectToLogin(request);
  if (session.kind === "unavailable") {
    const response = unavailableResponse(session.status);
    await persistReplacementSession(response, request, session);
    return response;
  }

  const path = requestedPath(request);
  if (!canAccessPath(path, session.me)) {
    const landing = new URL(defaultLandingPath(session.me), request.url);
    const response = NextResponse.redirect(landing);
    await persistWorkspaceSession(response, request, session);
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  const response = NextResponse.next({
    request: { headers: authorizedWorkspaceHeaders(request, session.me) },
  });
  await persistWorkspaceSession(response, request, session);
  response.headers.set("Cache-Control", "no-store, private");
  return response;
}

export const config = {
  matcher: ["/chat/:path*", "/admin/:path*", "/access-pending"],
};
