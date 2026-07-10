import { NextRequest, NextResponse } from "next/server";

import { clearSessionCookies, hasSameOrigin, SESSION_MARKER_COOKIE } from "@/lib/server/session";

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!hasSameOrigin(request)) {
    return NextResponse.json(
      { error: { code: "invalid_origin", message: "请求来源无效。" } },
      { status: 403 },
    );
  }
  const payload = (await request.json().catch(() => null)) as { session_marker?: unknown } | null;
  const conditional = Boolean(payload && Object.hasOwn(payload, "session_marker"));
  const expectedMarker = typeof payload?.session_marker === "string" ? payload.session_marker : null;
  const currentMarker = request.cookies.get(SESSION_MARKER_COOKIE)?.value ?? null;
  if (conditional && expectedMarker !== currentMarker) {
    const response = NextResponse.json({ authenticated: true, stale: true });
    response.headers.set("Cache-Control", "no-store");
    return response;
  }
  const response = NextResponse.json({ authenticated: false });
  clearSessionCookies(response);
  response.headers.set("Cache-Control", "no-store");
  return response;
}
