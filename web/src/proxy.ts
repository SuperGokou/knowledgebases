import { NextRequest, NextResponse } from "next/server";

const ACCESS_COOKIE = "kb_access";
const REFRESH_COOKIE = "kb_refresh";

export function proxy(request: NextRequest): NextResponse {
  const hasSession = Boolean(
    request.cookies.get(ACCESS_COOKIE)?.value || request.cookies.get(REFRESH_COOKIE)?.value,
  );
  if (!hasSession) {
    const login = new URL("/login", request.url);
    login.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/chat/:path*", "/admin/:path*"],
};
