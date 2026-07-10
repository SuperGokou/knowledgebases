import { createHash } from "node:crypto";

import type { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";

import { isSameOriginRequest } from "@/lib/server/same-origin";

export const ACCESS_COOKIE = "kb_access";
export const REFRESH_COOKIE = "kb_refresh";
export const IDENTITY_COOKIE = "kb_identity";
export const SESSION_MARKER_COOKIE = "kb_session_marker";
export const SESSION_FENCE_COOKIE = "kb_session_fence";

export type TokenPair = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
};

const secure = process.env.NODE_ENV === "production";
const refreshMaxAge = Number(process.env.SESSION_REFRESH_MAX_AGE_SECONDS ?? 604_800);

export function sessionMarker(refreshToken: string): string {
  return createHash("sha256").update(refreshToken).digest("hex");
}

export function setSessionCookies(
  response: NextResponse,
  pair: TokenPair,
  email?: string,
  options: { resetFence?: boolean } = {},
): void {
  response.cookies.set(ACCESS_COOKIE, pair.access_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(60, pair.expires_in),
  });
  response.cookies.set(REFRESH_COOKIE, pair.refresh_token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: Number.isFinite(refreshMaxAge) ? refreshMaxAge : 604_800,
  });
  response.cookies.set(SESSION_MARKER_COOKIE, sessionMarker(pair.refresh_token), {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: Number.isFinite(refreshMaxAge) ? refreshMaxAge : 604_800,
  });
  if (email) {
    response.cookies.set(IDENTITY_COOKIE, email, {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: Number.isFinite(refreshMaxAge) ? refreshMaxAge : 604_800,
    });
  }
  if (options.resetFence) {
    response.cookies.set(SESSION_FENCE_COOKIE, "", {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });
  }
}

export function clearSessionCookies(response: NextResponse): void {
  for (const name of [ACCESS_COOKIE, REFRESH_COOKIE, IDENTITY_COOKIE, SESSION_MARKER_COOKIE]) {
    response.cookies.set(name, "", {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });
  }
  response.cookies.set(SESSION_FENCE_COOKIE, "1", {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: Number.isFinite(refreshMaxAge) ? refreshMaxAge : 604_800,
  });
}

export function requestTokens(request: NextRequest): {
  access?: string;
  refresh?: string;
  email?: string;
  marker?: string;
  fenced: boolean;
} {
  return {
    access: request.cookies.get(ACCESS_COOKIE)?.value,
    refresh: request.cookies.get(REFRESH_COOKIE)?.value,
    email: request.cookies.get(IDENTITY_COOKIE)?.value,
    marker: request.cookies.get(SESSION_MARKER_COOKIE)?.value,
    fenced: request.cookies.get(SESSION_FENCE_COOKIE)?.value === "1",
  };
}

export async function sessionView(): Promise<{ authenticated: boolean; email?: string }> {
  const store = await cookies();
  const authenticated = Boolean(
    store.get(ACCESS_COOKIE)?.value || store.get(REFRESH_COOKIE)?.value,
  );
  const email = store.get(IDENTITY_COOKIE)?.value;
  return { authenticated, ...(email ? { email } : {}) };
}

export function hasSameOrigin(request: NextRequest): boolean {
  return isSameOriginRequest(request.headers, {
    production: process.env.NODE_ENV === "production",
    requestProtocol: request.nextUrl.protocol,
  });
}
