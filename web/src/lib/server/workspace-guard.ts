import type { NextRequest, NextResponse } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import {
  IDENTITY_COOKIE,
  requestTokens,
  setIdentityCookie,
  setSessionCookies,
  type TokenPair,
} from "@/lib/server/session";
import { refreshSessionOnce } from "@/lib/server/session-refresh";
import type { AuthMe } from "@/lib/types";

export const WORKSPACE_AUTHORIZED_HEADER = "x-kb-workspace-authorized";
export const WORKSPACE_EMAIL_HEADER = "x-kb-workspace-email";
const WORKSPACE_AUTHORIZED_VALUE = "v1";

type AuthenticatedWorkspaceSession = {
  kind: "authenticated";
  me: AuthMe;
  replacement?: TokenPair;
};

type UnauthenticatedWorkspaceSession = {
  kind: "unauthenticated";
};

type UnavailableWorkspaceSession = {
  kind: "unavailable";
  status: 502 | 503;
  reason?: "refresh_in_progress";
  replacement?: TokenPair;
};

export type WorkspaceSessionResolution =
  | AuthenticatedWorkspaceSession
  | UnauthenticatedWorkspaceSession
  | UnavailableWorkspaceSession;

type MeResolution =
  | { kind: "authenticated"; me: AuthMe }
  | { kind: "unauthenticated" }
  | { kind: "unavailable"; status: 502 | 503 };

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
  const validStatus = value.status === "active"
    || value.status === "disabled"
    || value.status === "locked";
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

async function resolveMe(accessToken: string): Promise<MeResolution> {
  const response = await safeBackendFetch(backendUrl("/api/v1/auth/me"), {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (response.status === 401) return { kind: "unauthenticated" };
  if (!response.ok) {
    return { kind: "unavailable", status: response.status >= 500 ? 503 : 502 };
  }

  const value = await response.json().catch(() => null);
  if (!isAuthMe(value)) return { kind: "unavailable", status: 502 };
  if (value.status !== "active") return { kind: "unauthenticated" };
  return { kind: "authenticated", me: value };
}

async function revokeRefreshToken(refreshToken: string): Promise<void> {
  try {
    await safeBackendFetch(backendUrl("/api/v1/auth/logout"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  } catch {
    // Best effort: this token has never been written to the browser by this guard.
  }
}

async function refreshSession(
  request: NextRequest,
  refreshToken: string,
): Promise<WorkspaceSessionResolution> {
  const outcome = await refreshSessionOnce(refreshToken, request);
  if (outcome.kind === "expired") return { kind: "unauthenticated" };
  if (outcome.kind === "unavailable") {
    if (outcome.reason === "refresh_in_progress") {
      return { kind: "unavailable", status: 503, reason: "refresh_in_progress" };
    }
    return { kind: "unavailable", status: outcome.status >= 500 ? 503 : 502 };
  }
  if (!isTokenPair(outcome.pair)) return { kind: "unavailable", status: 502 };
  const value = outcome.pair;

  const me = await resolveMe(value.access_token);
  if (me.kind === "authenticated") {
    return { kind: "authenticated", me: me.me, replacement: value };
  }
  if (me.kind === "unavailable") {
    return { ...me, replacement: value };
  }

  await revokeRefreshToken(value.refresh_token);
  return { kind: "unauthenticated" };
}

export async function resolveWorkspaceSession(
  request: NextRequest,
): Promise<WorkspaceSessionResolution> {
  try {
    const tokens = requestTokens(request);
    if (tokens.fenced || (!tokens.access && !tokens.refresh)) {
      return { kind: "unauthenticated" };
    }

    if (tokens.access) {
      const me = await resolveMe(tokens.access);
      if (me.kind === "authenticated" || me.kind === "unavailable") return me;
      if (!tokens.refresh) return { kind: "unauthenticated" };
    }

    if (!tokens.refresh) return { kind: "unauthenticated" };
    return await refreshSession(request, tokens.refresh);
  } catch {
    // Invalid server configuration and unexpected transport failures must never
    // fall through to rendering a protected Server Component tree.
    return { kind: "unavailable", status: 503 };
  }
}

export function authorizedWorkspaceHeaders(request: NextRequest, me: AuthMe): Headers {
  const headers = new Headers(request.headers);
  headers.delete(WORKSPACE_AUTHORIZED_HEADER);
  headers.delete(WORKSPACE_EMAIL_HEADER);
  headers.set(WORKSPACE_AUTHORIZED_HEADER, WORKSPACE_AUTHORIZED_VALUE);
  headers.set(WORKSPACE_EMAIL_HEADER, encodeURIComponent(me.email));
  return headers;
}

export function isAuthorizedWorkspaceRequest(headers: Headers): boolean {
  return headers.get(WORKSPACE_AUTHORIZED_HEADER) === WORKSPACE_AUTHORIZED_VALUE;
}

export function workspaceEmail(headers: Headers): string | undefined {
  const encoded = headers.get(WORKSPACE_EMAIL_HEADER);
  if (!encoded) return undefined;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
}

export function persistWorkspaceSession(
  response: NextResponse,
  request: NextRequest,
  session: AuthenticatedWorkspaceSession,
): void {
  if (session.replacement) {
    setSessionCookies(response, session.replacement, session.me.email);
  } else if (request.cookies.get(IDENTITY_COOKIE)?.value !== session.me.email) {
    setIdentityCookie(response, session.me.email);
  }
}

export function persistReplacementSession(
  response: NextResponse,
  session: UnavailableWorkspaceSession,
): void {
  if (session.replacement) {
    setSessionCookies(response, session.replacement);
  }
}
