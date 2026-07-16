import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/access-routing", async () => import("../src/lib/access-routing"));
vi.mock("@/lib/server/backend", async () => import("../src/lib/server/backend"));
vi.mock("@/lib/server/bounded-body", async () => import("../src/lib/server/bounded-body"));
vi.mock("@/lib/server/same-origin", async () => import("../src/lib/server/same-origin"));
vi.mock("@/lib/server/session", async () => import("../src/lib/server/session"));
vi.mock("@/lib/server/session-refresh", async () => import("../src/lib/server/session-refresh"));
vi.mock("@/lib/server/workspace-guard", async () => (
  import("../src/lib/server/workspace-guard")
));
vi.mock("@/lib/server/client-ip", () => {
  class BffSigningConfigurationError extends Error {}
  return {
    BffSigningConfigurationError,
    signedClientIpHeaders: () => ({}),
  };
});

import { POST as logout } from "../src/app/api/auth/logout/route";
import { proxy } from "../src/proxy";

const ORIGIN = "https://knowledge.example";
const REPLACEMENT_PAIR = {
  access_token: "replacement-access-token",
  refresh_token: "replacement-refresh-token",
  token_type: "bearer",
  expires_in: 900,
};

function setCookies(response: Response): string {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  return headers.getSetCookie?.().join("\n") ?? response.headers.get("set-cookie") ?? "";
}

function authenticatedUser(): Record<string, unknown> {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "member@example.com",
    display_name: "Member",
    status: "active",
    is_superuser: false,
    permission_codes: ["chat:query"],
    role_ids: [],
    limits: { requests_per_minute: 60 },
  };
}

describe("logout fence ordering", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let previousFastApiUrl: string | undefined;
  let previousPublicOrigin: string | undefined;

  beforeEach(() => {
    previousFastApiUrl = process.env.FASTAPI_URL;
    previousPublicOrigin = process.env.KB_PUBLIC_ORIGIN;
    delete process.env.FASTAPI_URL;
    process.env.KB_PUBLIC_ORIGIN = ORIGIN;
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    if (previousFastApiUrl === undefined) delete process.env.FASTAPI_URL;
    else process.env.FASTAPI_URL = previousFastApiUrl;
    if (previousPublicOrigin === undefined) delete process.env.KB_PUBLIC_ORIGIN;
    else process.env.KB_PUBLIC_ORIGIN = previousPublicOrigin;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("does not let a late refresh response clear a newer logout fence", async () => {
    let logoutCompleted = false;
    let replacementMeReached!: () => void;
    const reachedReplacementMe = new Promise<void>((resolve) => {
      replacementMeReached = resolve;
    });
    let releaseReplacementMe!: (response: Response) => void;
    const replacementMe = new Promise<Response>((resolve) => {
      releaseReplacementMe = resolve;
    });

    fetchMock.mockImplementation(async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = String(input);
      const authorization = new Headers(init?.headers).get("authorization");
      if (url.endsWith("/api/v1/auth/me") && authorization === "Bearer expired-access") {
        return Response.json({ error: { code: "invalid_token" } }, { status: 401 });
      }
      if (url.endsWith("/api/v1/auth/refresh")) return Response.json(REPLACEMENT_PAIR);
      if (
        url.endsWith("/api/v1/auth/me")
        && authorization === "Bearer replacement-access-token"
      ) {
        replacementMeReached();
        return replacementMe;
      }
      if (url.endsWith("/api/v1/auth/logout")) {
        logoutCompleted = true;
        return new Response(null, { status: 204 });
      }
      if (url.endsWith("/api/v1/auth/refresh/status")) {
        return new Response(null, { status: logoutCompleted ? 401 : 204 });
      }
      throw new Error(`Unexpected request ${url}`);
    });

    const workspaceRequest = new NextRequest(`${ORIGIN}/chat`, {
      headers: { Cookie: "kb_access=expired-access; kb_refresh=old-refresh" },
    });
    const lateWorkspaceResponse = proxy(workspaceRequest);
    await reachedReplacementMe;

    const logoutResponse = await logout(new NextRequest(`${ORIGIN}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: "kb_access=expired-access; kb_refresh=old-refresh",
        Origin: ORIGIN,
        Host: "knowledge.example",
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
      },
      body: "{}",
    }));
    const logoutCookies = setCookies(logoutResponse);
    expect(logoutCookies).toMatch(/kb_access=;[^\n]*Max-Age=0/i);
    expect(logoutCookies).toMatch(/kb_refresh=;[^\n]*Max-Age=0/i);
    expect(logoutCookies).toMatch(/kb_session_fence=1/i);

    releaseReplacementMe(Response.json(authenticatedUser()));
    const workspaceResponse = await lateWorkspaceResponse;
    const workspaceCookies = setCookies(workspaceResponse);
    expect(workspaceCookies).not.toContain("kb_access=replacement-access-token");
    expect(workspaceCookies).not.toContain("kb_refresh=replacement-refresh-token");
    expect(workspaceCookies).not.toMatch(/kb_session_fence=;[^\n]*Max-Age=0/i);
  });

  it("keeps the fence authoritative when logout lands after validation decides active", async () => {
    let replacementMeReached!: () => void;
    const reachedReplacementMe = new Promise<void>((resolve) => {
      replacementMeReached = resolve;
    });
    let releaseReplacementMe!: (response: Response) => void;
    const replacementMe = new Promise<Response>((resolve) => {
      releaseReplacementMe = resolve;
    });
    let validationReached!: () => void;
    const reachedValidation = new Promise<void>((resolve) => {
      validationReached = resolve;
    });
    let releaseStaleValidation!: (response: Response) => void;
    const staleValidation = new Promise<Response>((resolve) => {
      releaseStaleValidation = resolve;
    });

    fetchMock.mockImplementation(async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = String(input);
      const authorization = new Headers(init?.headers).get("authorization");
      if (url.endsWith("/api/v1/auth/me") && authorization === "Bearer expired-access") {
        return Response.json({ error: { code: "invalid_token" } }, { status: 401 });
      }
      if (url.endsWith("/api/v1/auth/refresh")) return Response.json(REPLACEMENT_PAIR);
      if (
        url.endsWith("/api/v1/auth/me")
        && authorization === "Bearer replacement-access-token"
      ) {
        replacementMeReached();
        return replacementMe;
      }
      if (url.endsWith("/api/v1/auth/refresh/status")) {
        validationReached();
        return staleValidation;
      }
      if (url.endsWith("/api/v1/auth/logout")) return new Response(null, { status: 204 });
      throw new Error(`Unexpected request ${url}`);
    });

    const workspaceRequest = new NextRequest(`${ORIGIN}/chat`, {
      headers: { Cookie: "kb_access=expired-access; kb_refresh=old-refresh" },
    });
    const lateWorkspaceResponse = proxy(workspaceRequest);
    await reachedReplacementMe;
    releaseReplacementMe(Response.json(authenticatedUser()));
    await reachedValidation;

    const logoutResponse = await logout(new NextRequest(`${ORIGIN}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: "kb_access=expired-access; kb_refresh=old-refresh",
        Origin: ORIGIN,
        Host: "knowledge.example",
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
      },
      body: "{}",
    }));
    expect(setCookies(logoutResponse)).toMatch(/kb_session_fence=1/i);

    // The backend's active decision predates logout, so physical Set-Cookie
    // suppression cannot be absolute without a response-delivery transaction.
    releaseStaleValidation(new Response(null, { status: 204 }));
    const workspaceResponse = await lateWorkspaceResponse;
    const workspaceCookies = setCookies(workspaceResponse);
    expect(workspaceCookies).toContain("kb_access=replacement-access-token");
    expect(workspaceCookies).toContain("kb_refresh=replacement-refresh-token");
    expect(workspaceCookies).not.toMatch(/kb_session_fence=;[^\n]*Max-Age=0/i);

    // Browser last-writer ordering may physically restore the credentials, but
    // the monotonic fence survives and prevents any subsequent authorization.
    const fencedFollowUp = await proxy(new NextRequest(`${ORIGIN}/chat`, {
      headers: {
        Cookie: [
          "kb_access=replacement-access-token",
          "kb_refresh=replacement-refresh-token",
          "kb_session_fence=1",
        ].join("; "),
      },
    }));
    expect(fencedFollowUp.status).toBe(307);
    expect(new URL(fencedFollowUp.headers.get("location")!).pathname).toBe("/login");
    const followUpCookies = setCookies(fencedFollowUp);
    expect(followUpCookies).toMatch(/kb_access=;[^\n]*Max-Age=0/i);
    expect(followUpCookies).toMatch(/kb_refresh=;[^\n]*Max-Age=0/i);
    expect(followUpCookies).toMatch(/kb_session_fence=1/i);
  });
});
