import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/access-routing", async () => import("../src/lib/access-routing"));
vi.mock("@/lib/server/backend", async () => import("../src/lib/server/backend"));
vi.mock("@/lib/server/same-origin", async () => import("../src/lib/server/same-origin"));
vi.mock("@/lib/server/session", async () => import("../src/lib/server/session"));
vi.mock("@/lib/server/session-refresh", async () => (
  import("../src/lib/server/session-refresh")
));
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

import { proxy } from "../src/proxy";

const APP_ORIGIN = "https://knowledge.example";
const ORIGINAL_FASTAPI_URL = process.env.FASTAPI_URL;
const REPLACEMENT_PAIR = {
  access_token: "replacement-access-token",
  refresh_token: "replacement-refresh-token",
  token_type: "bearer",
  expires_in: 900,
};

function workspaceRequest(
  path: string,
  cookies: Record<string, string>,
  extraHeaders: Record<string, string> = {},
): NextRequest {
  const cookie = Object.entries(cookies)
    .map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
    .join("; ");
  return new NextRequest(`${APP_ORIGIN}${path}`, {
    headers: { Cookie: cookie, ...extraHeaders },
  });
}

function authMe(permissionCodes: string[] = []): Record<string, unknown> {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "member@example.com",
    display_name: "Member",
    status: "active",
    is_superuser: false,
    permission_codes: permissionCodes,
    role_ids: ["00000000-0000-4000-8000-000000000002"],
    limits: { requests_per_minute: 60 },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function setCookieHeader(response: Response): string {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  return headers.getSetCookie?.().join("\n") ?? response.headers.get("set-cookie") ?? "";
}

describe("authoritative workspace proxy guard", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    delete process.env.FASTAPI_URL;
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    if (ORIGINAL_FASTAPI_URL === undefined) delete process.env.FASTAPI_URL;
    else process.env.FASTAPI_URL = ORIGINAL_FASTAPI_URL;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("authorizes before rendering and forwards only a server-created guard marker", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(authMe(["chat:query"])));

    const response = await proxy(workspaceRequest("/chat", {
      kb_access: "valid-access-token",
      kb_refresh: "valid-refresh-token",
      kb_identity: "forged@example.com",
    }, {
      "X-KB-Workspace-Authorized": "attacker-value",
      "X-KB-Workspace-Email": "attacker%40example.com",
    }));

    expect(response.status).toBe(200);
    expect(response.headers.get("x-middleware-next")).toBe("1");
    expect(response.headers.get("x-middleware-request-x-kb-workspace-authorized")).toBe("v1");
    expect(response.headers.get("x-middleware-request-x-kb-workspace-email")).toBe(
      "member%40example.com",
    );
    expect(setCookieHeader(response)).toMatch(
      /kb_identity=member%40example\.com[^\n]*HttpOnly/i,
    );
  });

  it("rejects a forged access cookie and clears it before redirecting to login", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: { code: "invalid_token" } }, 401));

    const response = await proxy(workspaceRequest("/admin/users?view=all", {
      kb_access: "forged-token",
    }, {
      "X-KB-Workspace-Authorized": "v1",
    }));

    expect(response.status).toBe(307);
    const location = new URL(response.headers.get("location")!);
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/admin/users?view=all");
    expect(response.headers.get("x-middleware-next")).toBeNull();
    expect(setCookieHeader(response)).toMatch(/kb_access=;[^\n]*Max-Age=0/i);
    expect(setCookieHeader(response)).toMatch(/kb_refresh=;[^\n]*Max-Age=0/i);
  });

  it("redirects an authenticated chat-only user before an admin page can render", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(authMe(["chat:query"])));

    const response = await proxy(workspaceRequest("/admin/users", {
      kb_access: "valid-access-token",
      kb_refresh: "valid-refresh-token",
    }));

    expect(response.status).toBe(307);
    expect(new URL(response.headers.get("location")!).pathname).toBe("/chat");
    expect(response.headers.get("x-middleware-next")).toBeNull();
  });

  it("recovers concurrent refresh followers without exposing the rotated credential pair", async () => {
    let oldMeCalls = 0;
    let refreshCalls = 0;
    let releaseRefresh: ((response: Response) => void) | undefined;
    const refreshResponse = new Promise<Response>((resolve) => {
      releaseRefresh = resolve;
    });

    fetchMock.mockImplementation(async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/v1/auth/me")) {
        const authorization = new Headers(init?.headers).get("authorization");
        if (authorization === "Bearer expired-access-token") {
          oldMeCalls += 1;
          if (oldMeCalls === 2) {
            queueMicrotask(() => releaseRefresh?.(jsonResponse(REPLACEMENT_PAIR)));
          }
          return jsonResponse({ error: { code: "invalid_token" } }, 401);
        }
        expect(authorization).toBe("Bearer replacement-access-token");
        return jsonResponse(authMe(["chat:query"]));
      }
      if (url.endsWith("/api/v1/auth/refresh")) {
        refreshCalls += 1;
        return refreshResponse;
      }
      throw new Error(`Unexpected backend request: ${url}`);
    });

    const cookies = {
      kb_access: "expired-access-token",
      kb_refresh: "shared-refresh-token",
    };
    const [first, second] = await Promise.all([
      proxy(workspaceRequest("/chat", cookies)),
      proxy(workspaceRequest("/chat", cookies)),
    ]);

    expect(oldMeCalls).toBe(2);
    expect(refreshCalls).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect([first.status, second.status].sort()).toEqual([200, 307]);
    const successful = first.status === 200 ? first : second;
    const recovering = first.status === 307 ? first : second;
    expect(successful.headers.get("x-middleware-next")).toBe("1");
    expect(setCookieHeader(successful)).toContain("kb_access=replacement-access-token");
    expect(setCookieHeader(successful)).toContain("kb_refresh=replacement-refresh-token");
    const recoveryLocation = new URL(recovering.headers.get("location")!);
    expect(recoveryLocation.pathname).toBe("/session-recovery");
    expect(recoveryLocation.searchParams.get("next")).toBe("/chat");
    expect(setCookieHeader(recovering)).toBe("");
    // Refresh persistence must never clear a newer logout fence. Only a fresh
    // successful login is allowed to reset that generation barrier.
    expect(setCookieHeader(successful)).not.toContain("kb_session_fence=;");
  });

  it("fails closed without clearing a potentially valid session when the backend is unavailable", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(
      { error: { code: "backend_unavailable" } },
      502,
    ));

    const response = await proxy(workspaceRequest("/chat", {
      kb_access: "possibly-valid-access-token",
      kb_refresh: "possibly-valid-refresh-token",
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get("x-middleware-next")).toBeNull();
    expect(setCookieHeader(response)).toBe("");
  });

  it("fails closed when the refresh endpoint returns a malformed token pair", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ error: { code: "invalid_token" } }, 401))
      .mockResolvedValueOnce(jsonResponse({ access_token: "incomplete" }));

    const response = await proxy(workspaceRequest("/chat", {
      kb_access: "expired-access-token",
      kb_refresh: "possibly-valid-refresh-token",
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get("x-middleware-next")).toBeNull();
    expect(setCookieHeader(response)).toBe("");
  });

  it("turns a synchronous backend configuration failure into a fail-closed response", async () => {
    process.env.FASTAPI_URL = "ftp://invalid.example";

    const response = await proxy(workspaceRequest("/chat", {
      kb_access: "possibly-valid-access-token",
    }));

    expect(response.status).toBe(503);
    expect(response.headers.get("x-middleware-next")).toBeNull();
    expect(setCookieHeader(response)).toBe("");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
