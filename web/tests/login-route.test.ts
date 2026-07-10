import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/access-routing", async () => import("../src/lib/access-routing"));
vi.mock("@/lib/server/backend", async () => import("../src/lib/server/backend"));
vi.mock("@/lib/server/same-origin", async () => import("../src/lib/server/same-origin"));
vi.mock("@/lib/server/session", async () => import("../src/lib/server/session"));
vi.mock("@/lib/server/client-ip", () => {
  class BffSigningConfigurationError extends Error {}
  return {
    BffSigningConfigurationError,
    signedClientIpHeaders: () => ({}),
  };
});

import { POST } from "../src/app/api/auth/login/route";

const APP_ORIGIN = "https://knowledge.example";
const ORIGINAL_FASTAPI_URL = process.env.FASTAPI_URL;
const TOKEN_PAIR = {
  access_token: "access-token-value",
  refresh_token: "refresh-token-value",
  token_type: "bearer",
  expires_in: 900,
};

type LoginBody = {
  email: string;
  password: string;
  next?: string;
  role?: string;
  is_superuser?: boolean;
};

function loginRequest(body: LoginBody): NextRequest {
  return new NextRequest(`${APP_ORIGIN}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Host: "knowledge.example",
      Origin: APP_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      "X-Forwarded-Host": "knowledge.example",
      "X-Forwarded-Proto": "https",
    },
    body: JSON.stringify(body),
  });
}

function authMe(permissionCodes: string[] = [], isSuperuser = false): Record<string, unknown> {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "member@example.com",
    display_name: "Member",
    status: "active",
    is_superuser: isSuperuser,
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

function expectNoSessionCookie(response: Response): void {
  expect(setCookieHeader(response)).toBe("");
}

describe("POST /api/auth/login", () => {
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

  it.each([
    { permissions: ["user:manage"], expectedLandingPath: "/admin" },
    { permissions: ["chat:query"], expectedLandingPath: "/chat" },
    { permissions: [], expectedLandingPath: "/access-pending" },
  ])(
    "returns only the server-derived $expectedLandingPath landing result and HttpOnly session cookies",
    async ({ permissions, expectedLandingPath }) => {
      fetchMock
        .mockResolvedValueOnce(jsonResponse(TOKEN_PAIR))
        .mockResolvedValueOnce(jsonResponse(authMe(permissions)));

      const response = await POST(loginRequest({
        email: "MEMBER@example.com ",
        password: "Correct-password-123!",
      }));

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        authenticated: true,
        landing_path: expectedLandingPath,
      });
      expect(response.headers.get("cache-control")).toBe("no-store");

      const cookies = setCookieHeader(response);
      expect(cookies).toContain("kb_access=access-token-value");
      expect(cookies).toContain("kb_refresh=refresh-token-value");
      expect(cookies).toMatch(/kb_access=[^\n]*HttpOnly/i);
      expect(cookies).toMatch(/kb_refresh=[^\n]*HttpOnly/i);
      expect(cookies).toMatch(/kb_identity=member%40example\.com[^\n]*HttpOnly/i);

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
        "http://127.0.0.1:8000/api/v1/auth/token",
      );
      const tokenRequest = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect(String(tokenRequest.body)).toBe(
        "username=member%40example.com&password=Correct-password-123%21",
      );
      expect(String(fetchMock.mock.calls[1]?.[0])).toBe(
        "http://127.0.0.1:8000/api/v1/auth/me",
      );
      const meRequest = fetchMock.mock.calls[1]?.[1] as RequestInit;
      expect(new Headers(meRequest.headers).get("authorization")).toBe(
        "Bearer access-token-value",
      );
    },
  );

  it("downgrades a chat-only account's requested admin destination", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(TOKEN_PAIR))
      .mockResolvedValueOnce(jsonResponse(authMe(["chat:query"])));

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
      next: "/admin/users",
    }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ authenticated: true, landing_path: "/chat" });
  });

  it("ignores client-supplied role and superuser claims", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(TOKEN_PAIR))
      .mockResolvedValueOnce(jsonResponse(authMe([])));

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
      next: "/admin",
      role: "system_admin",
      is_superuser: true,
    }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authenticated: true,
      landing_path: "/access-pending",
    });
    const tokenRequest = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(String(tokenRequest.body)).not.toContain("role");
    expect(String(tokenRequest.body)).not.toContain("superuser");
  });

  it("revokes the refresh token and issues no cookie when current-user resolution fails", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(TOKEN_PAIR))
      .mockResolvedValueOnce(jsonResponse({ error: { code: "backend_unavailable" } }, 503))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
    }));

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: {
        code: "login_initialization_failed",
        message: expect.any(String),
      },
    });
    expectNoSessionCookie(response);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(String(fetchMock.mock.calls[2]?.[0])).toBe(
      "http://127.0.0.1:8000/api/v1/auth/logout",
    );
    const logoutRequest = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(JSON.parse(String(logoutRequest.body))).toEqual({
      refresh_token: "refresh-token-value",
    });
  });

  it("fails closed without issuing a cookie for a malformed token response", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({
      access_token: "access-token-value",
      token_type: "bearer",
      expires_in: 900,
    }));

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
    }));

    expect(response.status).toBe(502);
    expect((await response.json()).error.code).toBe("login_initialization_failed");
    expectNoSessionCookie(response);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed, revokes the refresh token, and issues no cookie for malformed me data", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(TOKEN_PAIR))
      .mockResolvedValueOnce(jsonResponse({
        email: "member@example.com",
        status: "active",
        is_superuser: true,
        permission_codes: ["*"],
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
      next: "/admin",
    }));

    expect(response.status).toBe(502);
    expect((await response.json()).error.code).toBe("login_initialization_failed");
    expectNoSessionCookie(response);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(String(fetchMock.mock.calls[2]?.[0])).toBe(
      "http://127.0.0.1:8000/api/v1/auth/logout",
    );
  });

  it("returns a controlled error instead of crashing for an invalid backend URL", async () => {
    process.env.FASTAPI_URL = "ftp://invalid.example";

    const response = await POST(loginRequest({
      email: "member@example.com",
      password: "Correct-password-123!",
    }));

    expect(response.status).toBe(503);
    expect((await response.json()).error.code).toBe("login_initialization_failed");
    expectNoSessionCookie(response);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
