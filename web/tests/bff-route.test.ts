import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/server/backend", async () => import("../src/lib/server/backend"));
vi.mock("@/lib/server/backend-path", async () => import("../src/lib/server/backend-path"));
vi.mock("@/lib/server/bounded-body", async () => import("../src/lib/server/bounded-body"));
vi.mock("@/lib/server/bounded-response", async () => import("../src/lib/server/bounded-response"));
vi.mock("@/lib/server/client-ip-signing", async () => import("../src/lib/server/client-ip-signing"));
vi.mock("@/lib/server/client-ip", async () => import("../src/lib/server/client-ip"));
vi.mock("@/lib/server/same-origin", async () => import("../src/lib/server/same-origin"));
vi.mock("@/lib/server/session", async () => import("../src/lib/server/session"));
vi.mock("@/lib/server/session-refresh", async () => import("../src/lib/server/session-refresh"));
vi.mock("@/lib/chat-idempotency", async () => import("../src/lib/chat-idempotency"));

import { GET, POST } from "../src/app/api/backend/[...path]/route";

const ORIGINAL_FASTAPI_URL = process.env.FASTAPI_URL;
const ORIGINAL_BFF_SECRET = process.env.FASTAPI_BFF_SHARED_SECRET;
const BFF_SECRET = "0123456789abcdef0123456789abcdef"; // gitleaks:allow -- deterministic HMAC test fixture
const CONTEXT = {
  params: Promise.resolve({ path: ["api", "v1", "files"] }),
};
const CHAT_CONTEXT = {
  params: Promise.resolve({ path: ["api", "v1", "chat", "query"] }),
};

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function backendRequest(options: {
  signal?: AbortSignal;
  clientIp?: string;
  idempotencyKey?: string;
  refresh?: boolean;
  method?: "GET" | "POST";
} = {}): NextRequest {
  const method = options.method ?? "GET";
  const path = method === "POST" ? "chat/query" : "files";
  return new NextRequest(`https://knowledge.example/api/backend/api/v1/${path}`, {
    method,
    headers: {
      Cookie: `kb_access=access-token${options.refresh ? "; kb_refresh=refresh-token" : ""}`,
      ...(method === "POST" ? {
        "Content-Type": "application/json",
        Origin: "https://knowledge.example",
      } : {}),
      ...(options.idempotencyKey ? { "Idempotency-Key": options.idempotencyKey } : {}),
      ...(options.clientIp ? { "X-Vercel-Forwarded-For": options.clientIp } : {}),
    },
    body: method === "POST"
      ? JSON.stringify({ knowledge_base_id: "00000000-0000-4000-8000-000000000001", message: "hello" })
      : undefined,
    signal: options.signal,
  });
}

function rejectWhenAborted(): ReturnType<typeof vi.fn> {
  return vi.fn((_url: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal;
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
  }));
}

beforeEach(() => {
  process.env.FASTAPI_URL = "https://api.example.test";
  process.env.FASTAPI_BFF_SHARED_SECRET = BFF_SECRET;
});

afterEach(() => {
  restoreEnvironment("FASTAPI_URL", ORIGINAL_FASTAPI_URL);
  restoreEnvironment("FASTAPI_BFF_SHARED_SECRET", ORIGINAL_BFF_SECRET);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("catch-all backend BFF", () => {
  it("rejects an oversized backend response before buffering it", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", {
      status: 200,
      headers: { "Content-Length": String(16 * 1024 * 1024 + 1) },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(backendRequest(), CONTEXT);

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect((await response.json()).error.code).toBe("backend_response_too_large");
  });

  it("returns a controlled 503 without exposing an invalid backend URL", async () => {
    process.env.FASTAPI_URL = "ftp://configuration-secret.example";
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(backendRequest(), CONTEXT);
    const payload = await response.json();

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(payload.error.code).toBe("backend_configuration_error");
    expect(JSON.stringify(payload)).not.toContain("configuration-secret");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith("[bff_configuration]", expect.objectContaining({
      event: "bff_backend_configuration_error",
      request_path: "/api/backend/api/v1/files",
    }));
  });

  it("adds a signed canonical client IP to protected backend requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(Response.json([]));
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(backendRequest({ clientIp: "203.0.113.42" }), CONTEXT);

    expect(response.status).toBe(200);
    const forwardedHeaders = new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers);
    expect(forwardedHeaders.get("authorization")).toBe("Bearer access-token");
    expect(forwardedHeaders.get("x-kb-client-ip")).toBe("203.0.113.42");
    expect(forwardedHeaders.get("x-kb-client-timestamp")).toMatch(/^\d{10}$/);
    expect(forwardedHeaders.get("x-kb-client-signature")).toMatch(/^[a-f0-9]{64}$/);
  });

  it("returns a controlled 503 when production request signing is misconfigured", async () => {
    vi.stubEnv("NODE_ENV", "production");
    process.env.FASTAPI_BFF_SHARED_SECRET = "too-short"; // pragma: allowlist secret
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(backendRequest({ clientIp: "203.0.113.42" }), CONTEXT);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect((await response.json()).error.code).toBe("bff_signing_misconfigured");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith("[bff_configuration]", expect.objectContaining({
      event: "bff_signing_configuration_error",
    }));
  });

  it("propagates caller cancellation to FastAPI without logging a network error", async () => {
    const fetchMock = rejectWhenAborted();
    vi.stubGlobal("fetch", fetchMock);
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const controller = new AbortController();

    const pending = GET(backendRequest({ signal: controller.signal }), CONTEXT);
    controller.abort(new Error("browser request cancelled"));
    const response = await pending;

    expect(response.status).toBe(499);
    expect((await response.json()).error.code).toBe("request_cancelled");
    const forwardedSignal = (fetchMock.mock.calls[0]?.[1] as RequestInit).signal;
    expect(forwardedSignal?.aborted).toBe(true);
    expect(log).not.toHaveBeenCalled();
  });

  it("forwards one valid idempotency key across the automatic refresh replay", async () => {
    const key = "chat-11111111-1111-4111-8111-111111111111";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({ error: { code: "expired" } }, { status: 401 }))
      .mockResolvedValueOnce(Response.json({
        access_token: "replacement-access",
        refresh_token: "replacement-refresh",
        token_type: "bearer",
        expires_in: 900,
      }))
      .mockResolvedValueOnce(Response.json({ answer: "ok", citations: [] }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(backendRequest({
      idempotencyKey: key,
      method: "POST",
      refresh: true,
    }), CHAT_CONTEXT);

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(4);
    const firstHeaders = new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers);
    const replayHeaders = new Headers((fetchMock.mock.calls[2]?.[1] as RequestInit).headers);
    expect(firstHeaders.get("idempotency-key")).toBe(key);
    expect(replayHeaders.get("idempotency-key")).toBe(key);
    expect(String(fetchMock.mock.calls[3]?.[0])).toContain("/api/v1/auth/refresh/status");
  });

  it("rejects an invalid idempotency header instead of forwarding it", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(backendRequest({
      idempotencyKey: "chat key containing spaces",
      method: "POST",
    }), CHAT_CONTEXT);

    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe("invalid_idempotency_key");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
