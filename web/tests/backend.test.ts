import { afterEach, describe, expect, it, vi } from "vitest";

import {
  backendRequestTimeoutMs,
  backendRequestTimeoutMsForUrl,
  publicApiOrigin,
  safeBackendFetch,
} from "../src/lib/server/backend";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

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

describe("safe backend fetch", () => {
  it("uses an explicit public API origin without cloud-specific defaults", () => {
    expect(publicApiOrigin({
      KB_PUBLIC_API_ORIGIN: "https://kb.intranet.example:19443/",
      FASTAPI_URL: "https://api.example.invalid",
      VERCEL: "1",
    })).toBe("https://kb.intranet.example:19443");
  });

  it("uses the configured backend origin only for a Vercel split deployment", () => {
    expect(publicApiOrigin({
      FASTAPI_URL: "https://api.example.test",
      VERCEL: "1",
    })).toBe("https://api.example.test");
    expect(publicApiOrigin({
      FASTAPI_URL: "http://api:8000",
    })).toBeUndefined();
  });

  it.each([
    "javascript:alert(1)",
    "https://user:password@api.example.test",
    "https://api.example.test/private",
    "https://api.example.test?token=secret",
  ])("rejects an unsafe configured public API origin: %s", (configured) => {
    expect(() => publicApiOrigin({ KB_PUBLIC_API_ORIGIN: configured })).toThrow(
      /KB_PUBLIC_API_ORIGIN/,
    );
  });

  it("bounds configured request deadlines", () => {
    expect(backendRequestTimeoutMs("100")).toBe(1_000);
    expect(backendRequestTimeoutMs("90000")).toBe(90_000);
    expect(backendRequestTimeoutMs("999999")).toBe(120_000);
    expect(backendRequestTimeoutMs("invalid")).toBe(60_000);
  });

  it("gives only chat queries the bounded two-stage BFF budget", () => {
    expect(backendRequestTimeoutMsForUrl(
      new URL("https://api.example.test/api/v1/chat/query"),
    )).toBe(105_000);
    expect(backendRequestTimeoutMsForUrl(
      new URL("https://api.example.test/api/v1/public/chat/query"),
    )).toBe(105_000);
    expect(backendRequestTimeoutMsForUrl(
      new URL("https://api.example.test/api/v1/files"),
    )).toBe(60_000);
  });

  it("keeps the chat connection alive past the generic 60 second deadline", async () => {
    vi.useFakeTimers();
    const fetchMock = rejectWhenAborted();
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const pending = safeBackendFetch(
      new URL("https://api.example.test/api/v1/chat/query"),
      { method: "POST" },
    );
    await vi.advanceTimersByTimeAsync(60_000);
    const forwardedSignal = (fetchMock.mock.calls[0]?.[1] as RequestInit).signal;
    expect(forwardedSignal?.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(45_000);
    expect((await pending).status).toBe(504);
    expect(forwardedSignal?.aborted).toBe(true);
  });

  it("returns a synthetic 504 when the backend deadline elapses", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", rejectWhenAborted());
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const pending = safeBackendFetch(new URL("https://api.example.test/api/v1/chat/query"), {
      method: "POST",
      timeoutMs: 1_000,
    });
    await vi.advanceTimersByTimeAsync(1_000);
    const response = await pending;

    expect(response.status).toBe(504);
    expect((await response.json()).error.code).toBe("backend_timeout");
    expect(warning).toHaveBeenCalledWith("[backend_fetch]", expect.objectContaining({
      event: "backend_request_timeout",
      backend_path: "/api/v1/chat/query",
    }));
  });

  it("returns 502 and emits only sanitized metadata for network failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("secret socket failure")));
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await safeBackendFetch(
      new URL("https://api.example.test/api/v1/files?token=query-secret"),
      {
        method: "POST",
        headers: { Authorization: "Bearer header-secret" },
        body: "body-secret",
        timeoutMs: 1_000,
      },
    );

    expect(response.status).toBe(502);
    expect((await response.json()).error.code).toBe("backend_unavailable");
    const serializedLog = JSON.stringify(log.mock.calls);
    expect(serializedLog).not.toContain("query-secret");
    expect(serializedLog).not.toContain("header-secret");
    expect(serializedLog).not.toContain("body-secret");
    expect(serializedLog).not.toContain("secret socket failure");
  });

  it("composes caller cancellation and does not log it as a network error", async () => {
    const fetchMock = rejectWhenAborted();
    vi.stubGlobal("fetch", fetchMock);
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const caller = new AbortController();

    const pending = safeBackendFetch(new URL("https://api.example.test/api/v1/chat/query"), {
      signal: caller.signal,
      timeoutMs: 10_000,
    });
    caller.abort(new Error("user cancelled"));
    const response = await pending;

    expect(response.status).toBe(499);
    expect((await response.json()).error.code).toBe("request_cancelled");
    const forwardedSignal = (fetchMock.mock.calls[0]?.[1] as RequestInit).signal;
    expect(forwardedSignal?.aborted).toBe(true);
    expect(forwardedSignal?.reason).toBe(caller.signal.reason);
    expect(log).not.toHaveBeenCalled();
  });
});
