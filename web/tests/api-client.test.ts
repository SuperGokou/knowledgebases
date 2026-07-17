import { afterEach, describe, expect, it, vi } from "vitest";

import {
  apiRequest,
  PERMISSIONS_STALE_EVENT,
  signalPermissionsStale,
} from "../src/lib/api-client";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("permission refresh signaling", () => {
  it("does not treat a resource-level 403 as stale account permissions", async () => {
    const browserWindow = new EventTarget();
    const listener = vi.fn();
    browserWindow.addEventListener(PERMISSIONS_STALE_EVENT, listener);
    vi.stubGlobal("window", browserWindow);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: { code: "permission_denied", message: "Denied" } }),
      { status: 403, headers: { "Content-Type": "application/json" } },
    )));

    await expect(apiRequest("/api/v1/knowledge-bases/restricted")).rejects.toMatchObject({
      status: 403,
      code: "permission_denied",
    });
    expect(listener).not.toHaveBeenCalled();
  });

  it("emits a refresh signal only when a caller explicitly marks permissions stale", () => {
    const browserWindow = new EventTarget();
    const listener = vi.fn();
    browserWindow.addEventListener(PERMISSIONS_STALE_EVENT, listener);
    vi.stubGlobal("window", browserWindow);

    signalPermissionsStale();

    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("preserves the response request ID on API failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({
        request_id: "payload-request-id",
        error: { code: "service_error", message: "Failed" },
      }),
      {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": "header-request-id",
        },
      },
    )));

    await expect(apiRequest("/api/v1/failure")).rejects.toMatchObject({
      requestId: "header-request-id",
      status: 503,
      code: "service_error",
    });
  });
});

describe("API response decoding", () => {
  it.each([204, 205])("accepts an empty %i response even when a proxy preserves a JSON content type", async (status) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, {
      status,
      headers: { "Content-Type": "application/json" },
    })));

    await expect(apiRequest<void>("/api/v1/roles/temporary", { method: "DELETE" })).resolves.toBeUndefined();
  });

  it("reports malformed successful JSON as a bounded upstream response failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("not-json", {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "malformed-success-request",
      },
    })));

    await expect(apiRequest("/api/v1/roles")).rejects.toMatchObject({
      status: 502,
      code: "invalid_response",
      requestId: "malformed-success-request",
    });
  });

  it("preserves the backend status and request ID for malformed error JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("not-json", {
      status: 503,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "malformed-error-request",
      },
    })));

    await expect(apiRequest("/api/v1/failure")).rejects.toMatchObject({
      status: 503,
      code: "invalid_response",
      requestId: "malformed-error-request",
    });
  });

  it("accepts structured +json media types", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ value: 42 }), {
      status: 200,
      headers: { "Content-Type": "application/vnd.heyi+json; charset=utf-8" },
    })));

    await expect(apiRequest<{ value: number }>("/api/v1/value")).resolves.toEqual({ value: 42 });
  });

  it("preserves structured problem details from application/problem+json", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      request_id: "payload-request",
      error: {
        code: "role_in_use",
        message: "Role is still referenced",
        details: { references: 1 },
      },
    }), {
      status: 409,
      headers: {
        "Content-Type": "application/problem+json",
        "X-Request-Id": "header-request",
      },
    })));

    await expect(apiRequest("/api/v1/roles/temporary")).rejects.toMatchObject({
      status: 409,
      code: "role_in_use",
      details: { references: 1 },
      requestId: "header-request",
    });
  });

  it.each([
    { status: 200, expectedStatus: 502 },
    { status: 400, expectedStatus: 400 },
  ])("rejects empty declared JSON without leaking protocol details ($status)", async ({ status, expectedStatus }) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", {
      status,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "empty-json-request",
      },
    })));

    await expect(apiRequest("/api/v1/empty")).rejects.toMatchObject({
      status: expectedStatus,
      code: "invalid_response",
      requestId: "empty-json-request",
    });
  });

  it("does not expose a non-JSON upstream error body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>private upstream detail</html>", {
      status: 502,
      headers: {
        "Content-Type": "text/html",
        "X-Request-Id": "html-error-request",
      },
    })));

    let failure: unknown;
    try {
      await apiRequest("/api/v1/failure");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ status: 502, requestId: "html-error-request" });
    expect(String(failure)).not.toContain("private upstream detail");
  });

  it("rejects a non-JSON success response without exposing its body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>unexpected login page</html>", {
      status: 200,
      headers: {
        "Content-Type": "text/html",
        "X-Request-Id": "html-success-request",
      },
    })));

    let failure: unknown;
    try {
      await apiRequest("/api/v1/roles");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      status: 502,
      code: "invalid_response",
      requestId: "html-success-request",
    });
    expect(String(failure)).not.toContain("unexpected login page");
  });

  it("wraps a response body read failure and retains the request ID", async () => {
    const response = new Response(JSON.stringify({ value: 42 }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "body-read-request",
      },
    });
    vi.spyOn(response, "text").mockRejectedValue(new TypeError("private transport detail"));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    let failure: unknown;
    try {
      await apiRequest("/api/v1/value");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      status: 502,
      code: "invalid_response",
      requestId: "body-read-request",
    });
    expect(String(failure)).not.toContain("private transport detail");
  });
});
