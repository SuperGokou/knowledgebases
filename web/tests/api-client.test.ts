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
});
