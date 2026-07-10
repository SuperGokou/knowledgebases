import { describe, expect, it, vi } from "vitest";

import {
  createSingleFlight,
  isBlockingAccessRefresh,
  sessionRecoveryAction,
} from "../src/components/access-provider";

describe("access profile refresh coordination", () => {
  it("coalesces concurrent reload requests into one API operation", async () => {
    let release: (() => void) | undefined;
    const operation = vi.fn(() => new Promise<void>((resolve) => {
      release = resolve;
    }));
    const reload = createSingleFlight(operation);

    const first = reload();
    const second = reload();

    expect(second).toBe(first);
    expect(operation).toHaveBeenCalledTimes(0);
    await Promise.resolve();
    expect(operation).toHaveBeenCalledTimes(1);
    release?.();
    await first;

    const third = reload();
    expect(third).not.toBe(first);
    await Promise.resolve();
    expect(operation).toHaveBeenCalledTimes(2);
    release?.();
    await third;
  });

  it("keeps an already loaded page visible during a background refresh", () => {
    expect(isBlockingAccessRefresh(false)).toBe(true);
    expect(isBlockingAccessRefresh(true)).toBe(false);
  });

  it("redirects only after logout actually clears the expired session", () => {
    expect(sessionRecoveryAction("cleared")).toBe("redirect");
    expect(sessionRecoveryAction("stale")).toBe("retry");
    expect(sessionRecoveryAction("failed")).toBe("error");
  });
});
