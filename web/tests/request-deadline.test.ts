import { afterEach, describe, expect, it, vi } from "vitest";

import { createRequestDeadline } from "../src/lib/request-deadline";

afterEach(() => {
  vi.useRealTimers();
});

describe("request deadlines", () => {
  it("aborts with a timeout reason when the deadline elapses", () => {
    vi.useFakeTimers();
    const deadline = createRequestDeadline(1_000);

    vi.advanceTimersByTime(999);
    expect(deadline.signal.aborted).toBe(false);

    vi.advanceTimersByTime(1);
    expect(deadline.signal.aborted).toBe(true);
    expect(deadline.signal.reason).toMatchObject({ name: "TimeoutError" });
    expect(deadline.timedOut).toBe(true);
  });

  it("cancels without later being classified as a timeout", () => {
    vi.useFakeTimers();
    const deadline = createRequestDeadline(1_000);

    deadline.cancel();
    vi.advanceTimersByTime(1_000);

    expect(deadline.signal.aborted).toBe(true);
    expect(deadline.signal.reason).toMatchObject({ name: "AbortError" });
    expect(deadline.timedOut).toBe(false);
  });
});
