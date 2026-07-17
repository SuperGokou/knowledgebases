import { describe, expect, it } from "vitest";

import { createActionLock } from "../src/lib/action-lock";

describe("action lock", () => {
  it("admits one mutation and rejects duplicate submissions until release", () => {
    const lock = createActionLock();

    expect(lock.acquire()).toBe(true);
    expect(lock.isLocked()).toBe(true);
    expect(lock.acquire()).toBe(false);

    lock.release();

    expect(lock.isLocked()).toBe(false);
    expect(lock.acquire()).toBe(true);
  });

  it("can be released safely after a failed action", () => {
    const lock = createActionLock();
    expect(lock.acquire()).toBe(true);

    try {
      throw new Error("request failed");
    } catch {
      lock.release();
    }

    expect(lock.acquire()).toBe(true);
  });
});
