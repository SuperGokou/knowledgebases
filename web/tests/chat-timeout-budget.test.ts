import { describe, expect, it } from "vitest";

import {
  CHAT_BFF_TIMEOUT_MS,
  CHAT_BROWSER_TIMEOUT_MS,
  CHAT_SERVER_TIMEOUT_MS,
  isChatQueryPath,
} from "../src/lib/chat-timeout-budget";

describe("chat end-to-end timeout budget", () => {
  it("keeps a bounded cancellation margin at every hop", () => {
    expect(CHAT_SERVER_TIMEOUT_MS).toBe(95_000);
    expect(CHAT_BFF_TIMEOUT_MS).toBe(105_000);
    expect(CHAT_BROWSER_TIMEOUT_MS).toBe(115_000);
    expect(CHAT_SERVER_TIMEOUT_MS).toBeLessThan(CHAT_BFF_TIMEOUT_MS);
    expect(CHAT_BFF_TIMEOUT_MS).toBeLessThan(CHAT_BROWSER_TIMEOUT_MS);
    expect(CHAT_BROWSER_TIMEOUT_MS).toBeLessThanOrEqual(120_000);
  });

  it("recognizes only the canonical chat query endpoint", () => {
    expect(isChatQueryPath("/api/v1/chat/query")).toBe(true);
    expect(isChatQueryPath("/api/v1/public/chat/query")).toBe(true);
    expect(isChatQueryPath("/api/v1/chat/query/extra")).toBe(false);
    expect(isChatQueryPath("/api/v1/files")).toBe(false);
  });
});
