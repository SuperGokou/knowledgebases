import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  createChatIdempotencyController,
  isValidIdempotencyKey,
} from "../src/lib/chat-idempotency";

const component = readFileSync(
  new URL("../src/components/chat-workspace.tsx", import.meta.url),
  "utf8",
);

const UUIDS = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444",
];

describe("chat operation idempotency", () => {
  it("uses the browser cryptographic UUID source by default", () => {
    expect(createChatIdempotencyController().begin()).toMatch(
      /^chat-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("reuses one opaque high-entropy key for retries of a logical message", () => {
    let index = 0;
    const controller = createChatIdempotencyController(() => UUIDS[index++]!);

    const first = controller.begin();

    expect(first).toBe(`chat-${UUIDS[0]}`);
    expect(controller.begin()).toBe(first);
    expect(controller.retry()).toBe(first);
    expect(isValidIdempotencyKey(first)).toBe(true);
  });

  it("rotates after success, user editing, and an explicit new conversation", () => {
    let index = 0;
    const controller = createChatIdempotencyController(() => UUIDS[index++]!);

    const first = controller.begin();
    controller.complete();
    const afterSuccess = controller.begin();
    controller.messageEdited();
    const afterEdit = controller.begin();
    controller.conversationReset();
    const afterReset = controller.begin();

    expect(new Set([first, afterSuccess, afterEdit, afterReset])).toHaveLength(4);
    expect(controller.retry()).toBe(afterReset);
  });

  it("accepts only bounded log-safe idempotency headers", () => {
    expect(isValidIdempotencyKey("chat-11111111-1111-4111-8111-111111111111")).toBe(true);
    expect(isValidIdempotencyKey("")).toBe(false);
    expect(isValidIdempotencyKey(" contains-space")).toBe(false);
    expect(isValidIdempotencyKey("chat/contains-path-separator")).toBe(false);
    expect(isValidIdempotencyKey(`chat-${"a".repeat(156)}`)).toBe(false);
  });

  it("wires the opaque key into chat without browser persistence", () => {
    expect(component).toContain('headers: { "Idempotency-Key": idempotencyKey }');
    expect(component).toContain("idempotencyRef.current.retry()");
    expect(component).toContain("idempotencyRef.current.complete()");
    expect(component).toContain("idempotencyRef.current.messageEdited()");
    expect(component).toContain("idempotencyRef.current.conversationReset()");
    expect(component).not.toMatch(/localStorage|sessionStorage|indexedDB/);
  });
});
