import { describe, expect, it } from "vitest";

import { readBoundedBody, RequestBodyTooLargeError } from "../src/lib/server/bounded-body";

describe("readBoundedBody", () => {
  it("returns a body that is within the limit", async () => {
    const request = new Request("https://example.test/api", {
      method: "POST",
      body: "hello",
    });

    const body = await readBoundedBody(request, 5);
    expect(new Uint8Array(body ?? new ArrayBuffer(0))).toEqual(
      new TextEncoder().encode("hello"),
    );
  });

  it("rejects an oversized declared content length before reading", async () => {
    const request = new Request("https://example.test/api", {
      method: "POST",
      headers: { "Content-Length": "6" },
      body: "hello",
    });

    await expect(readBoundedBody(request, 5)).rejects.toBeInstanceOf(
      RequestBodyTooLargeError,
    );
  });

  it("rejects a streamed body that crosses the limit without content length", async () => {
    const request = new Request("https://example.test/api", {
      method: "POST",
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("hel"));
          controller.enqueue(new TextEncoder().encode("lo!"));
          controller.close();
        },
      }),
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    await expect(readBoundedBody(request, 5)).rejects.toBeInstanceOf(
      RequestBodyTooLargeError,
    );
  });

  it("does not read GET bodies", async () => {
    const request = new Request("https://example.test/api", { method: "GET" });
    await expect(readBoundedBody(request, 0)).resolves.toBeUndefined();
  });
});
