import { describe, expect, it } from "vitest";

import {
  BackendResponseTooLargeError,
  readBoundedResponseBody,
} from "../src/lib/server/bounded-response";


describe("readBoundedResponseBody", () => {
  it("accepts a legitimate chunked response within the byte budget", async () => {
    const response = new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("hello"));
        controller.enqueue(new TextEncoder().encode(" world"));
        controller.close();
      },
    }));

    const body = await readBoundedResponseBody(response, 11);

    expect(new TextDecoder().decode(body)).toBe("hello world");
  });

  it("cancels a chunked backend response as soon as it exceeds the byte budget", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(5));
        controller.enqueue(new Uint8Array(6));
      },
      cancel() {
        cancelled = true;
      },
    }));

    await expect(readBoundedResponseBody(response, 10)).rejects.toBeInstanceOf(
      BackendResponseTooLargeError,
    );
    expect(cancelled).toBe(true);
  });
});
