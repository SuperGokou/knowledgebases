import { describe, expect, it } from "vitest";

import { isSameOriginRequest } from "../src/lib/server/same-origin";

describe("isSameOriginRequest", () => {
  it("rejects a production mutation without an Origin header", () => {
    expect(isSameOriginRequest(new Headers({ host: "knowledge.example" }), {
      production: true,
      requestProtocol: "https:",
    })).toBe(false);
  });

  it("permits an Origin-less development request", () => {
    expect(isSameOriginRequest(new Headers({ host: "localhost:3000" }), {
      production: false,
      requestProtocol: "http:",
    })).toBe(true);
  });

  it("rejects cross-site fetch metadata even when Origin matches", () => {
    const headers = new Headers({
      origin: "https://knowledge.example",
      "sec-fetch-site": "cross-site",
      "x-forwarded-host": "knowledge.example",
      "x-forwarded-proto": "https",
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      requestProtocol: "http:",
    })).toBe(false);
  });

  it("accepts a same-origin request using the first forwarded host and protocol", () => {
    const headers = new Headers({
      origin: "https://knowledge.example",
      "sec-fetch-site": "same-origin",
      "x-forwarded-host": "knowledge.example, internal.example",
      "x-forwarded-proto": "https, http",
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      requestProtocol: "http:",
    })).toBe(true);
  });

  it.each([
    ["http", "knowledge.example"],
    ["https", "evil.example"],
    ["javascript", "knowledge.example"],
  ])("rejects forwarded destination %s://%s", (proto, host) => {
    const headers = new Headers({
      origin: "https://knowledge.example",
      "x-forwarded-host": host,
      "x-forwarded-proto": proto,
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      requestProtocol: "https:",
    })).toBe(false);
  });
});
