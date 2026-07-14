import { describe, expect, it } from "vitest";

import { isSameOriginRequest } from "../src/lib/server/same-origin";

describe("isSameOriginRequest", () => {
  it("rejects a production mutation without an Origin header", () => {
    expect(isSameOriginRequest(new Headers({ host: "knowledge.example" }), {
      production: true,
      trustedOrigin: "https://knowledge.example",
    })).toBe(false);
  });

  it("permits an Origin-less development request", () => {
    expect(isSameOriginRequest(new Headers({ host: "localhost:3000" }), {
      production: false,
      trustedOrigin: "http://localhost:3000",
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
      trustedOrigin: "https://knowledge.example",
    })).toBe(false);
  });

  it("accepts a request matching the fixed public origin", () => {
    const headers = new Headers({
      origin: "https://knowledge.example",
      "sec-fetch-site": "same-origin",
      "x-forwarded-host": "knowledge.example, internal.example",
      "x-forwarded-proto": "https, http",
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      trustedOrigin: "https://knowledge.example",
    })).toBe(true);
  });

  it("does not trust forged forwarded host or protocol headers", () => {
    const headers = new Headers({
      origin: "https://evil.example",
      "sec-fetch-site": "same-origin",
      host: "knowledge.internal",
      "x-forwarded-host": "evil.example",
      "x-forwarded-proto": "https",
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      trustedOrigin: "https://knowledge.example",
    })).toBe(false);
  });

  it("fails closed in production when no fixed public origin is configured", () => {
    const headers = new Headers({ origin: "https://knowledge.example" });
    expect(isSameOriginRequest(headers, {
      production: true,
      trustedOrigin: undefined,
    })).toBe(false);
  });

  it.each([
    ["http", "knowledge.example"],
    ["https", "evil.example"],
    ["javascript", "knowledge.example"],
  ])("ignores untrusted forwarded destination %s://%s", (proto, host) => {
    const headers = new Headers({
      origin: "https://knowledge.example",
      "x-forwarded-host": host,
      "x-forwarded-proto": proto,
    });
    expect(isSameOriginRequest(headers, {
      production: true,
      trustedOrigin: "https://knowledge.example",
    })).toBe(true);
  });
});
