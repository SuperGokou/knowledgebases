import { describe, expect, it } from "vitest";

import {
  BffSigningConfigurationError,
  createSignedClientIpHeaders,
} from "../src/lib/server/client-ip-signing";

const SECRET = "0123456789abcdef0123456789abcdef";
const NOW = () => 1_700_000_000_999;

describe("createSignedClientIpHeaders", () => {
  it("returns a stable HMAC signature for the canonical Vercel client IP", () => {
    const headers = new Headers({
      "x-vercel-forwarded-for": "203.0.113.7, 198.51.100.4",
      "x-forwarded-for": "198.51.100.8",
      "x-real-ip": "192.0.2.10",
    });

    expect(createSignedClientIpHeaders(headers, {
      secret: SECRET,
      production: true,
      now: NOW,
    })).toEqual({
      "X-KB-Client-IP": "203.0.113.7",
      "X-KB-Client-Timestamp": "1700000000",
      "X-KB-Client-Signature": "fba410cd9e7e9dc61e624c0de6c7f2b89be5c50e1eef4d3bf371a1102a06d662",
    });
  });

  it("falls back to the next trusted header and strips an IPv4 port", () => {
    const headers = new Headers({
      "x-vercel-forwarded-for": "not-an-ip, 203.0.113.9",
      "x-forwarded-for": "198.51.100.9:8443, 192.0.2.1",
    });

    expect(createSignedClientIpHeaders(headers, {
      secret: SECRET,
      production: true,
      now: NOW,
    })["X-KB-Client-IP"]).toBe("198.51.100.9");
  });

  it("returns no headers for an invalid client IP", () => {
    expect(createSignedClientIpHeaders(new Headers({ "x-forwarded-for": "attacker" }), {
      secret: SECRET,
      production: true,
      now: NOW,
    })).toEqual({});
  });

  it("permits an absent signing key only in development", () => {
    expect(createSignedClientIpHeaders(new Headers({ "x-real-ip": "192.0.2.1" }), {
      secret: "",
      production: false,
      now: NOW,
    })).toEqual({});
  });

  it("fails closed on an undersized production signing key", () => {
    expect(() => createSignedClientIpHeaders(new Headers({ "x-real-ip": "192.0.2.1" }), {
      secret: "too-short",
      production: true,
      now: NOW,
    })).toThrow(BffSigningConfigurationError);
  });
});
