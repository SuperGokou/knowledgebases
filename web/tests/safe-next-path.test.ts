import { describe, expect, it } from "vitest";

import { safeNextPath } from "../src/lib/safe-next-path";

const ORIGIN = "https://knowledge.example";

describe("safeNextPath", () => {
  it.each([
    "/chat",
    "/admin",
    "/admin/knowledge",
    "/admin/files",
    "/admin/users",
    "/admin/roles",
    "/admin/accounts",
  ])("allows the canonical application route %s", (path) => {
    expect(safeNextPath(path, ORIGIN)).toBe(path);
  });

  it("preserves a query string on an allowed route", () => {
    expect(safeNextPath("/admin/users?status=active&sort=email", ORIGIN)).toBe(
      "/admin/users?status=active&sort=email",
    );
  });

  it.each([
    null,
    "",
    "https://evil.example/",
    "//evil.example/",
    "/\\\\evil.example/",
    "/%5c%5cevil.example/",
    "/%255c%255cevil.example/",
    "/%2f%2fevil.example/",
    "/%252f%252fevil.example/",
    "/%25252f%25252fevil.example/",
    "/chat%0d%0aLocation:%20https://evil.example/",
    "/chat#https://evil.example/",
    "/admin/users/../roles",
    "/not-an-application-route",
  ])("falls back for an untrusted redirect target %#", (target) => {
    expect(safeNextPath(target, ORIGIN)).toBe("/chat");
  });

  it("fails closed when the trusted origin is malformed", () => {
    expect(safeNextPath("/admin", "not an origin")).toBe("/chat");
  });
});
