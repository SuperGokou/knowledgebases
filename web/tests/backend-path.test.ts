import { describe, expect, it } from "vitest";

import { backendAcceptHeader, isAllowedBackendPath } from "../src/lib/server/backend-path";

describe("isAllowedBackendPath", () => {
  it("selects CSV only for the exact GET audit export route", () => {
    expect(backendAcceptHeader(["api", "v1", "audit-logs", "export"], "GET"))
      .toBe("text/csv");
    expect(backendAcceptHeader(["api", "v1", "audit-logs"], "GET"))
      .toBe("application/json");
    expect(backendAcceptHeader(["api", "v1", "audit-logs", "export", "extra"], "GET"))
      .toBe("application/json");
    expect(backendAcceptHeader(["api", "v1", "audit-logs", "export"], "POST"))
      .toBe("application/json");
    expect(backendAcceptHeader(["api", "v1", "files", "export"], "GET"))
      .toBe("application/json");
  });

  it.each([
    "files",
    "users",
    "roles",
    "permissions",
    "limits",
    "knowledge-bases",
    "chat",
    "api-keys",
    "llm",
    "audit-logs",
  ])("allows the canonical %s API root", (root) => {
    const parts = ["api", "v1", root, "resource_01"];
    expect(isAllowedBackendPath(parts, "GET", `/api/backend/${parts.join("/")}`)).toBe(true);
  });

  it("only exposes the current-user endpoint below the auth root", () => {
    expect(isAllowedBackendPath(
      ["api", "v1", "auth", "me"],
      "GET",
      "/api/backend/api/v1/auth/me",
    )).toBe(true);
    expect(isAllowedBackendPath(
      ["api", "v1", "auth", "token"],
      "POST",
      "/api/backend/api/v1/auth/token",
    )).toBe(false);
    expect(isAllowedBackendPath(
      ["api", "v1", "auth", "me"],
      "POST",
      "/api/backend/api/v1/auth/me",
    )).toBe(false);
  });

  it("allows the canonical user-retirement DELETE path through the BFF", () => {
    const parts = ["api", "v1", "users", "00000000-0000-4000-8000-000000000401"];
    expect(isAllowedBackendPath(
      parts,
      "DELETE",
      `/api/backend/${parts.join("/")}`,
    )).toBe(true);
  });

  it.each([
    [["api", "v1"], "/api/backend/api/v1"],
    [["api", "v2", "files"], "/api/backend/api/v2/files"],
    [["api", "v1", "internal"], "/api/backend/api/v1/internal"],
    [["api", "v1", "files", "..", "users"], "/api/backend/api/v1/files/../users"],
    [["api", "v1", "files", "%2e%2e", "users"], "/api/backend/api/v1/files/%2e%2e/users"],
    [["api", "v1", "files", "%252e%252e"], "/api/backend/api/v1/files/%252e%252e"],
    [["api", "v1", "files", "a/b"], "/api/backend/api/v1/files/a/b"],
    [["api", "v1", "files", ""], "/api/backend/api/v1/files/"],
    [["api", "v1", "files", "知识"], "/api/backend/api/v1/files/知识"],
  ])("rejects non-canonical path segments %#", (parts, pathname) => {
    expect(isAllowedBackendPath(parts, "GET", pathname)).toBe(false);
  });

  it.each([
    "/api/backend/api/v1/files/",
    "/api/backend//api/v1/files",
    "/api/backend/api/v1/users",
    "/api/backend/api/v1/%66iles",
  ])("rejects a pathname that does not exactly match its route parts: %s", (pathname) => {
    expect(isAllowedBackendPath(["api", "v1", "files"], "GET", pathname)).toBe(false);
  });
});
