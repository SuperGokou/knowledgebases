import { describe, expect, it } from "vitest";

import { isAllowedBackendPath } from "../src/lib/server/backend-path";

describe("isAllowedBackendPath", () => {
  it.each([
    "files",
    "users",
    "roles",
    "permissions",
    "limits",
    "knowledge-bases",
    "chat",
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
