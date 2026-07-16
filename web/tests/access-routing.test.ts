import { describe, expect, it } from "vitest";

import {
  canAccessPath,
  defaultLandingPath,
  resolveLandingPath,
  type AccessPrincipal,
} from "../src/lib/access-routing";

const ORIGIN = "https://knowledge.example";

function principal(
  permissionCodes: string[] = [],
  isSuperuser = false,
): AccessPrincipal {
  return { is_superuser: isSuperuser, permission_codes: permissionCodes };
}

describe("defaultLandingPath", () => {
  it("routes superusers and control-plane accounts to the admin overview", () => {
    expect(defaultLandingPath(principal([], true))).toBe("/admin");
    for (const permission of [
      "user:manage",
      "role:read",
      "api-key:manage",
      "llm:manage",
      "audit:read",
    ]) {
      expect(defaultLandingPath(principal([permission]))).toBe("/admin");
    }
  });

  it("routes content editors to the relevant management page", () => {
    expect(defaultLandingPath(principal(["knowledge:create"]))).toBe("/admin/knowledge");
    expect(defaultLandingPath(principal(["file:upload"]))).toBe("/admin/files");
  });

  it("prefers chat for a chat user, including one with read-only content access", () => {
    expect(defaultLandingPath(principal(["chat:query"]))).toBe("/chat");
    expect(defaultLandingPath(principal(["chat:query", "knowledge:read", "file:read"]))).toBe(
      "/chat",
    );
  });

  it("routes read-only content accounts to their available page", () => {
    expect(defaultLandingPath(principal(["knowledge:read"]))).toBe("/admin/knowledge");
    expect(defaultLandingPath(principal(["file:read"]))).toBe("/admin/files");
  });

  it("does not route mutation-only roles to pages whose first screen requires read access", () => {
    expect(defaultLandingPath(principal(["knowledge:update"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["knowledge:grant"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["file:approve"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["file:delete"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["file:read:any"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["role:manage"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["role:assign"]))).toBe("/access-pending");
    expect(defaultLandingPath(principal(["quota:manage"]))).toBe("/access-pending");
  });

  it("routes accounts without a workspace capability to access pending", () => {
    expect(defaultLandingPath(principal())).toBe("/access-pending");
  });
});

describe("canAccessPath", () => {
  it("maps each protected route to its required capability", () => {
    expect(canAccessPath("/chat", principal(["chat:query"]))).toBe(true);
    expect(canAccessPath("/admin/knowledge", principal(["knowledge:read"]))).toBe(true);
    expect(canAccessPath("/admin/files", principal(["file:upload"]))).toBe(true);
    expect(canAccessPath("/admin/users", principal(["user:manage"]))).toBe(true);
    expect(canAccessPath("/admin/accounts", principal(["user:manage"]))).toBe(true);
    expect(canAccessPath("/admin/roles", principal(["role:read"]))).toBe(true);
    expect(canAccessPath("/admin/api-models", principal(["llm:manage"]))).toBe(true);
    expect(canAccessPath("/admin/audit", principal(["audit:read"]))).toBe(true);
  });

  it("requires the permission needed by each page's first API request", () => {
    expect(canAccessPath("/admin/knowledge", principal(["knowledge:create"]))).toBe(true);
    expect(canAccessPath("/admin/knowledge", principal(["knowledge:update"]))).toBe(false);
    expect(canAccessPath("/admin/files", principal(["file:upload"]))).toBe(true);
    expect(canAccessPath("/admin/files", principal(["file:approve"]))).toBe(false);
    expect(canAccessPath("/admin/roles", principal(["role:manage"]))).toBe(false);
    expect(canAccessPath("/admin", principal(["role:manage"]))).toBe(false);
  });

  it("rejects a route when the account only has an unrelated capability", () => {
    const chatUser = principal(["chat:query"]);
    expect(canAccessPath("/admin", chatUser)).toBe(false);
    expect(canAccessPath("/admin/users", chatUser)).toBe(false);
    expect(canAccessPath("/admin/audit", principal(["user:manage"]))).toBe(false);
    expect(canAccessPath("/unknown", chatUser)).toBe(false);
  });

  it("allows the pending page only when no usable capability exists", () => {
    expect(canAccessPath("/access-pending", principal())).toBe(true);
    expect(canAccessPath("/access-pending", principal(["chat:query"]))).toBe(false);
  });

  it("allows a superuser to use every application workspace", () => {
    const superuser = principal([], true);
    for (const path of [
      "/chat",
      "/admin",
      "/admin/knowledge",
      "/admin/files",
      "/admin/users",
      "/admin/roles",
      "/admin/accounts",
      "/admin/api-models",
      "/admin/audit",
    ]) {
      expect(canAccessPath(path, superuser)).toBe(true);
    }
    expect(canAccessPath("/not-a-route", superuser)).toBe(false);
  });

  it("honors global and resource-wide wildcard permissions", () => {
    expect(defaultLandingPath(principal(["*"]))).toBe("/admin");
    expect(canAccessPath("/admin/users", principal(["user:*"]))).toBe(true);
    expect(canAccessPath("/admin/files", principal(["file:*"]))).toBe(true);
    expect(canAccessPath("/chat", principal(["chat:*"]))).toBe(true);
  });
});

describe("resolveLandingPath", () => {
  it("preserves a safe and authorized requested destination", () => {
    expect(
      resolveLandingPath(
        principal(["user:manage"]),
        "/admin/users?status=active",
        ORIGIN,
      ),
    ).toBe("/admin/users?status=active");
  });

  it("falls back to the account landing page for a safe but unauthorized route", () => {
    expect(resolveLandingPath(principal(["chat:query"]), "/admin/users", ORIGIN)).toBe(
      "/chat",
    );
  });

  it("fails closed for an external or malformed requested destination", () => {
    const admin = principal(["user:manage"]);
    expect(resolveLandingPath(admin, "https://evil.example/", ORIGIN)).toBe("/admin");
    expect(resolveLandingPath(admin, "/%2f%2fevil.example/", ORIGIN)).toBe("/admin");
    expect(resolveLandingPath(admin, "/admin", "not an origin")).toBe("/admin");
  });
});
