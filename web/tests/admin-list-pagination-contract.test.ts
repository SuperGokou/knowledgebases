import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const usersPanel = readFileSync(join(process.cwd(), "src/components/users-panel.tsx"), "utf8");
const filesPanel = readFileSync(join(process.cwd(), "src/components/files-panel.tsx"), "utf8");
const rolesPanel = readFileSync(join(process.cwd(), "src/components/roles-panel.tsx"), "utf8");

describe("large admin-list reachability", () => {
  it("uses server-side member search and offset pagination instead of a fixed first page", () => {
    expect(usersPanel).toContain('buildOffsetListPath("/api/v1/users"');
    expect(usersPanel).toContain('aria-label="搜索成员"');
    expect(usersPanel).toContain('aria-label="成员列表分页"');
    expect(usersPanel).toContain("hasNextUsers");
    expect(usersPanel).not.toContain('/api/v1/users?limit=100&offset=0');
  });

  it("invalidates hidden member editors before search, refresh, or page navigation", () => {
    expect(usersPanel).toContain("function closeMemberEditors()");
    expect(usersPanel).toContain("function moveToUserOffset(offset: number)");
    expect(usersPanel).toContain('aria-labelledby="role-assignment-editor-title"');
    expect(usersPanel).toContain('aria-labelledby="password-reset-editor-title"');
    expect(usersPanel).toContain('aria-labelledby="user-retirement-editor-title"');
    expect(usersPanel).toContain("roleEditorUser?.email");
    expect(usersPanel).toContain("passwordEditorUser?.email");
    expect(usersPanel).toContain("retirementEditorUser?.display_name");
  });

  it("loads role candidates independently so a catalog failure cannot block member actions", () => {
    expect(usersPanel).toContain("loadRoleCandidates");
    expect(usersPanel).toContain("roleCatalogError");
    expect(usersPanel).toContain('aria-label="搜索角色候选"');
    expect(usersPanel).toContain("加载更多角色");
    expect(usersPanel).toContain("roleOptionsForSelection");
    expect(usersPanel).not.toContain('/api/v1/roles?limit=100&offset=0');
    expect(usersPanel).not.toContain("Promise.all([");
  });

  it("uses server-side filename search and makes pages beyond the first hundred reachable", () => {
    expect(filesPanel).toContain('buildOffsetListPath("/api/v1/files"');
    expect(filesPanel).toContain('aria-label="搜索文件名"');
    expect(filesPanel).toContain('aria-label="文件列表分页"');
    expect(filesPanel).toContain("hasNextFiles");
    expect(filesPanel).not.toContain('/api/v1/files?limit=100&offset=0');
    expect(filesPanel).not.toContain("files.filter(");
  });

  it("makes every role reachable without losing the selected role editor", () => {
    expect(rolesPanel).toContain("roleCatalogPagePath");
    expect(rolesPanel).toContain('aria-label="搜索角色目录"');
    expect(rolesPanel).toContain("加载更多角色");
    expect(rolesPanel).toContain("roleOptionsForSelection");
    expect(rolesPanel).toContain("knownRolesRef.current = mergeRoleCatalogItems");
    expect(rolesPanel).not.toContain('apiRequest<Role[]>("/api/v1/roles")');
  });
});
