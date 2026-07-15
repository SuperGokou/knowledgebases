import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  deleteRole,
  openRoleMetadataEditor,
  saveRoleMetadata,
  validateRoleDeleteConfirmation,
} from "../src/lib/role-administration";
import type { Role } from "../src/lib/types";

const role: Role = {
  id: "00000000-0000-4000-8000-000000000402",
  code: "quality_reviewer",
  name: "质量审核员",
  description: "审核知识内容",
  priority: 20,
  is_system: false,
  policy_version: 7,
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  permission_codes: ["knowledge:read"],
  limits: {},
};

describe("role metadata and deletion CAS", () => {
  it("sends the metadata editor snapshot version", async () => {
    const request = vi.fn().mockResolvedValue({ ...role, name: "高级质量审核员", policy_version: 8 });
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);
    const editor = {
      ...openRoleMetadataEditor(role),
      name: "高级质量审核员",
      description: null,
      priority: 30,
    };

    const result = await saveRoleMetadata(editor, {
      invalidateDraft,
      reloadLatest,
      request,
    });

    expect(result.status).toBe("saved");
    expect(request).toHaveBeenCalledWith(`/api/v1/roles/${role.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        expected_version: 7,
        name: "高级质量审核员",
        description: null,
        priority: 30,
      }),
    });
    expect(invalidateDraft).toHaveBeenCalledWith("saved");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
  });

  it("refuses to open an editor for immutable system roles", () => {
    expect(() => openRoleMetadataEditor({ ...role, is_system: true }))
      .toThrow("系统角色不可编辑");
  });

  it("closes a stale metadata draft before reloading", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_policy",
    ));
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveRoleMetadata(openRoleMetadataEditor(role), {
      invalidateDraft,
      reloadLatest,
      request,
    });

    expect(result).toEqual({ status: "stale" });
    expect(invalidateDraft).toHaveBeenCalledWith("stale");
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
  });

  it("requires an exact role-name confirmation and sends delete CAS in the query", async () => {
    expect(() => validateRoleDeleteConfirmation("质量审核", role.name))
      .toThrow("完整输入角色名称");
    const request = vi.fn().mockResolvedValue(undefined);
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    await deleteRole({
      roleId: role.id,
      roleName: role.name,
      isSystem: false,
      expectedVersion: role.policy_version,
      confirmation: role.name,
    }, {
      invalidateDraft,
      reloadLatest,
      request,
    });

    expect(request).toHaveBeenCalledWith(
      `/api/v1/roles/${role.id}?expected_version=7`,
      { method: "DELETE" },
    );
    expect(invalidateDraft).toHaveBeenCalledWith("deleted");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
  });

  it("refuses system-role deletion before any request is sent", async () => {
    const request = vi.fn();

    await expect(deleteRole({
      roleId: role.id,
      roleName: role.name,
      isSystem: true,
      expectedVersion: role.policy_version,
      confirmation: role.name,
    }, {
      invalidateDraft: vi.fn(),
      reloadLatest: vi.fn(),
      request,
    })).rejects.toThrow("系统角色不可删除");
    expect(request).not.toHaveBeenCalled();
  });

  it("closes a stale delete confirmation and never retries automatically", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_policy",
    ));
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await deleteRole({
      roleId: role.id,
      roleName: role.name,
      isSystem: false,
      expectedVersion: role.policy_version,
      confirmation: role.name,
    }, {
      invalidateDraft,
      reloadLatest,
      request,
    });

    expect(result).toEqual({ status: "stale" });
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("stale");
  });
});
