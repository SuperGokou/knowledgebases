import { describe, expect, it, vi } from "vitest";

import {
  deleteRole,
  openRoleDeleteEditor,
  validateRoleDeleteConfirmation,
  type RoleDeleteEditor,
} from "../src/lib/role-deletion";
import type { Role } from "../src/lib/types";

const policyEtag = "0123456789abcdef".repeat(4);

const customRole: Role = {
  id: "8ea7867a-0369-453e-934d-365cb9522459",
  code: "knowledge_auditor",
  name: "知识审计员",
  description: "审核知识库内容",
  priority: 200,
  is_system: false,
  created_at: "2026-07-17T00:00:00Z",
  updated_at: "2026-07-17T00:00:00Z",
  permission_codes: ["audit:read"],
  limits: {},
  policy_etag: policyEtag,
};

function confirmedEditor(overrides: Partial<RoleDeleteEditor> = {}): RoleDeleteEditor {
  return {
    roleId: customRole.id,
    roleName: customRole.name,
    isSystem: false,
    policyEtag,
    confirmation: customRole.name,
    ...overrides,
  };
}

describe("角色删除确认", () => {
  it("只接受与角色名称逐字一致的确认内容", () => {
    const editor = openRoleDeleteEditor(customRole);

    expect(editor).toEqual({
      roleId: customRole.id,
      roleName: customRole.name,
      isSystem: false,
      policyEtag,
      confirmation: "",
    });

    for (const confirmation of ["", "知识审计员 ", " 知识审计员", "知识审计", "KNOWLEDGE_AUDITOR"]) {
      expect(() => validateRoleDeleteConfirmation({ ...editor, confirmation })).toThrow(
        `请完整输入角色名称“${customRole.name}”以确认删除。`,
      );
    }

    expect(() => validateRoleDeleteConfirmation({
      ...editor,
      confirmation: customRole.name,
    })).not.toThrow();
  });

  it("系统角色在打开确认和提交删除两个入口均被禁止", async () => {
    const systemRole = { ...customRole, id: "system-role", is_system: true };
    const request = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);

    expect(() => openRoleDeleteEditor(systemRole)).toThrow("系统角色不可删除。");
    await expect(deleteRole(confirmedEditor({
      roleId: systemRole.id,
      isSystem: true,
    }), request)).rejects.toThrow("系统角色不可删除。");
    expect(request).not.toHaveBeenCalled();
  });

  it("使用 DELETE 并对 expected_name 中的中文和保留字符安全编码", async () => {
    const roleName = "仓储 管理员/华东+夜班";
    const request = vi.fn<(path: string, init: RequestInit) => Promise<void>>()
      .mockResolvedValue(undefined);

    await deleteRole(confirmedEditor({ roleName, confirmation: roleName }), request);

    expect(request).toHaveBeenCalledTimes(1);
    const [path, init] = request.mock.calls[0];
    expect(init).toEqual({ method: "DELETE" });
    expect(path).toContain("expected_name=%E4%BB%93%E5%82%A8+");
    expect(path).toContain("%2F");
    expect(path).toContain("%2B");
    expect(path).not.toContain(roleName);
    const searchParams = new URL(path, "https://knowledge.example").searchParams;
    expect(searchParams.get("expected_name")).toBe(roleName);
    expect(searchParams.get("expected_policy_etag")).toBe(policyEtag);
    expect(searchParams.get("expected_policy_etag")).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("不吞掉 API 错误，向调用方原样传播", async () => {
    const apiError = Object.assign(new Error("角色仍被成员或知识库引用"), {
      code: "role_in_use",
      status: 409,
    });
    const request = vi.fn<(path: string, init: RequestInit) => Promise<void>>()
      .mockRejectedValue(apiError);

    await expect(deleteRole(confirmedEditor(), request)).rejects.toBe(apiError);
    expect(request).toHaveBeenCalledTimes(1);
  });
});
