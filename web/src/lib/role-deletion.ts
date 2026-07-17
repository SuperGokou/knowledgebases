import { apiRequest } from "./api-client";
import type { Role } from "./types";

export type RoleDeleteEditor = {
  roleId: string;
  roleName: string;
  isSystem: boolean;
  policyEtag: string;
  confirmation: string;
};

type DeleteRequest = (path: string, init: RequestInit) => Promise<void>;

export function openRoleDeleteEditor(role: Role): RoleDeleteEditor {
  if (role.is_system) throw new Error("系统角色不可删除。");
  return {
    roleId: role.id,
    roleName: role.name,
    isSystem: role.is_system,
    policyEtag: role.policy_etag,
    confirmation: "",
  };
}

export function validateRoleDeleteConfirmation(editor: RoleDeleteEditor): void {
  if (editor.isSystem) throw new Error("系统角色不可删除。");
  if (editor.confirmation !== editor.roleName) {
    throw new Error(`请完整输入角色名称“${editor.roleName}”以确认删除。`);
  }
}

export async function deleteRole(
  editor: RoleDeleteEditor,
  request: DeleteRequest = (path, init) => apiRequest<void>(path, init),
): Promise<void> {
  validateRoleDeleteConfirmation(editor);
  const query = new URLSearchParams({
    expected_name: editor.roleName,
    expected_policy_etag: editor.policyEtag,
  });
  await request(`/api/v1/roles/${editor.roleId}?${query.toString()}`, { method: "DELETE" });
}
