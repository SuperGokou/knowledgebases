import { ApiClientError, apiRequest } from "./api-client";
import type { Role } from "./types";

export type RoleAdministrationInvalidationReason = "saved" | "stale" | "deleted";

export type RoleMetadataEditor = {
  roleId: string;
  expectedVersion: number;
  name: string;
  description: string | null;
  priority: number;
};

export type RoleDeleteEditor = {
  roleId: string;
  roleName: string;
  isSystem: boolean;
  expectedVersion: number;
  confirmation: string;
};

export type RoleAdministrationResult<T extends "saved" | "deleted"> =
  | { status: T; role?: Role }
  | { status: "stale" };

type RoleAdministrationDependencies<T> = {
  invalidateDraft: (reason: RoleAdministrationInvalidationReason) => void;
  reloadLatest: () => Promise<void>;
  request?: (path: string, init: RequestInit) => Promise<T>;
};

function validPolicyVersion(role: Role): number {
  if (!Number.isSafeInteger(role.policy_version) || role.policy_version < 1) {
    throw new Error("角色策略版本无效，请刷新页面后重试。");
  }
  return role.policy_version;
}

function isStaleRolePolicy(error: unknown): boolean {
  return error instanceof ApiClientError
    && error.status === 409
    && error.code === "stale_role_policy";
}

export function openRoleMetadataEditor(role: Role): RoleMetadataEditor {
  if (role.is_system) {
    throw new Error("系统角色不可编辑。");
  }
  return {
    roleId: role.id,
    expectedVersion: validPolicyVersion(role),
    name: role.name,
    description: role.description,
    priority: role.priority,
  };
}

export async function saveRoleMetadata(
  editor: RoleMetadataEditor,
  dependencies: RoleAdministrationDependencies<Role>,
): Promise<RoleAdministrationResult<"saved">> {
  const name = editor.name.trim();
  if (!name || name.length > 200) {
    throw new Error("角色名称不能为空，且不能超过 200 个字符。");
  }
  if ((editor.description?.length ?? 0) > 2_000) {
    throw new Error("角色描述不能超过 2000 个字符。");
  }
  if (!Number.isSafeInteger(editor.priority) || editor.priority < -10_000 || editor.priority > 10_000) {
    throw new Error("优先级必须是 -10000 到 10000 之间的整数。");
  }
  const request = dependencies.request
    ?? ((path: string, init: RequestInit) => apiRequest<Role>(path, init));
  let role: Role;
  try {
    role = await request(`/api/v1/roles/${editor.roleId}`, {
      method: "PATCH",
      body: JSON.stringify({
        expected_version: editor.expectedVersion,
        name,
        description: editor.description?.trim() || null,
        priority: editor.priority,
      }),
    });
  } catch (error) {
    if (!isStaleRolePolicy(error)) throw error;
    dependencies.invalidateDraft("stale");
    await dependencies.reloadLatest();
    return { status: "stale" };
  }

  dependencies.invalidateDraft("saved");
  await dependencies.reloadLatest();
  return { status: "saved", role };
}

export function validateRoleDeleteConfirmation(confirmation: string, roleName: string): void {
  if (confirmation !== roleName) {
    throw new Error(`请完整输入角色名称“${roleName}”以确认删除。`);
  }
}

export async function deleteRole(
  editor: RoleDeleteEditor,
  dependencies: RoleAdministrationDependencies<void>,
): Promise<RoleAdministrationResult<"deleted">> {
  if (editor.isSystem) {
    throw new Error("系统角色不可删除。");
  }
  if (!Number.isSafeInteger(editor.expectedVersion) || editor.expectedVersion < 1) {
    throw new Error("角色策略版本无效，请刷新页面后重试。");
  }
  validateRoleDeleteConfirmation(editor.confirmation, editor.roleName);
  const request = dependencies.request
    ?? ((path: string, init: RequestInit) => apiRequest<void>(path, init));
  try {
    await request(
      `/api/v1/roles/${editor.roleId}?expected_version=${editor.expectedVersion}`,
      { method: "DELETE" },
    );
  } catch (error) {
    if (!isStaleRolePolicy(error)) throw error;
    dependencies.invalidateDraft("stale");
    await dependencies.reloadLatest();
    return { status: "stale" };
  }

  dependencies.invalidateDraft("deleted");
  await dependencies.reloadLatest();
  return { status: "deleted" };
}
