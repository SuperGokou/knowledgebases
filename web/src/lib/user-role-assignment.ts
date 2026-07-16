import { apiRequest, ApiClientError } from "./api-client";
import type { User } from "./types";

export const STALE_ROLE_ASSIGNMENT_MESSAGE =
  "该成员的角色已被其他管理员更新。旧编辑草稿已关闭，系统已加载最新数据，请重新打开角色编辑器后再操作。";

export const STALE_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE =
  "该成员的角色已被其他管理员更新，旧编辑草稿已关闭。最新成员列表刷新失败，请点击“重试”重新加载；刷新成功前不能再次分配角色。";

export const SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE =
  "成员角色已保存，旧编辑草稿已关闭，但最新成员列表刷新失败。请点击“重试”重新加载；刷新成功前不能再次分配角色。";

export type RoleAssignmentDraftInvalidationReason = "saved" | "stale";

export type LatestRequestOutcome = "applied" | "superseded";

export type LatestRequestController = {
  invalidate: () => void;
  run: <T>(request: () => Promise<T>, apply: (value: T) => void) => Promise<LatestRequestOutcome>;
};

export type RoleAssignmentEditor = {
  userId: string;
  expectedVersion: number;
  roleIds: string[];
};

export type RoleAssignmentSaveResult =
  | { status: "saved"; user: User }
  | { status: "stale" };

type RoleAssignmentRequest = (path: string, init: RequestInit) => Promise<User>;

type SaveRoleAssignmentDependencies = {
  invalidateDraft: (reason: RoleAssignmentDraftInvalidationReason) => void;
  reloadLatest: () => Promise<void>;
  request?: RoleAssignmentRequest;
};

export function createLatestRequestController(): LatestRequestController {
  let latestRequest = 0;
  return {
    invalidate() {
      latestRequest += 1;
    },
    async run<T>(request: () => Promise<T>, apply: (value: T) => void) {
      latestRequest += 1;
      const requestSequence = latestRequest;
      try {
        const value = await request();
        if (requestSequence !== latestRequest) return "superseded";
        apply(value);
        return "applied";
      } catch (error) {
        if (requestSequence !== latestRequest) return "superseded";
        throw error;
      }
    },
  };
}

export function openRoleAssignmentEditor(user: User): RoleAssignmentEditor {
  if (!Number.isSafeInteger(user.role_assignment_version) || user.role_assignment_version < 1) {
    throw new Error("成员角色版本无效，请刷新页面后重试。");
  }
  return {
    userId: user.id,
    expectedVersion: user.role_assignment_version,
    roleIds: [...user.role_ids],
  };
}

export async function saveUserRoleAssignment(
  editor: RoleAssignmentEditor,
  dependencies: SaveRoleAssignmentDependencies,
): Promise<RoleAssignmentSaveResult> {
  const request = dependencies.request ?? ((path, init) => apiRequest<User>(path, init));
  let user: User;
  try {
    user = await request(`/api/v1/users/${editor.userId}/roles`, {
      method: "PUT",
      body: JSON.stringify({
        role_ids: [...editor.roleIds],
        expected_version: editor.expectedVersion,
      }),
    });
  } catch (error) {
    if (
      error instanceof ApiClientError
      && error.status === 409
      && error.code === "stale_role_assignment"
    ) {
      // Invalidate the obsolete editor synchronously, before any fallible
      // refresh. A failed refresh must never leave the stale role set reusable.
      dependencies.invalidateDraft("stale");
      await dependencies.reloadLatest();
      return { status: "stale" };
    }
    throw error;
  }

  // The write has committed. Close the editor and invalidate the pre-write
  // list before refreshing so a failed GET cannot replay the committed draft.
  dependencies.invalidateDraft("saved");
  await dependencies.reloadLatest();
  return { status: "saved", user };
}
