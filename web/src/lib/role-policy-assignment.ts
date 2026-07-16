import { apiRequest, ApiClientError } from "./api-client";
import type { Role } from "./types";

export const STALE_ROLE_POLICY_MESSAGE =
  "该角色策略已被其他管理员更新。旧编辑草稿已关闭，系统已加载最新数据；请重新打开策略编辑器后再操作。";

export const STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE =
  "该角色策略已被其他管理员更新，旧编辑草稿已关闭。最新角色策略刷新失败；刷新成功前不能再次提交。";

export const SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE =
  "角色策略已保存，旧编辑草稿已关闭，但最新角色策略刷新失败；刷新成功前不能再次提交。";

export type RolePolicyDraftInvalidationReason = "saved" | "stale";

export type LatestRolePolicyRequestOutcome = "applied" | "superseded";

export type LatestRolePolicyRequestController = {
  invalidate: () => void;
  run: <T>(
    request: () => Promise<T>,
    apply: (value: T) => void,
  ) => Promise<LatestRolePolicyRequestOutcome>;
};

export type RolePolicyEditor = {
  roleId: string;
  expectedVersion: number;
  permissionCodes: string[];
  limits: Record<string, number | null>;
};

export type RolePolicySaveResult =
  | { status: "saved"; role: Role }
  | { status: "stale" };

type RolePolicyRequest = (path: string, init: RequestInit) => Promise<Role>;

type SaveRolePolicyDependencies = {
  invalidateDraft: (reason: RolePolicyDraftInvalidationReason) => void;
  reloadLatest: () => Promise<void>;
  request?: RolePolicyRequest;
};

type LoadRoleCatalogAndDetailDependencies<T> = {
  catalogController: LatestRolePolicyRequestController;
  requestCatalog: () => Promise<T>;
  applyCatalog: (catalog: T) => string;
  requestDetail: (roleId: string) => Promise<LatestRolePolicyRequestOutcome>;
};

export function createLatestRolePolicyRequestController(): LatestRolePolicyRequestController {
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

export async function loadRoleCatalogAndDetail<T>(
  dependencies: LoadRoleCatalogAndDetailDependencies<T>,
): Promise<LatestRolePolicyRequestOutcome> {
  let selectedRoleId: string | null = null;
  const catalogOutcome = await dependencies.catalogController.run(
    dependencies.requestCatalog,
    (catalog) => {
      selectedRoleId = dependencies.applyCatalog(catalog);
    },
  );
  if (catalogOutcome === "superseded") return "superseded";
  if (selectedRoleId === null) {
    throw new Error("角色目录已加载，但未能确定需要刷新的角色。");
  }
  return dependencies.requestDetail(selectedRoleId);
}

export function openRolePolicyEditor(role: Role): RolePolicyEditor {
  if (!Number.isSafeInteger(role.policy_version) || role.policy_version < 1) {
    throw new Error("角色策略版本无效，请刷新页面后重试。");
  }
  return {
    roleId: role.id,
    expectedVersion: role.policy_version,
    permissionCodes: [...role.permission_codes],
    limits: { ...role.limits },
  };
}

export async function saveRolePolicy(
  editor: RolePolicyEditor,
  dependencies: SaveRolePolicyDependencies,
): Promise<RolePolicySaveResult> {
  const request = dependencies.request
    ?? ((path, init) => apiRequest<Role>(path, init));
  let role: Role;
  try {
    role = await request(`/api/v1/roles/${editor.roleId}/policy`, {
      method: "PUT",
      body: JSON.stringify({
        expected_version: editor.expectedVersion,
        permission_codes: [...editor.permissionCodes],
        limits: { ...editor.limits },
      }),
    });
  } catch (error) {
    if (
      error instanceof ApiClientError
      && error.status === 409
      && error.code === "stale_role_policy"
    ) {
      // Invalidate the obsolete editor synchronously before any fallible read.
      // A failed refresh must never leave the stale full-replacement payload reusable.
      dependencies.invalidateDraft("stale");
      await dependencies.reloadLatest();
      return { status: "stale" };
    }
    throw error;
  }

  // The PUT has committed. Invalidate the pre-write snapshot before the
  // fallible GET so refresh failure can never leave a reusable stale draft.
  dependencies.invalidateDraft("saved");
  await dependencies.reloadLatest();
  return { status: "saved", role };
}
