import { apiRequest, ApiClientError } from "./api-client";
import type {
  KnowledgeAccessLevel,
  KnowledgeBase,
  KnowledgeBaseRoleGrant,
} from "./types";

export const STALE_KNOWLEDGE_GRANTS_MESSAGE =
  "该知识库的角色授权已被其他管理员更新。系统已加载最新授权，旧草稿已关闭；请重新打开授权编辑后再操作。";

export const SAVED_KNOWLEDGE_GRANTS_REFRESH_FAILED_MESSAGE =
  "访问等级已保存，但最新授权刷新失败。请手动刷新确认，请勿重复提交。";

export const STALE_KNOWLEDGE_GRANTS_REFRESH_FAILED_MESSAGE =
  "检测到其他管理员已更新授权，但最新数据刷新失败。旧草稿已关闭，请手动刷新后重新操作。";

export type KnowledgeGrantEditor = {
  knowledgeBaseId: string;
  expectedVersion: number;
};

export type KnowledgeGrantInput = {
  role_id: string;
  access_level: KnowledgeAccessLevel;
};

export type KnowledgeGrantSaveResult =
  | { status: "saved"; grants: KnowledgeBaseRoleGrant[] }
  | { status: "saved_refresh_failed"; grants: KnowledgeBaseRoleGrant[]; error: unknown }
  | { status: "stale" }
  | { status: "stale_refresh_failed"; error: unknown };

export type KnowledgeGrantReloadReason = "saved" | "stale";

type KnowledgeGrantRequest = (
  path: string,
  init: RequestInit,
) => Promise<KnowledgeBaseRoleGrant[]>;

type SaveKnowledgeGrantDependencies = {
  reloadLatest: (reason: KnowledgeGrantReloadReason) => Promise<void>;
  request?: KnowledgeGrantRequest;
};

export function openKnowledgeGrantEditor(
  knowledgeBase: KnowledgeBase,
): KnowledgeGrantEditor {
  if (
    !Number.isSafeInteger(knowledgeBase.role_grant_version)
    || knowledgeBase.role_grant_version < 1
  ) {
    throw new Error("知识库授权版本无效，请刷新页面后重试。");
  }
  return {
    knowledgeBaseId: knowledgeBase.id,
    expectedVersion: knowledgeBase.role_grant_version,
  };
}

export async function saveKnowledgeGrantAssignment(
  editor: KnowledgeGrantEditor,
  grants: KnowledgeGrantInput[],
  dependencies: SaveKnowledgeGrantDependencies,
): Promise<KnowledgeGrantSaveResult> {
  const request = dependencies.request
    ?? ((path, init) => apiRequest<KnowledgeBaseRoleGrant[]>(path, init));
  let savedGrants: KnowledgeBaseRoleGrant[];
  try {
    savedGrants = await request(
      `/api/v1/knowledge-bases/${editor.knowledgeBaseId}/role-grants`,
      {
        method: "PUT",
        body: JSON.stringify({
          grants: grants.map(({ role_id, access_level }) => ({ role_id, access_level })),
          expected_version: editor.expectedVersion,
        }),
      },
    );
  } catch (error) {
    if (
      error instanceof ApiClientError
      && error.status === 409
      && error.code === "stale_knowledge_grants"
    ) {
      // Never replay an obsolete replacement set. Reloading is a read-only
      // reconciliation; the operator must explicitly open a new draft.
      try {
        await dependencies.reloadLatest("stale");
        return { status: "stale" };
      } catch (refreshError) {
        return { status: "stale_refresh_failed", error: refreshError };
      }
    }
    throw error;
  }

  try {
    await dependencies.reloadLatest("saved");
  } catch (error) {
    return { status: "saved_refresh_failed", grants: savedGrants, error };
  }
  return { status: "saved", grants: savedGrants };
}
