import { ApiClientError, apiRequest, readableError } from "./api-client";
import type { AuthMe, User } from "./types";

export type UserRetirementEditor = {
  userId: string;
  email: string;
  confirmationEmail: string;
  reason: string;
  replacementOwnerId: string;
};

export type UserRetirementRequest = (
  path: string,
  init: RequestInit,
) => Promise<void>;

export function canRetireUser(
  target: User,
  currentUser: AuthMe | null | undefined,
): boolean {
  if (!currentUser || target.retired_at || target.id === currentUser.id) return false;
  if (target.is_superuser && !currentUser.is_superuser) return false;
  return true;
}

export function validateUserRetirement(editor: UserRetirementEditor): void {
  if (editor.confirmationEmail.trim() !== editor.email) {
    throw new Error("请完整输入成员邮箱以确认删除账号。");
  }
  if (editor.reason.trim().length > 1_000) {
    throw new Error("退休原因不能超过 1000 个字符。");
  }
}

export function eligibleReplacementOwners(
  candidates: readonly User[],
  retiringUserId: string,
): User[] {
  return candidates.filter((candidate) => (
    candidate.id !== retiringUserId
    && candidate.status === "active"
    && !candidate.retired_at
  ));
}

export function mergeReplacementOwnerSearchResults(
  currentCandidates: readonly User[],
  searchResults: readonly User[],
  retiringUserId: string,
  selectedOwnerId: string,
): User[] {
  const eligibleResults = eligibleReplacementOwners(searchResults, retiringUserId);
  const selectedCandidate = selectedOwnerId
    ? eligibleReplacementOwners(currentCandidates, retiringUserId)
      .find((candidate) => candidate.id === selectedOwnerId)
    : undefined;

  if (!selectedCandidate) return eligibleResults;
  return [
    selectedCandidate,
    ...eligibleResults.filter((candidate) => candidate.id !== selectedCandidate.id),
  ];
}

export function readableUserRetirementError(error: unknown): string {
  if (error instanceof ApiClientError) {
    const messageByCode: Record<string, string> = {
      self_retirement_forbidden: "不能删除当前登录账号。请使用另一名管理员操作。",
      last_superuser_protected: "不能删除最后一个活跃超级管理员。请先创建另一名超级管理员。",
      user_ownership_conflict: "请先选择一名活跃成员接管并转移该成员名下的知识库，再删除账号。",
      replacement_owner_invalid: "接管成员必须处于正常状态，且不能是待删除成员本人。",
      replacement_owner_not_found: "未找到接管成员，请重新搜索并选择仍然有效的账号。",
      retirement_confirmation_mismatch: "确认邮箱不匹配，请完整输入目标成员邮箱。",
      superuser_protected: "只有超级管理员可以删除其他超级管理员账号。",
      user_retired: "该账号已经退休，不能再执行此操作。",
    };
    if (error.code && messageByCode[error.code]) return messageByCode[error.code];
  }
  return readableError(error);
}

export async function retireUser(
  editor: UserRetirementEditor,
  request: UserRetirementRequest = (path, init) => apiRequest<void>(path, init),
): Promise<void> {
  validateUserRetirement(editor);
  await request(`/api/v1/users/${editor.userId}`, {
    method: "DELETE",
    body: JSON.stringify({
      confirmation_email: editor.confirmationEmail.trim(),
      reason: editor.reason.trim() || null,
      replacement_owner_id: editor.replacementOwnerId || null,
    }),
  });
}

export type RetirementRefreshResult =
  | { status: "refreshed" }
  | { status: "refresh_failed"; error: unknown };

export async function retireUserWithRefresh(
  editor: UserRetirementEditor,
  options: {
    reload: () => Promise<void>;
    onCommitted: () => void;
    request?: UserRetirementRequest;
  },
): Promise<RetirementRefreshResult> {
  await retireUser(editor, options.request);
  options.onCommitted();
  try {
    await options.reload();
    return { status: "refreshed" };
  } catch (error) {
    return { status: "refresh_failed", error };
  }
}
