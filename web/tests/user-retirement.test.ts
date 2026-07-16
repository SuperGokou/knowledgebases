import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import type { AuthMe, User } from "../src/lib/types";
import {
  canRetireUser,
  eligibleReplacementOwners,
  mergeReplacementOwnerSearchResults,
  readableUserRetirementError,
  retireUser,
  retireUserWithRefresh,
  validateUserRetirement,
} from "../src/lib/user-retirement";

const usersPanel = readFileSync(
  join(process.cwd(), "src/components/users-panel.tsx"),
  "utf8",
);

const member: User = {
  id: "00000000-0000-4000-8000-000000000401",
  email: "member@example.com",
  display_name: "Member",
  status: "active",
  is_superuser: false,
  role_assignment_version: 1,
  retired_at: null,
  retired_by_id: null,
  retirement_reason: null,
  created_at: "2026-07-15T00:00:00Z",
  updated_at: "2026-07-15T00:00:00Z",
  role_ids: [],
};

const administrator: AuthMe = {
  id: "00000000-0000-4000-8000-000000000402",
  email: "admin@example.com",
  display_name: "Admin",
  status: "active",
  is_superuser: true,
  permission_codes: ["*"],
  role_ids: [],
  limits: {},
};

describe("auditable member retirement", () => {
  it("renders a strong-confirmation dialog and disables protected lifecycle actions", () => {
    expect(usersPanel).toContain('aria-labelledby="user-retirement-editor-title"');
    expect(usersPanel).toContain('aria-describedby="user-retirement-editor-description"');
    expect(usersPanel).toContain("autoFocus");
    expect(usersPanel).toContain('event.key === "Escape"');
    expect(usersPanel).toContain("完整输入");
    expect(usersPanel).toContain("retirementEditor.confirmationEmail.trim() !== retirementEditor.email");
    expect(usersPanel).toContain("pending || retired || protectedTarget");
    expect(usersPanel).toContain('retired ? "已退休"');
    expect(usersPanel).toContain("canRetireUser(user, me)");
  });

  it("does not claim an unverified successor transfer after an idempotent retirement", () => {
    expect(usersPanel).not.toContain("知识库已按选择完成接管");
    expect(usersPanel).toContain("知识库实际接管结果请在知识库与审计记录中核验");
  });

  it("hides the destructive action for self, retired users, and protected superusers", () => {
    expect(canRetireUser(member, administrator)).toBe(true);
    expect(canRetireUser({ ...member, id: administrator.id }, administrator)).toBe(false);
    expect(canRetireUser({ ...member, retired_at: "2026-07-15T01:00:00Z" }, administrator)).toBe(false);
    expect(canRetireUser({ ...member, is_superuser: true }, { ...administrator, is_superuser: false }))
      .toBe(false);
    expect(canRetireUser({ ...member, is_superuser: true }, administrator)).toBe(true);
  });

  it("requires the exact target email and bounds the operator reason", () => {
    expect(() => validateUserRetirement({
      userId: member.id,
      email: member.email,
      confirmationEmail: "wrong@example.com",
      reason: "Employment ended",
      replacementOwnerId: "",
    })).toThrow("完整输入成员邮箱");
    expect(() => validateUserRetirement({
      userId: member.id,
      email: member.email,
      confirmationEmail: "Member@example.com",
      reason: "Employment ended",
      replacementOwnerId: "",
    })).toThrow("完整输入成员邮箱");
    expect(() => validateUserRetirement({
      userId: member.id,
      email: member.email,
      confirmationEmail: member.email,
      reason: "x".repeat(1_001),
      replacementOwnerId: "",
    })).toThrow("不能超过 1000");
  });

  it("sends an idempotent DELETE with confirmation, reason, and optional successor", async () => {
    const request = vi.fn().mockResolvedValue(undefined);
    await retireUser({
      userId: member.id,
      email: member.email,
      confirmationEmail: member.email,
      reason: "  Employment ended  ",
      replacementOwnerId: administrator.id,
    }, request);

    expect(request).toHaveBeenCalledWith(`/api/v1/users/${member.id}`, {
      method: "DELETE",
      body: JSON.stringify({
        confirmation_email: member.email,
        reason: "Employment ended",
        replacement_owner_id: administrator.id,
      }),
    });
  });

  it("only offers active, non-retired, non-target successor accounts", () => {
    const eligible = eligibleReplacementOwners([
      member,
      { ...member, id: administrator.id, email: administrator.email },
      { ...member, id: "retired", email: "retired@example.com", retired_at: "2026-07-15T01:00:00Z" },
      { ...member, id: "disabled", email: "disabled@example.com", status: "disabled" },
    ], member.id);

    expect(eligible.map((candidate) => candidate.id)).toEqual([administrator.id]);
  });

  it("pins the selected successor across searches instead of submitting a hidden stale id", () => {
    const successorA = { ...member, id: administrator.id, email: administrator.email };
    const successorB = {
      ...member,
      id: "00000000-0000-4000-8000-000000000403",
      email: "successor-b@example.com",
    };

    const merged = mergeReplacementOwnerSearchResults(
      [successorA],
      [successorB],
      member.id,
      successorA.id,
    );

    expect(merged.map((candidate) => candidate.id)).toEqual([successorA.id, successorB.id]);
    expect(merged.some((candidate) => candidate.id === successorA.id)).toBe(true);
  });

  it("never reports a committed retirement as failed when list refresh fails", async () => {
    const order: string[] = [];
    const refreshError = new Error("reload unavailable");
    const result = await retireUserWithRefresh({
      userId: member.id,
      email: member.email,
      confirmationEmail: member.email,
      reason: "",
      replacementOwnerId: "",
    }, {
      request: vi.fn().mockImplementation(async () => { order.push("committed"); }),
      onCommitted: () => { order.push("notified"); },
      reload: vi.fn().mockImplementation(async () => {
        order.push("reload");
        throw refreshError;
      }),
    });

    expect(order).toEqual(["committed", "notified", "reload"]);
    expect(result).toEqual({ status: "refresh_failed", error: refreshError });
  });

  it("does not run commit UI or reload when DELETE itself fails", async () => {
    const onCommitted = vi.fn();
    const reload = vi.fn();
    await expect(retireUserWithRefresh({
      userId: member.id,
      email: member.email,
      confirmationEmail: member.email,
      reason: "",
      replacementOwnerId: "",
    }, {
      request: vi.fn().mockRejectedValue(new Error("delete failed")),
      onCommitted,
      reload,
    })).rejects.toThrow("delete failed");
    expect(onCommitted).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it.each([
    ["self_retirement_forbidden", "不能删除当前登录账号"],
    ["last_superuser_protected", "最后一个活跃超级管理员"],
    ["user_ownership_conflict", "转移该成员名下的知识库"],
    ["replacement_owner_invalid", "接管成员必须处于正常状态"],
    ["replacement_owner_not_found", "未找到接管成员"],
    ["retirement_confirmation_mismatch", "确认邮箱不匹配"],
  ])("renders the %s denial in Chinese", (code, expected) => {
    expect(readableUserRetirementError(new ApiClientError("server", 409, code)))
      .toContain(expected);
  });
});
