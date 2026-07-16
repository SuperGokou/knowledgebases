import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  createLatestRequestController,
  openRoleAssignmentEditor,
  SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE,
  saveUserRoleAssignment,
  STALE_ROLE_ASSIGNMENT_MESSAGE,
  STALE_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE,
} from "../src/lib/user-role-assignment";
import type { User } from "../src/lib/types";

const user: User = {
  id: "00000000-0000-4000-8000-000000000101",
  email: "member@example.com",
  display_name: "验收成员",
  status: "active",
  is_superuser: false,
  role_assignment_version: 7,
  retired_at: null,
  retired_by_id: null,
  retirement_reason: null,
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  role_ids: ["00000000-0000-4000-8000-000000000201"],
};

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

describe("user role assignment CAS", () => {
  it("rejects a missing initial CAS version instead of issuing an unsafe update", () => {
    expect(() => openRoleAssignmentEditor({
      ...user,
      role_assignment_version: 0,
    })).toThrow("成员角色版本无效");
  });

  it("saves a role set and reloads the latest users", async () => {
    const updated = { ...user, role_assignment_version: 8, role_ids: [] };
    const request = vi.fn().mockResolvedValue(updated);
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveUserRoleAssignment(
      { ...openRoleAssignmentEditor(user), roleIds: [] },
      { request, reloadLatest, invalidateDraft },
    );

    expect(result).toEqual({ status: "saved", user: updated });
    expect(invalidateDraft).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("saved");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
  });

  it("sends the editor snapshot version with the selected role IDs", async () => {
    const request = vi.fn().mockResolvedValue(user);

    await saveUserRoleAssignment(
      {
        userId: user.id,
        expectedVersion: 7,
        roleIds: ["00000000-0000-4000-8000-000000000202"],
      },
      {
        request,
        reloadLatest: vi.fn().mockResolvedValue(undefined),
        invalidateDraft: vi.fn(),
      },
    );

    expect(request).toHaveBeenCalledWith(`/api/v1/users/${user.id}/roles`, {
      method: "PUT",
      body: JSON.stringify({
        role_ids: ["00000000-0000-4000-8000-000000000202"],
        expected_version: 7,
      }),
    });
  });

  it("refreshes once on a stale assignment without retrying the overwrite", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_assignment",
    ));
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveUserRoleAssignment(openRoleAssignmentEditor(user), {
      request,
      reloadLatest,
      invalidateDraft,
    });

    expect(result).toEqual({ status: "stale" });
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("stale");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
    expect(STALE_ROLE_ASSIGNMENT_MESSAGE).toContain("已被其他管理员更新");
    expect(STALE_ROLE_ASSIGNMENT_MESSAGE).toContain("已加载最新数据");
    expect(STALE_ROLE_ASSIGNMENT_MESSAGE).toContain("旧编辑草稿已关闭");
  });

  it("discards the stale draft before a failed refresh and never retries it", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_assignment",
    ));
    const refreshFailure = new Error("refresh failed");
    let editorOpen = true;
    const invalidateDraft = vi.fn(() => {
      editorOpen = false;
    });
    const reloadLatest = vi.fn().mockRejectedValue(refreshFailure);

    await expect(saveUserRoleAssignment(openRoleAssignmentEditor(user), {
      request,
      reloadLatest,
      invalidateDraft,
    })).rejects.toBe(refreshFailure);

    expect(editorOpen).toBe(false);
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("stale");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
    expect(STALE_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE).toContain("刷新成功前不能再次分配角色");
  });

  it("invalidates a committed draft before a failed post-save refresh", async () => {
    const updated = { ...user, role_assignment_version: 8, role_ids: [] };
    const request = vi.fn().mockResolvedValue(updated);
    const refreshFailure = new ApiClientError(
      "refresh conflict",
      409,
      "stale_role_assignment",
    );
    let editorOpen = true;
    let usersSnapshotAvailable = true;
    const invalidateDraft = vi.fn(() => {
      editorOpen = false;
      usersSnapshotAvailable = false;
    });
    const reloadLatest = vi.fn().mockRejectedValue(refreshFailure);

    await expect(saveUserRoleAssignment(openRoleAssignmentEditor(user), {
      request,
      reloadLatest,
      invalidateDraft,
    })).rejects.toBe(refreshFailure);

    expect(editorOpen).toBe(false);
    expect(usersSnapshotAvailable).toBe(false);
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("saved");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
    expect(SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE).toContain("成员角色已保存");
    expect(SAVED_ROLE_ASSIGNMENT_REFRESH_FAILED_MESSAGE).toContain("刷新成功前不能再次分配角色");
  });

  it("never lets an earlier GET overwrite a newer completed refresh", async () => {
    const controller = createLatestRequestController();
    const earlier = deferred<User[]>();
    const newer = deferred<User[]>();
    const earlierUsers = [{ ...user, role_assignment_version: 7 }];
    const newerUsers = [{ ...user, role_assignment_version: 8, role_ids: [] }];
    let visibleUsers: User[] = [];

    const earlierLoad = controller.run(
      () => earlier.promise,
      (loadedUsers) => {
        visibleUsers = loadedUsers;
      },
    );
    const newerLoad = controller.run(
      () => newer.promise,
      (loadedUsers) => {
        visibleUsers = loadedUsers;
      },
    );

    newer.resolve(newerUsers);
    await expect(newerLoad).resolves.toBe("applied");
    expect(visibleUsers).toEqual(newerUsers);

    earlier.resolve(earlierUsers);
    await expect(earlierLoad).resolves.toBe("superseded");
    expect(visibleUsers).toEqual(newerUsers);
  });
});
