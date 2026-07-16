import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  createLatestRolePolicyRequestController,
  loadRoleCatalogAndDetail,
  openRolePolicyEditor,
  SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE,
  saveRolePolicy,
  STALE_ROLE_POLICY_MESSAGE,
  STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE,
} from "../src/lib/role-policy-assignment";
import type { Role } from "../src/lib/types";

const role: Role = {
  id: "00000000-0000-4000-8000-000000000301",
  code: "knowledge_editor",
  name: "知识编辑",
  description: null,
  priority: 10,
  is_system: false,
  policy_version: 7,
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  permission_codes: ["knowledge:read"],
  limits: { requests_per_minute: 60 },
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

describe("role policy CAS", () => {
  it("rejects a missing initial version instead of issuing an unsafe replacement", () => {
    expect(() => openRolePolicyEditor({ ...role, policy_version: 0 }))
      .toThrow("角色策略版本无效");
  });

  it("sends the editor snapshot version with the complete policy", async () => {
    const updated = { ...role, policy_version: 8 };
    const request = vi.fn().mockResolvedValue(updated);
    const reloadLatest = vi.fn().mockResolvedValue(undefined);
    const invalidateDraft = vi.fn();

    const result = await saveRolePolicy(openRolePolicyEditor(role), {
      request,
      reloadLatest,
      invalidateDraft,
    });

    expect(result).toEqual({ status: "saved", role: updated });
    expect(request).toHaveBeenCalledWith(`/api/v1/roles/${role.id}/policy`, {
      method: "PUT",
      body: JSON.stringify({
        expected_version: 7,
        permission_codes: ["knowledge:read"],
        limits: { requests_per_minute: 60 },
      }),
    });
    expect(invalidateDraft).toHaveBeenCalledWith("saved");
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
  });

  it("discards a stale draft before refreshing and never retries", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_policy",
    ));
    const invalidateDraft = vi.fn();
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveRolePolicy(openRolePolicyEditor(role), {
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
    expect(STALE_ROLE_POLICY_MESSAGE).toContain("旧编辑草稿已关闭");
  });

  it("keeps the stale draft closed when the refresh fails", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_role_policy",
    ));
    const refreshFailure = new Error("refresh failed");
    let editorOpen = true;
    const invalidateDraft = vi.fn(() => {
      editorOpen = false;
    });
    const reloadLatest = vi.fn().mockRejectedValue(refreshFailure);

    await expect(saveRolePolicy(openRolePolicyEditor(role), {
      request,
      reloadLatest,
      invalidateDraft,
    })).rejects.toBe(refreshFailure);

    expect(editorOpen).toBe(false);
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("stale");
    expect(STALE_ROLE_POLICY_REFRESH_FAILED_MESSAGE).toContain("刷新成功前不能再次提交");
  });

  it("invalidates a committed draft before a failed post-save refresh", async () => {
    const updated = { ...role, policy_version: 8 };
    const request = vi.fn().mockResolvedValue(updated);
    const refreshFailure = new Error("refresh failed");
    let editorOpen = true;
    let roleSnapshotAvailable = true;
    const invalidateDraft = vi.fn(() => {
      editorOpen = false;
      roleSnapshotAvailable = false;
    });
    const reloadLatest = vi.fn().mockRejectedValue(refreshFailure);

    await expect(saveRolePolicy(openRolePolicyEditor(role), {
      request,
      reloadLatest,
      invalidateDraft,
    })).rejects.toBe(refreshFailure);

    expect(editorOpen).toBe(false);
    expect(roleSnapshotAvailable).toBe(false);
    expect(request).toHaveBeenCalledTimes(1);
    expect(invalidateDraft).toHaveBeenCalledWith("saved");
    expect(invalidateDraft.mock.invocationCallOrder[0]).toBeLessThan(
      reloadLatest.mock.invocationCallOrder[0],
    );
    expect(SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE).toContain("角色策略已保存");
    expect(SAVED_ROLE_POLICY_REFRESH_FAILED_MESSAGE).toContain("刷新成功前不能再次提交");
  });

  it("never lets an earlier role GET overwrite a newer completed refresh", async () => {
    const controller = createLatestRolePolicyRequestController();
    const earlier = deferred<Role>();
    const newer = deferred<Role>();
    const olderRole = { ...role, policy_version: 7 };
    const newerRole = { ...role, policy_version: 8, permission_codes: [] };
    let visibleRole: Role | null = null;

    const earlierLoad = controller.run(
      () => earlier.promise,
      (loadedRole) => {
        visibleRole = loadedRole;
      },
    );
    const newerLoad = controller.run(
      () => newer.promise,
      (loadedRole) => {
        visibleRole = loadedRole;
      },
    );

    newer.resolve(newerRole);
    await expect(newerLoad).resolves.toBe("applied");
    expect(visibleRole).toEqual(newerRole);

    earlier.resolve(olderRole);
    await expect(earlierLoad).resolves.toBe("superseded");
    expect(visibleRole).toEqual(newerRole);
  });

  it("does not report a catalog refresh as complete when the selected detail fails", async () => {
    const catalogController = createLatestRolePolicyRequestController();
    const detailFailure = new Error("detail failed");
    const applyCatalog = vi.fn().mockReturnValue(role.id);
    const requestDetail = vi.fn().mockRejectedValue(detailFailure);

    await expect(loadRoleCatalogAndDetail({
      catalogController,
      requestCatalog: async () => [role],
      applyCatalog,
      requestDetail,
    })).rejects.toBe(detailFailure);

    expect(applyCatalog).toHaveBeenCalledWith([role]);
    expect(requestDetail).toHaveBeenCalledWith(role.id);
  });

  it("propagates a superseded detail outcome instead of claiming refreshed", async () => {
    const catalogController = createLatestRolePolicyRequestController();

    await expect(loadRoleCatalogAndDetail({
      catalogController,
      requestCatalog: async () => [role],
      applyCatalog: () => role.id,
      requestDetail: async () => "superseded",
    })).resolves.toBe("superseded");
  });
});
