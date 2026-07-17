import { describe, expect, it, vi } from "vitest";

import { canDeleteUser, deleteUser } from "../src/lib/user-deletion";
import type { AuthMe, User } from "../src/lib/types";

const currentUser = {
  id: "95c3fdf0-feec-4bd2-974b-9e2a2a88509e",
  is_superuser: true,
} as AuthMe;

const targetUser = {
  id: "0d124c10-e845-47a9-913b-fe2771185f5c",
} as User;

describe("账号删除策略", () => {
  it("只允许超级管理员删除其他账号", () => {
    expect(canDeleteUser(currentUser, targetUser)).toBe(true);
    expect(canDeleteUser({ ...currentUser, is_superuser: false }, targetUser)).toBe(false);
    expect(canDeleteUser(currentUser, { ...targetUser, id: currentUser.id })).toBe(false);
    expect(canDeleteUser(null, targetUser)).toBe(false);
  });

  it("使用 DELETE 调用指定账号接口", async () => {
    const request = vi.fn<(path: string, init: RequestInit) => Promise<void>>()
      .mockResolvedValue(undefined);

    await deleteUser(targetUser.id, request);

    expect(request).toHaveBeenCalledWith(`/api/v1/users/${targetUser.id}`, {
      method: "DELETE",
    });
  });
});
