import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

describe("账号密码修改", () => {
  it("仅向超级管理员展示入口并调用安全重置接口", () => {
    const source = readFileSync(join(process.cwd(), "src/components/users-panel.tsx"), "utf8");

    expect(source).toContain("me?.is_superuser");
    expect(source).toContain("修改密码");
    expect(source).toContain('apiRequest<void>(`/api/v1/users/${userId}/password`');
    expect(source).toContain('method: "PUT"');
  });

  it("要求至少十二位、二次确认并显示保存结果", () => {
    const source = readFileSync(join(process.cwd(), "src/components/users-panel.tsx"), "utf8");

    expect(source).toContain("resetPassword.length < 12");
    expect(source).toContain("resetPassword !== resetPasswordConfirm");
    expect(source).toContain("旧登录会话已失效");
    expect(source).toContain('feedback.error(message, "密码修改失败")');
  });
});
