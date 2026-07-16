import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  canResetUserPassword,
  passwordResetRevokesCurrentSession,
  readablePasswordResetError,
  resetUserPassword,
  validatePasswordReset,
} from "../src/lib/user-password-reset";

const usersPanel = readFileSync(
  join(process.cwd(), "src/components/users-panel.tsx"),
  "utf8",
);

describe("member password reset", () => {
  it("requires the current administrator session to close after a self reset", () => {
    expect(passwordResetRevokesCurrentSession("user-1", "user-1")).toBe(true);
    expect(passwordResetRevokesCurrentSession("user-2", "user-1")).toBe(false);
    expect(passwordResetRevokesCurrentSession("user-1", null)).toBe(false);
  });

  it("only exposes another account reset to a superuser", () => {
    expect(canResetUserPassword("user-1", "user-1", false)).toBe(true);
    expect(canResetUserPassword("user-2", "user-1", true)).toBe(true);
    expect(canResetUserPassword("user-2", "user-1", false)).toBe(false);
    expect(canResetUserPassword("user-2", null, true)).toBe(false);
  });

  it("uses the shared password validator before creating a member", () => {
    expect(usersPanel).toContain("validateStrongPassword(password);");
  });

  it.each([
    ["invalid_current_password", 401, "当前密码不正确"],
    ["current_password_required", 422, "必须输入当前密码"],
    ["current_password_not_allowed", 422, "请勿填写其当前密码"],
    ["superuser_required", 403, "只有超级管理员"],
  ])("renders the %s security error in Chinese", (code, status, message) => {
    expect(readablePasswordResetError(new ApiClientError("server message", status, code)))
      .toContain(message);
  });

  it("requires a strong matching confirmation and the current password for self changes", () => {
    expect(() => validatePasswordReset({
      userId: "user-1",
      isSelf: false,
      currentPassword: "",
      newPassword: "abcdefghijkl",
      confirmation: "abcdefghijkl",
    }))
      .toThrow("大写字母");
    expect(() => validatePasswordReset({
      userId: "user-1",
      isSelf: false,
      currentPassword: "",
      newPassword: "Strong-password-123!",
      confirmation: "different",
    }))
      .toThrow("两次输入的密码不一致");
    expect(() => validatePasswordReset({
      userId: "user-1",
      isSelf: true,
      currentPassword: "",
      newPassword: "Strong-password-123!",
      confirmation: "Strong-password-123!",
    })).toThrow("当前密码");
  });

  it.each([
    "Valid-Password-123!汉",
    "Valid-Password-123!é",
    "Valid-Password-123!😀",
  ])("rejects non-ASCII password code points: %s", (newPassword) => {
    expect(() => validatePasswordReset({
      userId: "user-1",
      isSelf: false,
      currentPassword: "",
      newPassword,
      confirmation: newPassword,
    })).toThrow("ASCII");
  });

  it("accepts the printable ASCII boundary symbol", () => {
    expect(() => validatePasswordReset({
      userId: "user-1",
      isSelf: false,
      currentPassword: "",
      newPassword: "Ascii-Boundary-123~",
      confirmation: "Ascii-Boundary-123~",
    })).not.toThrow();
  });

  it("sends only the new password when a superuser resets another account", async () => {
    const request = vi.fn().mockResolvedValue(undefined);

    await resetUserPassword({
      userId: "00000000-0000-4000-8000-000000000401",
      isSelf: false,
      currentPassword: "",
      newPassword: "Strong-password-123!",
      confirmation: "Strong-password-123!",
    }, request);

    expect(request).toHaveBeenCalledWith(
      "/api/v1/users/00000000-0000-4000-8000-000000000401/password",
      {
        method: "PUT",
        body: JSON.stringify({ new_password: "Strong-password-123!" }),
      },
    );
    const body = String(request.mock.calls[0]?.[1]?.body);
    expect(body).not.toContain("confirmation");
    expect(body).not.toContain("old_password");
    expect(body).not.toContain("current_password");
  });

  it("sends the current password only when changing the signed-in account", async () => {
    const request = vi.fn().mockResolvedValue(undefined);

    await resetUserPassword({
      userId: "00000000-0000-4000-8000-000000000401",
      isSelf: true,
      currentPassword: "Current-password-123!",
      newPassword: "Strong-password-456!",
      confirmation: "Strong-password-456!",
    }, request);

    expect(request).toHaveBeenCalledWith(
      "/api/v1/users/me/password",
      {
        method: "PUT",
        body: JSON.stringify({
          current_password: "Current-password-123!",
          new_password: "Strong-password-456!",
        }),
      },
    );
    const body = String(request.mock.calls[0]?.[1]?.body);
    expect(body).not.toContain("confirmation");
    expect(body).not.toContain("old_password");
  });
});
