import { ApiClientError, apiRequest, readableError } from "./api-client";

export type UserPasswordResetEditor = {
  userId: string;
  isSelf: boolean;
  currentPassword: string;
  newPassword: string;
  confirmation: string;
};

export type UserPasswordResetRequest = (
  path: string,
  init: RequestInit,
) => Promise<void>;

export function passwordResetRevokesCurrentSession(
  targetUserId: string,
  currentUserId: string | null | undefined,
): boolean {
  return Boolean(currentUserId && targetUserId === currentUserId);
}

export function canResetUserPassword(
  targetUserId: string,
  currentUserId: string | null | undefined,
  currentUserIsSuperuser: boolean,
): boolean {
  if (!currentUserId) return false;
  return targetUserId === currentUserId || currentUserIsSuperuser;
}

export function readablePasswordResetError(error: unknown): string {
  if (error instanceof ApiClientError) {
    const messageByCode: Record<string, string> = {
      invalid_current_password: "当前密码不正确，请重新输入。",
      current_password_required: "修改自己的密码时必须输入当前密码。",
      current_password_not_allowed: "为其他成员重置密码时请勿填写其当前密码。",
      superuser_required: "只有超级管理员可以重置其他成员的密码。",
    };
    if (error.code && messageByCode[error.code]) return messageByCode[error.code];
  }
  return readableError(error);
}

export function validateStrongPassword(newPassword: string): void {
  if (newPassword.length < 12 || newPassword.length > 256) {
    throw new Error("新密码必须为 12 到 256 个字符。");
  }
  if (/\s/u.test(newPassword)) {
    throw new Error("新密码不能包含空白字符。");
  }
  if (!/^[\x21-\x7E]+$/u.test(newPassword)) {
    throw new Error("新密码只能使用可打印 ASCII 字符（不含空格）。");
  }
  if (
    !/[a-z]/u.test(newPassword)
    || !/[A-Z]/u.test(newPassword)
    || !/[0-9]/u.test(newPassword)
    || !/[^A-Za-z0-9]/u.test(newPassword)
  ) {
    throw new Error("新密码必须同时包含小写字母、大写字母、数字和符号。");
  }
}

export function validatePasswordReset(editor: UserPasswordResetEditor): void {
  const { confirmation, currentPassword, isSelf, newPassword } = editor;
  validateStrongPassword(newPassword);
  if (newPassword !== confirmation) {
    throw new Error("两次输入的密码不一致。");
  }
  if (isSelf && !currentPassword) {
    throw new Error("修改自己的密码时必须输入当前密码。");
  }
}

export async function resetUserPassword(
  editor: UserPasswordResetEditor,
  request: UserPasswordResetRequest = (path, init) => apiRequest<void>(path, init),
): Promise<void> {
  validatePasswordReset(editor);
  const payload = editor.isSelf
    ? { current_password: editor.currentPassword, new_password: editor.newPassword }
    : { new_password: editor.newPassword };
  const path = editor.isSelf
    ? "/api/v1/users/me/password"
    : `/api/v1/users/${editor.userId}/password`;
  await request(path, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}
