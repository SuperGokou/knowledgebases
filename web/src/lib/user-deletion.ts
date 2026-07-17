import type { AuthMe, User } from "@/lib/types";

type CurrentUser = Pick<AuthMe, "id" | "is_superuser">;
type DeleteTarget = Pick<User, "id">;
type DeleteRequest = (path: string, init: RequestInit) => Promise<void>;

export function canDeleteUser(me: CurrentUser | null, target: DeleteTarget): boolean {
  return Boolean(me?.is_superuser && me.id !== target.id);
}

export async function deleteUser(userId: string, request: DeleteRequest): Promise<void> {
  await request(`/api/v1/users/${userId}`, { method: "DELETE" });
}
