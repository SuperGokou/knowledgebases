import type { AuthMe } from "./types";

import { safeNextPathOrNull } from "./safe-next-path";

export type AccessPrincipal = Pick<AuthMe, "is_superuser" | "permission_codes">;

const CONTROL_PLANE_PERMISSIONS = new Set([
  "user:manage",
  "role:read",
  "api-key:manage",
  "llm:manage",
]);

// The knowledge page can load its first screen with knowledge:read, or expose
// a create-only state without listing existing knowledge bases.
const KNOWLEDGE_PAGE_PERMISSIONS = new Set(["knowledge:read", "knowledge:create"]);

// The files page can load its list with file:read, or expose an upload-only
// state. Approval and deletion require a visible file list and therefore do
// not grant page entry on their own.
const FILE_PAGE_PERMISSIONS = new Set(["file:read", "file:upload"]);

function permissionSet(me: AccessPrincipal): Set<string> {
  return new Set(me.permission_codes);
}

function hasGrantedPermission(permissions: ReadonlySet<string>, required: string): boolean {
  if (permissions.has("*") || permissions.has(required)) return true;
  const separator = required.indexOf(":");
  return separator > 0 && permissions.has(`${required.slice(0, separator)}:*`);
}

function hasAny(permissions: ReadonlySet<string>, expected: ReadonlySet<string>): boolean {
  for (const permission of expected) {
    if (hasGrantedPermission(permissions, permission)) return true;
  }
  return false;
}

function canonicalPath(path: string): string {
  return path.split("?", 1)[0] ?? path;
}

export function defaultLandingPath(me: AccessPrincipal): string {
  const permissions = permissionSet(me);

  if (me.is_superuser || hasAny(permissions, CONTROL_PLANE_PERMISSIONS)) return "/admin";
  if (hasGrantedPermission(permissions, "knowledge:create")) return "/admin/knowledge";
  if (hasGrantedPermission(permissions, "file:upload")) return "/admin/files";
  if (hasGrantedPermission(permissions, "chat:query")) return "/chat";
  if (hasAny(permissions, KNOWLEDGE_PAGE_PERMISSIONS)) return "/admin/knowledge";
  if (hasAny(permissions, FILE_PAGE_PERMISSIONS)) return "/admin/files";
  return "/access-pending";
}

export function hasAccessPermission(me: AccessPrincipal, required: string): boolean {
  return me.is_superuser || hasGrantedPermission(permissionSet(me), required);
}

export function canAccessPath(path: string, me: AccessPrincipal): boolean {
  const pathname = canonicalPath(path);
  const permissions = permissionSet(me);
  if (me.is_superuser) {
    return pathname === "/chat"
      || pathname === "/admin"
      || pathname.startsWith("/admin/");
  }

  switch (pathname) {
    case "/chat":
      return hasGrantedPermission(permissions, "chat:query");
    case "/admin":
      return hasAny(permissions, CONTROL_PLANE_PERMISSIONS);
    case "/admin/knowledge":
      return hasAny(permissions, KNOWLEDGE_PAGE_PERMISSIONS);
    case "/admin/files":
      return hasAny(permissions, FILE_PAGE_PERMISSIONS);
    case "/admin/users":
    case "/admin/accounts":
      return hasGrantedPermission(permissions, "user:manage");
    case "/admin/roles":
      return hasGrantedPermission(permissions, "role:read");
    case "/admin/api-models":
      return hasGrantedPermission(permissions, "api-key:manage")
        || hasGrantedPermission(permissions, "llm:manage");
    case "/access-pending":
      return defaultLandingPath(me) === "/access-pending";
    default:
      return false;
  }
}

export function resolveLandingPath(
  me: AccessPrincipal,
  requestedNext: string | null | undefined,
  origin: string,
): string {
  const safeRequestedPath = safeNextPathOrNull(requestedNext, origin);
  if (safeRequestedPath && canAccessPath(safeRequestedPath, me)) return safeRequestedPath;
  return defaultLandingPath(me);
}
