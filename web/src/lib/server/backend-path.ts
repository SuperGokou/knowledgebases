const ALLOWED_ROOTS = new Set([
  "files",
  "users",
  "roles",
  "permissions",
  "limits",
  "auth",
  "knowledge-bases",
  "chat",
  "api-keys",
  "llm",
  "audit-logs",
]);

const CANONICAL_SEGMENT = /^[A-Za-z0-9:_-]+$/;

export function backendAcceptHeader(
  parts: readonly string[],
  method: string,
): "application/json" | "text/csv" {
  return method === "GET"
    && parts.length === 4
    && parts[0] === "api"
    && parts[1] === "v1"
    && parts[2] === "audit-logs"
    && parts[3] === "export"
    ? "text/csv"
    : "application/json";
}

export function isAllowedBackendPath(
  parts: readonly string[],
  method: string,
  pathname: string,
): boolean {
  if (parts.length < 3 || parts[0] !== "api" || parts[1] !== "v1") return false;
  if (parts.some((part) => !CANONICAL_SEGMENT.test(part) || part === "." || part === "..")) {
    return false;
  }
  if (pathname !== `/api/backend/${parts.join("/")}`) return false;
  if (parts[2] === "auth") {
    return method === "GET" && parts.length === 4 && parts[3] === "me";
  }
  return ALLOWED_ROOTS.has(parts[2]);
}
