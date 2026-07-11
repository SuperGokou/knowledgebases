const SAFE_IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/;

export type DigestError = Error & { digest?: unknown };

export function safeErrorDigest(error: DigestError): string | null {
  return typeof error.digest === "string" && SAFE_IDENTIFIER.test(error.digest)
    ? error.digest
    : null;
}

function fallbackIdentifier(): string {
  try {
    return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
  } catch {
    return `${Date.now()}-${Math.random()}`;
  }
}

export function workspaceErrorCode(
  error: DigestError,
  createFallback: () => string = fallbackIdentifier,
): string {
  const identifier = safeErrorDigest(error) ?? createFallback();
  const normalized = identifier.replace(/[^A-Za-z0-9._-]/g, "").slice(0, 32) || "unknown";
  return `WEB-${normalized}`;
}

export function workspaceErrorLogRecord(error: DigestError, errorCode: string) {
  return {
    event: "workspace_render_error",
    error_code: errorCode,
    digest: safeErrorDigest(error),
    error_name: SAFE_IDENTIFIER.test(error.name) ? error.name : "Error",
  };
}
