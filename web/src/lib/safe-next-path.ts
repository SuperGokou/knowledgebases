const FALLBACK_PATH = "/chat";
const ALLOWED_PATH = /^\/(?:chat|admin(?:\/(?:knowledge|files|users|roles|accounts|api-models))?)$/;
const UNSAFE_CHARACTER = /[\\\u0000-\u001f\u007f]/;

function hasDotPathSegment(path: string): boolean {
  return path.split("/").some((segment) => segment === "." || segment === "..");
}

function hasUnsafeDecodedPath(rawPath: string): boolean {
  let current = rawPath;
  for (let depth = 0; depth < 3; depth += 1) {
    if (
      UNSAFE_CHARACTER.test(current)
      || current.startsWith("//")
      || hasDotPathSegment(current)
    ) return true;
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      return true;
    }
    if (decoded === current) return false;
    current = decoded;
  }

  // Reject paths which are still encoded after three passes. Redirect targets
  // have no legitimate need for recursively encoded route delimiters.
  try {
    return decodeURIComponent(current) !== current
      || UNSAFE_CHARACTER.test(current)
      || hasDotPathSegment(current);
  } catch {
    return true;
  }
}

export function safeNextPath(value: string | null, origin: string): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("#")) {
    return FALLBACK_PATH;
  }

  const rawPath = value.split("?", 1)[0] ?? "";
  if (hasUnsafeDecodedPath(rawPath)) return FALLBACK_PATH;

  try {
    const trustedOrigin = new URL(origin).origin;
    const target = new URL(value, trustedOrigin);
    if (
      target.origin !== trustedOrigin
      || target.username
      || target.password
      || target.hash
      || !ALLOWED_PATH.test(target.pathname)
    ) {
      return FALLBACK_PATH;
    }
    return `${target.pathname}${target.search}`;
  } catch {
    return FALLBACK_PATH;
  }
}
