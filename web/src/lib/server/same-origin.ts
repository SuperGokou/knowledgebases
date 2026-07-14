type ReadableHeaders = {
  get(name: string): string | null;
};

export type SameOriginOptions = {
  production: boolean;
  trustedOrigin: string | undefined;
};

export function isSameOriginRequest(
  headers: ReadableHeaders,
  options: SameOriginOptions,
): boolean {
  const fetchSite = headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin") return false;

  const origin = headers.get("origin");
  if (!origin) return !options.production;

  try {
    const source = new URL(origin);
    if (!options.trustedOrigin) return false;
    const trusted = new URL(options.trustedOrigin);
    if (
      !["http:", "https:"].includes(trusted.protocol)
      || trusted.username
      || trusted.password
      || trusted.pathname !== "/"
      || trusted.search
      || trusted.hash
    ) return false;
    return source.origin === trusted.origin;
  } catch {
    return false;
  }
}
