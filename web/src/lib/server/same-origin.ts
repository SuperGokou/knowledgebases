type ReadableHeaders = {
  get(name: string): string | null;
};

export type SameOriginOptions = {
  production: boolean;
  requestProtocol: string;
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
    const forwardedHost = (headers.get("x-forwarded-host") ?? headers.get("host"))
      ?.split(",", 1)[0]
      ?.trim();
    const forwardedProto = (headers.get("x-forwarded-proto") ?? options.requestProtocol)
      .split(",", 1)[0]
      ?.trim()
      .replace(/:$/, "")
      .toLowerCase();
    if (!forwardedHost || !["http", "https"].includes(forwardedProto)) return false;
    return source.origin === new URL(`${forwardedProto}://${forwardedHost}`).origin;
  } catch {
    return false;
  }
}
