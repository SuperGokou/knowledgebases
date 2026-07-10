import { createHmac } from "node:crypto";
import { isIP } from "node:net";

export class BffSigningConfigurationError extends Error {
  constructor() {
    super("FASTAPI_BFF_SHARED_SECRET must contain at least 32 characters in production.");
    this.name = "BffSigningConfigurationError";
  }
}

export type ClientIpSigningOptions = {
  secret: string;
  production: boolean;
  now: () => number;
};

type ReadableHeaders = {
  get(name: string): string | null;
};

function firstValidIp(value: string | null): string | null {
  if (!value) return null;
  const raw = value.split(",", 1)[0]?.trim();
  if (!raw) return null;
  if (isIP(raw)) return raw;
  const bracketed = raw.match(/^\[([^\]]+)](?::\d+)?$/);
  if (bracketed && isIP(bracketed[1]) !== 0) return bracketed[1];
  const ipv4WithPort = raw.match(/^([^:]+):(\d+)$/);
  if (ipv4WithPort && isIP(ipv4WithPort[1]) === 4) return ipv4WithPort[1];
  return null;
}

export function createSignedClientIpHeaders(
  headers: ReadableHeaders,
  options: ClientIpSigningOptions,
): Record<string, string> {
  if (options.secret.length < 32) {
    if (options.production) throw new BffSigningConfigurationError();
    return {};
  }

  const ip = firstValidIp(headers.get("x-vercel-forwarded-for"))
    ?? firstValidIp(headers.get("x-forwarded-for"))
    ?? firstValidIp(headers.get("x-real-ip"));
  if (!ip) return {};

  const timestamp = String(Math.floor(options.now() / 1000));
  const canonical = `v1\n${timestamp}\n${ip}`;
  return {
    "X-KB-Client-IP": ip,
    "X-KB-Client-Timestamp": timestamp,
    "X-KB-Client-Signature": createHmac("sha256", options.secret).update(canonical).digest("hex"),
  };
}
