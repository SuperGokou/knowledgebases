import "server-only";

import type { NextRequest } from "next/server";

import { createSignedClientIpHeaders } from "@/lib/server/client-ip-signing";

export { BffSigningConfigurationError } from "@/lib/server/client-ip-signing";

export function signedClientIpHeaders(request: NextRequest): Record<string, string> {
  return createSignedClientIpHeaders(request.headers, {
    secret: process.env.FASTAPI_BFF_SHARED_SECRET ?? "",
    production: process.env.NODE_ENV === "production",
    now: Date.now,
  });
}
