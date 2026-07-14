import { createHash } from "node:crypto";

import type { NextRequest } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { signedClientIpHeaders } from "@/lib/server/client-ip";
import type { TokenPair } from "@/lib/server/session";

export type RefreshOutcome =
  | { kind: "refreshed"; pair: TokenPair }
  | { kind: "expired" }
  | { kind: "unavailable"; status: number };

const refreshFlights = new Set<string>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTokenPair(value: unknown): value is TokenPair {
  return isRecord(value)
    && typeof value.access_token === "string"
    && value.access_token.length > 0
    && typeof value.refresh_token === "string"
    && value.refresh_token.length > 0
    && value.token_type === "bearer"
    && typeof value.expires_in === "number"
    && Number.isInteger(value.expires_in)
    && value.expires_in > 0;
}

async function refreshSession(
  refreshToken: string,
  request: NextRequest,
): Promise<RefreshOutcome> {
  try {
    const response = await safeBackendFetch(backendUrl("/api/v1/auth/refresh"), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...signedClientIpHeaders(request),
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (response.ok) {
      const value = await response.json().catch(() => null);
      return isTokenPair(value)
        ? { kind: "refreshed", pair: value }
        : { kind: "unavailable", status: 502 };
    }
    if (response.status === 401) return { kind: "expired" };
    return { kind: "unavailable", status: response.status };
  } catch {
    // Configuration and signing failures are service availability errors, not
    // proof that the user's refresh token is invalid.
    return { kind: "unavailable", status: 503 };
  }
}

export async function refreshSessionOnce(
  refreshToken: string,
  request: NextRequest,
): Promise<RefreshOutcome> {
  // Never share a one-time rotated credential result between requests. A
  // concurrent bearer receives a retryable response while the first caller is
  // the sole recipient of the backend rotation result.
  const fingerprint = createHash("sha256").update(refreshToken).digest("hex");
  if (refreshFlights.has(fingerprint)) {
    return { kind: "unavailable", status: 409 };
  }
  refreshFlights.add(fingerprint);
  try {
    return await refreshSession(refreshToken, request);
  } finally {
    refreshFlights.delete(fingerprint);
  }
}
