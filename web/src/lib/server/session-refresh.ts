import { createHash } from "node:crypto";

import type { NextRequest } from "next/server";

import { backendUrl, safeBackendFetch } from "@/lib/server/backend";
import { signedClientIpHeaders } from "@/lib/server/client-ip";
import type { TokenPair } from "@/lib/server/session";

export type RefreshOutcome =
  | { kind: "refreshed"; pair: TokenPair }
  | { kind: "expired" }
  | { kind: "unavailable"; status: number };

const refreshFlights = new Map<string, Promise<RefreshOutcome>>();

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

export function refreshSessionOnce(
  refreshToken: string,
  request: NextRequest,
): Promise<RefreshOutcome> {
  const fingerprint = createHash("sha256").update(refreshToken).digest("hex");
  const current = refreshFlights.get(fingerprint);
  if (current) return current;

  const pending = refreshSession(refreshToken, request).finally(() => {
    if (refreshFlights.get(fingerprint) === pending) refreshFlights.delete(fingerprint);
  });
  refreshFlights.set(fingerprint, pending);
  return pending;
}
