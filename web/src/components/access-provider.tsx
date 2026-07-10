"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import type { AuthMe } from "@/lib/types";

type AccessContextValue = {
  me: AuthMe | null;
  loading: boolean;
  error: string;
  can: (permission: string) => boolean;
  canAny: (permissions: string[]) => boolean;
  reload: () => Promise<void>;
};

const AccessContext = createContext<AccessContextValue | null>(null);

async function closeExpiredSession(error: ApiClientError): Promise<"cleared" | "stale" | "failed"> {
  const details = error.details && typeof error.details === "object"
    ? error.details as { session_marker?: unknown }
    : null;
  const sessionMarker = typeof details?.session_marker === "string" ? details.session_marker : null;
  try {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_marker: sessionMarker }),
    });
    if (!response.ok) return "failed";
    const result = (await response.json()) as { stale?: boolean };
    return result.stale ? "stale" : "cleared";
  } catch {
    return "failed";
  }
}

export function AccessProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<AuthMe | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          setMe(await apiRequest<AuthMe>("/api/v1/auth/me"));
          return;
        } catch (reason) {
          if (!(reason instanceof ApiClientError) || reason.status !== 401) throw reason;
          setMe(null);
          const logout = await closeExpiredSession(reason);
          if (logout !== "stale") {
            window.location.replace("/login");
            return;
          }
        }
      }
      setError("会话正在更新，请刷新页面后重试。");
    } catch (reason) {
      setMe(null);
      setError(readableError(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timeout = window.setTimeout(() => void reload(), 0);
    return () => window.clearTimeout(timeout);
  }, [reload]);

  const value = useMemo<AccessContextValue>(() => {
    const can = (permission: string) => Boolean(me?.is_superuser || me?.permission_codes.includes(permission));
    return {
      me,
      loading,
      error,
      can,
      canAny: (permissions) => permissions.some(can),
      reload,
    };
  }, [error, loading, me, reload]);

  return <AccessContext.Provider value={value}>{children}</AccessContext.Provider>;
}

export function useAccess(): AccessContextValue {
  const value = useContext(AccessContext);
  if (!value) throw new Error("useAccess 必须在 AccessProvider 内使用。");
  return value;
}
