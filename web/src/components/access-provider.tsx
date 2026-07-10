"use client";

import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  ApiClientError,
  apiRequest,
  PERMISSIONS_STALE_EVENT,
  readableError,
} from "../lib/api-client";
import { hasAccessPermission } from "../lib/access-routing";
import type { AuthMe } from "../lib/types";

type AccessContextValue = {
  me: AuthMe | null;
  loading: boolean;
  error: string;
  can: (permission: string) => boolean;
  canAny: (permissions: string[]) => boolean;
  reload: () => Promise<void>;
};

const AccessContext = createContext<AccessContextValue | null>(null);
const PASSIVE_REFRESH_INTERVAL_MS = 30_000;

export type SessionRecoveryOutcome = "cleared" | "stale" | "failed";
export type SessionRecoveryAction = "redirect" | "retry" | "error";

export function sessionRecoveryAction(outcome: SessionRecoveryOutcome): SessionRecoveryAction {
  if (outcome === "cleared") return "redirect";
  if (outcome === "stale") return "retry";
  return "error";
}

export function createSingleFlight<T>(operation: () => Promise<T>): () => Promise<T> {
  let inFlight: Promise<T> | null = null;
  return () => {
    if (inFlight) return inFlight;
    const current = Promise.resolve().then(operation);
    const tracked = current.finally(() => {
      if (inFlight === tracked) inFlight = null;
    });
    inFlight = tracked;
    return tracked;
  };
}

export function isBlockingAccessRefresh(hasLoadedProfile: boolean): boolean {
  return !hasLoadedProfile;
}

class SessionRecoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionRecoveryError";
  }
}

async function closeExpiredSession(error: ApiClientError): Promise<SessionRecoveryOutcome> {
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
  const meRef = useRef<AuthMe | null>(null);
  const lastRefreshAtRef = useRef(0);
  const singleFlightRef = useRef<(() => Promise<void>) | null>(null);

  const performReload = useCallback(async () => {
    const blocksWorkspace = isBlockingAccessRefresh(meRef.current !== null);
    if (blocksWorkspace) setLoading(true);
    setError("");
    try {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const profile = await apiRequest<AuthMe>("/api/v1/auth/me");
          meRef.current = profile;
          setMe(profile);
          return;
        } catch (reason) {
          if (!(reason instanceof ApiClientError) || reason.status !== 401) throw reason;
          const action = sessionRecoveryAction(await closeExpiredSession(reason));
          if (action === "retry") continue;
          meRef.current = null;
          setMe(null);
          if (action === "redirect") {
            window.location.replace("/login");
            return;
          }
          throw new SessionRecoveryError(
            "登录状态已失效，但安全会话暂时无法清理。请重试；系统不会自动跳转。",
          );
        }
      }
      meRef.current = null;
      setMe(null);
      throw new SessionRecoveryError("会话正在更新，请稍后重试。");
    } catch (reason) {
      if (reason instanceof SessionRecoveryError || meRef.current === null) {
        setError(readableError(reason));
      }
    } finally {
      lastRefreshAtRef.current = Date.now();
      setLoading(false);
    }
  }, []);

  const reload = useCallback(() => {
    if (!singleFlightRef.current) {
      singleFlightRef.current = createSingleFlight(performReload);
    }
    return singleFlightRef.current();
  }, [performReload]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void reload(), 0);
    return () => window.clearTimeout(timeout);
  }, [reload]);

  useEffect(() => {
    const refreshPermissions = () => void reload();
    const refreshPassively = () => {
      const now = Date.now();
      if (now - lastRefreshAtRef.current < PASSIVE_REFRESH_INTERVAL_MS) return;
      lastRefreshAtRef.current = now;
      void reload();
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") refreshPassively();
    };
    window.addEventListener("focus", refreshPassively);
    window.addEventListener(PERMISSIONS_STALE_EVENT, refreshPermissions);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.removeEventListener("focus", refreshPassively);
      window.removeEventListener(PERMISSIONS_STALE_EVENT, refreshPermissions);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [reload]);

  const value = useMemo<AccessContextValue>(() => {
    const can = (permission: string) => Boolean(me && hasAccessPermission(me, permission));
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
