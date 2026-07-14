const DEFAULT_BACKEND = "http://127.0.0.1:8000";
const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
const MIN_REQUEST_TIMEOUT_MS = 1_000;
const MAX_REQUEST_TIMEOUT_MS = 120_000;

export class BackendConfigurationError extends Error {
  constructor() {
    super("FASTAPI_URL must be a valid HTTP(S) origin without embedded credentials");
    this.name = "BackendConfigurationError";
  }
}

export class PublicApiOriginConfigurationError extends Error {
  constructor() {
    super(
      "KB_PUBLIC_API_ORIGIN must be a valid HTTP(S) origin without credentials, path, query, or fragment",
    );
    this.name = "PublicApiOriginConfigurationError";
  }
}

type PublicApiOriginEnvironment = Readonly<Record<string, string | undefined>>;

export type SafeBackendFetchInit = RequestInit & {
  timeoutMs?: number;
};

export function backendRequestTimeoutMs(
  configured = process.env.FASTAPI_REQUEST_TIMEOUT_MS,
): number {
  if (!configured) return DEFAULT_REQUEST_TIMEOUT_MS;
  const parsed = Number(configured);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.min(MAX_REQUEST_TIMEOUT_MS, Math.max(MIN_REQUEST_TIMEOUT_MS, Math.trunc(parsed)));
}

export function backendOrigin(): string {
  const configured = process.env.FASTAPI_URL?.trim() || DEFAULT_BACKEND;
  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    throw new BackendConfigurationError();
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new BackendConfigurationError();
  }
  return url.origin;
}

export function publicApiOrigin(
  environment: PublicApiOriginEnvironment = process.env,
): string | undefined {
  const explicitOrigin = environment.KB_PUBLIC_API_ORIGIN?.trim();
  const vercelBackendOrigin = environment.VERCEL === "1"
    ? environment.FASTAPI_URL?.trim()
    : undefined;
  const configured = explicitOrigin || vercelBackendOrigin;
  if (!configured) return undefined;

  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    throw new PublicApiOriginConfigurationError();
  }
  if (
    !["http:", "https:"].includes(url.protocol)
    || url.username
    || url.password
    || url.pathname !== "/"
    || url.search
    || url.hash
  ) {
    throw new PublicApiOriginConfigurationError();
  }
  return url.origin;
}

export function backendUrl(path: string, search = ""): URL {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, backendOrigin());
  url.search = search;
  return url;
}

function abortError(name: "AbortError" | "TimeoutError"): Error {
  const error = new Error(name === "TimeoutError" ? "Backend request timed out" : "Backend request cancelled");
  error.name = name;
  return error;
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownError";
}

function logBackendFailure(
  event: "backend_request_timeout" | "backend_request_network_error",
  url: URL,
  method: string,
  startedAt: number,
  timeoutMs: number,
  error: unknown,
): void {
  const record = {
    event,
    method,
    backend_origin: url.origin,
    backend_path: url.pathname,
    elapsed_ms: Date.now() - startedAt,
    timeout_ms: timeoutMs,
    error_name: errorName(error),
  };
  if (event === "backend_request_timeout") console.warn("[backend_fetch]", record);
  else console.error("[backend_fetch]", record);
}

export async function safeBackendFetch(url: URL, init: SafeBackendFetchInit): Promise<Response> {
  const {
    timeoutMs: configuredTimeoutMs,
    signal: callerSignal,
    ...requestInit
  } = init;
  const timeoutMs = backendRequestTimeoutMs(
    configuredTimeoutMs === undefined ? undefined : String(configuredTimeoutMs),
  );
  const controller = new AbortController();
  let timedOut = false;
  let callerCancelled = Boolean(callerSignal?.aborted);
  const forwardCallerAbort = () => {
    callerCancelled = true;
    if (!controller.signal.aborted) {
      controller.abort(callerSignal?.reason ?? abortError("AbortError"));
    }
  };
  if (callerSignal?.aborted) forwardCallerAbort();
  else callerSignal?.addEventListener("abort", forwardCallerAbort, { once: true });

  const timeout = setTimeout(() => {
    timedOut = true;
    if (!controller.signal.aborted) controller.abort(abortError("TimeoutError"));
  }, timeoutMs);
  const startedAt = Date.now();
  const method = requestInit.method?.toUpperCase() || "GET";
  try {
    return await fetch(url, {
      ...requestInit,
      cache: "no-store",
      signal: controller.signal,
    });
  } catch (error) {
    if (timedOut) {
      logBackendFailure("backend_request_timeout", url, method, startedAt, timeoutMs, error);
      return Response.json(
        {
          error: {
            code: "backend_timeout",
            message: "FastAPI 后台响应超时，请稍后重试。",
          },
        },
        { status: 504, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (callerCancelled) {
      return Response.json(
        {
          error: {
            code: "request_cancelled",
            message: "请求已取消。",
          },
        },
        { status: 499, headers: { "Cache-Control": "no-store" } },
      );
    }
    logBackendFailure("backend_request_network_error", url, method, startedAt, timeoutMs, error);
    return Response.json(
      {
        error: {
          code: "backend_unavailable",
          message: "FastAPI 后台暂时无法连接，请检查服务地址与运行状态。",
        },
      },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
  } finally {
    clearTimeout(timeout);
    callerSignal?.removeEventListener("abort", forwardCallerAbort);
  }
}
