import type { ApiProblem } from "@/lib/types";

export class ApiClientError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/backend${path}`, {
    ...init,
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });

  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? ((await response.json()) as T | ApiProblem)
    : null;

  if (!response.ok) {
    const problem = payload as ApiProblem | null;
    throw new ApiClientError(
      problem?.error?.message ?? problem?.message ?? "请求未能完成，请稍后再试。",
      response.status,
      problem?.error?.code,
      problem?.error?.details,
    );
  }

  return payload as T;
}

export function readableError(error: unknown): string {
  if (error instanceof ApiClientError) {
    if (error.status === 401) return "登录状态已失效，请重新登录。";
    if (error.status === 403) return "当前账号没有访问此功能的权限。";
    if (error.status === 429) return "操作过于频繁，请稍后再试。";
    if (error.status >= 500) return "后台服务暂时不可用，请稍后重试。";
    return error.message;
  }
  return error instanceof Error ? error.message : "发生未知错误。";
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
