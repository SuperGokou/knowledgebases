const DEFAULT_BACKEND = "http://127.0.0.1:8000";

export function backendOrigin(): string {
  const configured = process.env.FASTAPI_URL?.trim() || DEFAULT_BACKEND;
  const url = new URL(configured);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error("FASTAPI_URL must be an HTTP(S) origin without embedded credentials");
  }
  return url.origin;
}

export function backendUrl(path: string, search = ""): URL {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, backendOrigin());
  url.search = search;
  return url;
}

export async function safeBackendFetch(url: URL, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, { ...init, cache: "no-store" });
  } catch {
    return Response.json(
      {
        error: {
          code: "backend_unavailable",
          message: "FastAPI 后台暂时无法连接，请检查服务地址与运行状态。",
        },
      },
      { status: 502 },
    );
  }
}
