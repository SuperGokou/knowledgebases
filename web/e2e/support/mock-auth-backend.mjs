import { createServer } from "node:http";

const HOST = "127.0.0.1";
const PORT = 3199;
const MAX_REQUEST_BODY_BYTES = 1_024;
const MAX_RESPONSE_BODY_BYTES = 16_384;

const profiles = new Map([
  ["p1-files-access", {
    id: "00000000-0000-4000-8000-000000000001",
    email: "qa-files@example.invalid",
    display_name: "文件质量验收员",
    status: "active",
    is_superuser: false,
    permission_codes: ["file:read", "file:approve"],
    role_ids: [],
    limits: {},
  }],
  ["p1-chat-access", {
    id: "00000000-0000-4000-8000-000000000002",
    email: "qa-chat@example.invalid",
    display_name: "问答质量验收员",
    status: "active",
    is_superuser: false,
    permission_codes: ["chat:query"],
    role_ids: [],
    limits: {},
  }],
]);

function sendJson(response, status, value, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  if (body.byteLength > MAX_RESPONSE_BODY_BYTES) {
    response.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
    response.end('{"error":{"code":"mock_response_too_large"}}');
    return;
  }
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": String(body.byteLength),
    "Content-Type": "application/json; charset=utf-8",
    ...extraHeaders,
  });
  response.end(body);
}

function boundedBody(request) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    request.on("data", (chunk) => {
      bytes += chunk.byteLength;
      if (bytes > MAX_REQUEST_BODY_BYTES) reject(new Error("request_too_large"));
    });
    request.on("end", resolve);
    request.on("error", reject);
  });
}

const server = createServer({ maxHeaderSize: 8_192 }, async (request, response) => {
  try {
    await boundedBody(request);
  } catch {
    sendJson(response, 413, { error: { code: "request_too_large" } });
    return;
  }

  const url = new URL(request.url ?? "/", `http://${HOST}:${PORT}`);
  const exactUrl = url.search === "";
  const knownPath = url.pathname === "/healthz" || url.pathname === "/api/v1/auth/me";
  if (!knownPath || !exactUrl) {
    sendJson(response, 404, { error: { code: "not_found" } });
    return;
  }
  if (request.method !== "GET") {
    sendJson(response, 405, { error: { code: "method_not_allowed" } }, { Allow: "GET" });
    return;
  }
  if (url.pathname === "/healthz") {
    sendJson(response, 200, { status: "ok", service: "p1-mock-auth" });
    return;
  }

  const authorization = request.headers.authorization ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const profile = profiles.get(token);
  if (!profile) {
    sendJson(response, 401, { error: { code: "not_authenticated" } });
    return;
  }
  sendJson(response, 200, profile);
});

server.requestTimeout = 2_000;
server.headersTimeout = 2_000;
server.keepAliveTimeout = 1_000;

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 2_000).unref();
}

server.on("error", (error) => {
  process.stderr.write(`mock-auth backend failed: ${error.code ?? "unknown"}\n`);
  process.exit(1);
});
server.listen(PORT, HOST, () => {
  process.stdout.write(`mock-auth backend ready on ${HOST}:${PORT}\n`);
});
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
