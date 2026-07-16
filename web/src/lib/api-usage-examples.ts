import { CHAT_BROWSER_TIMEOUT_MS } from "./chat-timeout-budget";

export const API_ORIGIN_PLACEHOLDER = "https://YOUR_KNOWLEDGEBASE_HOST";

export type ApiExampleLanguage = "curl" | "python" | "node";
export type PublicApiOperation = "chat" | "search";

const operations: Record<PublicApiOperation, { path: string; body: Record<string, unknown> }> = {
  chat: {
    path: "/api/v1/public/chat/query",
    body: {
      knowledge_base_id: "YOUR_KNOWLEDGE_BASE_ID",
      message: "请总结这份知识库中的核心产品信息",
      limit: 5,
    },
  },
  search: {
    path: "/api/v1/public/knowledge-bases/YOUR_KNOWLEDGE_BASE_ID/search",
    body: { query: "产品规格", limit: 10 },
  },
};

const CONTROL_PLANE_CLIENT_TIMEOUT_MS = 30_000;

export function buildApiUsageExample(
  language: ApiExampleLanguage,
  operation: PublicApiOperation,
  apiOrigin: string,
): string {
  const spec = operations[operation];
  const url = `${normalizeApiOrigin(apiOrigin)}${spec.path}`;
  const compactBody = JSON.stringify(spec.body);
  const formattedBody = JSON.stringify(spec.body, null, 2);
  const isChat = operation === "chat";
  const clientTimeoutMs = isChat
    ? CHAT_BROWSER_TIMEOUT_MS
    : CONTROL_PLANE_CLIENT_TIMEOUT_MS;
  const clientTimeoutSeconds = clientTimeoutMs / 1_000;

  if (language === "curl") {
    return `curl --request POST '${url}' \\
  --connect-timeout 10 \\
  --max-time ${clientTimeoutSeconds} \\
  --header "X-API-Key: $KNOWLEDGEBASES_API_KEY" \\
${isChat ? '  --header "Idempotency-Key: $KNOWLEDGEBASES_IDEMPOTENCY_KEY" \\\n' : ""}  --header 'Content-Type: application/json' \\
  --data '${compactBody}'`;
  }

  if (language === "python") {
    const imports = isChat ? "import os\nimport uuid\n\nimport requests" : "import os\n\nimport requests";
    const idempotencySetup = isChat
      ? '\nidempotency_key = f"chat-{uuid.uuid4()}"\n'
      : "";
    const idempotencyHeader = isChat
      ? '        "Idempotency-Key": idempotency_key,\n'
      : "";
    return `${imports}
${idempotencySetup}

response = requests.post(
    "${url}",
    headers={
        "X-API-Key": os.environ["KNOWLEDGEBASES_API_KEY"],
${idempotencyHeader}        "Content-Type": "application/json",
    },
    json=${formattedBody.replaceAll("null", "None")},
    timeout=(10, ${clientTimeoutSeconds}),
)
response.raise_for_status()
print(response.json())`;
  }

  const idempotencySetup = isChat
    ? "\nconst idempotencyKey = `chat-${crypto.randomUUID()}`;"
    : "";
  const idempotencyHeader = isChat
    ? '    "Idempotency-Key": idempotencyKey,\n'
    : "";
  return `const apiKey = process.env.KNOWLEDGEBASES_API_KEY;
if (!apiKey) throw new Error("KNOWLEDGEBASES_API_KEY is required");
${idempotencySetup}

const response = await fetch("${url}", {
  method: "POST",
  headers: {
    "X-API-Key": apiKey,
${idempotencyHeader}    "Content-Type": "application/json",
  },
  body: JSON.stringify(${formattedBody}),
  signal: AbortSignal.timeout(${clientTimeoutMs}),
});

if (!response.ok) throw new Error(\`API request failed: \${response.status}\`);
console.log(await response.json());`;
}

export function normalizeApiOrigin(value: string): string {
  const candidate = value.trim();
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("API origin must be an absolute HTTP(S) URL");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
  ) {
    throw new Error("API origin must contain only an HTTP(S) scheme, host, and optional port");
  }
  return parsed.origin;
}
