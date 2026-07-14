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

export function buildApiUsageExample(
  language: ApiExampleLanguage,
  operation: PublicApiOperation,
  apiOrigin: string,
): string {
  const spec = operations[operation];
  const url = `${normalizeApiOrigin(apiOrigin)}${spec.path}`;
  const compactBody = JSON.stringify(spec.body);
  const formattedBody = JSON.stringify(spec.body, null, 2);

  if (language === "curl") {
    return `curl --request POST '${url}' \\
  --header "X-API-Key: $KNOWLEDGEBASES_API_KEY" \\
  --header 'Content-Type: application/json' \\
  --data '${compactBody}'`;
  }

  if (language === "python") {
    return `import os
import requests

response = requests.post(
    "${url}",
    headers={
        "X-API-Key": os.environ["KNOWLEDGEBASES_API_KEY"],
        "Content-Type": "application/json",
    },
    json=${formattedBody.replaceAll("null", "None")},
    timeout=30,
)
response.raise_for_status()
print(response.json())`;
  }

  return `const apiKey = process.env.KNOWLEDGEBASES_API_KEY;
if (!apiKey) throw new Error("KNOWLEDGEBASES_API_KEY is required");

const response = await fetch("${url}", {
  method: "POST",
  headers: {
    "X-API-Key": apiKey,
    "Content-Type": "application/json",
  },
  body: JSON.stringify(${formattedBody}),
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
