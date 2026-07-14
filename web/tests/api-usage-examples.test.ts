import { describe, expect, it } from "vitest";

import {
  API_ORIGIN_PLACEHOLDER,
  buildApiUsageExample,
  normalizeApiOrigin,
  type ApiExampleLanguage,
} from "../src/lib/api-usage-examples";

const LAN_API_ORIGIN = "https://kb.intranet.example:19443";

describe("buildApiUsageExample", () => {
  it.each<ApiExampleLanguage>(["curl", "python", "node"])(
    "builds a %s same-origin example without embedding a credential",
    (language) => {
      const example = buildApiUsageExample(language, "chat", LAN_API_ORIGIN);

      expect(example).toContain(`${LAN_API_ORIGIN}/api/v1/public/chat/query`);
      expect(example).toContain("KNOWLEDGEBASES_API_KEY");
      expect(example).toContain("X-API-Key");
      expect(example).not.toMatch(/vercel\.app/i);
      expect(example).not.toMatch(/kb_[A-Za-z0-9_-]{20,}/);
    },
  );

  it("builds the knowledge-base scoped search endpoint", () => {
    const example = buildApiUsageExample("curl", "search", LAN_API_ORIGIN);

    expect(example).toContain(
      "/api/v1/public/knowledge-bases/YOUR_KNOWLEDGE_BASE_ID/search",
    );
  });

  it("normalizes a trailing slash without creating a double slash", () => {
    const example = buildApiUsageExample("curl", "chat", `${LAN_API_ORIGIN}/`);

    expect(example).toContain(`${LAN_API_ORIGIN}/api/v1/public/chat/query`);
    expect(example).not.toContain(`${LAN_API_ORIGIN}//api`);
  });

  it.each([
    "javascript:alert(1)",
    "https://user:password@kb.intranet.example",
    "https://kb.intranet.example/private",
    "https://kb.intranet.example?token=secret",
  ])("rejects unsafe API origins: %s", (origin) => {
    expect(() => normalizeApiOrigin(origin)).toThrow();
  });

  it("uses a deployment-neutral server-render placeholder", () => {
    expect(API_ORIGIN_PLACEHOLDER).toBe("https://YOUR_KNOWLEDGEBASE_HOST");
    expect(API_ORIGIN_PLACEHOLDER).not.toMatch(/vercel\.app/i);
  });
});
