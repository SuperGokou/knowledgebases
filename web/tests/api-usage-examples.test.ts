import { describe, expect, it } from "vitest";

import {
  buildApiUsageExample,
  PUBLIC_API_ORIGIN,
  type ApiExampleLanguage,
} from "../src/lib/api-usage-examples";

describe("buildApiUsageExample", () => {
  it.each<ApiExampleLanguage>(["curl", "python", "node"])(
    "builds a %s example without embedding a credential",
    (language) => {
      const example = buildApiUsageExample(language, "chat");

      expect(example).toContain(`${PUBLIC_API_ORIGIN}/api/v1/public/chat/query`);
      expect(example).toContain("KNOWLEDGEBASES_API_KEY");
      expect(example).toContain("X-API-Key");
      expect(example).not.toMatch(/kb_[A-Za-z0-9_-]{20,}/);
    },
  );

  it("builds the knowledge-base scoped search endpoint", () => {
    const example = buildApiUsageExample("curl", "search");

    expect(example).toContain("/api/v1/public/knowledge-bases/YOUR_KNOWLEDGE_BASE_ID/search");
    expect(example).toContain("产品规格");
  });
});
