import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ADMIN_PAGE_SIZE,
  apiKeyPagePath,
  knowledgeBasePagePath,
  mergeAdminPage,
  replaceRotatedApiKey,
  splitAdminPage,
} from "../src/lib/api-key-administration";

type Item = { id: string; name: string };
const apiKeysPanel = readFileSync(
  join(process.cwd(), "src/components/api-keys-panel.tsx"),
  "utf8",
);

describe("API key administration pagination", () => {
  it("uses a 50+1 request so the UI can determine whether another page exists", () => {
    expect(apiKeyPagePath(0)).toBe("/api/v1/api-keys?limit=51&offset=0");

    const page = splitAdminPage(
      Array.from({ length: ADMIN_PAGE_SIZE + 1 }, (_, index) => ({
        id: `item-${index}`,
        name: `Item ${index}`,
      })),
    );

    expect(page.items).toHaveLength(ADMIN_PAGE_SIZE);
    expect(page.hasMore).toBe(true);
  });

  it("deduplicates the overlapping boundary item when a subsequent page is appended", () => {
    const current: Item[] = [
      { id: "item-1", name: "First" },
      { id: "item-2", name: "Second" },
    ];
    const incoming: Item[] = [
      { id: "item-2", name: "Second refreshed" },
      { id: "item-3", name: "Third" },
    ];

    expect(mergeAdminPage(current, incoming, false)).toEqual([
      { id: "item-1", name: "First" },
      { id: "item-2", name: "Second refreshed" },
      { id: "item-3", name: "Third" },
    ]);
  });

  it("encodes knowledge-base search terms without changing literal wildcard characters", () => {
    const path = knowledgeBasePagePath({ offset: 50, query: "  研发%_  " });
    const url = new URL(path, "https://knowledge.example.test");

    expect(url.pathname).toBe("/api/v1/knowledge-bases");
    expect(url.searchParams.get("limit")).toBe("51");
    expect(url.searchParams.get("offset")).toBe("50");
    expect(url.searchParams.get("q")).toBe("研发%_");
  });

  it("moves a rotated credential to the head without retaining the revoked row", () => {
    const rotated = replaceRotatedApiKey(
      [
        { id: "old", name: "ERP" },
        { id: "other", name: "MES" },
      ],
      "old",
      { id: "new", name: "ERP" },
    );

    expect(rotated).toEqual([
      { id: "new", name: "ERP" },
      { id: "other", name: "MES" },
    ]);
  });

  it("keeps the production UI lifecycle on accessible controls and independent loaders", () => {
    expect(apiKeysPanel).toContain('aria-label={`轮换 ${key.name}`}');
    expect(apiKeysPanel).toContain('aria-label={`撤销 ${key.name}`}');
    expect(apiKeysPanel).toContain("/api/v1/api-keys/${key.id}/rotate");
    expect(apiKeysPanel).toContain("我已保存，关闭明文");
    expect(apiKeysPanel).toContain('data-sensitive="true"');
    expect(apiKeysPanel).toContain("加载更多 API Key");
    expect(apiKeysPanel).toContain("搜索知识库");
    expect(apiKeysPanel).toContain("加载更多知识库");
    expect(apiKeysPanel).not.toContain("Promise.all");
    expect(apiKeysPanel).not.toContain("console.");
  });
});
