import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  KNOWLEDGE_CANDIDATE_PAGE_SIZE,
  candidatesWithSelection,
  knowledgeCandidatePagePath,
  mergeKnowledgeCandidates,
  splitKnowledgeCandidatePage,
} from "../src/lib/knowledge-base-catalog";
import type { KnowledgeBase } from "../src/lib/types";

function knowledgeBase(id: string, name = id): KnowledgeBase {
  return {
    id,
    owner_id: "owner",
    name,
    description: null,
    custom_metadata: {},
    external_llm_processing_enabled: false,
    access_level: "manager",
    role_grant_version: 1,
    created_at: "2026-07-14T00:00:00Z",
    updated_at: "2026-07-14T00:00:00Z",
  };
}

const filesPanel = readFileSync(join(process.cwd(), "src/components/files-panel.tsx"), "utf8");
const grantsPanel = readFileSync(
  join(process.cwd(), "src/components/knowledge-grants-panel.tsx"),
  "utf8",
);
const knowledgePanel = readFileSync(
  join(process.cwd(), "src/components/knowledge-panel.tsx"),
  "utf8",
);
const chatWorkspace = readFileSync(
  join(process.cwd(), "src/components/chat-workspace.tsx"),
  "utf8",
);

describe("knowledge-base candidate catalogs", () => {
  it("requests 50+1 rows with bounded SQL search and the required access level", () => {
    const path = knowledgeCandidatePagePath({
      offset: 50,
      query: "  研发%_  ",
      minimumAccessLevel: "editor",
    });
    const url = new URL(path, "https://knowledge.example.test");

    expect(url.searchParams.get("limit")).toBe("51");
    expect(url.searchParams.get("offset")).toBe("50");
    expect(url.searchParams.get("q")).toBe("研发%_");
    expect(url.searchParams.get("minimum_access_level")).toBe("editor");
  });

  it("splits lookahead rows and merges subsequent pages without duplicates", () => {
    const page = splitKnowledgeCandidatePage(
      Array.from({ length: KNOWLEDGE_CANDIDATE_PAGE_SIZE + 1 }, (_, index) =>
        knowledgeBase(`kb-${index}`)),
    );
    expect(page.items).toHaveLength(KNOWLEDGE_CANDIDATE_PAGE_SIZE);
    expect(page.hasMore).toBe(true);
    expect(
      mergeKnowledgeCandidates(
        [knowledgeBase("first"), knowledgeBase("overlap", "old")],
        [knowledgeBase("overlap", "fresh"), knowledgeBase("next")],
        false,
      ).map((item) => [item.id, item.name]),
    ).toEqual([
      ["first", "first"],
      ["overlap", "fresh"],
      ["next", "next"],
    ]);
  });

  it("keeps a selected knowledge base available outside the current search page", () => {
    const selected = knowledgeBase("selected", "已选知识库");
    expect(candidatesWithSelection([knowledgeBase("visible")], selected)).toEqual([
      selected,
      knowledgeBase("visible"),
    ]);
    expect(candidatesWithSelection([selected], selected)).toEqual([selected]);
  });

  it("keeps file-list governance independent from the editable knowledge catalog", () => {
    expect(filesPanel).toContain('minimumAccessLevel: "editor"');
    expect(filesPanel).toContain("搜索可编辑知识库");
    expect(filesPanel).toContain("加载更多知识库");
    expect(filesPanel).toContain("knowledgeError");
    expect(filesPanel).toContain("candidatesWithSelection");
    expect(filesPanel).not.toContain('apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases")');
  });

  it("loads grant candidates independently and refreshes the selected resource by id", () => {
    expect(grantsPanel).toContain('minimumAccessLevel: "manager"');
    expect(grantsPanel).toContain("搜索可管理知识库");
    expect(grantsPanel).toContain("加载更多知识库");
    expect(grantsPanel).toContain("搜索角色");
    expect(grantsPanel).toContain("加载更多角色");
    expect(grantsPanel).toContain("knowledgeCatalogError");
    expect(grantsPanel).toContain("roleCatalogError");
    expect(grantsPanel).toContain("`/api/v1/knowledge-bases/${selectedId}`");
    expect(grantsPanel).not.toContain("Promise.all");
  });

  it("keeps the knowledge administration catalog searchable beyond its first page", () => {
    expect(knowledgePanel).toContain('minimumAccessLevel: "reader"');
    expect(knowledgePanel).toContain('aria-label="搜索知识空间"');
    expect(knowledgePanel).toContain("加载更多知识空间");
    expect(knowledgePanel).toContain("splitKnowledgeCandidatePage");
    expect(knowledgePanel).not.toContain('apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases")');
  });

  it("keeps chat usable while its reader-level knowledge catalog searches and paginates", () => {
    expect(chatWorkspace).toContain('minimumAccessLevel: "reader"');
    expect(chatWorkspace).toContain('aria-label="搜索可问答知识库"');
    expect(chatWorkspace).toContain("加载更多知识库");
    expect(chatWorkspace).toContain("candidatesWithSelection");
    expect(chatWorkspace).toContain("knowledgeCatalogError");
    expect(chatWorkspace).toContain("当前对话仍可继续");
    expect(chatWorkspace).not.toContain(
      'apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases")',
    );
  });
});
