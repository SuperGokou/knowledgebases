import { describe, expect, it } from "vitest";

import { fileKnowledgePresentation } from "../src/lib/file-knowledge-status";

describe("file knowledge ingestion status", () => {
  it("distinguishes downloadable files from searchable knowledge", () => {
    expect(fileKnowledgePresentation("indexed")).toEqual({
      label: "已入知识库",
      tone: "success",
      searchable: true,
    });
    expect(fileKnowledgePresentation("unsupported")).toEqual({
      label: "暂不支持解析",
      tone: "warning",
      searchable: false,
    });
    expect(fileKnowledgePresentation("failed")).toEqual({
      label: "知识转换失败",
      tone: "danger",
      searchable: false,
    });
  });
});
