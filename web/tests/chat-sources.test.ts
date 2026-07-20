import { describe, expect, it } from "vitest";

import {
  answerWithoutEmbeddedSources,
  citationLocators,
  citationMarker,
  citationTraceLabel,
  sourceSummary,
} from "../src/lib/chat-sources";
import type { ChatCitation, ChatSourceStatus } from "../src/lib/types";

const citation: ChatCitation = {
  entry_id: "entry-1",
  source_file_id: "file-1",
  title: "质量管理制度",
  excerpt: "所有发布内容都必须经过审核。",
  source_path: "policies/quality.md",
  format_version: "1.0",
  citation_number: 3,
  marker: "[3]",
};

const groundedStatus: ChatSourceStatus = {
  status: "grounded",
  strategy: "rag",
  reason: "llm_generated",
  citation_count: 1,
};

describe("chat answer sources", () => {
  it("removes a server-appended Chinese source section from the answer body", () => {
    const answer = "审核前不得发布。\n\n答案来源（知识库）：\n[1] 质量管理制度（policies/quality.md）";

    expect(answerWithoutEmbeddedSources(answer)).toBe("审核前不得发布。");
    expect(
      answerWithoutEmbeddedSources("当前没有匹配结果。\n\n答案来源：当前知识库未检索到可引用内容。"),
    ).toBe("当前没有匹配结果。");
  });

  it("keeps ordinary source wording inside the answer", () => {
    expect(answerWithoutEmbeddedSources("这段内容的来源需要进一步确认。")).toBe(
      "这段内容的来源需要进一步确认。",
    );
    expect(
      answerWithoutEmbeddedSources("结论如下。\n\n答案来源：请以公司官网公告为准。"),
    ).toBe("结论如下。\n\n答案来源：请以公司官网公告为准。");
    expect(
      answerWithoutEmbeddedSources("结论如下。\n\n参考来源：\n公司内部制度。"),
    ).toBe("结论如下。\n\n参考来源：\n公司内部制度。");
  });

  it("uses the validated server marker and falls back to display order", () => {
    expect(citationMarker(citation, 0)).toBe("[3]");
    expect(citationMarker({ ...citation, citation_number: Number.NaN, marker: "bad" }, 1)).toBe("[2]");
  });

  it("describes grounded, empty, and failed source states without overclaiming", () => {
    expect(sourceSummary([citation], groundedStatus)).toEqual({
      title: "已引用 1 条知识来源",
      detail: "回答已由模型结合授权知识条目生成。",
      state: "grounded",
    });
    expect(sourceSummary([], { ...groundedStatus, status: "no_results", reason: "no_matching_content", citation_count: 0 })).toEqual({
      title: "当前回答暂无可引用来源",
      detail: "当前知识库未检索到可引用内容。",
      state: "empty",
    });
    expect(sourceSummary([], undefined, true).title).toBe("请求未完成，未生成知识答案");
  });

  it("explains that structured spreadsheet answers are locally and deterministically verified", () => {
    const structuredStatus: ChatSourceStatus = {
      status: "grounded",
      strategy: "structured",
      reason: "structured_query",
      citation_count: 1,
    };
    const explanation = "系统已在本地执行确定性表格查询，仅返回可由原始单元格核验的结果。";

    expect(sourceSummary([citation], structuredStatus).detail).toBe(explanation);
    expect(
      sourceSummary([], { ...structuredStatus, status: "no_results", citation_count: 0 }).detail,
    ).toBe(explanation);
  });

  it("explains when the deployment-level model egress is disabled", () => {
    const disabledStatus: ChatSourceStatus = {
      status: "grounded",
      strategy: "retrieval_fallback",
      reason: "deployment_external_llm_disabled",
      citation_count: 1,
    };

    expect(sourceSummary([citation], disabledStatus).detail).toBe(
      "当前部署未启用外部模型出口，回答已安全回退到本地检索。",
    );
  });

  it("reports whether a citation has an associated source file", () => {
    expect(citationTraceLabel(citation)).toBe("源文件已关联");
    expect(citationTraceLabel({ ...citation, source_file_id: null })).toBe("知识条目可追溯");
  });

  it("always returns the stable entry locator and keeps source path separately", () => {
    expect(citationLocators(citation)).toEqual({
      entryId: "entry:entry-1",
      sourcePath: "policies/quality.md",
    });
    expect(citationLocators({ ...citation, source_path: null })).toEqual({
      entryId: "entry:entry-1",
      sourcePath: null,
    });
  });
});
