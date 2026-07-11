import { describe, expect, it } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import { parseChatReply } from "../src/lib/chat-contract";

const validReply = {
  knowledge_base_id: "00000000-0000-4000-8000-000000000001",
  answer: "制度要求先审批 [1]。",
  mode: "rag",
  provider: "deepseek",
  model: "deepseek-chat",
  answer_review: {
    status: "passed",
    reason: "semantic_verified",
  },
  table: {
    title: "审批信息",
    columns: ["项目", "要求"],
    rows: [["发布", "必须先审批"]],
    citation_numbers: [1],
  },
  citations: [
    {
      entry_id: "00000000-0000-4000-8000-000000000002",
      source_file_id: null,
      title: "发布制度",
      excerpt: "内容发布前必须完成审批。",
      source_path: "policy/publish.md",
      format_version: "okf/0.1",
      citation_number: 1,
      marker: "[1]",
    },
  ],
  source_status: {
    status: "grounded",
    strategy: "rag",
    reason: "llm_generated",
    citation_count: 1,
  },
};

describe("parseChatReply", () => {
  it("accepts a response that matches the runtime chat contract", () => {
    expect(parseChatReply(validReply)).toEqual(validReply);
  });

  it.each([
    { ...validReply, citations: null },
    { ...validReply, provider: { name: "deepseek" } },
    {
      ...validReply,
      citations: [{ ...validReply.citations[0], source_path: { unsafe: true } }],
    },
    {
      ...validReply,
      source_status: { ...validReply.source_status, citation_count: 9 },
    },
    {
      ...validReply,
      table: { ...validReply.table, rows: [["缺少第二列"]] },
    },
    {
      ...validReply,
      table: { ...validReply.table, citation_numbers: [99] },
    },
    {
      ...validReply,
      answer_review: { status: "passed", reason: "retrieval_only" },
    },
    {
      ...validReply,
      answer_review: { status: "unknown", reason: "semantic_verified" },
    },
  ])("rejects malformed successful JSON before React renders it", (payload) => {
    expect(() => parseChatReply(payload)).toThrowError(ApiClientError);
    try {
      parseChatReply(payload);
    } catch (error) {
      expect(error).toMatchObject({ status: 502, code: "invalid_chat_response" });
    }
  });
});
