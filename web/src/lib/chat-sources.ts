import type { ChatCitation, ChatSourceStatus } from "@/lib/types";

const GROUNDED_SOURCE_FOOTER =
  /\r?\n\r?\n答案来源（知识库）：\r?\n(?:\[[1-9][0-9]*\][^\r\n]*(?:\r?\n|$))+$/u;
const NO_RESULTS_SOURCE_FOOTER =
  /\r?\n\r?\n答案来源：当前知识库未检索到可引用内容。\s*$/u;

const reasonDescriptions: Record<ChatSourceStatus["reason"], string> = {
  llm_generated: "回答已由模型结合授权知识条目生成。",
  external_processing_disabled: "当前知识库未启用外部模型处理，回答来自本地检索。",
  provider_unconfigured: "模型服务尚未配置，回答来自本地检索。",
  provider_configuration_error: "模型配置暂不可用，回答已回退到本地检索。",
  provider_unavailable: "模型服务暂不可用，回答已回退到本地检索。",
  missing_model_citations: "模型未提供有效引用，回答已回退到可验证的检索结果。",
  invalid_model_citations: "模型引用未通过校验，回答已回退到可验证的检索结果。",
  invalid_model_response: "模型回答格式未通过校验，已改用可验证的检索结果。",
  no_matching_content: "当前知识库未检索到可引用内容。",
};

export function answerWithoutEmbeddedSources(answer: string): string {
  return answer
    .replace(GROUNDED_SOURCE_FOOTER, "")
    .replace(NO_RESULTS_SOURCE_FOOTER, "")
    .trim();
}

export function citationMarker(citation: ChatCitation, index: number): string {
  const fallbackNumber = index + 1;
  const number =
    typeof citation.citation_number === "number" &&
    Number.isInteger(citation.citation_number) &&
    citation.citation_number > 0
      ? citation.citation_number
      : fallbackNumber;
  const marker = citation.marker?.trim();
  return marker && /^\[[1-9][0-9]*\]$/u.test(marker) ? marker : `[${number}]`;
}

export function citationTraceLabel(citation: ChatCitation): string {
  return citation.source_file_id ? "源文件已关联" : "知识条目可追溯";
}

export function citationLocators(citation: ChatCitation): {
  entryId: string;
  sourcePath: string | null;
} {
  return {
    entryId: `entry:${citation.entry_id}`,
    sourcePath: citation.source_path?.trim() || null,
  };
}

export function sourceSummary(
  citations: ChatCitation[],
  sourceStatus?: ChatSourceStatus,
  failed = false,
): { title: string; detail: string; state: "grounded" | "empty" | "failed" } {
  if (failed) {
    return {
      title: "请求未完成，未生成知识答案",
      detail: "本条消息没有可核验的知识库来源，请重新发送问题。",
      state: "failed",
    };
  }
  if (citations.length > 0) {
    const serverCount = sourceStatus?.citation_count;
    const count = serverCount === citations.length ? serverCount : citations.length;
    return {
      title: `已引用 ${count} 条知识来源`,
      detail: sourceStatus
        ? reasonDescriptions[sourceStatus.reason]
        : "以下条目来自当前授权知识库，可用于核验回答。",
      state: "grounded",
    };
  }
  return {
    title: "当前回答暂无可引用来源",
    detail: sourceStatus
      ? reasonDescriptions[sourceStatus.reason]
      : "当前知识库未返回匹配条目，请勿将本回答作为关键业务结论。",
    state: "empty",
  };
}
