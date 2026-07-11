import { ApiClientError } from "./api-client";
import type { ChatCitation, ChatReply, ChatSourceStatus } from "./types";

const SOURCE_STATUSES = new Set<ChatSourceStatus["status"]>(["grounded", "no_results"]);
const SOURCE_STRATEGIES = new Set<ChatSourceStatus["strategy"]>([
  "rag",
  "retrieval",
  "retrieval_fallback",
]);
const SOURCE_REASONS = new Set<ChatSourceStatus["reason"]>([
  "llm_generated",
  "external_processing_disabled",
  "provider_unconfigured",
  "provider_configuration_error",
  "provider_unavailable",
  "missing_model_citations",
  "invalid_model_citations",
  "no_matching_content",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isCitation(value: unknown): value is ChatCitation {
  if (!isRecord(value)) return false;
  return (
    typeof value.entry_id === "string" &&
    isNullableString(value.source_file_id) &&
    typeof value.title === "string" &&
    typeof value.excerpt === "string" &&
    isNullableString(value.source_path) &&
    isNullableString(value.format_version) &&
    Number.isInteger(value.citation_number) &&
    Number(value.citation_number) > 0 &&
    typeof value.marker === "string" &&
    /^\[[1-9][0-9]*\]$/u.test(value.marker)
  );
}

function isSourceStatus(value: unknown): value is ChatSourceStatus {
  if (!isRecord(value)) return false;
  return (
    SOURCE_STATUSES.has(value.status as ChatSourceStatus["status"]) &&
    SOURCE_STRATEGIES.has(value.strategy as ChatSourceStatus["strategy"]) &&
    SOURCE_REASONS.has(value.reason as ChatSourceStatus["reason"]) &&
    Number.isInteger(value.citation_count) &&
    Number(value.citation_count) >= 0
  );
}

/** Validate the BFF response before untrusted JSON reaches React render functions. */
export function parseChatReply(value: unknown): ChatReply {
  if (
    !isRecord(value) ||
    typeof value.knowledge_base_id !== "string" ||
    typeof value.answer !== "string" ||
    typeof value.mode !== "string" ||
    !(value.provider === undefined || isNullableString(value.provider)) ||
    !(value.model === undefined || isNullableString(value.model)) ||
    !Array.isArray(value.citations) ||
    !value.citations.every(isCitation) ||
    !isSourceStatus(value.source_status) ||
    value.source_status.citation_count !== value.citations.length
  ) {
    throw new ApiClientError(
      "后台返回了无效的问答数据，请稍后重试。",
      502,
      "invalid_chat_response",
    );
  }
  return value as ChatReply;
}
