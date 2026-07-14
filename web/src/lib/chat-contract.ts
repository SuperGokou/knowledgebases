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
  "usage_governance_unavailable",
  "usage_budget_exceeded",
  "usage_metering_unavailable",
  "duplicate_request",
  "missing_model_citations",
  "invalid_model_citations",
  "invalid_model_response",
  "answer_review_rejected",
  "answer_review_unavailable",
  "answer_review_invalid",
  "independent_reviewer_unavailable",
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

function isChatTable(value: unknown, citationNumbers: Set<number>): boolean {
  if (!isRecord(value) || typeof value.title !== "string" || !value.title.trim()) return false;
  const columns = value.columns;
  const rows = value.rows;
  const tableCitations = value.citation_numbers;
  if (!Array.isArray(columns) || columns.length < 1 || columns.length > 8) return false;
  if (!columns.every((column) => typeof column === "string" && column.trim().length > 0 && column.length <= 80)) return false;
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 50) return false;
  if (!rows.every((row) => Array.isArray(row) && row.length === columns.length && row.every((cell) => typeof cell === "string" && cell.length <= 1_000))) return false;
  if (!Array.isArray(tableCitations) || tableCitations.length < 1 || tableCitations.length > 20) return false;
  return tableCitations.every((number) => Number.isInteger(number) && citationNumbers.has(Number(number)));
}

function isAnswerReview(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value.status === "passed") return value.reason === "semantic_verified";
  if (value.status !== "fallback") return false;
  return new Set([
    "retrieval_only",
    "answer_review_rejected",
    "answer_review_unavailable",
    "answer_review_invalid",
  ]).has(String(value.reason));
}

/** Validate the BFF response before untrusted JSON reaches React render functions. */
export function parseChatReply(value: unknown): ChatReply {
  const citations = isRecord(value) && Array.isArray(value.citations) ? value.citations : [];
  const citationNumbers = new Set(
    citations.filter(isCitation).map((citation) => citation.citation_number),
  );
  if (
    !isRecord(value) ||
    typeof value.knowledge_base_id !== "string" ||
    typeof value.answer !== "string" ||
    typeof value.mode !== "string" ||
    !(value.provider === undefined || isNullableString(value.provider)) ||
    !(value.model === undefined || isNullableString(value.model)) ||
    !Array.isArray(value.citations) ||
    !value.citations.every(isCitation) ||
    !(value.table === undefined || value.table === null || isChatTable(value.table, citationNumbers)) ||
    !isAnswerReview(value.answer_review) ||
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
