import { ApiClientError, readableError } from "./api-client";
import type { ApiProblem } from "./types";

export const AUDIT_LOG_PAGE_SIZE = 50;

export type AuditResult = "success" | "failure" | "denied";

export type AuditLogFilters = Readonly<{
  action: string;
  result: AuditResult | "";
  resourceType: string;
  resourceId: string;
  actorId: string;
  createdFrom: string;
  createdTo: string;
}>;

export type AuditLogEntry = Readonly<{
  id: number;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  request_id: string | null;
  result: AuditResult;
  created_at: string;
}>;

export type AuditLogPage = Readonly<{
  items: AuditLogEntry[];
  next_cursor: number | null;
}>;

const DEFAULT_EXPORT_FILENAME = "audit-logs.csv";
const SAFE_EXPORT_FILENAME = /^audit-logs-\d{8}T\d{6}Z\.csv$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function appendTrimmed(params: URLSearchParams, name: string, value: string): void {
  const normalized = value.trim();
  if (normalized) params.set(name, normalized);
}

function auditFilterParams(filters: AuditLogFilters): URLSearchParams {
  const params = new URLSearchParams();
  appendTrimmed(params, "action", filters.action);
  appendTrimmed(params, "actor_id", filters.actorId);
  appendTrimmed(params, "resource_type", filters.resourceType);
  appendTrimmed(params, "resource_id", filters.resourceId);
  appendTrimmed(params, "result", filters.result);
  appendTrimmed(params, "created_from", filters.createdFrom);
  appendTrimmed(params, "created_to", filters.createdTo);
  return params;
}

export function auditLogListPath(filters: AuditLogFilters, cursor?: number | null): string {
  const params = auditFilterParams(filters);
  if (cursor !== undefined && cursor !== null) params.set("cursor", String(cursor));
  params.set("limit", String(AUDIT_LOG_PAGE_SIZE));
  return `/api/v1/audit-logs?${params.toString()}`;
}

export function auditLogExportPath(filters: AuditLogFilters): string {
  const query = auditFilterParams(filters).toString();
  return `/api/v1/audit-logs/export${query ? `?${query}` : ""}`;
}

export function auditResultPresentation(result: AuditResult): {
  label: string;
  tone: "success" | "danger" | "warning";
} {
  if (result === "success") return { label: "成功", tone: "success" };
  if (result === "failure") return { label: "失败", tone: "danger" };
  return { label: "已拒绝", tone: "warning" };
}

export function auditTimestampPresentation(value: string): {
  label: string;
  dateTime?: string;
} {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return { label: "时间未知" };

  try {
    return {
      label: new Intl.DateTimeFormat("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(parsed),
      dateTime: value,
    };
  } catch {
    return { label: "时间未知" };
  }
}

export function toAuditApiTimestamp(value: string): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error("日期时间格式无效，请重新选择。");
  return parsed.toISOString();
}

export function validateAuditTimeRange(createdFrom: string, createdTo: string): void {
  if (createdFrom && createdTo && Date.parse(createdFrom) > Date.parse(createdTo)) {
    throw new Error("开始时间不能晚于结束时间。");
  }
}

export function validateAuditActorId(actorId: string): void {
  if (actorId && !UUID.test(actorId)) {
    throw new Error("操作者 ID 必须是完整的 UUID。");
  }
}

export function readableAuditError(error: unknown): string {
  if (error instanceof ApiClientError) {
    if (error.code === "audit_export_too_large") {
      return "当前筛选结果超过 5,000 条，请缩小时间或资源范围后重试。";
    }
    if (error.status === 422) {
      return "筛选条件无效，请检查操作者 ID 和时间范围后重试。";
    }
  }
  return readableError(error);
}

export function auditExportFilename(contentDisposition: string | null): string {
  if (!contentDisposition) return DEFAULT_EXPORT_FILENAME;
  const extended = /filename\*=UTF-8''([^;]+)/i.exec(contentDisposition)?.[1];
  const quoted = /filename="([^"]+)"/i.exec(contentDisposition)?.[1];
  let candidate = extended ?? quoted;
  if (!candidate) return DEFAULT_EXPORT_FILENAME;
  try {
    candidate = decodeURIComponent(candidate);
  } catch {
    return DEFAULT_EXPORT_FILENAME;
  }
  return SAFE_EXPORT_FILENAME.test(candidate) ? candidate : DEFAULT_EXPORT_FILENAME;
}

export async function requestAuditExport(
  filters: AuditLogFilters,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(`/api/backend${auditLogExportPath(filters)}`, {
    cache: "no-store",
    headers: { Accept: "text/csv" },
  });
  const contentType = response.headers.get("content-type") ?? "";
  if (!response.ok) {
    let problem: ApiProblem | null = null;
    if (contentType.toLowerCase().includes("json")) {
      try {
        problem = await response.json() as ApiProblem;
      } catch {
        problem = null;
      }
    }
    const headerRequestId = response.headers.get("x-request-id")?.trim() || undefined;
    const payloadRequestId = typeof problem?.request_id === "string"
      ? problem.request_id.trim() || undefined
      : undefined;
    throw new ApiClientError(
      problem?.error?.message ?? problem?.message ?? "审计日志导出未能完成，请稍后重试。",
      response.status,
      problem?.error?.code,
      problem?.error?.details,
      headerRequestId ?? payloadRequestId,
    );
  }
  if (!contentType.toLowerCase().startsWith("text/csv")) {
    throw new ApiClientError(
      "审计日志导出响应格式无效，请联系系统管理员。",
      502,
      "invalid_audit_export_response",
    );
  }
  return {
    blob: await response.blob(),
    filename: auditExportFilename(response.headers.get("content-disposition")),
  };
}
