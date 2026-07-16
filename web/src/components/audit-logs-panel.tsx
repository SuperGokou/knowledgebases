"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { apiRequest } from "@/lib/api-client";
import {
  auditLogListPath,
  auditResultPresentation,
  auditTimestampPresentation,
  readableAuditError,
  requestAuditExport,
  toAuditApiTimestamp,
  validateAuditActorId,
  validateAuditTimeRange,
  type AuditLogFilters,
  type AuditLogPage,
  type AuditResult,
} from "@/lib/audit-log";

const EMPTY_FILTERS: AuditLogFilters = {
  action: "",
  result: "",
  resourceType: "",
  resourceId: "",
  actorId: "",
  createdFrom: "",
  createdTo: "",
};

export function AuditLogsPanel() {
  const { can, loading: accessLoading } = useAccess();
  const [draft, setDraft] = useState<AuditLogFilters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<AuditLogFilters>(EMPTY_FILTERS);
  const [cursorHistory, setCursorHistory] = useState<Array<number | null>>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [page, setPage] = useState<AuditLogPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filterError, setFilterError] = useState("");
  const [exportError, setExportError] = useState("");
  const [notice, setNotice] = useState("");
  const [exportPending, setExportPending] = useState(false);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const requestSequence = useRef(0);
  const cursor = cursorHistory[pageIndex] ?? null;

  const load = useCallback(async () => {
    if (accessLoading || !can("audit:read")) return;
    const sequence = ++requestSequence.current;
    setLoading(true);
    setError("");
    try {
      const loaded = await apiRequest<AuditLogPage>(auditLogListPath(filters, cursor));
      if (sequence !== requestSequence.current) return;
      setPage(loaded);
    } catch (reason) {
      if (sequence !== requestSequence.current) return;
      setError(readableAuditError(reason));
    } finally {
      if (sequence === requestSequence.current) setLoading(false);
    }
  }, [accessLoading, can, cursor, filters]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => {
      window.clearTimeout(timeout);
      requestSequence.current += 1;
    };
  }, [load, refreshVersion]);

  function updateDraft(field: keyof AuditLogFilters, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function applyFilters(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilterError("");
    setNotice("");
    try {
      const next: AuditLogFilters = {
        ...draft,
        action: draft.action.trim(),
        resourceType: draft.resourceType.trim(),
        resourceId: draft.resourceId.trim(),
        actorId: draft.actorId.trim(),
        createdFrom: toAuditApiTimestamp(draft.createdFrom),
        createdTo: toAuditApiTimestamp(draft.createdTo),
      };
      validateAuditActorId(next.actorId);
      validateAuditTimeRange(next.createdFrom, next.createdTo);
      setFilters(next);
      setCursorHistory([null]);
      setPageIndex(0);
      setPage(null);
      setRefreshVersion((value) => value + 1);
    } catch (reason) {
      setFilterError(reason instanceof Error ? reason.message : "筛选条件无效，请检查后重试。");
    }
  }

  function resetFilters() {
    setDraft(EMPTY_FILTERS);
    setFilters(EMPTY_FILTERS);
    setFilterError("");
    setNotice("");
    setCursorHistory([null]);
    setPageIndex(0);
    setPage(null);
    setRefreshVersion((value) => value + 1);
  }

  function moveToNextPage() {
    if (loading || page?.next_cursor === null || page?.next_cursor === undefined) return;
    const nextCursor = page.next_cursor;
    setCursorHistory((current) => [
      ...current.slice(0, pageIndex + 1),
      nextCursor,
    ]);
    setPageIndex((value) => value + 1);
    setPage(null);
  }

  function moveToPreviousPage() {
    if (loading || pageIndex === 0) return;
    setPageIndex((value) => value - 1);
    setPage(null);
  }

  async function exportCurrentFilters() {
    if (exportPending || !can("audit:read")) return;
    setExportPending(true);
    setExportError("");
    setNotice("");
    try {
      const { blob, filename } = await requestAuditExport(filters);
      const objectUrl = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = filename;
        anchor.rel = "noopener";
        document.body.append(anchor);
        try {
          anchor.click();
        } finally {
          anchor.remove();
        }
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      }
      setNotice(`已生成 ${filename}；导出事件已写入安全审计。`);
    } catch (reason) {
      setExportError(readableAuditError(reason));
    } finally {
      setExportPending(false);
    }
  }

  if (accessLoading) return <LoadingRows count={5} />;
  if (!can("audit:read")) {
    return <ErrorState title="无权访问审计日志" message="当前账号缺少“查看审计日志”权限。" />;
  }

  return (
    <article className="panel audit-log-panel">
      <div className="panel-header audit-log-heading">
        <div>
          <h2>审计事件</h2>
          <p>仅展示脱敏元数据；详情、IP、凭证和文档内容不会出现在页面或导出文件中。</p>
        </div>
        <div className="button-row">
          <button
            aria-label="刷新审计日志"
            className="button ghost small"
            type="button"
            disabled={loading}
            onClick={() => setRefreshVersion((value) => value + 1)}
          >
            <Icon name="refresh" />{loading ? "刷新中…" : "刷新"}
          </button>
          <button
            aria-label="导出当前筛选结果为 CSV"
            className="button secondary small"
            type="button"
            disabled={exportPending}
            onClick={() => void exportCurrentFilters()}
          >
            <Icon name="download" />{exportPending ? "正在导出…" : "导出当前筛选结果"}
          </button>
        </div>
      </div>

      <form className="audit-filter-grid" aria-label="审计日志筛选" onSubmit={applyFilters}>
        <label>动作
          <input maxLength={150} placeholder="例如 file.approved" value={draft.action} onChange={(event) => updateDraft("action", event.target.value)} />
        </label>
        <label>结果
          <select value={draft.result} onChange={(event) => updateDraft("result", event.target.value as AuditResult | "")}>
            <option value="">全部结果</option>
            <option value="success">成功</option>
            <option value="failure">失败</option>
            <option value="denied">已拒绝</option>
          </select>
        </label>
        <label>资源类型
          <input maxLength={100} placeholder="例如 file" value={draft.resourceType} onChange={(event) => updateDraft("resourceType", event.target.value)} />
        </label>
        <label>资源标识
          <input maxLength={255} placeholder="精确资源 ID" value={draft.resourceId} onChange={(event) => updateDraft("resourceId", event.target.value)} />
        </label>
        <label>操作者 ID
          <input maxLength={36} placeholder="UUID" value={draft.actorId} onChange={(event) => updateDraft("actorId", event.target.value)} />
        </label>
        <label>开始时间
          <input type="datetime-local" value={draft.createdFrom} onChange={(event) => updateDraft("createdFrom", event.target.value)} />
        </label>
        <label>结束时间
          <input type="datetime-local" value={draft.createdTo} onChange={(event) => updateDraft("createdTo", event.target.value)} />
        </label>
        <div className="audit-filter-actions">
          <button className="button primary small" type="submit" disabled={loading}>应用筛选</button>
          <button className="button ghost small" type="button" disabled={loading} onClick={resetFilters}>重置</button>
        </div>
      </form>

      {filterError ? <div className="inline-error" role="alert"><Icon name="warning" />{filterError}</div> : null}
      {notice ? <div className="notice info-notice" role="status" aria-live="polite"><Icon name="check" /><div><strong>导出已完成</strong><p>{notice}</p></div></div> : null}
      {exportError ? <ErrorState title="导出失败" message={exportError} retryLabel="重试导出" onRetry={() => void exportCurrentFilters()} /> : null}
      {error ? <ErrorState message={error} onRetry={() => void load()} retryLabel="重新加载审计日志" /> : null}
      {loading && page === null ? <LoadingRows count={6} /> : null}
      {!loading && !error && page?.items.length === 0 ? (
        <EmptyState compact icon="clock" title="没有匹配的审计事件" description="调整筛选条件，或等待新的安全与管理操作写入审计日志。" />
      ) : null}
      {page?.items.length ? (
        <div className="table-wrap" aria-busy={loading}>
          <table>
            <caption className="sr-only">审计事件列表，仅包含时间、结果、动作、操作者、资源和请求标识。</caption>
            <thead><tr><th>时间</th><th>结果</th><th>动作</th><th>操作者</th><th>资源</th><th>请求标识</th></tr></thead>
            <tbody>
              {page.items.map((event) => {
                const result = auditResultPresentation(event.result);
                const timestamp = auditTimestampPresentation(event.created_at);
                return (
                  <tr key={event.id}>
                    <td><time dateTime={timestamp.dateTime}>{timestamp.label}</time></td>
                    <td><StatusBadge tone={result.tone}>{result.label}</StatusBadge></td>
                    <td><span className="audit-action mono">{event.action}</span></td>
                    <td><span className="audit-identifier mono">{event.actor_id ?? "系统"}</span></td>
                    <td><div className="audit-resource"><strong>{event.resource_type}</strong><small className="mono">{event.resource_id ?? "无资源标识"}</small></div></td>
                    <td><span className="audit-identifier mono">{event.request_id ?? "未提供"}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <nav className="pagination-bar" aria-label="审计日志分页">
            <span>第 {pageIndex + 1} 页 · 本页 {page.items.length} 项</span>
            <div className="button-row">
              <button className="button ghost small" type="button" disabled={loading || pageIndex === 0} onClick={moveToPreviousPage}>上一页</button>
              <button className="button ghost small" type="button" disabled={loading || page.next_cursor === null} onClick={moveToNextPage}>下一页</button>
            </div>
          </nav>
        </div>
      ) : null}
    </article>
  );
}
