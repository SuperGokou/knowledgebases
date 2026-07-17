"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { useActionFeedback } from "@/components/action-feedback";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { createActionLock } from "@/lib/action-lock";
import { ApiClientError, apiRequest, mutationOutcomeMayBeUncertain, readableError } from "@/lib/api-client";
import { createLatestRequestController } from "@/lib/latest-request";
import {
  knowledgeCandidatePagePath,
  mergeKnowledgeCandidates,
  splitKnowledgeCandidatePage,
} from "@/lib/knowledge-base-catalog";
import type { KnowledgeBase } from "@/lib/types";

export function KnowledgePanel() {
  const { can, canAny, loading: accessLoading } = useAccess();
  const feedback = useActionFeedback();
  const actionLock = useMemo(() => createActionLock(), []);
  const [items, setItems] = useState<KnowledgeBase[] | null>(null);
  const [query, setQuery] = useState("");
  const [activeQuery, setActiveQuery] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [error, setError] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [externalProcessing, setExternalProcessing] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const skipNextAutoLoadRef = useRef(false);
  const catalogLoadController = useMemo(() => createLatestRequestController(), []);

  const load = useCallback(async ({
    search = "",
    offset = 0,
    append = false,
    propagateError = false,
  }: { search?: string; offset?: number; append?: boolean; propagateError?: boolean } = {}) => {
    if (accessLoading) return;
    setError("");
    if (!canAny(["knowledge:read", "chat:query", "file:upload"])) {
      setItems([]);
      setHasMore(false);
      return;
    }
    setCatalogLoading(true);
    let requestSuperseded = false;
    try {
      const outcome = await catalogLoadController.run(
        () => apiRequest<KnowledgeBase[]>(knowledgeCandidatePagePath({
          offset,
          query: search,
          minimumAccessLevel: "reader",
        })),
        (response) => {
          const page = splitKnowledgeCandidatePage(response);
          setItems((current) => mergeKnowledgeCandidates(current ?? [], page.items, !append));
          setHasMore(page.hasMore);
          setUnavailable(false);
        },
      );
      if (outcome === "superseded") {
        requestSuperseded = true;
        if (propagateError) throw new Error("知识空间列表刷新已被新的请求取代，请等待最新刷新完成后确认结果。");
      }
    } catch (reason) {
      if (reason instanceof ApiClientError && [404, 501].includes(reason.status)) {
        setItems([]);
        setUnavailable(true);
      } else {
        setError(readableError(reason));
      }
      if (propagateError) throw reason;
    } finally {
      if (!requestSuperseded) setCatalogLoading(false);
    }
  }, [accessLoading, canAny, catalogLoadController]);

  useEffect(() => {
    if (skipNextAutoLoadRef.current) {
      skipNextAutoLoadRef.current = false;
      return;
    }
    const timeout = window.setTimeout(
      () => void load({ search: activeQuery, offset: 0, append: false }),
      0,
    );
    return () => window.clearTimeout(timeout);
  }, [activeQuery, load]);

  useEffect(() => () => catalogLoadController.invalidate(), [catalogLoadController]);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!actionLock.acquire()) return;
    let createdKnowledgeBase: KnowledgeBase | null = null;
    setPending(true);
    setError("");
    feedback.dismiss();
    try {
      const created = await apiRequest<KnowledgeBase>("/api/v1/knowledge-bases", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || null,
          external_llm_processing_enabled: externalProcessing,
        }),
      });
      createdKnowledgeBase = created;
      setName("");
      setDescription("");
      setExternalProcessing(false);
      setQuery("");
      skipNextAutoLoadRef.current = activeQuery !== "";
      setActiveQuery("");
      if (canAny(["knowledge:read", "chat:query", "file:upload"])) {
        await load({ search: "", offset: 0, append: false, propagateError: true });
      }
      else setItems((current) => [...(current ?? []), created]);
      feedback.success(`知识库“${created.name}”已创建，可以开始上传并审核企业资料。`, "知识库创建成功");
    } catch (reason) {
      const detail = readableError(reason);
      const outcomeUncertain = !createdKnowledgeBase && mutationOutcomeMayBeUncertain(reason);
      if (outcomeUncertain) {
        void load({ search: "", offset: 0, append: false });
      }
      const message = createdKnowledgeBase
        ? `知识库“${createdKnowledgeBase.name}”已创建，但列表刷新失败。请手动刷新确认，请勿重复创建。错误详情：${detail}`
        : outcomeUncertain
          ? `知识库的创建结果无法确认。请先刷新列表核验，请勿重复创建。错误详情：${detail}`
        : detail;
      setError(message);
      feedback.error(
        message,
        createdKnowledgeBase ? "已创建，但刷新失败" : outcomeUncertain ? "创建结果无法确认" : "知识库创建失败",
      );
    } finally {
      actionLock.release();
      setPending(false);
    }
  }

  async function toggleExternalProcessing(item: KnowledgeBase) {
    const enabled = !item.external_llm_processing_enabled;
    if (enabled && !window.confirm("开启后，符合条件的 TXT/CSV 内容会发送给当前启用的外部模型生成 OKF 草稿。确认该知识空间允许外部模型处理吗？")) {
      return;
    }
    if (!actionLock.acquire()) return;
    let updateCommitted = false;
    setUpdatingId(item.id);
    setError("");
    feedback.dismiss();
    try {
      await apiRequest<KnowledgeBase>(`/api/v1/knowledge-bases/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ external_llm_processing_enabled: enabled }),
      });
      updateCommitted = true;
      await load({ search: activeQuery, offset: 0, append: false, propagateError: true });
      feedback.success(`知识库“${item.name}”的外部模型自动转换已${enabled ? "开启" : "关闭"}。`, "处理策略已保存");
    } catch (reason) {
      const detail = readableError(reason);
      const message = updateCommitted
        ? `知识库“${item.name}”的处理策略已保存，但列表刷新失败。请手动刷新确认，请勿重复操作。错误详情：${detail}`
        : detail;
      setError(message);
      feedback.error(message, updateCommitted ? "已保存，但刷新失败" : "处理策略保存失败");
    } finally {
      actionLock.release();
      setUpdatingId(null);
    }
  }

  return (
    <div className="page-stack">
      <section className="knowledge-hero">
        <p className="eyebrow light-text">KNOWLEDGE PIPELINE</p>
        <h2>把分散内容整理成可治理的知识空间</h2>
        <p>知识空间负责组织文件、检索范围与访问策略；文件字节仍直接进入对象存储，不经过 Web 或 FastAPI。</p>
        <div className="knowledge-steps"><span><b>1</b>建立知识空间</span><span><b>2</b>上传并完成内容审核</span><span><b>3</b>授权角色并开放问答</span></div>
      </section>
      {error ? <ErrorState message={error} onRetry={() => void load({ search: activeQuery, offset: 0, append: false })} /> : null}
      <section className="panel">
        <div className="panel-header">
          <div><h2>知识空间</h2><p>按业务域组织知识与后续检索边界</p></div>
          <form className="toolbar" role="search" onSubmit={(event) => {
            event.preventDefault();
            setActiveQuery(query.trim());
          }}>
            <input aria-label="搜索知识空间" type="search" maxLength={200} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="按名称搜索全部知识空间" disabled={pending || updatingId !== null} />
            <button className="button secondary small" type="submit" disabled={catalogLoading || pending || updatingId !== null}>搜索</button>
            {!unavailable ? <StatusBadge tone="info">API 已连接</StatusBadge> : <StatusBadge tone="warning">等待后台 API</StatusBadge>}
          </form>
        </div>
        {items === null && !error ? <LoadingRows count={3} /> : null}
        {items?.length ? (
          <div className="panel-body feature-list">
            {items.map((item) => (
              <div className="feature-link knowledge-space-row" key={item.id}>
                <span><Icon name="book" /></span>
                <span><strong>{item.name}</strong><small>{item.description || "暂无描述"}</small></span>
                {item.access_level === "manager" && can("knowledge:update") ? (
                  <button
                    className="button secondary compact-button"
                    type="button"
                    disabled={updatingId !== null}
                    aria-busy={updatingId === item.id}
                    onClick={() => void toggleExternalProcessing(item)}
                    aria-pressed={item.external_llm_processing_enabled}
                  >
                    {updatingId === item.id
                      ? <><span className="spinner" />保存中…</>
                      : item.external_llm_processing_enabled
                        ? "外部模型自动转换：已开启"
                        : "外部模型自动转换：未开启"}
                  </button>
                ) : null}
                <StatusBadge tone={item.access_level === "manager" ? "success" : "neutral"}>
                  {item.access_level === "manager" ? "管理" : item.access_level === "editor" ? "编辑" : "只读"}
                </StatusBadge>
              </div>
            ))}
            {hasMore ? (
              <button className="button secondary" type="button" disabled={catalogLoading || pending || updatingId !== null} onClick={() => void load({ search: activeQuery, offset: items.length, append: true })}>
                {catalogLoading ? "正在加载…" : "加载更多知识空间"}
              </button>
            ) : null}
          </div>
        ) : null}
        {items?.length === 0 ? (
          <EmptyState
            icon="book"
            compact
            title={unavailable ? "知识空间 API 尚未接入" : "还没有知识空间"}
            description={unavailable ? "前端已经准备好接口与状态展示；后台完成 /knowledge-bases 后会自动呈现真实数据。" : "创建第一个知识空间，随后可把审核通过的文件纳入检索范围。"}
          />
        ) : null}
        {!unavailable && can("knowledge:create") ? (
          <details className="drawer-form">
            <summary>＋ 新建知识空间</summary>
            <form className="form-grid" onSubmit={create}>
              <label>名称<input value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：产品与研发" required /></label>
              <label>描述<input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="这个空间收录什么？" /></label>
              <label className="full consent-control">
                <input
                  type="checkbox"
                  checked={externalProcessing}
                  onChange={(event) => setExternalProcessing(event.target.checked)}
                />
                <span><strong>允许当前外部模型自动转换</strong><small>仅第一阶段支持 UTF-8 TXT/CSV；内容会发送到后台选定的 DeepSeek、Qwen 或 MiniMax，默认关闭。</small></span>
              </label>
              <div className="form-actions full"><button className="button primary" type="submit" disabled={pending || updatingId !== null || !name.trim()} aria-busy={pending}>{pending ? <><span className="spinner" />正在创建…</> : "创建空间"}</button></div>
            </form>
          </details>
        ) : null}
      </section>
    </div>
  );
}
