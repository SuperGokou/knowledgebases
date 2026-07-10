"use client";

import { useCallback, useEffect, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import type { KnowledgeBase } from "@/lib/types";

export function KnowledgePanel() {
  const { can } = useAccess();
  const [items, setItems] = useState<KnowledgeBase[] | null>(null);
  const [error, setError] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [pending, setPending] = useState(false);

  const load = useCallback(async () => {
    setError("");
    try {
      setItems(await apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases"));
      setUnavailable(false);
    } catch (reason) {
      if (reason instanceof ApiClientError && [404, 501].includes(reason.status)) {
        setItems([]);
        setUnavailable(true);
      } else {
        setError(readableError(reason));
      }
    }
  }, []);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      await apiRequest<KnowledgeBase>("/api/v1/knowledge-bases", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), description: description.trim() || null }),
      });
      setName("");
      setDescription("");
      await load();
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setPending(false);
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
      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      <section className="panel">
        <div className="panel-header">
          <div><h2>知识空间</h2><p>按业务域组织知识与后续检索边界</p></div>
          {!unavailable ? <StatusBadge tone="info">API 已连接</StatusBadge> : <StatusBadge tone="warning">等待后台 API</StatusBadge>}
        </div>
        {items === null && !error ? <LoadingRows count={3} /> : null}
        {items?.length ? (
          <div className="panel-body feature-list">
            {items.map((item) => (
              <div className="feature-link" key={item.id}>
                <span><Icon name="book" /></span>
                <span><strong>{item.name}</strong><small>{item.description || "暂无描述"}</small></span>
                <StatusBadge tone={item.access_level === "manager" ? "success" : "neutral"}>
                  {item.access_level === "manager" ? "管理" : item.access_level === "editor" ? "编辑" : "只读"}
                </StatusBadge>
              </div>
            ))}
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
              <div className="form-actions full"><button className="button primary" type="submit" disabled={pending || !name.trim()}>{pending ? "正在创建…" : "创建空间"}</button></div>
            </form>
          </details>
        ) : null}
      </section>
    </div>
  );
}
