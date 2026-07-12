"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { apiRequest, formatBytes, readableError } from "@/lib/api-client";
import { fileKnowledgePresentation } from "@/lib/file-knowledge-status";
import type { FileRecord, KnowledgeBase, PartUrlResponse, UploadPlan } from "@/lib/types";

type CompletedPart = { part_number: number; etag: string };

const toneByStatus: Record<FileRecord["status"], "success" | "warning" | "danger" | "neutral" | "info"> = {
  pending: "neutral",
  uploading: "info",
  processing: "warning",
  available: "success",
  quarantined: "danger",
  failed: "danger",
  deleted: "neutral",
};

const labelByStatus: Record<FileRecord["status"], string> = {
  pending: "等待上传",
  uploading: "上传中",
  processing: "等待审核",
  available: "可用",
  quarantined: "已隔离",
  failed: "失败",
  deleted: "已删除",
};

function directHeaders(required: Record<string, string>): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(required)) {
    if (!["content-length", "host"].includes(name.toLowerCase())) headers.set(name, value);
  }
  return headers;
}

async function concurrentMap<T, R>(items: T[], concurrency: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  async function run() {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => run()));
  return results;
}

export function FilesPanel() {
  const { can, loading: accessLoading } = useAccess();
  const [files, setFiles] = useState<FileRecord[] | null>(null);
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [knowledgeBaseId, setKnowledgeBaseId] = useState("");
  const [selected, setSelected] = useState<File | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("");
  const [dragging, setDragging] = useState(false);

  const load = useCallback(async () => {
    if (accessLoading) return;
    setError("");
    if (!can("file:read")) {
      setFiles([]);
      return;
    }
    try {
      setFiles(await apiRequest<FileRecord[]>("/api/v1/files?limit=100&offset=0"));
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  useEffect(() => {
    if (accessLoading || !can("file:upload")) {
      return;
    }
    let active = true;
    async function loadKnowledgeBases() {
      try {
        const items = await apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases");
        if (!active) return;
        const editable = items.filter((item) => item.access_level === "editor" || item.access_level === "manager");
        setKnowledgeBases(editable);
        setKnowledgeBaseId((current) => current || editable[0]?.id || "");
      } catch (reason) {
        if (!active) return;
        setKnowledgeBases([]);
        setError(readableError(reason));
      }
    }
    void loadKnowledgeBases();
    return () => { active = false; };
  }, [accessLoading, can]);

  const filtered = useMemo(() => {
    if (!files) return [];
    const needle = query.trim().toLowerCase();
    return needle ? files.filter((file) => file.original_name.toLowerCase().includes(needle)) : files;
  }, [files, query]);

  async function upload() {
    if (!selected || !knowledgeBaseId || pending || !can("file:upload")) return;
    setPending(true);
    setError("");
    setProgress(2);
    setPhase("正在创建安全上传会话");
    try {
      const idempotencyKey = crypto.randomUUID();
      const plan = await apiRequest<UploadPlan>("/api/v1/files/uploads", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({
          filename: selected.name,
          size_bytes: selected.size,
          content_type: selected.type || "application/octet-stream",
          knowledge_base_id: knowledgeBaseId,
          idempotency_key: idempotencyKey,
          custom_metadata: { source: "web-console" },
        }),
      });

      let parts: CompletedPart[] = [];
      if (plan.mode === "single") {
        if (!plan.upload_url) throw new Error("后台没有返回单文件上传地址。" );
        setPhase("文件正在直传对象存储");
        const stored = await fetch(plan.upload_url, {
          method: "PUT",
          headers: directHeaders(plan.required_headers),
          body: selected,
        });
        if (!stored.ok) throw new Error(`对象存储拒绝上传（${stored.status}）。请检查 CORS 与签名配置。`);
        setProgress(92);
      } else {
        setPhase(`正在上传 ${plan.part_count} 个分片`);
        const numbers = Array.from({ length: plan.part_count }, (_, index) => index + 1);
        const signed: PartUrlResponse["parts"] = [];
        for (let start = 0; start < numbers.length; start += 100) {
          const response = await apiRequest<PartUrlResponse>(
            `/api/v1/files/uploads/${plan.upload_session_id}/parts`,
            { method: "POST", body: JSON.stringify({ part_numbers: numbers.slice(start, start + 100) }) },
          );
          signed.push(...response.parts);
        }
        let uploadedBytes = 0;
        parts = await concurrentMap(signed, 4, async (part) => {
          const from = (part.part_number - 1) * plan.part_size_bytes;
          const chunk = selected.slice(from, Math.min(selected.size, from + part.size_bytes));
          const response = await fetch(part.url, { method: "PUT", body: chunk });
          if (!response.ok) throw new Error(`第 ${part.part_number} 个分片上传失败（${response.status}）。`);
          const etag = response.headers.get("etag");
          if (!etag) throw new Error("对象存储未暴露 ETag；请在 Bucket CORS 中暴露 ETag 响应头。" );
          uploadedBytes += chunk.size;
          setProgress(Math.min(92, Math.max(4, Math.round((uploadedBytes / selected.size) * 90))));
          return { part_number: part.part_number, etag };
        });
      }

      setPhase("正在核对对象并提交元数据");
      await apiRequest<FileRecord>(`/api/v1/files/uploads/${plan.upload_session_id}/complete`, {
        method: "POST",
        body: JSON.stringify({ parts: parts.sort((a, b) => a.part_number - b.part_number) }),
      });
      setProgress(100);
      setPhase("上传完成，正在生成知识草稿");
      setSelected(null);
      await load();
    } catch (reason) {
      setError(readableError(reason));
      setPhase("上传未完成");
    } finally {
      setPending(false);
    }
  }

  async function download(file: FileRecord) {
    try {
      const grant = await apiRequest<{ url: string }>(`/api/v1/files/${file.id}/download`, { method: "POST", body: "{}" });
      window.location.assign(grant.url);
    } catch (reason) {
      setError(readableError(reason));
    }
  }

  async function approve(file: FileRecord) {
    try {
      await apiRequest<FileRecord>(`/api/v1/files/${file.id}/approve`, { method: "POST", body: "{}" });
      await load();
    } catch (reason) {
      setError(readableError(reason));
    }
  }

  const canReadFiles = !accessLoading && can("file:read");
  const canUploadFiles = !accessLoading && can("file:upload");

  return (
    <div className="page-stack">
      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      <section className="panel-grid">
        {canUploadFiles ? <article className={`panel ${canReadFiles ? "span-4" : "span-12"}`}>
          <div className="panel-header"><div><h2>上传文件</h2><p>文件字节直接进入对象存储</p></div><Icon name="upload" /></div>
          <div className="panel-body">
            <label>目标知识库
              <select value={knowledgeBaseId} onChange={(event) => setKnowledgeBaseId(event.target.value)} disabled={pending || !knowledgeBases?.length}>
                {!knowledgeBases?.length ? <option value="">没有可编辑的知识库</option> : null}
                {knowledgeBases?.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
              </select>
            </label>
            <div
              className={`upload-drop${dragging ? " dragging" : ""}`}
              onDragOver={(event) => event.preventDefault()}
              onDragEnter={() => setDragging(true)}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                setSelected(event.dataTransfer.files[0] ?? null);
              }}
            >
              <input
                aria-label="选择文件"
                type="file"
                accept=".txt,.doc,.docx,.xls,.xlsx,.csv,.pdf,.ppt,.pptx"
                disabled={pending || !knowledgeBaseId || accessLoading || !can("file:upload")}
                onChange={(event) => setSelected(event.target.files?.[0] ?? null)}
              />
              <div><span className="empty-icon"><Icon name="upload" /></span><strong>拖放文件或点击选择</strong><p>TXT、Office、CSV、PDF、PPT</p></div>
            </div>
            {selected ? (
              <div className="selected-file">
                <span><Icon name="file" /></span><span><strong>{selected.name}</strong><small>{formatBytes(selected.size)}</small></span>
                <button className="button ghost small" type="button" onClick={() => setSelected(null)} disabled={pending}>移除</button>
              </div>
            ) : null}
            {phase ? <div aria-live="polite" role="progressbar" aria-label="文件上传进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}><div className="progress-track"><i style={{ width: `${progress}%` }} /></div><div className="progress-meta"><span>{phase}</span><span>{progress}%</span></div></div> : null}
            <button className="button primary" style={{ width: "100%", marginTop: 15 }} type="button" onClick={() => void upload()} disabled={!selected || !knowledgeBaseId || pending || accessLoading || !can("file:upload")}>
              {pending ? <span className="spinner" /> : <Icon name="upload" />}{pending ? "正在上传" : "开始安全上传"}
            </button>
          </div>
        </article> : null}
        {canReadFiles ? <article className={`panel ${canUploadFiles ? "span-8" : "span-12"}`}>
          <div className="panel-header">
            <div><h2>文件中心</h2><p>查看上传、处理、隔离和可用状态</p></div>
            <div className="toolbar"><div className="search-box"><Icon name="search" /><input aria-label="搜索文件名" placeholder="搜索文件名" value={query} onChange={(event) => setQuery(event.target.value)} /></div><button className="button ghost small" type="button" onClick={() => void load()}><Icon name="refresh" />刷新</button></div>
          </div>
          {files === null && !error ? <LoadingRows count={5} /> : null}
          {files?.length === 0 ? <EmptyState compact icon="file" title="还没有文件" description="从左侧选择文件开始上传，上传完成后将在这里显示处理状态。" /> : null}
          {files?.length ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>文件</th><th>大小</th><th>文件状态</th><th>知识状态</th><th>更新时间</th><th>操作</th></tr></thead>
                <tbody>
                  {filtered.map((file) => (
                    <tr key={file.id}>
                      <td><div className="primary-cell"><span className="file-icon"><Icon name="file" /></span><span><strong>{file.original_name}</strong><small>{file.content_type}</small></span></div></td>
                      <td>{formatBytes(file.size_bytes)}</td>
                      <td><StatusBadge tone={toneByStatus[file.status]}>{labelByStatus[file.status]}</StatusBadge></td>
                      <td title={file.knowledge_error_code ?? undefined}>
                        <StatusBadge tone={fileKnowledgePresentation(file.knowledge_status).tone}>
                          {fileKnowledgePresentation(file.knowledge_status).label}
                        </StatusBadge>
                      </td>
                      <td>{new Intl.DateTimeFormat("zh-CN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(file.updated_at))}</td>
                      <td><div className="button-row">
                        {file.status === "available" && can("file:read") ? <button className="button ghost small" type="button" onClick={() => void download(file)}>下载</button> : null}
                        {file.status === "processing" && can("file:approve") ? <button className="button secondary small" type="button" onClick={() => void approve(file)}>审批</button> : null}
                      </div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 ? <EmptyState compact icon="search" title="没有匹配文件" description="尝试更换搜索关键词。" /> : null}
            </div>
          ) : null}
        </article> : null}
      </section>
    </div>
  );
}
