"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { AnswerSources } from "@/components/answer-sources";
import { ChatDataTable } from "@/components/chat-data-table";
import { Icon } from "@/components/icon";
import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import { parseChatReply } from "@/lib/chat-contract";
import { createChatIdempotencyController } from "@/lib/chat-idempotency";
import { answerWithoutEmbeddedSources } from "@/lib/chat-sources";
import {
  INITIAL_CHAT_SERVICE_STATUS,
  beginChatServiceCheck,
  settleChatServiceCheck,
  type ChatServiceResolution,
} from "@/lib/chat-service-status";
import { CHAT_BROWSER_TIMEOUT_MS } from "@/lib/chat-timeout-budget";
import { scrollIntoViewIfSupported } from "@/lib/dom";
import {
  candidatesWithSelection,
  knowledgeCandidatePagePath,
  mergeKnowledgeCandidates,
  splitKnowledgeCandidatePage,
} from "@/lib/knowledge-base-catalog";
import { createRequestDeadline, type RequestDeadline } from "@/lib/request-deadline";
import type { ChatMessage, KnowledgeBase } from "@/lib/types";

const CHAT_MESSAGE_MAX_LENGTH = 2_000;

const suggestions = [
  "帮我总结这个知识库中的主要制度。",
  "查找与客户数据保留相关的说明。",
  "列出最近内容中提到的风险与行动项。",
  "给我一份适合新成员阅读的知识摘要。",
];

type ChatOperation = {
  content: string;
  knowledgeBaseId: string;
  userMessage: ChatMessage;
};

export function ChatWorkspace() {
  const { can, loading: accessLoading, me } = useAccess();
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [knowledgeBaseId, setKnowledgeBaseId] = useState("");
  const [selectedKnowledgeBase, setSelectedKnowledgeBase] = useState<KnowledgeBase | null>(null);
  const [knowledgeQuery, setKnowledgeQuery] = useState("");
  const [activeKnowledgeQuery, setActiveKnowledgeQuery] = useState("");
  const [knowledgeHasMore, setKnowledgeHasMore] = useState(false);
  const [knowledgeCatalogLoading, setKnowledgeCatalogLoading] = useState(false);
  const [knowledgeCatalogError, setKnowledgeCatalogError] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const [serviceStatus, setServiceStatus] = useState(INITIAL_CHAT_SERVICE_STATUS);
  const [retryFailureId, setRetryFailureId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const activeRequestRef = useRef<RequestDeadline | null>(null);
  const idempotencyRef = useRef(createChatIdempotencyController());
  const retryOperationRef = useRef<ChatOperation | null>(null);
  const knowledgeRequestId = useRef(0);
  const knowledgeBaseIdRef = useRef("");
  const serviceRevisionRef = useRef(INITIAL_CHAT_SERVICE_STATUS.revision);

  const beginServiceRequest = useCallback((hint: string): number => {
    const started = beginChatServiceCheck(serviceRevisionRef.current, hint);
    serviceRevisionRef.current = started.revision;
    setServiceStatus(started.status);
    return started.revision;
  }, []);

  const settleServiceRequest = useCallback((
    revision: number,
    resolution: ChatServiceResolution,
  ) => {
    if (revision !== serviceRevisionRef.current) return;
    setServiceStatus((current) => settleChatServiceCheck(current, revision, resolution));
  }, []);

  const loadKnowledgeBases = useCallback(async ({
    search = activeKnowledgeQuery,
    offset = 0,
    append = false,
  }: { search?: string; offset?: number; append?: boolean } = {}) => {
    const requestId = ++knowledgeRequestId.current;
    const serviceRevision = beginServiceRequest("正在连接知识检索");
    setKnowledgeCatalogLoading(true);
    setKnowledgeCatalogError("");
    try {
      const response = await apiRequest<KnowledgeBase[]>(knowledgeCandidatePagePath({
        offset,
        query: search,
        minimumAccessLevel: "reader",
      }));
      if (requestId !== knowledgeRequestId.current) return;
      const page = splitKnowledgeCandidatePage(response);
      setKnowledgeBases((current) => mergeKnowledgeCandidates(current ?? [], page.items, !append));
      setKnowledgeHasMore(page.hasMore);

      const selectedId = knowledgeBaseIdRef.current;
      const refreshedSelection = selectedId
        ? page.items.find((item) => item.id === selectedId)
        : page.items[0];
      if (!selectedId && refreshedSelection) {
        knowledgeBaseIdRef.current = refreshedSelection.id;
        setKnowledgeBaseId(refreshedSelection.id);
        setSelectedKnowledgeBase(refreshedSelection);
      } else if (refreshedSelection) {
        setSelectedKnowledgeBase(refreshedSelection);
      }

      const hasSelection = Boolean(knowledgeBaseIdRef.current || refreshedSelection);
      settleServiceRequest(serviceRevision, {
        state: hasSelection ? "connected" : "warning",
        hint: hasSelection ? "知识检索已连接" : "暂无可访问知识库",
      });
    } catch (reason) {
      if (requestId !== knowledgeRequestId.current) return;
      setKnowledgeBases((current) => current ?? []);
      setKnowledgeCatalogError(readableError(reason));
      settleServiceRequest(serviceRevision, {
        state: "warning",
        hint: reason instanceof ApiClientError && [404, 501].includes(reason.status)
          ? "问答服务尚未接入"
          : "连接异常",
      });
    } finally {
      if (requestId === knowledgeRequestId.current) setKnowledgeCatalogLoading(false);
    }
  }, [activeKnowledgeQuery, beginServiceRequest, settleServiceRequest]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void loadKnowledgeBases(), 0);
    return () => {
      window.clearTimeout(timeout);
      knowledgeRequestId.current += 1;
      serviceRevisionRef.current += 1;
    };
  }, [loadKnowledgeBases]);

  useEffect(() => {
    scrollIntoViewIfSupported(bottomRef.current, { behavior: "smooth" });
  }, [messages]);

  useEffect(() => () => {
    const activeRequest = activeRequestRef.current;
    activeRequestRef.current = null;
    activeRequest?.cancel();
  }, []);

  function startNewConversation() {
    const activeRequest = activeRequestRef.current;
    activeRequestRef.current = null;
    activeRequest?.cancel();
    retryOperationRef.current = null;
    idempotencyRef.current.conversationReset();
    setRetryFailureId(null);
    setPending(false);
    setMessages([]);
    if (activeRequest) {
      beginServiceRequest("请求已取消");
    } else if (!knowledgeBaseIdRef.current) {
      beginServiceRequest("暂无可访问知识库");
    }
  }

  function updateInput(nextInput: string) {
    if (!pending && retryOperationRef.current) {
      retryOperationRef.current = null;
      idempotencyRef.current.messageEdited();
      setRetryFailureId(null);
    }
    setInput(nextInput);
  }

  async function executeOperation(
    operation: ChatOperation,
    idempotencyKey: string,
    appendUserMessage: boolean,
  ) {
    const deadline = createRequestDeadline(CHAT_BROWSER_TIMEOUT_MS);
    activeRequestRef.current = deadline;
    const serviceRevision = beginServiceRequest("正在检索知识库");
    retryOperationRef.current = operation;
    if (appendUserMessage) {
      setMessages((current) => [...current, operation.userMessage]);
    }
    setPending(true);
    try {
      const reply = parseChatReply(
        await apiRequest<unknown>("/api/v1/chat/query", {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey },
          body: JSON.stringify({
            knowledge_base_id: operation.knowledgeBaseId,
            message: operation.content,
            limit: 5,
          }),
          signal: deadline.signal,
        }),
      );
      if (activeRequestRef.current !== deadline) return;
      retryOperationRef.current = null;
      idempotencyRef.current.complete();
      setRetryFailureId(null);
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: answerWithoutEmbeddedSources(reply.answer),
          createdAt: new Date().toISOString(),
          citations: reply.citations,
          sourceStatus: reply.source_status,
          provider: reply.provider,
          model: reply.model,
          table: reply.table,
          answerReview: reply.answer_review,
        },
      ]);
      settleServiceRequest(serviceRevision, {
        state: "connected",
        hint: "知识检索已连接",
      });
    } catch (reason) {
      if (
        activeRequestRef.current !== deadline
        || (deadline.signal.aborted && !deadline.timedOut)
      ) return;
      const timedOut = deadline.timedOut;
      const unavailable = reason instanceof ApiClientError && [404, 501].includes(reason.status);
      const failureId = crypto.randomUUID();
      setRetryFailureId(failureId);
      setMessages((current) => [
        ...current,
        {
          id: failureId,
          role: "assistant",
          content: timedOut
            ? "问答请求超时，请稍后重试。"
            : unavailable
              ? "聊天 API 尚未接入，请稍后再试。"
              : readableError(reason),
          createdAt: new Date().toISOString(),
          failed: true,
        },
      ]);
      settleServiceRequest(serviceRevision, {
        state: "warning",
        hint: timedOut ? "请求超时" : unavailable ? "问答服务尚未接入" : "连接异常",
      });
    } finally {
      deadline.dispose();
      if (activeRequestRef.current === deadline) {
        activeRequestRef.current = null;
        setPending(false);
      }
    }
  }

  async function send() {
    const content = input.trim();
    if (
      !content
      || content.length > CHAT_MESSAGE_MAX_LENGTH
      || !knowledgeBaseId
      || pending
      || activeRequestRef.current
      || !can("chat:query")
    ) return;
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      createdAt: new Date().toISOString(),
    };
    const operation: ChatOperation = { content, knowledgeBaseId, userMessage };
    const idempotencyKey = idempotencyRef.current.begin();
    setInput("");
    await executeOperation(operation, idempotencyKey, true);
  }

  async function retryFailedOperation() {
    const operation = retryOperationRef.current;
    const idempotencyKey = idempotencyRef.current.retry();
    if (
      !operation
      || !idempotencyKey
      || pending
      || activeRequestRef.current
      || !can("chat:query")
    ) return;
    if (retryFailureId) {
      setMessages((current) => current.filter((message) => message.id !== retryFailureId));
    }
    setRetryFailureId(null);
    await executeOperation(operation, idempotencyKey, false);
  }

  const canQuery = !accessLoading && can("chat:query");
  const ready = canQuery && Boolean(knowledgeBaseId);
  const displayName = me?.display_name?.trim() || me?.email.split("@")[0] || "您好";
  const knowledgeBaseOptions = candidatesWithSelection(
    knowledgeBases ?? [],
    selectedKnowledgeBase,
  );

  function searchKnowledgeBases(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextQuery = knowledgeQuery.trim();
    if (nextQuery === activeKnowledgeQuery) {
      void loadKnowledgeBases({ search: nextQuery, offset: 0, append: false });
    } else {
      setActiveKnowledgeQuery(nextQuery);
    }
  }

  function selectKnowledgeBase(nextId: string) {
    const next = knowledgeBaseOptions.find((item) => item.id === nextId) ?? null;
    knowledgeBaseIdRef.current = nextId;
    setKnowledgeBaseId(nextId);
    setSelectedKnowledgeBase(next);
    startNewConversation();
  }

  return (
    <section className="chat-layout">
      <div className="chat-main">
        <header className="chat-head">
          <div className="chat-heading">
            <p>知识问答 · Enterprise Intelligence</p>
            <h1>{displayName}，您好</h1>
            <span>有什么可以帮您？每个回答都会附上可核验的答案来源。</span>
          </div>
          <div className="chat-controls">
            <form className="chat-knowledge-search" role="search" onSubmit={searchKnowledgeBases}>
              <input
                aria-label="搜索可问答知识库"
                type="search"
                maxLength={200}
                value={knowledgeQuery}
                onChange={(event) => setKnowledgeQuery(event.target.value)}
                placeholder="搜索全部授权知识库"
              />
              <button className="button secondary small" type="submit" disabled={knowledgeCatalogLoading}>
                搜索
              </button>
            </form>
            <select
              aria-label="选择知识库"
              value={knowledgeBaseId}
              onChange={(event) => selectKnowledgeBase(event.target.value)}
              disabled={!knowledgeBaseOptions.length || pending}
            >
              {!knowledgeBaseOptions.length ? <option value="">暂无可访问知识库</option> : null}
              {knowledgeBaseOptions.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
            </select>
            {knowledgeHasMore ? (
              <button
                className="button secondary small"
                type="button"
                disabled={knowledgeCatalogLoading}
                onClick={() => void loadKnowledgeBases({
                  search: activeKnowledgeQuery,
                  offset: knowledgeBases?.length ?? 0,
                  append: true,
                })}
              >
                {knowledgeCatalogLoading ? "正在加载…" : "加载更多知识库"}
              </button>
            ) : null}
            {knowledgeCatalogError ? (
              <span className="chat-catalog-error" role="status">
                知识库列表加载失败；当前对话仍可继续。{knowledgeCatalogError}
              </span>
            ) : null}
            <span className="chat-status" data-state={serviceStatus.state} aria-live="polite"><span />{serviceStatus.hint}</span>
            <button className="button secondary small" type="button" onClick={startNewConversation}>
              <Icon name="plus" /> 新对话
            </button>
          </div>
        </header>
        <div className="message-area" aria-live="polite" aria-busy={pending}>
          {messages.length === 0 ? (
            <div className="chat-welcome">
              <span className="chat-orb"><Icon name="spark" /></span>
              <h2>{knowledgeBases === null ? "正在读取知识库…" : knowledgeBaseId ? "今天想了解什么？" : "还没有可问答的知识库"}</h2>
              <p>{!knowledgeBaseId && knowledgeCatalogError
                ? knowledgeCatalogError
                : knowledgeBaseId
                  ? "先选择一个知识库，再从授权内容中检索答案与来源。"
                  : "请联系管理员授予知识库访问权限，或先在管理控制台创建知识库。"}</p>
              {ready ? (
                <div className="suggestion-grid">
                  {suggestions.map((suggestion) => (
                    <button className="suggestion" type="button" key={suggestion} onClick={() => updateInput(suggestion)}>{suggestion}</button>
                  ))}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="messages">
              {messages.map((message) => (
                <article className={`message ${message.role}${message.failed ? " failed" : ""}`} key={message.id}>
                  <span className="message-avatar"><Icon name={message.role === "user" ? "users" : "spark"} /></span>
                  <div className="message-bubble">
                    <div className="answer-response">
                      <div className="message-content">{message.content}</div>
                      {message.role === "assistant" && message.table ? <ChatDataTable table={message.table} /> : null}
                      {message.failed && message.id === retryFailureId ? (
                        <button
                          className="button secondary small"
                          type="button"
                          onClick={() => void retryFailedOperation()}
                          disabled={pending}
                        >
                          重新发送
                        </button>
                      ) : null}
                    </div>
                    {message.role === "assistant" ? (
                      <AnswerSources
                        citations={message.citations}
                        failed={message.failed}
                        headingId={`answer-sources-${message.id}`}
                        model={message.model}
                        provider={message.provider}
                        answerReview={message.answerReview}
                        sourceStatus={message.sourceStatus}
                      />
                    ) : null}
                  </div>
                </article>
              ))}
              {pending ? (
                <article className="message assistant">
                  <span className="message-avatar"><Icon name="spark" /></span>
                  <div className="message-bubble">正在检索可访问的知识…</div>
                </article>
              ) : null}
              <div ref={bottomRef} />
            </div>
          )}
        </div>
        <footer className="composer-wrap">
          <div className="composer">
            <textarea
              aria-label="输入问题"
              placeholder={ready ? "输入问题，按 Enter 发送…" : "请选择一个可访问的知识库"}
              value={input}
              disabled={!ready || pending}
              maxLength={CHAT_MESSAGE_MAX_LENGTH}
              onChange={(event) => updateInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
                  event.preventDefault();
                  void send();
                }
              }}
            />
            <button className="send-button" type="button" aria-label="发送" onClick={() => void send()} disabled={!ready || !input.trim() || pending}>
              <Icon name="send" />
            </button>
          </div>
          <p className="composer-note">AI 输出可能有误；关键业务结论请回看来源文件。</p>
        </footer>
      </div>
    </section>
  );
}
