"use client";

import { useEffect, useRef, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { AnswerSources } from "@/components/answer-sources";
import { ChatDataTable } from "@/components/chat-data-table";
import { Icon } from "@/components/icon";
import { ApiClientError, apiRequest, readableError } from "@/lib/api-client";
import { parseChatReply } from "@/lib/chat-contract";
import { answerWithoutEmbeddedSources } from "@/lib/chat-sources";
import { scrollIntoViewIfSupported } from "@/lib/dom";
import { createRequestDeadline, type RequestDeadline } from "@/lib/request-deadline";
import type { ChatMessage, KnowledgeBase } from "@/lib/types";

const CHAT_MESSAGE_MAX_LENGTH = 2_000;
const CHAT_REQUEST_TIMEOUT_MS = 70_000;

const suggestions = [
  "帮我总结这个知识库中的主要制度。",
  "查找与客户数据保留相关的说明。",
  "列出最近内容中提到的风险与行动项。",
  "给我一份适合新成员阅读的知识摘要。",
];

export function ChatWorkspace() {
  const { can, loading: accessLoading, me } = useAccess();
  const [knowledgeBases, setKnowledgeBases] = useState<KnowledgeBase[] | null>(null);
  const [knowledgeBaseId, setKnowledgeBaseId] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [serviceHint, setServiceHint] = useState("正在连接知识检索");
  const bottomRef = useRef<HTMLDivElement>(null);
  const activeRequestRef = useRef<RequestDeadline | null>(null);

  useEffect(() => {
    let active = true;
    async function loadKnowledgeBases() {
      try {
        const items = await apiRequest<KnowledgeBase[]>("/api/v1/knowledge-bases");
        if (!active) return;
        setKnowledgeBases(items);
        setKnowledgeBaseId((current) => current || items[0]?.id || "");
        setServiceHint(items.length ? "知识检索已连接" : "暂无可访问知识库");
      } catch (reason) {
        if (!active) return;
        setKnowledgeBases([]);
        setLoadError(readableError(reason));
        setServiceHint(reason instanceof ApiClientError && [404, 501].includes(reason.status) ? "问答服务尚未接入" : "连接异常");
      }
    }
    void loadKnowledgeBases();
    return () => { active = false; };
  }, []);

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
    setPending(false);
    setMessages([]);
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
    const deadline = createRequestDeadline(CHAT_REQUEST_TIMEOUT_MS);
    activeRequestRef.current = deadline;
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      createdAt: new Date().toISOString(),
    };
    setMessages((current) => [...current, userMessage]);
    setInput("");
    setPending(true);
    try {
      const reply = parseChatReply(
        await apiRequest<unknown>("/api/v1/chat/query", {
          method: "POST",
          body: JSON.stringify({ knowledge_base_id: knowledgeBaseId, message: content, limit: 5 }),
          signal: deadline.signal,
        }),
      );
      if (activeRequestRef.current !== deadline) return;
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
      setServiceHint("知识检索已连接");
    } catch (reason) {
      if (
        activeRequestRef.current !== deadline
        || (deadline.signal.aborted && !deadline.timedOut)
      ) return;
      const timedOut = deadline.timedOut;
      const unavailable = reason instanceof ApiClientError && [404, 501].includes(reason.status);
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
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
      setServiceHint(timedOut ? "请求超时" : unavailable ? "问答服务尚未接入" : "连接异常");
    } finally {
      deadline.dispose();
      if (activeRequestRef.current === deadline) {
        activeRequestRef.current = null;
        setPending(false);
      }
    }
  }

  const canQuery = !accessLoading && can("chat:query");
  const ready = canQuery && Boolean(knowledgeBaseId);
  const displayName = me?.display_name?.trim() || me?.email.split("@")[0] || "您好";

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
            <select
              aria-label="选择知识库"
              value={knowledgeBaseId}
              onChange={(event) => {
                setKnowledgeBaseId(event.target.value);
                startNewConversation();
              }}
              disabled={!knowledgeBases?.length || pending}
            >
              {!knowledgeBases?.length ? <option value="">暂无可访问知识库</option> : null}
              {knowledgeBases?.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
            </select>
            <span className="chat-status"><span />{serviceHint}</span>
            <button className="button secondary small" type="button" onClick={startNewConversation}>
              <Icon name="plus" /> 新对话
            </button>
          </div>
        </header>
        <div className="message-area" aria-live="polite" aria-busy={pending}>
          {messages.length === 0 ? (
            <div className="chat-welcome">
              <span className="chat-orb"><Icon name="spark" /></span>
              <h2>{knowledgeBases === null ? "正在读取知识库…" : knowledgeBases.length ? "今天想了解什么？" : "还没有可问答的知识库"}</h2>
              <p>{loadError || (knowledgeBases?.length ? "先选择一个知识库，再从授权内容中检索答案与来源。" : "请联系管理员授予知识库访问权限，或先在管理控制台创建知识库。")}</p>
              {ready ? (
                <div className="suggestion-grid">
                  {suggestions.map((suggestion) => (
                    <button className="suggestion" type="button" key={suggestion} onClick={() => setInput(suggestion)}>{suggestion}</button>
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
              disabled={!ready}
              maxLength={CHAT_MESSAGE_MAX_LENGTH}
              onChange={(event) => setInput(event.target.value)}
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
