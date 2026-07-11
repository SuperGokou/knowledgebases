"use client";

import { useState } from "react";

import { Icon } from "@/components/icon";
import {
  citationLocators,
  citationMarker,
  citationTraceLabel,
  sourceSummary,
} from "@/lib/chat-sources";
import type { ChatAnswerReview, ChatCitation, ChatSourceStatus } from "@/lib/types";

type AnswerSourcesProps = {
  citations?: ChatCitation[];
  failed?: boolean;
  headingId: string;
  model?: string | null;
  provider?: string | null;
  sourceStatus?: ChatSourceStatus;
  answerReview?: ChatAnswerReview;
};

const providerLabels: Record<string, string> = {
  deepseek: "DeepSeek",
  qwen: "Qwen",
  minimax: "MiniMax",
};

export function AnswerSources({
  citations = [],
  failed = false,
  headingId,
  model,
  provider,
  sourceStatus,
  answerReview,
}: AnswerSourcesProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const summary = sourceSummary(citations, sourceStatus, failed);
  const showGenerationMetadata =
    !failed && sourceStatus?.strategy === "rag" && Boolean(provider || model);
  const providerLabel = provider ? providerLabels[provider.toLowerCase()] ?? provider : null;
  const selectedCitation = citations[Math.min(selectedIndex, Math.max(citations.length - 1, 0))];
  const selectedLocators = selectedCitation ? citationLocators(selectedCitation) : null;

  return (
    <div className="answer-evidence">
      <section
        className={`answer-sources ${summary.state}`}
        aria-labelledby={headingId}
      >
        <header className="answer-sources-head">
          <span className="answer-sources-icon"><Icon name="book" /></span>
          <div>
            <h3 id={headingId}>答案来源</h3>
            <p>{summary.title}</p>
          </div>
          <span className={`source-state ${summary.state}`}>
            {summary.state === "grounded" ? <Icon name="check" /> : <Icon name="warning" />}
            {answerReview?.status === "passed" ? "已审核" : summary.state === "grounded" ? "可核验" : summary.state === "failed" ? "未生成" : "无引用"}
          </span>
        </header>

        {citations.length > 0 && !failed ? (
          <ol className="citation-list" aria-label={`本回答的 ${citations.length} 条知识来源`}>
            {citations.map((citation, index) => {
              const locators = citationLocators(citation);
              const selected = index === selectedIndex;
              return (
                <li key={`${citation.entry_id}-${index}`}>
                  <button
                    className={`citation-card${selected ? " selected" : ""}`}
                    type="button"
                    aria-pressed={selected}
                    onClick={() => setSelectedIndex(index)}
                  >
                    <span className="citation-marker" aria-hidden="true">
                      {citationMarker(citation, index)}
                    </span>
                    <span className="citation-copy">
                      <span className="citation-title-row">
                        <strong>{citation.title || "未命名知识条目"}</strong>
                        <span className="citation-availability">
                          <Icon name="check" /> {citationTraceLabel(citation)}
                        </span>
                      </span>
                      <span className="citation-excerpt">
                        {citation.excerpt || "该来源未提供摘录，请在知识库中查看原始条目。"}
                      </span>
                      <span className="citation-meta">
                        <span title={locators.entryId}>{locators.entryId}</span>
                        {locators.sourcePath ? <span title={locators.sourcePath}>路径：{locators.sourcePath}</span> : null}
                        {citation.format_version ? <span>OKF {citation.format_version}</span> : null}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="answer-sources-empty">{summary.detail}</p>
        )}

        {citations.length > 0 && !failed ? <p className="answer-sources-note">{summary.detail}</p> : null}
        {showGenerationMetadata ? (
          <div className="answer-generation" aria-label="回答生成方式">
            <span>生成方式</span>
            <strong>RAG</strong>
            {providerLabel ? <span>{providerLabel}</span> : null}
            {model ? <code>{model}</code> : null}
            {answerReview?.status === "passed" ? <span>语义审核通过</span> : <span>确定性检索</span>}
          </div>
        ) : null}
      </section>

      {selectedCitation && !failed ? (
        <aside className="source-preview" aria-label="当前来源预览">
          <header>
            <span><Icon name="file" /></span>
            <div>
              <p>Source preview</p>
              <h4>{selectedCitation.title || "未命名知识条目"}</h4>
            </div>
          </header>
          <blockquote>{selectedCitation.excerpt || "该来源没有可显示的摘录。"}</blockquote>
          <footer>
            <span>{selectedLocators?.entryId}</span>
            {selectedLocators?.sourcePath ? <span>{selectedLocators.sourcePath}</span> : null}
            {selectedCitation.format_version ? <span>OKF {selectedCitation.format_version}</span> : null}
          </footer>
        </aside>
      ) : null}
    </div>
  );
}
