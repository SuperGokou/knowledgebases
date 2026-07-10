import { Icon } from "@/components/icon";
import {
  citationLocators,
  citationMarker,
  citationTraceLabel,
  sourceSummary,
} from "@/lib/chat-sources";
import type { ChatCitation, ChatSourceStatus } from "@/lib/types";

type AnswerSourcesProps = {
  citations?: ChatCitation[];
  failed?: boolean;
  headingId: string;
  model?: string | null;
  provider?: string | null;
  sourceStatus?: ChatSourceStatus;
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
}: AnswerSourcesProps) {
  const summary = sourceSummary(citations, sourceStatus, failed);
  const showGenerationMetadata =
    !failed && sourceStatus?.strategy === "rag" && Boolean(provider || model);
  const providerLabel = provider ? providerLabels[provider.toLowerCase()] ?? provider : null;

  return (
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
          {summary.state === "grounded" ? "可核验" : summary.state === "failed" ? "未生成" : "无引用"}
        </span>
      </header>

      {citations.length > 0 && !failed ? (
        <ol className="citation-list" aria-label={`本回答的 ${citations.length} 条知识来源`}>
          {citations.map((citation, index) => {
            const locators = citationLocators(citation);
            return (
              <li className="citation-card" key={`${citation.entry_id}-${index}`}>
                <span className="citation-marker" aria-hidden="true">
                  {citationMarker(citation, index)}
                </span>
                <div className="citation-copy">
                  <div className="citation-title-row">
                    <strong>{citation.title || "未命名知识条目"}</strong>
                    <span className="citation-availability">
                      <Icon name="check" /> {citationTraceLabel(citation)}
                    </span>
                  </div>
                  <p>{citation.excerpt || "该来源未提供摘录，请在知识库中查看原始条目。"}</p>
                  <div className="citation-meta">
                    <span title={locators.entryId}>{locators.entryId}</span>
                    {locators.sourcePath ? <span title={locators.sourcePath}>路径：{locators.sourcePath}</span> : null}
                    {citation.format_version ? <span>OKF {citation.format_version}</span> : null}
                  </div>
                </div>
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
        </div>
      ) : null}
    </section>
  );
}
