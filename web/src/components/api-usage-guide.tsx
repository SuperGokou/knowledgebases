"use client";

import { useState, useSyncExternalStore } from "react";

import { Icon } from "@/components/icon";
import {
  buildApiUsageExample,
  API_ORIGIN_PLACEHOLDER,
  type ApiExampleLanguage,
  type PublicApiOperation,
} from "@/lib/api-usage-examples";

const languages: Array<{ id: ApiExampleLanguage; label: string }> = [
  { id: "curl", label: "cURL" },
  { id: "python", label: "Python" },
  { id: "node", label: "Node.js" },
];

const operations: Array<{ id: PublicApiOperation; label: string; path: string }> = [
  { id: "chat", label: "知识问答", path: "/api/v1/public/chat/query" },
  { id: "search", label: "知识检索", path: "/api/v1/public/knowledge-bases/{id}/search" },
];

function subscribeToApiOrigin(): () => void {
  return () => undefined;
}

function readBrowserApiOrigin(): string {
  return window.location.origin;
}

function readServerApiOrigin(): string {
  return API_ORIGIN_PLACEHOLDER;
}

export function ApiUsageGuide({ configuredApiOrigin }: { configuredApiOrigin?: string }) {
  const [language, setLanguage] = useState<ApiExampleLanguage>("curl");
  const [operation, setOperation] = useState<PublicApiOperation>("chat");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const browserApiOrigin = useSyncExternalStore(
    subscribeToApiOrigin,
    readBrowserApiOrigin,
    readServerApiOrigin,
  );
  const apiOrigin = configuredApiOrigin ?? browserApiOrigin;
  const example = buildApiUsageExample(language, operation, apiOrigin);
  const openApiUrl = `${apiOrigin}/openapi.json`;

  async function copyExample() {
    try {
      await navigator.clipboard.writeText(example);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <section className="panel api-guide-panel">
      <div className="panel-header">
        <div><h2>API 使用说明</h2><p>通过标准 HTTP 接口把知识问答和检索集成到业务系统</p></div>
        <span className="status-badge info">REST · JSON</span>
      </div>
      <div className="panel-body api-guide-body">
        <ol className="api-onboarding-steps">
          <li><span>1</span><div><strong>生成凭证</strong><p>为每个系统单独创建 API Key，便于独立撤销和审计。</p></div></li>
          <li><span>2</span><div><strong>保存到密钥管理器</strong><p>将明文写入服务端环境变量，不要放进前端代码或 Git。</p></div></li>
          <li><span>3</span><div><strong>发送请求</strong><p>使用 <code>X-API-Key</code> 请求头；平台仍会执行权限与限额检查。</p></div></li>
        </ol>

        <div className="api-endpoint-list" aria-label="公开 API 端点">
          {operations.map((item) => (
            <button
              className={operation === item.id ? "api-endpoint active" : "api-endpoint"}
              type="button"
              aria-pressed={operation === item.id}
              onClick={() => { setOperation(item.id); setCopyState("idle"); }}
              key={item.id}
            >
              <span className="http-method">POST</span>
              <span><strong>{item.label}</strong><code>{item.path}</code></span>
              <Icon name="arrow" />
            </button>
          ))}
        </div>

        <div className="code-example">
          <div className="code-toolbar">
            <div className="code-tabs" role="group" aria-label="示例语言">
              {languages.map((item) => (
                <button
                  className={language === item.id ? "active" : ""}
                  type="button"
                  aria-pressed={language === item.id}
                  onClick={() => { setLanguage(item.id); setCopyState("idle"); }}
                  key={item.id}
                >{item.label}</button>
              ))}
            </div>
            <button className="code-copy" type="button" onClick={() => void copyExample()}>
              <Icon name={copyState === "copied" ? "check" : "file"} />
              {copyState === "copied" ? "已复制" : copyState === "failed" ? "复制失败" : "复制示例"}
            </button>
          </div>
          <pre><code>{example}</code></pre>
        </div>

        <div className="api-origin-row">
          <span>API Origin</span><code>{apiOrigin}</code>
          <a className="button ghost small" href={openApiUrl} target="_blank" rel="noreferrer">
            OpenAPI JSON
          </a>
        </div>
        {operation === "chat" ? (
          <div className="notice api-security-notice">
            <Icon name="book" />
            <div>
              <strong>回答来源协议</strong>
              <p>
                每个成功回答都会返回正文来源脚注、结构化 <code>citations</code> 与
                <code> source_status</code>。请用稳定 <code>entry_id</code> 核验来源；
                <code>retrieval_fallback</code> 表示模型回答已被安全检索结果替代。
              </p>
            </div>
          </div>
        ) : null}
        <div className="notice api-security-notice">
          <Icon name="lock" />
          <div><strong>生产安全提示</strong><p>API Key 仅用于服务端调用。请按应用隔离凭证、定期轮换；一旦疑似泄露，立即在上方撤销并生成新 Key。</p></div>
        </div>
      </div>
    </section>
  );
}
