"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { useAccess } from "@/components/access-provider";
import { useActionFeedback } from "@/components/action-feedback";
import { Icon } from "@/components/icon";
import { EmptyState, ErrorState, LoadingRows, StatusBadge } from "@/components/ui";
import { createActionLock } from "@/lib/action-lock";
import { apiRequest, readableError } from "@/lib/api-client";
import { buildProviderUpdate, microUsdToUsd } from "@/lib/model-settings";
import type { LlmProviderName, LlmProviderSettings, LlmProvidersResponse } from "@/lib/types";

const providerMeta: Record<LlmProviderName, { label: string; short: string; description: string }> = {
  deepseek: { label: "DeepSeek", short: "DS", description: "通用问答与知识内容转换" },
  qwen: { label: "Qwen 通义千问", short: "QW", description: "阿里云兼容模式模型服务" },
  minimax: { label: "MiniMax", short: "MM", description: "企业级文本生成模型服务" },
};

export function ModelSettingsPanel() {
  const { can, loading: accessLoading } = useAccess();
  const feedback = useActionFeedback();
  const actionLock = useMemo(() => createActionLock(), []);
  const [providers, setProviders] = useState<LlmProviderSettings[] | null>(null);
  const [selected, setSelected] = useState<LlmProviderName | null>(null);
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [inputPriceUsd, setInputPriceUsd] = useState("");
  const [outputPriceUsd, setOutputPriceUsd] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  function selectProvider(provider: LlmProviderSettings) {
    setSelected(provider.provider);
    setModel(provider.model);
    setBaseUrl(provider.base_url);
    setApiKey("");
    setInputPriceUsd(microUsdToUsd(provider.input_micro_usd_per_million_tokens));
    setOutputPriceUsd(microUsdToUsd(provider.output_micro_usd_per_million_tokens));
    feedback.dismiss();
  }

  const load = useCallback(async () => {
    if (accessLoading) return;
    if (!can("llm:manage")) {
      setProviders([]);
      return;
    }
    setError("");
    try {
      const response = await apiRequest<LlmProvidersResponse>("/api/v1/llm/providers");
      const items = response.providers;
      setProviders(items);
      const first = items.find((item) => item.provider === response.default_provider) ?? items[0];
      if (first) {
        setSelected(first.provider);
        setModel(first.model);
        setBaseUrl(first.base_url);
        setApiKey("");
        setInputPriceUsd(microUsdToUsd(first.input_micro_usd_per_million_tokens));
        setOutputPriceUsd(microUsdToUsd(first.output_micro_usd_per_million_tokens));
      }
    } catch (reason) {
      setError(readableError(reason));
    }
  }, [accessLoading, can]);

  useEffect(() => {
    const timeout = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeout);
  }, [load]);

  const current = providers?.find((provider) => provider.provider === selected) ?? null;

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || !actionLock.acquire()) return;
    setPending(true);
    setError("");
    feedback.dismiss();
    try {
      const payload = buildProviderUpdate({
        model,
        baseUrl,
        apiKey,
        inputPriceUsd,
        outputPriceUsd,
      });
      const updated = await apiRequest<LlmProviderSettings>(`/api/v1/llm/providers/${selected}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      setProviders((items) => items?.map((item) => item.provider === updated.provider
        ? updated
        : { ...item, is_default: false }) ?? [updated]);
      setModel(updated.model);
      setBaseUrl(updated.base_url);
      setApiKey("");
      setInputPriceUsd(microUsdToUsd(updated.input_micro_usd_per_million_tokens));
      setOutputPriceUsd(microUsdToUsd(updated.output_micro_usd_per_million_tokens));
      feedback.success(`已切换到 ${providerMeta[updated.provider].label}，新请求将使用 ${updated.model}。`, "模型配置已保存");
    } catch (reason) {
      const message = readableError(reason);
      setError(message);
      feedback.error(message, "模型配置保存失败");
    } finally {
      actionLock.release();
      setPending(false);
    }
  }

  if (!accessLoading && !can("llm:manage")) {
    return <EmptyState compact icon="lock" title="没有模型配置权限" description="当前角色不包含 llm:manage；模型密钥不会发送到浏览器。" />;
  }

  return (
    <section className="panel model-settings-panel">
      <div className="panel-header">
        <div><h2>模型供应商</h2><p>在 DeepSeek、Qwen 和 MiniMax 之间切换企业知识处理模型</p></div>
        {providers?.find((provider) => provider.is_default) ? <StatusBadge tone="success">正在运行</StatusBadge> : <StatusBadge tone="warning">待配置</StatusBadge>}
      </div>
      {error ? <div className="panel-inline-state"><ErrorState message={error} onRetry={() => void load()} /></div> : null}
      {providers === null && !error ? <LoadingRows count={3} /> : null}
      {providers?.length === 0 && !error ? <EmptyState compact icon="spark" title="没有可用模型" description="请先在 FastAPI 后台初始化模型供应商。" /> : null}
      {providers?.length ? (
        <div className="model-settings-layout">
          <div className="provider-picker" role="group" aria-label="模型供应商">
            {providers.map((provider) => {
              const meta = providerMeta[provider.provider];
              return (
                <button
                  className={selected === provider.provider ? "provider-card selected" : "provider-card"}
                  type="button"
                  disabled={pending}
                  onClick={() => selectProvider(provider)}
                  key={provider.provider}
                >
                  <span className={`provider-mark provider-${provider.provider}`}>{meta.short}</span>
                  <span><strong>{meta.label}</strong><small>{meta.description}</small></span>
                  <span className="provider-state">
                    {provider.is_default ? <StatusBadge tone="success">当前</StatusBadge> : null}
                    <i className={provider.configured ? "configured" : ""} />
                    {provider.configured ? `已配置 · ${provider.credential_source === "environment" ? "环境变量" : "加密存储"}` : "缺少 Key"}
                  </span>
                </button>
              );
            })}
          </div>

          {current ? (
            <form className="provider-form" onSubmit={save}>
              <div className="provider-form-heading">
                <div><span className={`provider-mark provider-${current.provider}`}>{providerMeta[current.provider].short}</span><div><h3>{providerMeta[current.provider].label}</h3><p>配置采用 OpenAI 兼容接口，保存后立即切换。</p></div></div>
                <StatusBadge tone={current.configured ? "success" : "warning"}>{current.configured ? "API Key 已配置" : "需要 API Key"}</StatusBadge>
              </div>
              <div className="form-grid">
                <label>模型名称<input value={model} maxLength={100} disabled={pending} onChange={(event) => setModel(event.target.value)} placeholder="例如：qwen-plus" required /></label>
                <label>API Base URL<input type="url" value={baseUrl} maxLength={500} disabled={pending} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://api.example.com/v1" required /></label>
                <label>输入价格（美元 / 百万 Token）
                  <input inputMode="decimal" value={inputPriceUsd} disabled={pending} onChange={(event) => setInputPriceUsd(event.target.value)} placeholder="例如：0.8" required />
                  <span className="field-hint">用于请求前成本预留，最多保留 6 位小数。</span>
                </label>
                <label>输出价格（美元 / 百万 Token）
                  <input inputMode="decimal" value={outputPriceUsd} disabled={pending} onChange={(event) => setOutputPriceUsd(event.target.value)} placeholder="例如：2" required />
                  <span className="field-hint">价格以微美元整数存储，避免浮点误差。</span>
                </label>
                <label className="full">供应商 API Key
                  <input type="password" value={apiKey} autoComplete="new-password" disabled={pending} onChange={(event) => setApiKey(event.target.value)} placeholder={current.configured ? "已配置 · 留空表示保持不变" : "输入供应商 API Key"} required={!current.configured} />
                  <span className="field-hint">密钥提交后加密保存，此页面永远不会回显已有明文。留空不会覆盖已配置密钥。</span>
                </label>
              </div>
              <div className="provider-form-footer">
                <div><Icon name="shield" /><span><strong>切换影响范围</strong><small>新发起的聊天、检索增强和 OKF 转换任务</small></span></div>
                <button className="button primary" type="submit" disabled={pending || !model.trim() || !baseUrl.trim()} aria-busy={pending}>{pending ? <><span className="spinner" />正在保存…</> : `保存并切换到 ${providerMeta[current.provider].label}`}</button>
              </div>
            </form>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
