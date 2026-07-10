import { ApiKeysPanel } from "@/components/api-keys-panel";
import { ApiUsageGuide } from "@/components/api-usage-guide";
import { ModelSettingsPanel } from "@/components/model-settings-panel";
import { PageHeader } from "@/components/ui";

export const metadata = { title: "API 与模型" };

export default function ApiModelsPage() {
  return (
    <div className="page-stack developer-platform-page">
      <PageHeader
        eyebrow="DEVELOPER PLATFORM"
        title="API 与模型"
        description="为业务系统生成可撤销的 API 凭证，并统一切换 DeepSeek、Qwen 与 MiniMax 模型服务。"
      />
      <div className="developer-platform-hero">
        <div>
          <span className="developer-hero-icon"><span>&lt;/&gt;</span></span>
          <div><p>ENTERPRISE API GATEWAY</p><h2>用一个安全入口连接企业知识</h2><span>每个请求都会经过 API Key 校验、知识权限过滤、角色限额与审计链路。</span></div>
        </div>
        <div className="developer-hero-metrics">
          <span><strong>3</strong><small>模型供应商</small></span>
          <span><strong>2</strong><small>公开 API</small></span>
          <span><strong>100%</strong><small>服务端鉴权</small></span>
        </div>
      </div>
      <ApiKeysPanel />
      <ModelSettingsPanel />
      <ApiUsageGuide />
    </div>
  );
}
