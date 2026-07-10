import { KnowledgeGrantsPanel } from "@/components/knowledge-grants-panel";
import { KnowledgePanel } from "@/components/knowledge-panel";
import { PageHeader } from "@/components/ui";

export const metadata = { title: "知识库" };

export default function KnowledgePage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="KNOWLEDGE" title="知识库" description="组织业务知识、文件来源和检索边界；未接入的后台能力会以明确空态呈现。" />
      <KnowledgePanel />
      <KnowledgeGrantsPanel />
    </div>
  );
}
