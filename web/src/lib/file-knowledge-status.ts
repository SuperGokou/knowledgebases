import type { FileRecord } from "./types";

type BadgeTone = "success" | "warning" | "danger" | "neutral" | "info";

type KnowledgePresentation = {
  label: string;
  tone: BadgeTone;
  searchable: boolean;
};

const PRESENTATION: Record<FileRecord["knowledge_status"], KnowledgePresentation> = {
  not_requested: { label: "未加入知识库", tone: "neutral", searchable: false },
  pending: { label: "知识转换中", tone: "info", searchable: false },
  draft_ready: { label: "草稿待审核", tone: "warning", searchable: false },
  indexed: { label: "已入知识库", tone: "success", searchable: true },
  failed: { label: "知识转换失败", tone: "danger", searchable: false },
  unsupported: { label: "暂不支持解析", tone: "warning", searchable: false },
};

export function fileKnowledgePresentation(
  status: FileRecord["knowledge_status"],
): KnowledgePresentation {
  return PRESENTATION[status];
}
