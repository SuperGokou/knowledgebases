import { FilesPanel } from "@/components/files-panel";
import { PageHeader } from "@/components/ui";

export const metadata = { title: "文件中心" };

export default function FilesPage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="FILES" title="文件中心" description="上传文件并跟踪从对象存储到内容审核的完整状态。大文件自动使用 Multipart 直传。" />
      <FilesPanel />
    </div>
  );
}
