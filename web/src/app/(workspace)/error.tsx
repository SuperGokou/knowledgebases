"use client";

import { ErrorState } from "@/components/ui";

export default function WorkspaceError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="page-stack">
      <ErrorState message="页面渲染时遇到问题，请重试。" onRetry={reset} />
    </div>
  );
}
