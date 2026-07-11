"use client";

import { useEffect, useMemo } from "react";

import { ErrorState } from "@/components/ui";
import {
  type DigestError,
  workspaceErrorCode,
  workspaceErrorLogRecord,
} from "@/lib/error-reporting";

export default function WorkspaceError({
  error,
  reset,
}: {
  error: DigestError;
  reset: () => void;
}) {
  const errorCode = useMemo(() => workspaceErrorCode(error), [error]);

  useEffect(() => {
    console.error("[workspace_error]", workspaceErrorLogRecord(error, errorCode));
  }, [error, errorCode]);

  return (
    <div className="page-stack">
      <ErrorState
        message={`页面渲染时遇到问题，请重试。错误编号：${errorCode}`}
        onRetry={reset}
      />
    </div>
  );
}
