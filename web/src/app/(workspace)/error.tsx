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
        message={`页面渲染时遇到问题，请重新加载最新版。错误编号：${errorCode}`}
        onRetry={() => window.location.reload()}
      />
    </div>
  );
}
