import { ApiClientError } from "./api-client";
import type { FileRecord } from "./types";

export type FileApprovalState = Pick<
  FileRecord,
  "status" | "malware_scan_status" | "knowledge_status" | "knowledge_error_code"
>;

export type FileApprovalPresentation = Readonly<{
  action: "approve" | "status" | "none";
  label: string;
  reason: string;
}>;

const NO_APPROVAL_ACTION: FileApprovalPresentation = {
  action: "none",
  label: "",
  reason: "",
};

function blocked(label: string, reason: string): FileApprovalPresentation {
  return { action: "status", label, reason };
}

export function fileApprovalPresentation(file: FileApprovalState): FileApprovalPresentation {
  if (
    file.status === "available"
    || file.status === "deleted"
    || file.knowledge_status === "indexed"
  ) {
    return NO_APPROVAL_ACTION;
  }

  if (file.status === "pending" || file.status === "uploading") {
    return blocked("等待上传完成", "文件上传完成后才会进入安全扫描和知识转换流程。");
  }

  if (file.malware_scan_status === "pending") {
    return blocked("等待安全扫描", "文件将在安全扫描通过后进入知识转换。");
  }
  if (file.malware_scan_status === "processing") {
    return blocked("安全扫描中", "正在检查文件安全性，扫描通过前不能审批。");
  }
  if (file.malware_scan_status === "infected") {
    return blocked("安全扫描未通过", "文件已被隔离，不能进入审批流程。");
  }
  if (file.malware_scan_status === "error") {
    return blocked("安全扫描异常", "安全扫描未完成，请联系管理员处理后重试。");
  }

  if (file.knowledge_status === "pending") {
    return blocked("知识转换中", "正在生成可审核的知识草稿，完成后才能审批。");
  }
  if (file.knowledge_status === "failed") {
    return blocked("知识转换失败", "未生成可审批草稿，请检查文件内容或重新转换。");
  }
  if (file.knowledge_status === "unsupported") {
    return blocked("暂不支持审批", "当前文件格式无法生成知识草稿，不能审批入库。");
  }
  if (file.knowledge_status === "not_requested") {
    return blocked("等待知识转换", "尚未生成知识草稿，当前不能审批。");
  }

  if (file.status !== "processing") {
    return blocked("暂不可审批", "文件状态尚未进入审批阶段，请刷新后重试。");
  }

  return {
    action: "approve",
    label: "审批",
    reason: "安全扫描已通过，知识草稿已准备完成。",
  };
}

export function fileApprovalErrorMessage(error: unknown): string | null {
  if (!(error instanceof ApiClientError) || error.status !== 409) return null;

  switch (error.code) {
    case "malware_scan_not_clean":
      return "文件尚未通过安全扫描，请等待扫描完成并刷新状态。";
    case "okf_conversion_not_completed":
      return "知识转换尚未完成，请等待转换完成并刷新后再审批。";
    case "okf_conversion_result_missing":
      return "知识草稿不可用，请重新执行知识转换或联系管理员。";
    case "file_state_conflict":
      return "文件状态已发生变化，请刷新列表后再操作。";
    default:
      return "当前文件暂不可审批，请刷新状态后重试。";
  }
}
