import { describe, expect, it } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  fileApprovalErrorMessage,
  fileApprovalPresentation,
  type FileApprovalState,
} from "../src/lib/file-approval";

function fileState(overrides: Partial<FileApprovalState> = {}): FileApprovalState {
  return {
    status: "processing",
    malware_scan_status: "clean",
    knowledge_status: "draft_ready",
    knowledge_error_code: null,
    ...overrides,
  };
}

describe("file approval presentation", () => {
  it("permits approval only after a clean scan and a ready knowledge draft", () => {
    expect(fileApprovalPresentation(fileState())).toEqual({
      action: "approve",
      label: "审批",
      reason: "安全扫描已通过，知识草稿已准备完成。",
    });

    expect(fileApprovalPresentation(fileState({ malware_scan_status: "pending" })).action)
      .toBe("status");
    expect(fileApprovalPresentation(fileState({ knowledge_status: "pending" })).action)
      .toBe("status");
    expect(fileApprovalPresentation(fileState({ status: "quarantined" })).action)
      .toBe("status");
  });

  it.each([
    [
      fileState({ status: "quarantined", malware_scan_status: "pending" }),
      "等待安全扫描",
      "文件将在安全扫描通过后进入知识转换。",
    ],
    [
      fileState({ status: "quarantined", malware_scan_status: "processing" }),
      "安全扫描中",
      "正在检查文件安全性，扫描通过前不能审批。",
    ],
    [
      fileState({ status: "quarantined", malware_scan_status: "infected" }),
      "安全扫描未通过",
      "文件已被隔离，不能进入审批流程。",
    ],
    [
      fileState({ status: "quarantined", malware_scan_status: "error" }),
      "安全扫描异常",
      "安全扫描未完成，请联系管理员处理后重试。",
    ],
    [
      fileState({ knowledge_status: "pending" }),
      "知识转换中",
      "正在生成可审核的知识草稿，完成后才能审批。",
    ],
    [
      fileState({ knowledge_status: "failed", knowledge_error_code: "parser_failed" }),
      "知识转换失败",
      "未生成可审批草稿，请检查文件内容或重新转换。",
    ],
    [
      fileState({ knowledge_status: "unsupported" }),
      "暂不支持审批",
      "当前文件格式无法生成知识草稿，不能审批入库。",
    ],
  ])("shows the Chinese %s status and reason for a blocked state", (state, label, reason) => {
    expect(fileApprovalPresentation(state)).toEqual({ action: "status", label, reason });
  });

  it("does not render an approval action for completed or deleted files", () => {
    expect(fileApprovalPresentation(fileState({ status: "available", knowledge_status: "indexed" })))
      .toEqual({ action: "none", label: "", reason: "" });
    expect(fileApprovalPresentation(fileState({ status: "deleted" })))
      .toEqual({ action: "none", label: "", reason: "" });
  });
});

describe("file approval conflict messages", () => {
  it.each([
    ["malware_scan_not_clean", "文件尚未通过安全扫描，请等待扫描完成并刷新状态。"],
    ["okf_conversion_not_completed", "知识转换尚未完成，请等待转换完成并刷新后再审批。"],
    ["okf_conversion_result_missing", "知识草稿不可用，请重新执行知识转换或联系管理员。"],
    ["file_state_conflict", "文件状态已发生变化，请刷新列表后再操作。"],
    ["unknown_conflict", "当前文件暂不可审批，请刷新状态后重试。"],
  ])("maps %s to an actionable Chinese message", (code, expected) => {
    expect(fileApprovalErrorMessage(new ApiClientError("server message", 409, code)))
      .toBe(expected);
  });

  it("leaves non-conflict errors to the shared API error presenter", () => {
    expect(fileApprovalErrorMessage(new ApiClientError("forbidden", 403, "forbidden")))
      .toBeNull();
    expect(fileApprovalErrorMessage(new Error("network"))).toBeNull();
  });
});
