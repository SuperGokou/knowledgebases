import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  INITIAL_CHAT_SERVICE_STATUS,
  beginChatServiceCheck,
  settleChatServiceCheck,
} from "../src/lib/chat-service-status";

const component = readFileSync(
  new URL("../src/components/chat-workspace.tsx", import.meta.url),
  "utf8",
);
const styles = readFileSync(
  new URL("../src/app/globals.css", import.meta.url),
  "utf8",
);

describe("knowledge connection status", () => {
  it("starts yellow, becomes green only after a successful request with a selection", () => {
    expect(INITIAL_CHAT_SERVICE_STATUS).toMatchObject({
      state: "warning",
      hint: "正在连接知识检索",
    });

    const checking = beginChatServiceCheck(0, "正在刷新知识库");
    expect(checking.status).toEqual({
      revision: 1,
      state: "warning",
      hint: "正在刷新知识库",
    });
    expect(settleChatServiceCheck(checking.status, checking.revision, {
      state: "connected",
      hint: "知识检索已连接",
    })).toEqual({
      revision: 1,
      state: "connected",
      hint: "知识检索已连接",
    });
  });

  it("keeps an empty catalog or any catalog/query failure yellow", () => {
    const empty = beginChatServiceCheck(3, "正在连接知识检索");
    expect(settleChatServiceCheck(empty.status, empty.revision, {
      state: "warning",
      hint: "暂无可访问知识库",
    }).state).toBe("warning");

    const failedRefresh = beginChatServiceCheck(empty.revision, "正在刷新知识库");
    expect(settleChatServiceCheck(failedRefresh.status, failedRefresh.revision, {
      state: "warning",
      hint: "连接异常",
    })).toMatchObject({ state: "warning", hint: "连接异常" });

    const recovered = beginChatServiceCheck(failedRefresh.revision, "正在刷新知识库");
    expect(settleChatServiceCheck(recovered.status, recovered.revision, {
      state: "connected",
      hint: "知识检索已连接",
    })).toMatchObject({ state: "connected", hint: "知识检索已连接" });
  });

  it("does not let an older request overwrite the latest connection result", () => {
    const older = beginChatServiceCheck(0, "正在刷新知识库");
    const newer = beginChatServiceCheck(older.revision, "正在检索知识库");
    const latestFailure = settleChatServiceCheck(newer.status, newer.revision, {
      state: "warning",
      hint: "请求超时",
    });

    expect(settleChatServiceCheck(latestFailure, older.revision, {
      state: "connected",
      hint: "知识检索已连接",
    })).toBe(latestFailure);

    const latestSuccess = settleChatServiceCheck(newer.status, newer.revision, {
      state: "connected",
      hint: "知识检索已连接",
    });
    expect(settleChatServiceCheck(latestSuccess, older.revision, {
      state: "warning",
      hint: "连接异常",
    })).toBe(latestSuccess);
  });

  it("wires the explicit state object to the status indicator", () => {
    expect(component).toContain('data-state={serviceStatus.state}');
    expect(component).toContain("beginChatServiceCheck");
    expect(component).toContain("settleChatServiceCheck");
  });

  it("uses green for connected and yellow for every non-connected state", () => {
    expect(styles).toMatch(
      /\.chat-status\[data-state="connected"\]\s*>\s*span\s*\{[^}]*background:\s*var\(--green\)/,
    );
    expect(styles).toMatch(
      /\.chat-status\[data-state="warning"\]\s*>\s*span\s*\{[^}]*background:\s*#d6a350/,
    );
  });
});
