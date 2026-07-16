export type ChatServiceIndicatorState = "connected" | "warning";

export type ChatServiceStatus = Readonly<{
  revision: number;
  state: ChatServiceIndicatorState;
  hint: string;
}>;

export type ChatServiceResolution = Readonly<{
  state: ChatServiceIndicatorState;
  hint: string;
}>;

export const INITIAL_CHAT_SERVICE_STATUS: ChatServiceStatus = {
  revision: 0,
  state: "warning",
  hint: "正在连接知识检索",
};

export function beginChatServiceCheck(
  currentRevision: number,
  hint: string,
): { revision: number; status: ChatServiceStatus } {
  const revision = currentRevision + 1;
  return {
    revision,
    status: { revision, state: "warning", hint },
  };
}

export function settleChatServiceCheck(
  current: ChatServiceStatus,
  revision: number,
  resolution: ChatServiceResolution,
): ChatServiceStatus {
  if (current.revision !== revision) return current;
  return { revision, ...resolution };
}
