const IDEMPOTENCY_KEY_MAX_LENGTH = 160;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

export type ChatIdempotencyController = {
  begin: () => string;
  retry: () => string | null;
  complete: () => void;
  messageEdited: () => void;
  conversationReset: () => void;
};

export function isValidIdempotencyKey(value: string | null): value is string {
  return value !== null
    && value.length >= 1
    && value.length <= IDEMPOTENCY_KEY_MAX_LENGTH
    && IDEMPOTENCY_KEY_PATTERN.test(value);
}

export function createChatIdempotencyController(
  randomUUID: () => string = () => crypto.randomUUID(),
): ChatIdempotencyController {
  let activeKey: string | null = null;
  const rotate = () => { activeKey = null; };

  return {
    begin() {
      activeKey ??= `chat-${randomUUID()}`;
      return activeKey;
    },
    retry() {
      return activeKey;
    },
    complete: rotate,
    messageEdited: rotate,
    conversationReset: rotate,
  };
}
