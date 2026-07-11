export type RequestDeadline = {
  readonly signal: AbortSignal;
  readonly timedOut: boolean;
  cancel(): void;
  dispose(): void;
};

function abortReason(name: "AbortError" | "TimeoutError"): Error {
  const error = new Error(name === "TimeoutError" ? "Request timed out" : "Request cancelled");
  error.name = name;
  return error;
}

export function createRequestDeadline(timeoutMs: number): RequestDeadline {
  const controller = new AbortController();
  const duration = Number.isFinite(timeoutMs) ? Math.max(1, Math.trunc(timeoutMs)) : 1;
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | null = setTimeout(() => {
    timer = null;
    timedOut = true;
    if (!controller.signal.aborted) controller.abort(abortReason("TimeoutError"));
  }, duration);

  const clearTimer = () => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  };

  return {
    signal: controller.signal,
    get timedOut() {
      return timedOut;
    },
    cancel() {
      clearTimer();
      if (!controller.signal.aborted) controller.abort(abortReason("AbortError"));
    },
    dispose: clearTimer,
  };
}
