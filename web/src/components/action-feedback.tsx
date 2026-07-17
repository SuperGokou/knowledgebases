"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";

import { Icon } from "@/components/icon";

export type ActionFeedbackTone = "success" | "error" | "info";

interface ActionFeedbackInput {
  tone: ActionFeedbackTone;
  title: string;
  message: string;
  durationMs?: number;
}

interface ActionFeedbackItem extends ActionFeedbackInput {
  id: number;
  durationMs: number;
  focusTarget: HTMLElement | null;
}

interface ActionFeedbackApi {
  success: (message: string, title?: string) => number;
  error: (message: string, title?: string) => number;
  info: (message: string, title?: string) => number;
  dismiss: () => void;
}

const ActionFeedbackContext = createContext<ActionFeedbackApi | null>(null);

function FeedbackToast({
  item,
  onDismiss,
}: {
  item: ActionFeedbackItem;
  onDismiss: (id: number, focusTarget?: HTMLElement | null) => void;
}) {
  const timeoutRef = useRef<number | null>(null);
  const remainingMsRef = useRef(item.durationMs);
  const startedAtRef = useRef(0);
  const hoveringRef = useRef(false);
  const focusWithinRef = useRef(false);
  const [paused, setPaused] = useState(false);

  const clearTimer = useCallback((trackElapsed: boolean) => {
    if (timeoutRef.current === null) return;
    window.clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    if (trackElapsed) {
      remainingMsRef.current = Math.max(
        0,
        remainingMsRef.current - (Date.now() - startedAtRef.current),
      );
    }
  }, []);

  const scheduleTimer = useCallback(() => {
    if (remainingMsRef.current <= 0 || timeoutRef.current !== null) return;
    startedAtRef.current = Date.now();
    timeoutRef.current = window.setTimeout(
      () => {
        timeoutRef.current = null;
        onDismiss(item.id);
      },
      remainingMsRef.current,
    );
  }, [item.id, onDismiss]);

  useEffect(() => {
    if (item.durationMs <= 0) return;
    scheduleTimer();
    return () => clearTimer(false);
  }, [clearTimer, item.durationMs, scheduleTimer]);

  function pauseTimer() {
    if (item.durationMs <= 0) return;
    clearTimer(true);
    setPaused(true);
  }

  function resumeTimerIfIdle() {
    if (item.durationMs <= 0 || hoveringRef.current || focusWithinRef.current) return;
    setPaused(false);
    scheduleTimer();
  }

  const icon = item.tone === "success" ? "check" : item.tone === "error" ? "warning" : "refresh";
  const style = item.durationMs > 0
    ? ({ "--feedback-duration": `${item.durationMs}ms` } as CSSProperties)
    : undefined;

  return (
    <div
      className={`action-feedback ${item.tone}${paused ? " paused" : ""}`}
      data-tone={item.tone}
      style={style}
      onMouseEnter={() => {
        hoveringRef.current = true;
        pauseTimer();
      }}
      onMouseLeave={() => {
        hoveringRef.current = false;
        resumeTimerIfIdle();
      }}
      onFocusCapture={() => {
        focusWithinRef.current = true;
        pauseTimer();
      }}
      onBlurCapture={(event) => {
        if (event.currentTarget.contains(event.relatedTarget)) return;
        focusWithinRef.current = false;
        resumeTimerIfIdle();
      }}
    >
      <span className="action-feedback-icon"><Icon name={icon} /></span>
      <div className="action-feedback-copy">
        <strong>{item.title}</strong>
        <p>{item.message}</p>
      </div>
      <button
        className="action-feedback-close"
        type="button"
        aria-label="关闭操作提示"
        onClick={() => onDismiss(item.id, item.focusTarget)}
      >
        关闭
      </button>
      {item.durationMs > 0 ? <span className="action-feedback-progress" aria-hidden="true" /> : null}
    </div>
  );
}

export function ActionFeedbackProvider({ children }: { children: ReactNode }) {
  const sequence = useRef(0);
  const pendingFocusTargetRef = useRef<HTMLElement | null>(null);
  const [item, setItem] = useState<ActionFeedbackItem | null>(null);

  const dismissById = useCallback((id: number, focusTarget?: HTMLElement | null) => {
    setItem((current) => current?.id === id ? null : current);
    if (focusTarget?.isConnected) window.setTimeout(() => focusTarget.focus(), 0);
  }, []);
  const dismiss = useCallback(() => {
    const activeElement = document.activeElement;
    pendingFocusTargetRef.current = activeElement instanceof HTMLElement
      && !activeElement.closest(".action-feedback")
      ? activeElement
      : null;
    setItem(null);
  }, []);
  const show = useCallback((input: ActionFeedbackInput) => {
    const id = ++sequence.current;
    const durationMs = input.durationMs
      ?? (input.tone === "success" ? 6_000 : input.tone === "info" ? 7_000 : 0);
    const activeElement = document.activeElement;
    const currentFocusTarget = activeElement instanceof HTMLElement
      && !activeElement.closest(".action-feedback")
      ? activeElement
      : null;
    const focusTarget = pendingFocusTargetRef.current?.isConnected
      ? pendingFocusTargetRef.current
      : currentFocusTarget;
    pendingFocusTargetRef.current = null;
    setItem({ ...input, id, durationMs, focusTarget });
    return id;
  }, []);
  const api = useMemo<ActionFeedbackApi>(() => ({
    success: (message, title = "保存成功") => show({ tone: "success", title, message }),
    error: (message, title = "操作未完成") => show({ tone: "error", title, message }),
    info: (message, title = "请注意") => show({ tone: "info", title, message }),
    dismiss,
  }), [dismiss, show]);

  return (
    <ActionFeedbackContext.Provider value={api}>
      {children}
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {item && item.tone !== "error" ? <span key={item.id}>{item.title}。{item.message}</span> : null}
      </div>
      <div className="action-feedback-viewport" role="region" aria-label="操作结果通知">
        {item ? <FeedbackToast item={item} onDismiss={dismissById} key={item.id} /> : null}
      </div>
    </ActionFeedbackContext.Provider>
  );
}

export function useActionFeedback(): ActionFeedbackApi {
  const context = useContext(ActionFeedbackContext);
  if (!context) throw new Error("useActionFeedback must be used within ActionFeedbackProvider");
  return context;
}
