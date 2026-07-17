import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const feedback = readFileSync(join(process.cwd(), "src/components/action-feedback.tsx"), "utf8");
const shell = readFileSync(join(process.cwd(), "src/components/app-shell.tsx"), "utf8");
const styles = readFileSync(join(process.cwd(), "src/app/globals.css"), "utf8");

describe("action feedback source contract", () => {
  it("is available to every authenticated workspace page", () => {
    expect(shell).toContain("<ActionFeedbackProvider>");
    expect(shell).toContain("</ActionFeedbackProvider>");
  });

  it("keeps one stable polite live region without duplicating inline error alerts", () => {
    expect(feedback).toContain('role="status" aria-live="polite" aria-atomic="true"');
    expect(feedback).toContain('<span key={item.id}>');
    expect(feedback).not.toContain('role={item.tone === "error" ? "alert" : undefined}');
  });

  it("auto-dismisses success while keeping failures visible until acknowledged", () => {
    expect(feedback).toContain('input.tone === "success" ? 6_000');
    expect(feedback).toContain('input.tone === "info" ? 7_000 : 0');
    expect(feedback).toContain("关闭操作提示");
    expect(feedback).toContain("onMouseEnter");
    expect(feedback).toContain("onFocusCapture");
    expect(feedback).toContain("focusTarget.focus()");
  });

  it("uses lightweight motion and honors reduced-motion preferences", () => {
    expect(styles).toContain("@keyframes action-feedback-in");
    expect(styles).toContain("@keyframes action-feedback-icon-in");
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
    expect(styles).toContain("animation-duration: .01ms !important");
  });
});
