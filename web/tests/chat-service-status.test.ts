import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const component = readFileSync(
  new URL("../src/components/chat-workspace.tsx", import.meta.url),
  "utf8",
);
const styles = readFileSync(
  new URL("../src/app/globals.css", import.meta.url),
  "utf8",
);

describe("knowledge connection status", () => {
  it("exposes the connection state to the status indicator", () => {
    expect(component).toContain('data-state={serviceState}');
    expect(component).toContain('setServiceState("connected")');
    expect(component).toContain('setServiceState("warning")');
  });

  it("uses green for connected and yellow for every non-connected state", () => {
    expect(styles).toMatch(
      /\.chat-status\[data-state="connected"\]\s*>\s*span\s*\{[^}]*background:\s*var\(--green\)/s,
    );
    expect(styles).toMatch(
      /\.chat-status\[data-state="warning"\]\s*>\s*span\s*\{[^}]*background:\s*#d6a350/s,
    );
  });
});
