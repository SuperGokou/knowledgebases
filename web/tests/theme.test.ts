import { describe, expect, it } from "vitest";

import { DEFAULT_THEME, isThemeId, THEME_OPTIONS } from "../src/lib/theme";

describe("workspace themes", () => {
  it("uses 和熠智汇 as the default selected direction", () => {
    expect(DEFAULT_THEME).toBe("prism-lab");
  });

  it("accepts only published theme identifiers", () => {
    expect(THEME_OPTIONS).toHaveLength(3);
    expect(isThemeId("obsidian-stage")).toBe(true);
    expect(isThemeId("evidence-editorial")).toBe(true);
    expect(isThemeId("prism-lab")).toBe(true);
    expect(isThemeId("unknown-theme")).toBe(false);
    expect(isThemeId(null)).toBe(false);
  });

  it("uses concise Chinese enterprise-facing labels", () => {
    expect(THEME_OPTIONS.map((theme) => theme.label)).toEqual([
      "深曜商务",
      "典雅公文",
      "和熠智汇",
    ]);
    for (const theme of THEME_OPTIONS) {
      expect(theme.label).not.toMatch(/[A-Za-z]/);
    }
  });
});
