export const THEME_STORAGE_KEY = "efdkb-workspace-theme";

export const THEME_OPTIONS = [
  { id: "obsidian-stage", label: "深曜商务" },
  { id: "evidence-editorial", label: "典雅公文" },
  { id: "prism-lab", label: "和熠智汇" },
] as const;

export type ThemeId = (typeof THEME_OPTIONS)[number]["id"];

export const DEFAULT_THEME: ThemeId = "prism-lab";

export function isThemeId(value: string | null): value is ThemeId {
  return THEME_OPTIONS.some((theme) => theme.id === value);
}
