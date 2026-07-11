export const THEME_STORAGE_KEY = "efdkb-workspace-theme";

export const THEME_OPTIONS = [
  { id: "obsidian-stage", label: "赤曜光幕 / Obsidian Stage" },
  { id: "evidence-editorial", label: "证据出版物 / Evidence Editorial" },
  { id: "prism-lab", label: "棱镜实验台 / Prism Lab" },
] as const;

export type ThemeId = (typeof THEME_OPTIONS)[number]["id"];

export const DEFAULT_THEME: ThemeId = "prism-lab";

export function isThemeId(value: string | null): value is ThemeId {
  return THEME_OPTIONS.some((theme) => theme.id === value);
}
