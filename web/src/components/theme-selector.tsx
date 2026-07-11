"use client";

import { useEffect, useSyncExternalStore } from "react";

import { Icon } from "@/components/icon";
import {
  DEFAULT_THEME,
  isThemeId,
  THEME_OPTIONS,
  THEME_STORAGE_KEY,
  type ThemeId,
} from "@/lib/theme";

const subscribers = new Set<() => void>();
let volatileTheme: ThemeId = DEFAULT_THEME;

function selectedTheme(): ThemeId {
  if (typeof window === "undefined") return DEFAULT_THEME;
  try {
    const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemeId(savedTheme)) volatileTheme = savedTheme;
    return isThemeId(savedTheme) ? savedTheme : volatileTheme;
  } catch {
    return volatileTheme;
  }
}

function subscribe(onStoreChange: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key !== THEME_STORAGE_KEY) return;
    volatileTheme = isThemeId(event.newValue) ? event.newValue : DEFAULT_THEME;
    onStoreChange();
  };
  subscribers.add(onStoreChange);
  window.addEventListener("storage", onStorage);
  return () => {
    subscribers.delete(onStoreChange);
    window.removeEventListener("storage", onStorage);
  };
}

function chooseTheme(theme: ThemeId) {
  volatileTheme = theme;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The visual preference still applies for this session when storage is blocked.
  }
  document.documentElement.dataset.theme = theme;
  subscribers.forEach((notify) => notify());
}

export function ThemeSelector() {
  const theme = useSyncExternalStore(subscribe, selectedTheme, () => DEFAULT_THEME);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <label className="theme-selector">
      <Icon name="layers" />
      <span className="sr-only">界面主题</span>
      <select
        aria-label="选择界面主题"
        value={theme}
        onChange={(event) => {
          if (isThemeId(event.target.value)) chooseTheme(event.target.value);
        }}
      >
        {THEME_OPTIONS.map((option) => (
          <option value={option.id} key={option.id}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}
