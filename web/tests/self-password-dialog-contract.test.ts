import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const dialogPath = join(process.cwd(), "src/components/self-password-dialog.tsx");
const shell = readFileSync(join(process.cwd(), "src/components/app-shell.tsx"), "utf8");

describe("self-service password entry", () => {
  it("is reachable from every authenticated workspace shell", () => {
    expect(existsSync(dialogPath)).toBe(true);
    expect(shell).toContain("<SelfPasswordDialog />");
  });

  it("closes the browser session and returns to login after success", () => {
    const dialog = readFileSync(dialogPath, "utf8");

    expect(dialog).toContain("resetUserPassword");
    expect(dialog).toContain('fetch("/api/auth/logout"');
    expect(dialog).toContain('window.location.replace("/login")');
    expect(dialog).toContain('autoComplete="current-password"');
    expect(dialog.match(/autoComplete="new-password"/gu)).toHaveLength(2);
  });
});
