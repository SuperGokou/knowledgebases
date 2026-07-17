import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { canDeleteFile } from "../src/lib/file-deletion";

describe("file deletion policy", () => {
  it("shows deletion only to the uploader or a super administrator", () => {
    const file = { owner_id: "owner-1" };

    expect(canDeleteFile({ id: "owner-1", is_superuser: false }, file)).toBe(true);
    expect(canDeleteFile({ id: "admin-1", is_superuser: true }, file)).toBe(true);
    expect(canDeleteFile({ id: "other-1", is_superuser: false }, file)).toBe(false);
    expect(canDeleteFile(null, file)).toBe(false);
  });

  it("confirms, calls the DELETE API, refreshes, and reports the result", () => {
    const source = readFileSync(join(process.cwd(), "src/components/files-panel.tsx"), "utf8");

    expect(source).toContain("window.confirm");
    expect(source).toContain('apiRequest<void>(`/api/v1/files/${file.id}`, { method: "DELETE" })');
    expect(source).toContain("await load()");
    expect(source).toContain('feedback.success(`文件“${file.original_name}”已删除。`, "文件删除成功")');
    expect(source).toContain('feedback.error(message, "文件删除失败")');
  });
});
