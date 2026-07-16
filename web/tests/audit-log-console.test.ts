import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  auditExportFilename,
  auditLogExportPath,
  auditLogListPath,
  auditResultPresentation,
  auditTimestampPresentation,
  readableAuditError,
  requestAuditExport,
  toAuditApiTimestamp,
  validateAuditActorId,
  validateAuditTimeRange,
  type AuditLogFilters,
} from "../src/lib/audit-log";
import { ApiClientError } from "../src/lib/api-client";

const filters: AuditLogFilters = {
  action: " file.approved ",
  result: "denied",
  resourceType: " file ",
  resourceId: " file-01 ",
  actorId: " 00000000-0000-4000-8000-000000000101 ",
  createdFrom: "2026-07-15T08:00:00.000Z",
  createdTo: "2026-07-15T09:00:00.000Z",
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function cssRuleBody(css: string, selector: string): string {
  const selectorStart = css.lastIndexOf(`${selector} {`);
  if (selectorStart < 0) throw new Error(`Missing CSS rule: ${selector}`);
  const bodyStart = css.indexOf("{", selectorStart) + 1;
  const bodyEnd = css.indexOf("}", bodyStart);
  return css.slice(bodyStart, bodyEnd);
}

function cssPixelValue(body: string, property: string): number {
  const value = new RegExp(`${property}:\\s*(\\d+)px`).exec(body)?.[1];
  if (!value) throw new Error(`Missing pixel property: ${property}`);
  return Number(value);
}

function relativeLuminance(hex: string): number {
  const channels = hex.slice(1).match(/.{2}/g);
  if (!channels || channels.length !== 3) throw new Error(`Invalid hex color: ${hex}`);
  const [red, green, blue] = channels.map((channel) => {
    const normalized = Number.parseInt(channel, 16) / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
}

function contrastRatio(foreground: string, background: string): number {
  const lighter = Math.max(relativeLuminance(foreground), relativeLuminance(background));
  const darker = Math.min(relativeLuminance(foreground), relativeLuminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

describe("audit-log query contract", () => {
  it("serializes every supported filter with stable cursor pagination", () => {
    const url = new URL(auditLogListPath(filters, 91), "https://knowledge.example");
    expect(url.pathname).toBe("/api/v1/audit-logs");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      action: "file.approved",
      actor_id: "00000000-0000-4000-8000-000000000101",
      created_from: "2026-07-15T08:00:00.000Z",
      created_to: "2026-07-15T09:00:00.000Z",
      cursor: "91",
      limit: "50",
      resource_id: "file-01",
      resource_type: "file",
      result: "denied",
    });
  });

  it("exports the exact active filters without a presentation cursor", () => {
    const url = new URL(auditLogExportPath(filters), "https://knowledge.example");
    expect(url.pathname).toBe("/api/v1/audit-logs/export");
    expect(url.searchParams.get("action")).toBe("file.approved");
    expect(url.searchParams.has("cursor")).toBe(false);
    expect(url.searchParams.has("limit")).toBe(false);
  });

  it("omits empty filters and validates an aware chronological time range", () => {
    expect(auditLogListPath({
      action: " ",
      result: "",
      resourceType: "",
      resourceId: "",
      actorId: "",
      createdFrom: "",
      createdTo: "",
    })).toBe("/api/v1/audit-logs?limit=50");

    const timestamp = toAuditApiTimestamp("2026-07-15T12:34");
    expect(timestamp).toMatch(/Z$/);
    expect(Number.isNaN(Date.parse(timestamp))).toBe(false);
    expect(toAuditApiTimestamp("")).toBe("");
    expect(() => toAuditApiTimestamp("not-a-date")).toThrow(/日期时间/);
    expect(() => validateAuditTimeRange(
      "2026-07-15T10:00:00.000Z",
      "2026-07-15T09:00:00.000Z",
    )).toThrow(/开始时间/);
    expect(() => validateAuditTimeRange(
      "2026-07-15T08:00:00.000Z",
      "2026-07-15T09:00:00.000Z",
    )).not.toThrow();
    expect(() => validateAuditActorId("00000000-0000-4000-8000-000000000101"))
      .not.toThrow();
    expect(() => validateAuditActorId("not-a-uuid")).toThrow(/操作者 ID/);
  });

  it("uses Chinese result semantics and accepts only the fixed safe export filename", () => {
    expect(auditResultPresentation("success")).toEqual({ label: "成功", tone: "success" });
    expect(auditResultPresentation("failure")).toEqual({ label: "失败", tone: "danger" });
    expect(auditResultPresentation("denied")).toEqual({ label: "已拒绝", tone: "warning" });

    expect(auditExportFilename(
      'attachment; filename="audit-logs-20260715T123000Z.csv"; filename*=UTF-8\'\'audit-logs-20260715T123000Z.csv',
    )).toBe("audit-logs-20260715T123000Z.csv");
    expect(auditExportFilename('attachment; filename="../../danger.csv"'))
      .toBe("audit-logs.csv");
    expect(auditExportFilename(null)).toBe("audit-logs.csv");

    expect(readableAuditError(new ApiClientError(
      "server message",
      422,
      "audit_export_too_large",
    ))).toContain("5,000");
    expect(readableAuditError(new ApiClientError(
      "server message",
      422,
      "validation_error",
    ))).toBe("筛选条件无效，请检查操作者 ID 和时间范围后重试。");
  });

  it("renders malformed audit timestamps with a visible safe fallback", () => {
    const valid = auditTimestampPresentation("2026-07-15T12:30:00.000Z");
    expect(valid.dateTime).toBe("2026-07-15T12:30:00.000Z");
    expect(valid.label).not.toBe("时间未知");

    expect(auditTimestampPresentation("not-a-date")).toEqual({ label: "时间未知" });
    expect(() => auditTimestampPresentation("not-a-date")).not.toThrow();
  });

  it("downloads only a CSV response and preserves the server's safe filename", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      "\ufeffid,action\r\n1,file.approved\r\n",
      {
        status: 200,
        headers: {
          "Content-Disposition": 'attachment; filename="audit-logs-20260715T123000Z.csv"',
          "Content-Type": "text/csv; charset=utf-8",
        },
      },
    ));
    vi.stubGlobal("fetch", fetchMock);

    const exported = await requestAuditExport(filters);

    expect(exported.filename).toBe("audit-logs-20260715T123000Z.csv");
    expect(await exported.blob.text()).toContain("file.approved");
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/backend/api/v1/audit-logs/export?"),
      expect.objectContaining({ cache: "no-store", headers: { Accept: "text/csv" } }),
    );
  });

  it("surfaces controlled export errors and rejects a non-CSV success response", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({
        error: { code: "audit_export_too_large", message: "server message" },
      }, { status: 422 }))
      .mockResolvedValueOnce(Response.json({ items: [] }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestAuditExport(filters)).rejects.toMatchObject({
      code: "audit_export_too_large",
      status: 422,
    });
    await expect(requestAuditExport(filters)).rejects.toMatchObject({
      code: "invalid_audit_export_response",
      status: 502,
    });
  });
});

describe("audit-log console integration contract", () => {
  const panel = readFileSync(
    join(process.cwd(), "src/components/audit-logs-panel.tsx"),
    "utf8",
  );
  const page = readFileSync(
    join(process.cwd(), "src/app/(workspace)/admin/audit/page.tsx"),
    "utf8",
  );
  const sideNav = readFileSync(join(process.cwd(), "src/components/side-nav.tsx"), "utf8");
  const overview = readFileSync(
    join(process.cwd(), "src/components/admin-access-panels.tsx"),
    "utf8",
  );
  const backendPath = readFileSync(
    join(process.cwd(), "src/lib/server/backend-path.ts"),
    "utf8",
  );
  const bff = readFileSync(
    join(process.cwd(), "src/app/api/backend/[...path]/route.ts"),
    "utf8",
  );
  const css = readFileSync(join(process.cwd(), "src/app/globals.css"), "utf8");

  it("provides an accessible, fail-closed console without rendering sensitive details", () => {
    expect(page).toContain("<AuditLogsPanel />");
    expect(panel).toContain('if (!can("audit:read"))');
    expect(panel).toContain('aria-label="审计日志筛选"');
    expect(panel).toContain('aria-label="审计日志分页"');
    expect(panel).toContain('<caption className="sr-only">');
    expect(panel).toContain("加载审计日志");
    expect(panel).toContain("导出当前筛选结果");
    expect(panel).toContain("exportPending");
    expect(panel).toContain("requestAuditExport");
    expect(panel).not.toContain("details");
    expect(panel).not.toContain("ip_address");
  });

  it("exposes the page only through permission-filtered enterprise navigation", () => {
    expect(sideNav).toContain('{ href: "/admin/audit", label: "审计日志"');
    expect(overview).toContain('{ href: "/admin/audit"');
    expect(backendPath).toContain('"audit-logs"');
    expect(bff).toContain('"content-disposition"');
  });

  it("keeps audit metadata legible, high-contrast, and inside the scroll container", () => {
    for (const selector of [
      ".audit-log-panel th,.audit-log-panel td",
      ".audit-action",
      ".audit-identifier",
      ".audit-resource small",
    ]) {
      expect(cssPixelValue(cssRuleBody(css, selector), "font-size")).toBeGreaterThanOrEqual(12);
    }
    expect(cssPixelValue(cssRuleBody(css, ".audit-resource strong"), "font-size"))
      .toBeGreaterThanOrEqual(13);

    const resourceIdRule = cssRuleBody(css, ".audit-resource small");
    const resourceIdColor = /color:\s*(#[0-9a-f]{6})/i.exec(resourceIdRule)?.[1];
    expect(resourceIdColor).toBeDefined();
    expect(contrastRatio(resourceIdColor ?? "#ffffff", "#ffffff"))
      .toBeGreaterThanOrEqual(4.5);
    expect(resourceIdRule).toContain("text-overflow: ellipsis");
    expect(resourceIdRule).toContain("white-space: nowrap");
    expect(cssRuleBody(css, ".table-wrap")).toContain("overflow-x: auto");
  });
});
