import AxeBuilder from "@axe-core/playwright";
import {
  expect,
  test as base,
  type BrowserContext,
  type Page,
  type TestInfo,
} from "@playwright/test";

import {
  requireEnterpriseConfig,
  type EnterpriseConfig,
} from "./enterprise-config";
import { loadDocumentFixtures, type DocumentFixture } from "./document-fixtures";

type NetworkFailure = {
  readonly kind: "http" | "request";
  readonly method: string;
  readonly path: string;
  readonly status?: number;
  readonly reason?: string;
};

export interface QualityProbe {
  allowHttpStatus(status: number, path: string): void;
  allowRequestFailure(path: string): void;
  newIsolatedPage(baseURL: string): Promise<Page>;
}

type Fixtures = {
  enterprise: EnterpriseConfig;
  quality: QualityProbe;
  enterpriseDocuments: readonly DocumentFixture[];
};

function safePath(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname;
  } catch {
    return "<invalid-url>";
  }
}

function evidenceAnnotations(testInfo: TestInfo): boolean {
  return testInfo.annotations.some((item) => item.type === "evidence-check");
}

async function attachJson(testInfo: TestInfo, name: string, value: unknown) {
  await testInfo.attach(name, {
    body: Buffer.from(JSON.stringify(value, null, 2), "utf8"),
    contentType: "application/json",
  });
}

export const test = base.extend<Fixtures>({
  enterprise: async ({}, fixtureUse) => {
    await fixtureUse(requireEnterpriseConfig());
  },
  enterpriseDocuments: async ({ enterprise }, fixtureUse) => {
    await fixtureUse(
      loadDocumentFixtures(
        enterprise.documentFixtureRoot,
        enterprise.documentFixtureManifest,
      ),
    );
  },
  quality: async ({ page, browser }, fixtureUse, testInfo) => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    const networkFailures: NetworkFailure[] = [];
    const allowedStatuses = new Set<string>();
    const allowedRequestFailures = new Set<string>();
    const monitoredPages = new Map<Page, string>();
    const ownedContexts: BrowserContext[] = [];

    function monitor(target: Page, label: string) {
      if (monitoredPages.has(target)) return;
      monitoredPages.set(target, label);
      target.on("console", (message) => {
        if (message.type() === "error") {
          consoleErrors.push(`${label}: ${message.text().slice(0, 500)}`);
        }
      });
      target.on("pageerror", (error) =>
        pageErrors.push(`${label}: ${error.message.slice(0, 500)}`),
      );
      target.on("response", (response) => {
        if (response.status() < 500) return;
        const responsePath = safePath(response.url());
        if (allowedStatuses.has(`${response.status()}:${responsePath}`)) return;
        networkFailures.push({
          kind: "http",
          method: response.request().method(),
          path: responsePath,
          status: response.status(),
        });
      });
      target.on("requestfailed", (request) => {
        const requestPath = safePath(request.url());
        if (allowedRequestFailures.has(requestPath)) return;
        networkFailures.push({
          kind: "request",
          method: request.method(),
          path: requestPath,
          reason: request.failure()?.errorText.slice(0, 160),
        });
      });
    }

    monitor(page, "main");

    const quality: QualityProbe = {
      allowHttpStatus(status, path) {
        allowedStatuses.add(`${status}:${path}`);
      },
      allowRequestFailure(path) {
        allowedRequestFailures.add(path);
      },
      async newIsolatedPage(baseURL) {
        const context = await browser.newContext({ baseURL });
        ownedContexts.push(context);
        const isolatedPage = await context.newPage();
        monitor(isolatedPage, `isolated-${ownedContexts.length}`);
        return isolatedPage;
      },
    };

    await fixtureUse(quality);

    if (!evidenceAnnotations(testInfo)) return;

    const blockingA11y: Array<{
      page: string;
      id: string;
      impact: string | null;
      nodes: number;
    }> = [];
    const viewportOverflow: Array<{
      page: string;
      viewport_width: number;
      document_width: number;
    }> = [];
    for (const [target, label] of monitoredPages) {
      if (target.isClosed() || target.url() === "about:blank") continue;
      const result = await new AxeBuilder({ page: target }).analyze();
      blockingA11y.push(
        ...result.violations
          .filter((item) => item.impact === "critical" || item.impact === "serious")
          .map((item) => ({
            page: label,
            id: item.id,
            impact: item.impact ?? null,
            nodes: item.nodes.length,
          })),
      );
      const dimensions = await target.evaluate(() => ({
        viewport_width: document.documentElement.clientWidth,
        document_width: Math.max(
          document.documentElement.scrollWidth,
          document.body?.scrollWidth ?? 0,
        ),
      }));
      if (dimensions.document_width > dimensions.viewport_width + 1) {
        viewportOverflow.push({ page: label, ...dimensions });
      }
      const sensitiveContent = target.locator('[data-sensitive="true"], input[type="password"]');
      await testInfo.attach(`e2e-screenshot-${label}`, {
        body: await target.screenshot({
          fullPage: true,
          mask: [sensitiveContent],
          maskColor: "#111827",
        }),
        contentType: "image/png",
      });
    }

    await attachJson(testInfo, "e2e-a11y", {
      blocking: blockingA11y,
      viewport_overflow: viewportOverflow,
      monitored_pages: monitoredPages.size,
    });
    await attachJson(testInfo, "e2e-observability", {
      console_errors: consoleErrors,
      page_errors: pageErrors,
      network_failures: networkFailures,
    });

    try {
      expect(blockingA11y, "critical/serious accessibility violations").toEqual([]);
      expect(viewportOverflow, "page must not overflow the mobile viewport").toEqual([]);
      expect(consoleErrors, "unexpected browser console errors").toEqual([]);
      expect(pageErrors, "uncaught browser exceptions").toEqual([]);
      expect(networkFailures, "unexpected HTTP 5xx or request failures").toEqual([]);
    } finally {
      await Promise.all(ownedContexts.map((context) => context.close()));
    }
  },
});

export { expect } from "@playwright/test";

export async function loginAs(
  page: Page,
  credentials: { readonly email: string; readonly password: string },
) {
  await page.goto("/login");
  await page.getByLabel("工作邮箱").fill(credentials.email);
  await page.getByLabel("密码").fill(credentials.password);
  await page.getByRole("button", { name: "安全登录" }).click();
  await expect(page).not.toHaveURL(/\/login(?:\?|$)/, { timeout: 30_000 });
}

export type BffResponse<T = unknown> = {
  readonly status: number;
  readonly body: T;
};

export async function bffRequest<T = unknown>(
  page: Page,
  apiPath: string,
  options: {
    readonly method?: string;
    readonly body?: unknown;
    readonly idempotencyKey?: string;
  } = {},
): Promise<BffResponse<T>> {
  if (!apiPath.startsWith("/api/v1/")) {
    throw new Error("BFF path must start with /api/v1/");
  }
  return page.evaluate(
    async ({ apiPath: path, method, body, idempotencyKey }) => {
      const headers = new Headers();
      if (body !== undefined) headers.set("content-type", "application/json");
      if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
      const response = await fetch(`/api/backend${path}`, {
        method,
        credentials: "same-origin",
        headers: body === undefined && idempotencyKey === undefined ? undefined : headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      let parsed: unknown = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = { non_json_response: true, length: text.length };
        }
      }
      return { status: response.status, body: parsed };
    },
    {
      apiPath,
      method: options.method ?? "GET",
      body: options.body,
      idempotencyKey: options.idempotencyKey,
    },
  ) as Promise<BffResponse<T>>;
}
