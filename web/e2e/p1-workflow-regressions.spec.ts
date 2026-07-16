import { expect, test, type Page, type Route } from "@playwright/test";

const NOW = "2026-07-15T12:00:00.000Z";
const KNOWLEDGE_BASE_ID = "00000000-0000-4000-8000-000000000101";

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(body),
  });
}

async function mockCurrentUser(page: Page, accessToken: string, permissions: string[]) {
  await page.context().addCookies([{
    name: "kb_access",
    value: accessToken,
    url: "http://127.0.0.1:3100",
    httpOnly: true,
    sameSite: "Lax",
  }]);
  await page.route("**/api/backend/api/v1/auth/me", (route) => fulfillJson(route, {
    id: "00000000-0000-4000-8000-000000000001",
    email: "qa@example.com",
    display_name: "质量验收员",
    status: "active",
    is_superuser: false,
    permission_codes: permissions,
    role_ids: [],
    limits: {},
  }));
}

function fileRecord(
  id: string,
  name: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    id,
    owner_id: "00000000-0000-4000-8000-000000000001",
    knowledge_base_id: KNOWLEDGE_BASE_ID,
    original_name: name,
    extension: ".txt",
    content_type: "text/plain",
    size_bytes: 1024,
    checksum_algorithm: "sha256",
    checksum_value: "a".repeat(64),
    status: "processing",
    malware_scan_status: "clean",
    knowledge_status: "draft_ready",
    knowledge_error_code: null,
    searchable: false,
    custom_metadata: {},
    created_at: NOW,
    updated_at: NOW,
    available_at: null,
    ...overrides,
  };
}

test("文件审批只放行安全且草稿就绪的文件，并友好呈现 409", async ({ page }) => {
  await mockCurrentUser(page, "p1-files-access", ["file:read", "file:approve"]);
  const ready = fileRecord("00000000-0000-4000-8000-000000000201", "可审批.txt");
  const conflict = fileRecord("00000000-0000-4000-8000-000000000202", "状态冲突.txt");
  const files = [
    ready,
    conflict,
    fileRecord("00000000-0000-4000-8000-000000000203", "转换中.txt", {
      knowledge_status: "pending",
    }),
    fileRecord("00000000-0000-4000-8000-000000000204", "转换失败.txt", {
      knowledge_status: "failed",
      knowledge_error_code: "parser_failed",
    }),
    fileRecord("00000000-0000-4000-8000-000000000205", "格式不支持.txt", {
      knowledge_status: "unsupported",
    }),
    fileRecord("00000000-0000-4000-8000-000000000206", "等待扫描.txt", {
      status: "quarantined",
      malware_scan_status: "pending",
      knowledge_status: "pending",
    }),
  ];

  await page.route("**/api/backend/api/v1/files**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === "POST" && pathname.endsWith(`/${String(ready.id)}/approve`)) {
      Object.assign(ready, {
        status: "available",
        knowledge_status: "indexed",
        searchable: true,
        available_at: NOW,
      });
      await fulfillJson(route, ready);
      return;
    }
    if (request.method() === "POST" && pathname.endsWith(`/${String(conflict.id)}/approve`)) {
      await fulfillJson(route, {
        error: {
          code: "okf_conversion_not_completed",
          message: "The current file version requires a successful OKF conversion before approval",
        },
      }, 409);
      return;
    }
    if (request.method() === "GET") {
      await fulfillJson(route, files);
      return;
    }
    await route.abort("failed");
  });

  await page.goto("/admin/files");
  const fileCenter = page.locator("article.panel").filter({
    has: page.getByRole("heading", { name: "文件中心" }),
  });
  await expect(fileCenter.getByText("可审批.txt")).toBeVisible();

  for (const [name, status, reason] of [
    ["转换中.txt", "知识转换中", "正在生成可审核的知识草稿，完成后才能审批。"],
    ["转换失败.txt", "知识转换失败", "未生成可审批草稿，请检查文件内容或重新转换。"],
    ["格式不支持.txt", "暂不支持审批", "当前文件格式无法生成知识草稿，不能审批入库。"],
    ["等待扫描.txt", "等待安全扫描", "文件将在安全扫描通过后进入知识转换。"],
  ]) {
    const row = fileCenter.locator("tbody tr").filter({ hasText: name });
    await expect(row).toContainText(status);
    await expect(row).toContainText(reason);
    await expect(row.getByRole("button", { name: /审批文件/ })).toHaveCount(0);
  }

  const readyRow = fileCenter.locator("tbody tr").filter({ hasText: "可审批.txt" });
  await readyRow.getByRole("button", { name: "审批文件：可审批.txt" }).click();
  await expect(readyRow).toContainText("已入知识库");
  await expect(readyRow.getByRole("button", { name: "审批文件：可审批.txt" })).toHaveCount(0);

  const conflictRow = fileCenter.locator("tbody tr").filter({ hasText: "状态冲突.txt" });
  await conflictRow.getByRole("button", { name: "审批文件：状态冲突.txt" }).click();
  await expect(page.locator(".notice.error-notice")).toContainText(
    "知识转换尚未完成，请等待转换完成并刷新后再审批。",
  );
});

test("知识连接灯不会被失败刷新或过期请求错误恢复为绿色", async ({ page }) => {
  await mockCurrentUser(page, "p1-chat-access", ["chat:query"]);
  let releaseSlowCatalog: (() => void) | undefined;
  const slowCatalog = new Promise<void>((resolve) => {
    releaseSlowCatalog = resolve;
  });
  let chatAttempts = 0;
  const knowledgeBase = {
    id: KNOWLEDGE_BASE_ID,
    owner_id: "00000000-0000-4000-8000-000000000001",
    name: "连接状态验收库",
    description: null,
    custom_metadata: {},
    external_llm_processing_enabled: true,
    access_level: "reader",
    role_grant_version: 1,
    created_at: NOW,
    updated_at: NOW,
  };

  await page.route("**/api/backend/api/v1/knowledge-bases**", async (route) => {
    const query = new URL(route.request().url()).searchParams.get("q") ?? "";
    if (query === "慢刷新") await slowCatalog;
    if (query === "刷新失败") {
      await fulfillJson(route, { error: { code: "catalog_unavailable", message: "目录服务异常" } }, 503);
      return;
    }
    await fulfillJson(route, [knowledgeBase]);
  });
  await page.route("**/api/backend/api/v1/chat/query", async (route) => {
    chatAttempts += 1;
    if (chatAttempts === 1) {
      await fulfillJson(route, { error: { code: "query_unavailable", message: "检索服务异常" } }, 503);
      return;
    }
    await fulfillJson(route, {
      knowledge_base_id: KNOWLEDGE_BASE_ID,
      answer: "制度要求先审批 [1]。",
      mode: "rag",
      provider: "deepseek",
      model: "deepseek-chat",
      answer_review: { status: "passed", reason: "semantic_verified" },
      table: null,
      citations: [{
        entry_id: "00000000-0000-4000-8000-000000000301",
        source_file_id: null,
        title: "审批制度",
        excerpt: "内容发布前必须完成审批。",
        source_path: "policy/approval.md",
        format_version: "okf/0.1",
        citation_number: 1,
        marker: "[1]",
      }],
      source_status: {
        status: "grounded",
        strategy: "rag",
        reason: "llm_generated",
        citation_count: 1,
      },
    });
  });

  await page.goto("/chat");
  const status = page.locator(".chat-status");
  await expect(status).toHaveAttribute("data-state", "connected");

  const search = page.getByRole("search");
  const slowRequest = page.waitForRequest((request) =>
    new URL(request.url()).searchParams.get("q") === "慢刷新");
  await search.getByLabel("搜索可问答知识库").fill("慢刷新");
  await search.getByRole("button", { name: "搜索" }).click();
  await slowRequest;
  await expect(status).toHaveAttribute("data-state", "warning");

  await page.getByLabel("输入问题").fill("审批要求是什么？");
  await page.getByRole("button", { name: "发送" }).click();
  await expect(page.getByText("后台服务暂时不可用，请稍后重试。")).toBeVisible();
  await expect(status).toHaveAttribute("data-state", "warning");
  await expect(status).toContainText("连接异常");

  releaseSlowCatalog?.();
  await expect(search.getByRole("button", { name: "搜索" })).toBeEnabled();
  await expect(status).toHaveAttribute("data-state", "warning");
  await expect(status).toContainText("连接异常");

  await page.getByRole("button", { name: "重新发送" }).click();
  await expect(page.getByText("制度要求先审批 [1]。")).toBeVisible();
  await expect(status).toHaveAttribute("data-state", "connected");

  await search.getByLabel("搜索可问答知识库").fill("刷新失败");
  await search.getByRole("button", { name: "搜索" }).click();
  await expect(page.getByText(/知识库列表加载失败/)).toBeVisible();
  await expect(status).toHaveAttribute("data-state", "warning");

  await search.getByLabel("搜索可问答知识库").fill("恢复");
  await search.getByRole("button", { name: "搜索" }).click();
  await expect(status).toHaveAttribute("data-state", "connected");
  await expect(status).toContainText("知识检索已连接");
});
