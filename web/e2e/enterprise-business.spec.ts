import { randomUUID } from "node:crypto";

import type { APIRequestContext, Page, TestInfo } from "@playwright/test";

import {
  bffRequest,
  expect,
  loginAs,
  test,
} from "./support/enterprise-fixtures";
import type {
  EnterpriseConfig,
  FaultMode,
} from "./support/enterprise-config";
import type { DocumentFixture } from "./support/document-fixtures";

type Row = Record<string, unknown>;

function annotate(testInfo: TestInfo, check: string) {
  testInfo.annotations.push({ type: "evidence-check", description: check });
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`E2E_BLOCKED: missing ${name}`);
  return value;
}

function suffix(testInfo: TestInfo): string {
  return `${testInfo.project.name}-${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .slice(-48);
}

function assertStatus(actual: number, expected: number, operation: string) {
  if (actual !== expected) {
    throw new Error(`${operation}: expected HTTP ${expected}, received ${actual}`);
  }
}

function row(value: unknown, operation: string): Row {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${operation}: invalid response contract`);
  }
  return value as Row;
}

async function loginAdmin(page: Page, enterprise: EnterpriseConfig) {
  await loginAs(page, {
    email: enterprise.adminEmail,
    password: enterprise.adminPassword,
  });
  await expect(page).toHaveURL(/\/admin(?:\/|$)/);
}

async function createRole(page: Page, testInfo: TestInfo, permissions: string[]) {
  const id = suffix(testInfo);
  const response = await bffRequest<Row>(page, "/api/v1/roles", {
    method: "POST",
    body: {
      code: `e2e_${id}`.replace(/-/g, "_").slice(0, 90),
      name: `E2E 验收角色 ${id}`,
      description: "Playwright enterprise acceptance role",
      priority: -9_000,
      permission_codes: permissions,
      limits: {},
    },
  });
  assertStatus(response.status, 201, "create role");
  return row(response.body, "create role");
}

async function createUser(page: Page, testInfo: TestInfo, roleIds: string[] = []) {
  const id = suffix(testInfo);
  const credentials = {
    email: `enterprise-${id}@example.com`,
    password: `E2E!${id}Aa123456789`,
  };
  const response = await bffRequest<Row>(page, "/api/v1/users", {
    method: "POST",
    body: {
      ...credentials,
      display_name: `E2E 验收成员 ${id}`,
      role_ids: roleIds,
    },
  });
  assertStatus(response.status, 201, "create user");
  return { credentials, user: row(response.body, "create user") };
}

async function createKnowledgeBase(page: Page, testInfo: TestInfo) {
  const id = suffix(testInfo);
  const response = await bffRequest<Row>(page, "/api/v1/knowledge-bases", {
    method: "POST",
    body: {
      name: `E2E 验收知识库 ${id}`,
      description: "Disposable enterprise E2E knowledge base",
      external_llm_processing_enabled: false,
      custom_metadata: { source: "playwright-enterprise" },
    },
  });
  assertStatus(response.status, 201, "create knowledge base");
  return row(response.body, "create knowledge base");
}

async function setFaultMode(
  request: APIRequestContext,
  enterprise: EnterpriseConfig,
  mode: FaultMode,
) {
  const url = `${enterprise.faultControlOrigin}/v1/runs/${encodeURIComponent(enterprise.runId)}/mode`;
  try {
    const response = await request.post(url, {
      headers: { authorization: `Bearer ${enterprise.faultControlToken}` },
      data: { mode },
    });
    if (response.status() !== 204) {
      throw new Error(`HTTP ${response.status()}`);
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message.slice(0, 120) : "unavailable";
    throw new Error(`E2E_BLOCKED: fault controller ${mode} unavailable (${reason})`);
  }
}

async function uploadMultipartFixture(
  page: Page,
  request: APIRequestContext,
  enterprise: EnterpriseConfig,
  knowledgeBaseId: string,
  testInfo: TestInfo,
) {
  const idempotencyKey = `e2e-multipart-${suffix(testInfo)}`;
  const initiated = await bffRequest<Row>(page, "/api/v1/files/uploads", {
    method: "POST",
    body: {
      filename: `enterprise-multipart-${suffix(testInfo)}.txt`,
      size_bytes: enterprise.multipartBytes,
      content_type: "text/plain",
      knowledge_base_id: knowledgeBaseId,
      idempotency_key: idempotencyKey,
      custom_metadata: { source: "playwright-enterprise-multipart" },
    },
  });
  assertStatus(initiated.status, 201, "initiate multipart upload");
  const plan = row(initiated.body, "multipart upload plan");
  if (plan.mode !== "multipart") {
    throw new Error(
      `E2E_BLOCKED: KB_E2E_MULTIPART_BYTES=${enterprise.multipartBytes} did not select multipart`,
    );
  }
  const uploadSessionId = String(plan.upload_session_id ?? "");
  const partCount = Number(plan.part_count);
  if (!uploadSessionId || !Number.isSafeInteger(partCount) || partCount < 2) {
    throw new Error("multipart upload plan omitted a valid session or part count");
  }

  const completedParts: Array<{ part_number: number; etag: string }> = [];
  for (let start = 1; start <= partCount; start += 100) {
    const numbers = Array.from(
      { length: Math.min(100, partCount - start + 1) },
      (_, index) => start + index,
    );
    const signed = await bffRequest<Row>(
      page,
      `/api/v1/files/uploads/${uploadSessionId}/parts`,
      { method: "POST", body: { part_numbers: numbers } },
    );
    assertStatus(signed.status, 200, "sign multipart parts");
    const parts = row(signed.body, "multipart part URLs").parts;
    if (!Array.isArray(parts) || parts.length !== numbers.length) {
      throw new Error("multipart part signing returned an incomplete batch");
    }
    for (const rawPart of parts) {
      const part = row(rawPart, "multipart part URL");
      const partNumber = Number(part.part_number);
      const partBytes = Number(part.size_bytes);
      const partUrl = String(part.url ?? "");
      if (
        !Number.isSafeInteger(partNumber) ||
        !Number.isSafeInteger(partBytes) ||
        partBytes <= 0 ||
        !partUrl
      ) {
        throw new Error("multipart part URL contract is invalid");
      }
      const payload = Buffer.alloc(partBytes, 0x20);
      if (partNumber === 1) {
        payload.write("E2E-MULTIPART-SOURCE-2026\n", 0, "utf8");
      }
      const stored = await request.put(partUrl, {
        data: payload,
        failOnStatusCode: false,
      });
      assertStatus(stored.status(), 200, `upload multipart part ${partNumber}`);
      const etag = stored.headers().etag;
      if (!etag) throw new Error(`multipart part ${partNumber} omitted ETag`);
      completedParts.push({ part_number: partNumber, etag });
    }
  }
  const completed = await bffRequest(
    page,
    `/api/v1/files/uploads/${uploadSessionId}/complete`,
    {
      method: "POST",
      body: { parts: completedParts.sort((left, right) => left.part_number - right.part_number) },
    },
  );
  assertStatus(completed.status, 200, "complete multipart upload");
}

async function sendChatQuestion(page: Page, question: string) {
  await page.getByLabel("输入问题").fill(question);
  await page.getByRole("button", { name: "发送" }).click();
  await expect(page.locator(".message-area")).toHaveAttribute("aria-busy", "false", {
    timeout: 90_000,
  });
  const answer = page.locator("article.message.assistant").last();
  await expect(answer.locator(".answer-sources")).toBeVisible();
  return answer;
}

async function uploadApproveAndGroundFixture(
  page: Page,
  enterprise: EnterpriseConfig,
  knowledgeBaseId: string,
  fixture: DocumentFixture,
) {
  await page.locator('input[type="file"]').setInputFiles(fixture.absolutePath);
  await page.locator(".panel-grid article .panel-body > button.button.primary").click();

  let file: Row | undefined;
  await expect.poll(async () => {
    const response = await bffRequest<Row[]>(page, "/api/v1/files?limit=100&offset=0");
    if (response.status !== 200 || !Array.isArray(response.body)) return "missing";
    file = response.body.find(
      (item) =>
        item.original_name === fixture.filename &&
        String(item.knowledge_base_id ?? "") === knowledgeBaseId,
    );
    if (!file) return "missing";
    return `${String(file.status)}:${String(file.malware_scan_status)}`;
  }, { timeout: enterprise.jobTimeoutMs }).toBe("processing:clean");
  if (!file?.id) throw new Error(`${fixture.extension} upload did not return a file id`);

  await expect.poll(async () => {
    const conversion = await bffRequest<Row>(
      page,
      `/api/v1/files/${String(file!.id)}/okf-conversion`,
    );
    return conversion.status === 200
      ? String(row(conversion.body, `${fixture.extension} OKF conversion`).status)
      : `http-${conversion.status}`;
  }, { timeout: enterprise.jobTimeoutMs }).toBe("succeeded");

  assertStatus(
    (
      await bffRequest(page, `/api/v1/files/${String(file.id)}/approve`, {
        method: "POST",
        body: {},
      })
    ).status,
    200,
    `approve ${fixture.extension}`,
  );

  const searched = await bffRequest<Row>(
    page,
    `/api/v1/knowledge-bases/${knowledgeBaseId}/search`,
    { method: "POST", body: { query: fixture.token, limit: 5 } },
  );
  assertStatus(searched.status, 200, `search ${fixture.extension}`);
  const searchItems = row(searched.body, `${fixture.extension} search`).items;
  if (!Array.isArray(searchItems)) {
    throw new Error(`${fixture.extension} search omitted items`);
  }
  const sourceHit = searchItems
    .map((item) => row(item, `${fixture.extension} search hit`))
    .find((item) => String(item.source_file_id ?? "") === String(file!.id));
  if (!sourceHit || !String(sourceHit.excerpt ?? "").includes(fixture.token)) {
    throw new Error(`${fixture.extension} was not retrieved from its approved source file`);
  }

  const chat = await bffRequest<Row>(page, "/api/v1/chat/query", {
    method: "POST",
    body: {
      knowledge_base_id: knowledgeBaseId,
      message: `Return the documented service level for ${fixture.token}.`,
      limit: 5,
    },
  });
  assertStatus(chat.status, 200, `chat ${fixture.extension}`);
  const citations = row(chat.body, `${fixture.extension} chat`).citations;
  if (!Array.isArray(citations)) {
    throw new Error(`${fixture.extension} chat omitted citations`);
  }
  const citation = citations
    .map((item) => row(item, `${fixture.extension} citation`))
    .find((item) => String(item.source_file_id ?? "") === String(file!.id));
  if (!citation || !String(citation.excerpt ?? "").includes(fixture.token)) {
    throw new Error(`${fixture.extension} chat citation is not bound to the uploaded source`);
  }

  const entry = await bffRequest<Row>(
    page,
    `/api/v1/knowledge-bases/${knowledgeBaseId}/entries/${String(citation.entry_id)}`,
  );
  assertStatus(entry.status, 200, `read ${fixture.extension} citation entry`);
  const entryBody = row(entry.body, `${fixture.extension} citation entry`);
  const metadata = row(entryBody.custom_metadata, `${fixture.extension} entry metadata`);
  const locations = metadata.source_locations;
  if (!Array.isArray(locations)) {
    throw new Error(`${fixture.extension} entry omitted source locations`);
  }
  for (const expectedLocation of fixture.expectedSourceLocations) {
    if (!locations.includes(expectedLocation)) {
      throw new Error(
        `${fixture.extension} citation omitted expected source location ${expectedLocation}`,
      );
    }
  }
  if (
    String(entryBody.source_file_id ?? "") !== String(file.id) ||
    !String(entryBody.content ?? "").includes(fixture.token)
  ) {
    throw new Error(`${fixture.extension} entry lost source identity or grounding token`);
  }
}

test("@enterprise unified login routes accounts by effective role", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "login_role_routing");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, testInfo, ["chat:query", "knowledge:read"]);
  const created = await createUser(page, testInfo, [String(role.id)]);

  const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(memberPage, created.credentials);
  await expect(memberPage).toHaveURL(/\/chat(?:\?|$)/);

  const contentRole = await createRole(page, testInfo, [
    "knowledge:read",
    "knowledge:create",
    "knowledge:update",
    "file:read",
    "file:upload",
    "file:approve",
  ]);
  const contentManager = await createUser(page, testInfo, [String(contentRole.id)]);
  const contentPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(contentPage, contentManager.credentials);
  await expect(contentPage).toHaveURL(/\/admin\/knowledge(?:\?|$)/);
  await expect(contentPage.getByRole("heading", { name: "知识库" })).toBeVisible();

  const pending = await createUser(page, testInfo);
  const pendingPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(pendingPage, pending.credentials);
  await expect(pendingPage).toHaveURL(/\/access-pending(?:\?|$)/);
});

test("@enterprise account lifecycle rejects duplicates and revokes active access", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "account_lifecycle");
  annotate(testInfo, "error_loading_states");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, testInfo, ["chat:query"]);
  const created = await createUser(page, testInfo, [String(role.id)]);
  const duplicate = await bffRequest(page, "/api/v1/users", {
    method: "POST",
    body: { ...created.credentials, display_name: "duplicate", role_ids: [role.id] },
  });
  assertStatus(duplicate.status, 409, "duplicate user");

  const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(memberPage, created.credentials);
  const revoke = await bffRequest(page, `/api/v1/users/${String(created.user.id)}/roles`, {
    method: "PUT",
    body: { role_ids: [] },
  });
  assertStatus(revoke.status, 200, "revoke roles");
  await memberPage.goto("/chat");
  await expect(memberPage).toHaveURL(/\/access-pending(?:\?|$)/);
  const disable = await bffRequest(page, `/api/v1/users/${String(created.user.id)}`, {
    method: "PATCH",
    body: { status: "disabled" },
  });
  assertStatus(disable.status, 200, "disable user");
  const staleSession = await bffRequest(memberPage, "/api/v1/auth/me");
  expect([401, 403]).toContain(staleSession.status);
});

test("@enterprise knowledge grants are visible then fail closed immediately after revocation", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "knowledge_acl");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, testInfo, ["chat:query", "knowledge:read"]);
  const created = await createUser(page, testInfo, [String(role.id)]);
  const knowledgeBase = await createKnowledgeBase(page, testInfo);
  const grant = await bffRequest(page, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}/role-grants`, {
    method: "PUT",
    body: { grants: [{ role_id: role.id, access_level: "reader" }] },
  });
  assertStatus(grant.status, 200, "grant knowledge access");

  const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(memberPage, created.credentials);
  assertStatus((await bffRequest(memberPage, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}`)).status, 200, "read granted knowledge base");
  assertStatus((await bffRequest(page, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}/role-grants`, { method: "PUT", body: { grants: [] } })).status, 200, "revoke knowledge access");
  assertStatus((await bffRequest(memberPage, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}`)).status, 404, "conceal revoked knowledge base");
});

test("@enterprise all nine document formats complete scan, OKF, approval, retrieval and cited chat", async ({ page, enterprise, enterpriseDocuments, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "file_upload_scan_okf_approval_download");
  await loginAdmin(page, enterprise);
  const knowledgeBase = await createKnowledgeBase(page, testInfo);
  await uploadMultipartFixture(
    page,
    request,
    enterprise,
    String(knowledgeBase.id),
    testInfo,
  );
  await page.goto("/admin/files");
  await page.locator("select").first().selectOption(String(knowledgeBase.id));
  expect(enterpriseDocuments).toHaveLength(9);
  for (const fixture of enterpriseDocuments) {
    await uploadApproveAndGroundFixture(
      page,
      enterprise,
      String(knowledgeBase.id),
      fixture,
    );
  }
});

test("@enterprise chat renders citations, no-answer, audited rejection and sourced table", async ({ page, enterprise, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "chat_citations_audit_table");
  const knowledgeBaseId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
  await loginAdmin(page, enterprise);
  await page.goto("/chat");
  await page.getByLabel("选择知识库").selectOption(knowledgeBaseId);
  try {
    const grounded = await sendChatQuestion(
      page,
      "E2E-KNOWLEDGE-SOURCE-2026 的服务等级是什么？",
    );
    await expect(grounded.getByRole("heading", { name: "答案来源" })).toBeVisible();
    await expect(grounded.locator(".source-card").first()).toBeVisible();

    const noAnswer = await bffRequest<Row>(page, "/api/v1/chat/query", {
      method: "POST",
      body: { knowledge_base_id: knowledgeBaseId, message: `NO-MATCH-${enterprise.runId}`, limit: 5 },
    });
    assertStatus(noAnswer.status, 200, "no-answer chat");
    expect(row(row(noAnswer.body, "no-answer chat").source_status, "source status").status).toBe("no_results");

    await page.getByRole("button", { name: "新对话" }).click();
    await setFaultMode(request, enterprise, "review_reject");
    const rejected = await sendChatQuestion(page, "请总结验收样本");
    await expect(rejected).toContainText("回答内容未通过语义审核");
    await expect(rejected).toContainText("确定性检索");

    await page.getByRole("button", { name: "新对话" }).click();
    await setFaultMode(request, enterprise, "table_response");
    const table = await sendChatQuestion(page, "请把联系人数据整理成表格");
    await expect(table.locator(".chat-data-card table")).toBeVisible();
    await expect(table).toContainText("数据来源：");
    await expect(table.getByRole("heading", { name: "答案来源" })).toBeVisible();
  } finally {
    await setFaultMode(request, enterprise, "normal");
  }
});

test("@enterprise configured model switches and provider failure degrades safely", async ({ page, enterprise, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "model_switch");
  await loginAdmin(page, enterprise);
  const listed = await bffRequest<Row>(page, "/api/v1/llm/providers");
  assertStatus(listed.status, 200, "list providers");
  const body = row(listed.body, "list providers");
  const providers = Array.isArray(body.providers) ? body.providers.map((item) => row(item, "provider")) : [];
  const original = providers.find((item) => item.provider === body.default_provider);
  const requiredProviders = ["deepseek", "qwen", "minimax"] as const;
  if (
    !original ||
    requiredProviders.some(
      (provider) => !providers.some((item) => item.provider === provider && item.configured === true),
    )
  ) {
    throw new Error("E2E_BLOCKED: DeepSeek, Qwen and MiniMax must all be configured");
  }
  await page.goto("/admin/api-models");
  try {
    for (const provider of requiredProviders) {
      const label = provider === "deepseek" ? "DeepSeek" : provider === "qwen" ? "Qwen 通义千问" : "MiniMax";
      await page.getByRole("button", { name: new RegExp(label) }).click();
      const response = page.waitForResponse(
        (candidate) =>
          candidate.request().method() === "PATCH" &&
          candidate.url().includes(`/api/backend/api/v1/llm/providers/${provider}`),
      );
      await page.getByRole("button", { name: new RegExp(`保存并切换到 ${label}`) }).click();
      assertStatus((await response).status(), 200, `switch UI to ${provider}`);
      await expect(page.getByRole("status")).toContainText(`已切换到 ${label}`);
    }

    const knowledgeBaseId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
    await setFaultMode(request, enterprise, "provider_5xx");
    const unavailable = await bffRequest<Row>(page, "/api/v1/chat/query", { method: "POST", body: { knowledge_base_id: knowledgeBaseId, message: "请总结验收样本", limit: 5 } });
    assertStatus(unavailable.status, 200, "provider 5xx fallback");
    expect(row(row(unavailable.body, "provider 5xx fallback").source_status, "source status").strategy).toBe("retrieval_fallback");
    await setFaultMode(request, enterprise, "provider_timeout");
    const timeout = await bffRequest<Row>(page, "/api/v1/chat/query", { method: "POST", body: { knowledge_base_id: knowledgeBaseId, message: "请总结验收样本", limit: 5 } });
    assertStatus(timeout.status, 200, "provider timeout fallback");
    expect(row(row(timeout.body, "provider timeout fallback").source_status, "source status").strategy).toBe("retrieval_fallback");
  } finally {
    await setFaultMode(request, enterprise, "normal");
    assertStatus((await bffRequest(page, `/api/v1/llm/providers/${String(original.provider)}`, { method: "PATCH", body: { model: original.model, base_url: original.base_url, make_default: true } })).status, 200, "restore model provider");
  }
});

test("@enterprise API key enforces knowledge scope, rate limit and revocation", async ({ page, enterprise, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "api_key_lifecycle");
  annotate(testInfo, "error_loading_states");
  const allowedId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
  const deniedId = requiredEnv("KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID");
  await loginAdmin(page, enterprise);
  await page.goto("/admin/api-models");
  await expect(page.getByRole("heading", { name: "API 使用说明" })).toBeVisible();
  await expect(page.getByText("X-API-Key", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("cURL");
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("Python");
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("Node.js");
  const created = await bffRequest<Row>(page, "/api/v1/api-keys", {
    method: "POST",
    body: { name: `E2E API ${suffix(testInfo)}`, permission_codes: ["knowledge:read"], knowledge_base_ids: [allowedId], requests_per_minute: 2 },
  });
  assertStatus(created.status, 201, "create API key");
  const key = String(row(created.body, "create API key").key ?? "");
  const keyId = String(row(created.body, "create API key").id ?? "");
  if (!key || !keyId) throw new Error("API key create contract omitted one-time secret or id");
  const headers = { "x-api-key": key };
  const denied = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${deniedId}/search`, { headers, data: { query: "test", limit: 1 } });
  assertStatus(denied.status(), 404, "API key knowledge scope");
  const limited = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers, data: { query: "E2E", limit: 1 } });
  assertStatus(limited.status(), 200, "API key allowed scope");
  const rateLimited = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers, data: { query: "E2E", limit: 1 } });
  assertStatus(rateLimited.status(), 429, "API key rate limit");
  assertStatus((await bffRequest(page, `/api/v1/api-keys/${keyId}`, { method: "DELETE" })).status, 204, "revoke API key");
  const revoked = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers, data: { query: "E2E", limit: 1 } });
  assertStatus(revoked.status(), 401, "revoked API key");
});

test("@enterprise loading and 401/403/409/429/5xx/timeout states fail visibly", async ({ page, enterprise, request, quality }, testInfo) => {
  annotate(testInfo, "error_loading_states");
  quality.allowHttpStatus(503, "/api/backend/api/v1/knowledge-bases");
  quality.allowHttpStatus(504, "/api/backend/api/v1/knowledge-bases");
  await loginAdmin(page, enterprise);
  const loading = page.goto("/admin/users", { waitUntil: "commit" });
  await expect(page.locator("[aria-busy=true], .loading-rows").first()).toBeVisible();
  await loading;

  const anonymousPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await anonymousPage.goto("/login");
  assertStatus((await bffRequest(anonymousPage, "/api/v1/auth/me")).status, 401, "anonymous BFF request");

  const role = await createRole(page, testInfo, ["chat:query"]);
  const created = await createUser(page, testInfo, [String(role.id)]);
  const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(memberPage, created.credentials);
  assertStatus((await bffRequest(memberPage, "/api/v1/users?limit=1&offset=0")).status, 403, "forbidden BFF request");
  try {
    await setFaultMode(request, enterprise, "backend_5xx");
    assertStatus((await bffRequest(page, "/api/v1/knowledge-bases")).status, 503, "backend 5xx state");
    await setFaultMode(request, enterprise, "backend_timeout");
    assertStatus((await bffRequest(page, "/api/v1/knowledge-bases")).status, 504, "backend timeout state");
  } finally {
    await setFaultMode(request, enterprise, "normal");
  }
});
