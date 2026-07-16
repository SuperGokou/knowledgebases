import { createHash, randomBytes, randomUUID } from "node:crypto";

import type {
  APIRequestContext,
  Download,
  Page,
  Response as PlaywrightResponse,
  TestInfo,
} from "@playwright/test";

import {
  bffRequest,
  expect,
  loginAs,
  test,
} from "./support/enterprise-fixtures";
import { parseRfc4180Csv } from "./support/audit-csv";
import {
  probeEnterpriseTlsOrigin,
  validateObjectDownloadUrl,
  type EnterpriseConfig,
  type FaultMode,
} from "./support/enterprise-config";
import type { DocumentFixture } from "./support/document-fixtures";

type Row = Record<string, unknown>;
type SyntheticUser = {
  readonly credentials: { readonly email: string; readonly password: string };
  readonly user: Row;
};

function annotate(testInfo: TestInfo, check: string) {
  testInfo.annotations.push({ type: "evidence-check", description: check });
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`E2E_BLOCKED: missing ${name}`);
  return value;
}

function suffix(testInfo: TestInfo): string {
  const runId = requiredEnv("KB_E2E_RUN_ID").toLowerCase().replace(/[^a-z0-9_-]/g, "-");
  const runTag = runId.slice(0, 16);
  const projectTag = testInfo.project.name.toLowerCase().replace(/[^a-z0-9]/g, "").slice(-8);
  return `${runTag}-${projectTag}-${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`
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

function isAuditListResponse(response: PlaywrightResponse, action: string): boolean {
  if (response.request().method() !== "GET") return false;
  const url = new URL(response.url());
  return url.pathname === "/api/backend/api/v1/audit-logs"
    && url.searchParams.get("action") === action;
}

function isAuditExportResponse(response: PlaywrightResponse, action: string): boolean {
  if (response.request().method() !== "GET") return false;
  const url = new URL(response.url());
  return url.pathname === "/api/backend/api/v1/audit-logs/export"
    && url.searchParams.get("action") === action;
}

function requireAuditFixturePage(
  value: unknown,
  action: string,
  expectedRows: number,
  expectsNextCursor: boolean,
): { readonly items: Row[]; readonly nextCursor: number | null } {
  const body = row(value, `audit fixture ${action}`);
  if (!Array.isArray(body.items)) {
    throw new Error(`E2E_BLOCKED: dedicated audit fixture ${action} returned no item list`);
  }
  const items = body.items.map((item) => row(item, `audit fixture ${action} item`));
  const nextCursor = body.next_cursor;
  const cursorIsValid = nextCursor === null || Number.isSafeInteger(nextCursor);
  if (
    items.length !== expectedRows
    || !cursorIsValid
    || (expectsNextCursor ? nextCursor === null : nextCursor !== null)
    || items.some((item) => item.action !== action)
  ) {
    throw new Error(
      `E2E_BLOCKED: dedicated audit fixture ${action} is not the required isolated dataset`,
    );
  }
  return { items, nextCursor: nextCursor as number | null };
}

async function readDownloadPayload(download: Download): Promise<Buffer> {
  const stream = await download.createReadStream();
  if (!stream) throw new Error("audit CSV browser download stream is unavailable");
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function roleAssignmentVersion(user: Row, operation: string): number {
  const version = user.role_assignment_version;
  if (!Number.isSafeInteger(version) || Number(version) < 1) {
    throw new Error(`${operation}: user response omitted a valid role_assignment_version`);
  }
  return Number(version);
}

function roleGrantVersion(knowledgeBase: Row, operation: string): number {
  const version = knowledgeBase.role_grant_version;
  if (!Number.isSafeInteger(version) || Number(version) < 1) {
    throw new Error(`${operation}: knowledge base response omitted a valid role_grant_version`);
  }
  return Number(version);
}

function rolePolicyVersion(role: Row, operation: string): number {
  const version = role.policy_version;
  if (!Number.isSafeInteger(version) || Number(version) < 1) {
    throw new Error(`${operation}: role response omitted a valid policy_version`);
  }
  return Number(version);
}

function syntheticPassword(): string {
  return `E2E!Aa9${randomBytes(32).toString("base64url")}`;
}

async function loginAdmin(page: Page, enterprise: EnterpriseConfig) {
  await loginAs(page, {
    email: enterprise.adminEmail,
    password: enterprise.adminPassword,
  });
  await expect(page).toHaveURL(/\/admin(?:\/|$)/);
}

async function createRole(
  page: Page,
  enterprise: EnterpriseConfig,
  testInfo: TestInfo,
  permissions: string[],
) {
  const id = suffix(testInfo);
  const response = await bffRequest<Row>(page, "/api/v1/roles", {
    method: "POST",
    body: {
      code: `e2e_${id}`.replace(/-/g, "_").slice(0, 90),
      name: `E2E 验收角色 [run_id=${enterprise.runId}] ${id}`,
      description: `Playwright enterprise acceptance role; run_id=${enterprise.runId}`,
      priority: -9_000,
      permission_codes: permissions,
      limits: {},
    },
  });
  assertStatus(response.status, 201, "create role");
  return row(response.body, "create role");
}

async function createUser(
  page: Page,
  enterprise: EnterpriseConfig,
  testInfo: TestInfo,
  roleIds: string[] = [],
) {
  const id = suffix(testInfo);
  const credentials = {
    email: `enterprise-${id}@example.com`,
    password: syntheticPassword(),
  };
  const response = await bffRequest<Row>(page, "/api/v1/users", {
    method: "POST",
    body: {
      ...credentials,
      display_name: `E2E 验收成员 [run_id=${enterprise.runId}] ${id}`,
      role_ids: roleIds,
    },
  });
  assertStatus(response.status, 201, "create user");
  return { credentials, user: row(response.body, "create user") };
}

async function createKnowledgeBase(
  page: Page,
  enterprise: EnterpriseConfig,
  testInfo: TestInfo,
) {
  const id = suffix(testInfo);
  const response = await bffRequest<Row>(page, "/api/v1/knowledge-bases", {
    method: "POST",
    body: {
      name: `E2E 验收知识库 [run_id=${enterprise.runId}] ${id}`,
      description: `Retained enterprise E2E knowledge base; run_id=${enterprise.runId}`,
      external_llm_processing_enabled: false,
      custom_metadata: { source: "playwright-enterprise", e2e_run_id: enterprise.runId },
    },
  });
  assertStatus(response.status, 201, "create knowledge base");
  return row(response.body, "create knowledge base");
}

async function retireSyntheticUser(page: Page, user: Row) {
  const userId = String(user.id ?? "");
  if (!userId) throw new Error("retire synthetic user: response omitted user id");
  const email = String(user.email ?? "");
  if (!email) throw new Error("retire synthetic user: response omitted user email");
  const query = new URLSearchParams({ limit: "10", offset: "0", search: email });
  const listed = await bffRequest<Row[]>(page, `/api/v1/users?${query.toString()}`);
  assertStatus(listed.status, 200, "load synthetic user for retirement");
  const current = Array.isArray(listed.body)
    ? listed.body.find((item) => String(item.id ?? "") === userId)
    : undefined;
  if (!current) throw new Error("retire synthetic user: current user is not in the bounded admin list");
  if (Array.isArray(current.role_ids) && current.role_ids.length > 0) {
    const revoked = await bffRequest<Row>(page, `/api/v1/users/${userId}/roles`, {
      method: "PUT",
      body: {
        role_ids: [],
        expected_version: roleAssignmentVersion(current, "retire synthetic user"),
      },
    });
    assertStatus(revoked.status, 200, "remove retained synthetic user roles");
  }
  if (current.status !== "disabled") {
    const disabled = await bffRequest<Row>(page, `/api/v1/users/${userId}`, {
      method: "PATCH",
      body: { status: "disabled" },
    });
    assertStatus(disabled.status, 200, "disable retained synthetic user");
  }
}

async function deleteRoleIfPresent(page: Page, roleId: string) {
  const current = await bffRequest<Row>(page, `/api/v1/roles/${roleId}`);
  if (current.status === 404) return;
  assertStatus(current.status, 200, "load synthetic role for cleanup");
  const deleted = await bffRequest(
    page,
    `/api/v1/roles/${roleId}?expected_version=${rolePolicyVersion(row(current.body, "load synthetic role for cleanup"), "load synthetic role for cleanup")}`,
    { method: "DELETE" },
  );
  assertStatus(deleted.status, 204, "delete unreferenced synthetic role");
}

async function clearSyntheticKnowledgeGrants(page: Page, knowledgeBase: Row) {
  const knowledgeBaseId = String(knowledgeBase.id ?? "");
  if (!knowledgeBaseId) {
    throw new Error("clear synthetic knowledge grants: response omitted knowledge base id");
  }
  const current = await bffRequest<Row>(page, `/api/v1/knowledge-bases/${knowledgeBaseId}`);
  assertStatus(current.status, 200, "load synthetic knowledge base for grant cleanup");
  const cleared = await bffRequest<Row>(
    page,
    `/api/v1/knowledge-bases/${knowledgeBaseId}/role-grants`,
    {
      method: "PUT",
      body: {
        grants: [],
        expected_version: roleGrantVersion(
          row(current.body, "load synthetic knowledge base for grant cleanup"),
          "load synthetic knowledge base for grant cleanup",
        ),
      },
    },
  );
  assertStatus(cleared.status, 200, "clear synthetic knowledge base role grants");
}

async function cleanupSyntheticAccess(
  page: Page,
  resources: {
    readonly users?: ReadonlyArray<Row | null>;
    readonly knowledgeBases?: ReadonlyArray<Row | null>;
    readonly roles?: ReadonlyArray<Row | null>;
  },
) {
  const failures: unknown[] = [];
  for (const user of resources.users ?? []) {
    if (!user) continue;
    try {
      await retireSyntheticUser(page, user);
    } catch (error) {
      failures.push(error);
    }
  }
  for (const knowledgeBase of resources.knowledgeBases ?? []) {
    if (!knowledgeBase) continue;
    try {
      await clearSyntheticKnowledgeGrants(page, knowledgeBase);
    } catch (error) {
      failures.push(error);
    }
  }
  for (const role of resources.roles ?? []) {
    if (!role) continue;
    try {
      await deleteRoleIfPresent(page, String(role.id ?? ""));
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "synthetic access cleanup did not complete");
  }
}

async function expectLoginRejected(
  page: Page,
  credentials: { readonly email: string; readonly password: string },
) {
  await page.goto("/login");
  await page.getByLabel("工作邮箱").fill(credentials.email);
  await page.getByLabel("密码").fill(credentials.password);
  await page.getByRole("button", { name: "安全登录" }).click();
  await expect(page).toHaveURL(/\/login(?:\?|$)/);
  await expect(page.getByRole("alert")).toBeVisible();
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
    void error;
    throw new Error(`E2E_BLOCKED: fault controller ${mode} is unavailable`);
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
      custom_metadata: {
        source: "playwright-enterprise-multipart",
        e2e_run_id: enterprise.runId,
      },
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

  const fileCenter = page.locator("article.panel").filter({
    has: page.getByRole("heading", { name: "文件中心" }),
  });
  const refreshedFiles = page.waitForResponse((response) => {
    if (response.request().method() !== "GET") return false;
    const url = new URL(response.url());
    return url.pathname.endsWith("/api/backend/api/v1/files")
      && url.searchParams.get("offset") === "0";
  });
  await fileCenter.getByRole("button", { name: "刷新" }).click();
  assertStatus((await refreshedFiles).status(), 200, `refresh ${fixture.extension} file state`);

  const fileRow = fileCenter.locator("tbody tr").filter({ hasText: fixture.filename });
  await expect(fileRow).toContainText("草稿待审核");
  const approveButton = fileRow.getByRole("button", {
    name: `审批文件：${fixture.filename}`,
  });
  await expect(approveButton).toBeEnabled();
  const approvalResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
      && new URL(response.url()).pathname.endsWith(
        `/api/backend/api/v1/files/${String(file!.id)}/approve`,
      ));
  await approveButton.click();
  assertStatus((await approvalResponse).status(), 200, `approve ${fixture.extension} through UI`);
  await expect(fileRow).toContainText("已入知识库");

  const downloadButton = fileRow.getByRole("button", { name: "下载", exact: true });
  await expect(downloadButton).toBeVisible();
  const grantResponsePromise = page.waitForResponse((response) =>
    response.request().method() === "POST"
      && new URL(response.url()).pathname.endsWith(
        `/api/backend/api/v1/files/${String(file!.id)}/download`,
      ),
  );
  const objectResponsePromise = page.waitForResponse((response) => {
    if (response.request().method() !== "GET") return false;
    try {
      return new URL(response.url()).origin === enterprise.objectsOrigin;
    } catch {
      return false;
    }
  });
  const browserDownloadPromise = page.waitForEvent("download");
  await downloadButton.click();

  const grantResponse = await grantResponsePromise;
  assertStatus(grantResponse.status(), 200, `create ${fixture.extension} download grant through UI`);
  const grantBody = row(await grantResponse.json(), `${fixture.extension} download grant`);
  const rawDownloadUrl = String(grantBody.url ?? "");
  const expiresIn = Number(grantBody.expires_in);
  if (
    !rawDownloadUrl ||
    !Number.isSafeInteger(expiresIn) ||
    expiresIn < 1 ||
    expiresIn > 300
  ) {
    throw new Error(`${fixture.extension} download grant contract is invalid`);
  }
  const downloadUrl = validateObjectDownloadUrl(rawDownloadUrl, enterprise.objectsOrigin);
  const [objectResponse, browserDownload] = await Promise.all([
    objectResponsePromise,
    browserDownloadPromise,
  ]);
  assertStatus(objectResponse.status(), 200, `download ${fixture.extension} from object storage`);
  const disposition = objectResponse.headers()["content-disposition"] ?? "";
  const encodedFilename = /(?:^|;\s*)filename\*=UTF-8''([^;]+)/i.exec(disposition)?.[1]
    ?.trim()
    .replace(/^"(.*)"$/, "$1");
  if (!encodedFilename) {
    throw new Error(`${fixture.extension} download omitted an RFC 5987 filename`);
  }
  let responseFilename: string;
  try {
    responseFilename = decodeURIComponent(encodedFilename);
  } catch {
    throw new Error(`${fixture.extension} download returned an invalid encoded filename`);
  }
  if (responseFilename !== fixture.filename) {
    throw new Error(
      `${fixture.extension} response filename mismatch: expected ${fixture.filename}, received ${responseFilename}`,
    );
  }
  const observedObjectUrl = validateObjectDownloadUrl(
    objectResponse.url(),
    enterprise.objectsOrigin,
  );
  if (observedObjectUrl !== downloadUrl) {
    throw new Error(`${fixture.extension} browser download did not use the signed object URL`);
  }
  if (browserDownload.url() !== objectResponse.url()) {
    throw new Error(`${fixture.extension} browser download response identity changed unexpectedly`);
  }
  if (await browserDownload.failure()) {
    throw new Error(`${fixture.extension} browser download failed`);
  }
  if (browserDownload.suggestedFilename() !== fixture.filename) {
    throw new Error(
      `${fixture.extension} download filename mismatch: expected ${fixture.filename}, received ${browserDownload.suggestedFilename()}`,
    );
  }
  const stream = await browserDownload.createReadStream();
  if (!stream) throw new Error(`${fixture.extension} browser download stream is unavailable`);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const payload = Buffer.concat(chunks);
  if (payload.byteLength !== fixture.bytes) {
    throw new Error(
      `${fixture.extension} download size mismatch: expected ${fixture.bytes}, received ${payload.byteLength}`,
    );
  }
  const downloadedSha256 = createHash("sha256").update(payload).digest("hex");
  if (downloadedSha256 !== fixture.sha256) {
    throw new Error(`${fixture.extension} download SHA-256 does not match the fixture manifest`);
  }

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
    idempotencyKey: `e2e-${enterprise.runId}-file-${fixture.extension}-chat`,
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

test("@enterprise TLS validates trusted identity and short-lived certificate renewal architecture", async ({ page, enterprise, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "tls_ca_trust");
  annotate(testInfo, "tls_san_identity");
  annotate(testInfo, "tls_validity_and_renewal");
  annotate(testInfo, "tls_strict_client");

  const tlsEvidence = Object.fromEntries(
    await Promise.all(
      [
        ["web", enterprise.baseUrl],
        ["api", enterprise.publicApiOrigin],
        ["objects", enterprise.objectsOrigin],
      ].map(async ([name, origin]) => [name, await probeEnterpriseTlsOrigin(origin)] as const),
    ),
  );
  const response = await page.goto("/login", { waitUntil: "domcontentloaded" });
  assertStatus(response?.status() ?? 0, 200, "strict TLS login page");
  await expect(page.getByLabel("工作邮箱")).toBeVisible();
  await testInfo.attach("e2e-tls-validation", {
    body: Buffer.from(JSON.stringify({
      leaf_certificates: tlsEvidence,
      renewal_evidence: {
        evidence_id: "EXT-LINUX-HOST-001",
        required_checks: [
          "caddy_ca_persistent_storage",
          "caddy_automatic_certificate_management",
          "caddy_renewal_health",
        ],
        assertion_source: "formal_host_evidence_not_socket_probe",
      },
    })),
    contentType: "application/json",
  });
});

test("@enterprise unified login routes accounts by effective role", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "login_role_routing");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, enterprise, testInfo, ["chat:query", "knowledge:read"]);
  const created = await createUser(page, enterprise, testInfo, [String(role.id)]);

  const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(memberPage, created.credentials);
  await expect(memberPage).toHaveURL(/\/chat(?:\?|$)/);

  const contentRole = await createRole(page, enterprise, testInfo, [
    "knowledge:read",
    "knowledge:create",
    "knowledge:update",
    "file:read",
    "file:upload",
    "file:approve",
  ]);
  const contentManager = await createUser(page, enterprise, testInfo, [String(contentRole.id)]);
  const contentPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(contentPage, contentManager.credentials);
  await expect(contentPage).toHaveURL(/\/admin\/knowledge(?:\?|$)/);
  await expect(contentPage.getByRole("heading", { name: "知识库" })).toBeVisible();

  const pending = await createUser(page, enterprise, testInfo);
  const pendingPage = await quality.newIsolatedPage(enterprise.baseUrl);
  await loginAs(pendingPage, pending.credentials);
  await expect(pendingPage).toHaveURL(/\/access-pending(?:\?|$)/);
});

test("@enterprise account lifecycle rejects duplicates and revokes active access", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "account_lifecycle");
  annotate(testInfo, "error_loading_states");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, enterprise, testInfo, ["chat:query"]);
  const id = suffix(testInfo);
  const originalCredentials = {
    email: `enterprise-ui-${id}@example.com`,
    password: syntheticPassword(),
  };
  const resetCredentials = {
    email: originalCredentials.email,
    password: syntheticPassword(),
  };
  let createdUser: Row | null = null;

  try {
    await page.goto("/admin/users");
    const createDrawer = page.locator("details.drawer-form").filter({ hasText: "新建成员账号" });
    await createDrawer.locator("summary").click();
    await createDrawer.getByLabel("邮箱").fill(originalCredentials.email);
    await createDrawer.getByLabel("显示名称").fill(`E2E UI 成员 [run_id=${enterprise.runId}] ${id}`);
    await createDrawer.getByLabel("初始密码").fill(originalCredentials.password);
    const createdResponse = page.waitForResponse(
      (response) => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/api/backend/api/v1/users",
    );
    await createDrawer.getByRole("button", { name: "创建账号" }).click();
    const created = await createdResponse;
    assertStatus(created.status(), 201, "create member through the admin UI");
    createdUser = row(await created.json(), "create member through the admin UI");
    const userId = String(createdUser.id ?? "");
    if (!userId) throw new Error("UI-created member response omitted id");

    const memberSearch = page.getByRole("search");
    await memberSearch.getByLabel("搜索成员").fill(originalCredentials.email);
    const memberSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/users?")
        && new URL(response.url()).searchParams.get("search") === originalCredentials.email,
    );
    await memberSearch.getByRole("button", { name: "搜索" }).click();
    assertStatus((await memberSearchResponse).status(), 200, "search member through the admin UI");

    const duplicate = await bffRequest(page, "/api/v1/users", {
      method: "POST",
      body: { ...originalCredentials, display_name: "duplicate", role_ids: [] },
    });
    assertStatus(duplicate.status, 409, "duplicate user");

    let memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    await expect(memberRow).toHaveCount(1);
    await memberRow.getByRole("button", { name: "修改密码" }).click();
    const passwordDialog = page.getByRole("dialog", {
      name: new RegExp(`重置成员密码：.*${originalCredentials.email}`),
    });
    await passwordDialog.getByLabel("新密码", { exact: true }).fill(resetCredentials.password);
    await passwordDialog.getByLabel("确认新密码", { exact: true }).fill(resetCredentials.password);
    const resetResponse = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/users/${userId}/password`),
    );
    await passwordDialog.getByRole("button", { name: "确认修改并撤销旧会话" }).click();
    assertStatus((await resetResponse).status(), 204, "reset UI-created member password");
    await expect(page.getByRole("status")).toContainText("全部旧会话已撤销");

    memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    const roleCandidateQuery = String(role.name);
    await page.getByLabel("搜索角色候选").fill(roleCandidateQuery);
    const roleCandidateSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/roles?")
        && new URL(response.url()).searchParams.get("q") === roleCandidateQuery
        && new URL(response.url()).searchParams.get("assignable") === "true",
    );
    await page.getByRole("button", { name: "搜索角色" }).click();
    assertStatus(
      (await roleCandidateSearchResponse).status(),
      200,
      "search assignable role through the member administration UI",
    );
    await memberRow.getByRole("button", { name: "分配角色" }).click();
    const roleDialog = page.getByRole("dialog", {
      name: new RegExp(`分配角色：.*${originalCredentials.email}`),
    });
    await roleDialog.getByRole("checkbox", { name: new RegExp(String(role.name)) }).check();
    const assignedResponse = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/users/${userId}/roles`),
    );
    await roleDialog.getByRole("button", { name: "保存角色" }).click();
    const assigned = await assignedResponse;
    assertStatus(assigned.status(), 200, "assign member role through the admin UI");
    createdUser = row(await assigned.json(), "assign member role through the admin UI");
    expect(createdUser.role_ids).toContain(String(role.id));

    memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    await memberRow.getByRole("button", { name: "分配角色" }).click();
    await expect(page.getByRole("dialog", { name: new RegExp("分配角色") })).toBeVisible();
    await memberSearch.getByLabel("搜索成员").fill(`missing-${id}`);
    const hiddenDraftSearch = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/users?")
        && new URL(response.url()).searchParams.get("search") === `missing-${id}`,
    );
    await memberSearch.getByRole("button", { name: "搜索" }).click();
    assertStatus((await hiddenDraftSearch).status(), 200, "invalidate hidden member draft on search");
    await expect(page.getByRole("dialog", { name: new RegExp("分配角色") })).toHaveCount(0);
    await memberSearch.getByLabel("搜索成员").fill(originalCredentials.email);
    const restoreMemberSearch = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/users?")
        && new URL(response.url()).searchParams.get("search") === originalCredentials.email,
    );
    await memberSearch.getByRole("button", { name: "搜索" }).click();
    assertStatus((await restoreMemberSearch).status(), 200, "restore member search after draft invalidation");
    await expect(page.locator("tbody tr").filter({ hasText: originalCredentials.email })).toHaveCount(1);

    const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(memberPage, resetCredentials);
    await expect(memberPage).toHaveURL(/\/chat(?:\?|$)/);

    memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    const disabledResponse = page.waitForResponse(
      (response) => response.request().method() === "PATCH"
        && response.url().includes(`/api/v1/users/${userId}`),
    );
    await memberRow.getByRole("button", { name: "停用" }).click();
    assertStatus((await disabledResponse).status(), 200, "disable member through the admin UI");
    await expect(memberRow).toContainText("已停用");
    const staleSession = await bffRequest(memberPage, "/api/v1/auth/me");
    expect([401, 403]).toContain(staleSession.status);

    const enabledResponse = page.waitForResponse(
      (response) => response.request().method() === "PATCH"
        && response.url().includes(`/api/v1/users/${userId}`),
    );
    await memberRow.getByRole("button", { name: "启用" }).click();
    assertStatus((await enabledResponse).status(), 200, "enable member through the admin UI");
    await expect(memberRow).toContainText("正常");
    const reenabledPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(reenabledPage, resetCredentials);
    await expect(reenabledPage).toHaveURL(/\/chat(?:\?|$)/);

    memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    await memberRow.getByRole("button", { name: "删除账号" }).click();
    const retirementDialog = page.getByRole("dialog", {
      name: new RegExp(`删除成员账号：.*${originalCredentials.email}`),
    });
    const confirmRetirement = retirementDialog.getByRole("button", { name: "确认删除账号" });
    await expect(confirmRetirement).toBeDisabled();
    await retirementDialog.getByLabel("确认成员邮箱").fill(`wrong-${originalCredentials.email}`);
    await expect(confirmRetirement).toBeDisabled();
    await retirementDialog.getByLabel("确认成员邮箱").fill(originalCredentials.email);
    await retirementDialog.getByLabel(/退休原因/).fill("enterprise E2E lifecycle completion");
    await expect(confirmRetirement).toBeEnabled();
    const retiredResponse = page.waitForResponse(
      (response) => response.request().method() === "DELETE"
        && response.url().includes(`/api/v1/users/${userId}`),
    );
    await confirmRetirement.click();
    assertStatus((await retiredResponse).status(), 204, "retire member through the admin UI");
    await expect(page.getByRole("status")).toContainText("成员账号已安全退休");
    memberRow = page.locator("tbody tr").filter({ hasText: originalCredentials.email });
    await expect(memberRow).toContainText("已退休");
    await expect(memberRow.getByRole("button", { name: `修改密码 ${originalCredentials.email}` })).toBeDisabled();
    await expect(memberRow.getByRole("button", { name: `分配角色 ${originalCredentials.email}` })).toBeDisabled();
    await expect(memberRow.getByRole("button", { name: `删除账号 ${originalCredentials.email}` })).toBeDisabled();
    const retiredSession = await bffRequest(reenabledPage, "/api/v1/auth/me");
    expect([401, 403]).toContain(retiredSession.status);
    const retiredLoginPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await expectLoginRejected(retiredLoginPage, resetCredentials);
  } finally {
    await cleanupSyntheticAccess(page, {
      users: [createdUser],
      roles: [role],
    });
  }
});

test("@enterprise password reset enforces scope and revokes old credentials and sessions", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "account_lifecycle");
  await loginAdmin(page, enterprise);
  let memberRole: Row | null = null;
  let managerRole: Row | null = null;
  let ownerRole: Row | null = null;
  let member: SyntheticUser | null = null;
  let manager: SyntheticUser | null = null;
  let owner: SyntheticUser | null = null;

  try {
    memberRole = await createRole(page, enterprise, testInfo, ["chat:query"]);
    member = await createUser(page, enterprise, testInfo, [String(memberRole.id)]);
    managerRole = await createRole(page, enterprise, testInfo, ["user:manage"]);
    manager = await createUser(page, enterprise, testInfo, [String(managerRole.id)]);
    ownerRole = await createRole(page, enterprise, testInfo, ["knowledge:create", "knowledge:read"]);
    owner = await createUser(page, enterprise, testInfo, [String(ownerRole.id)]);
    const memberUserId = String(member.user.id);
    const memberNewPassword = syntheticPassword();
    const managerNewPassword = syntheticPassword();
    const unauthorizedPassword = syntheticPassword();

    const activeMemberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(activeMemberPage, member.credentials);

    await page.goto("/admin/users");
    const memberRow = page.locator("tbody tr").filter({ hasText: member.credentials.email });
    await expect(memberRow).toHaveCount(1);
    await memberRow.getByRole("button", { name: "修改密码" }).click();
    await expect(page.getByLabel("当前密码", { exact: true })).toHaveCount(0);
    await page.getByLabel("新密码", { exact: true }).fill(memberNewPassword);
    await page.getByLabel("确认新密码", { exact: true }).fill(memberNewPassword);
    const administrativeReset = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/users/${memberUserId}/password`),
    );
    await page.getByRole("button", { name: "确认修改并撤销旧会话" }).click();
    assertStatus((await administrativeReset).status(), 204, "superuser password reset without current password");
    await expect(page.getByRole("status")).toContainText("全部旧会话已撤销");

    const revokedSession = await bffRequest(activeMemberPage, "/api/v1/auth/me");
    expect([401, 403]).toContain(revokedSession.status);
    const oldPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await expectLoginRejected(oldPasswordPage, member.credentials);
    const newPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(newPasswordPage, {
      email: member.credentials.email,
      password: memberNewPassword,
    });
    await expect(newPasswordPage).toHaveURL(/\/chat(?:\?|$)/);

    const ownerPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(ownerPage, owner.credentials);
    const ownedKnowledgeBase = await createKnowledgeBase(ownerPage, enterprise, testInfo);
    expect(String(ownedKnowledgeBase.owner_id ?? "")).toBe(String(owner.user.id));

    const selfManagerPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(selfManagerPage, manager.credentials);
    await selfManagerPage.goto("/admin/users");
    const ownerRow = selfManagerPage.locator("tbody tr").filter({ hasText: owner.credentials.email });
    await expect(ownerRow).toHaveCount(1);
    await expect(ownerRow.getByRole("button", { name: "修改密码" })).toHaveCount(0);
    const unauthorizedReset = await bffRequest(
      selfManagerPage,
      `/api/v1/users/${String(owner.user.id)}/password`,
      {
        method: "PUT",
        body: {
          new_password: unauthorizedPassword,
        },
      },
    );
    assertStatus(unauthorizedReset.status, 403, "non-superuser reset of knowledge owner");
    const ownerOriginalPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(ownerOriginalPasswordPage, owner.credentials);
    await expect(ownerOriginalPasswordPage).toHaveURL(/\/admin\/knowledge(?:\?|$)/);
    const ownerUnauthorizedPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await expectLoginRejected(ownerUnauthorizedPasswordPage, {
      email: owner.credentials.email,
      password: unauthorizedPassword,
    });

    const siblingManagerPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(siblingManagerPage, manager.credentials);
    await selfManagerPage.getByRole("button", { name: "修改登录密码" }).click();
    await selfManagerPage.getByLabel("当前密码", { exact: true }).fill("Wrong-current-password-123!");
    await selfManagerPage.getByLabel("新密码", { exact: true }).fill(managerNewPassword);
    await selfManagerPage.getByLabel("确认新密码", { exact: true }).fill(managerNewPassword);
    const rejectedChange = selfManagerPage.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes("/api/v1/users/me/password"),
    );
    await selfManagerPage.getByRole("button", { name: "确认修改" }).click();
    assertStatus((await rejectedChange).status(), 401, "self password change with wrong current password");
    await expect(selfManagerPage).toHaveURL(/\/admin\/users(?:\?|$)/);
    await expect(selfManagerPage.getByRole("alert")).toBeVisible();

    await selfManagerPage.getByLabel("当前密码", { exact: true }).fill(manager.credentials.password);
    const acceptedChange = selfManagerPage.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes("/api/v1/users/me/password"),
    );
    await selfManagerPage.getByRole("button", { name: "确认修改" }).click();
    assertStatus((await acceptedChange).status(), 204, "self password change with current password");
    await expect(selfManagerPage).toHaveURL(/\/login(?:\?|$)/, { timeout: 30_000 });
    const revokedSiblingSession = await bffRequest(siblingManagerPage, "/api/v1/auth/me");
    expect([401, 403]).toContain(revokedSiblingSession.status);

    const selfOldPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await expectLoginRejected(selfOldPasswordPage, manager.credentials);
    const selfNewPasswordPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(selfNewPasswordPage, {
      email: manager.credentials.email,
      password: managerNewPassword,
    });
    await expect(selfNewPasswordPage).toHaveURL(/\/admin(?:\?|$)/);
  } finally {
    await cleanupSyntheticAccess(page, {
      users: [member?.user ?? null, manager?.user ?? null, owner?.user ?? null],
      roles: [memberRole, managerRole, ownerRole],
    });
  }
});

test("@enterprise role administration edits and deletes safely under references and concurrency", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "account_lifecycle");
  await loginAdmin(page, enterprise);
  let idleRoleForCleanup: Row | null = null;
  let referencedRole: Row | null = null;
  let referencedUser: SyntheticUser | null = null;
  let referencedKnowledgeBase: Row | null = null;

  try {
    await page.goto("/admin/roles");
    const roleId = suffix(testInfo);
    const roleCode = `e2e_ui_${roleId}`.replace(/-/g, "_").slice(0, 90);
    const roleName = `E2E UI 角色 [run_id=${enterprise.runId}] ${roleId}`;
    const roleDescription = `Created through the role administration UI; run_id=${enterprise.runId}`;
    const roleDrawer = page.locator("details.role-create-drawer");
    await roleDrawer.locator("summary").click();
    await roleDrawer.getByPlaceholder("例如 knowledge_editor").fill(roleCode);
    await roleDrawer.getByLabel("角色名称").fill(roleName);
    await roleDrawer.getByLabel("优先级").fill("-9000");
    await roleDrawer.getByLabel("描述").fill(roleDescription);
    const roleCreatedResponse = page.waitForResponse(
      (response) => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/api/backend/api/v1/roles",
    );
    await roleDrawer.getByRole("button", { name: "创建角色" }).click();
    const roleCreated = await roleCreatedResponse;
    assertStatus(roleCreated.status(), 201, "create custom role through the admin UI");
    const idleRole = row(await roleCreated.json(), "create custom role through the admin UI");
    idleRoleForCleanup = idleRole;
    await expect(page.getByRole("status")).toContainText("已创建");
    await expect(page.locator(".role-item").filter({ hasText: roleName })).toBeVisible();
    await page.getByLabel("搜索角色目录").fill(roleName);
    const createdRoleSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/roles?")
        && new URL(response.url()).searchParams.get("q") === roleName,
    );
    await page.locator("form.role-catalog-toolbar").getByRole("button", { name: "搜索", exact: true }).click();
    assertStatus((await createdRoleSearchResponse).status(), 200, "search created role through the role administration UI");
    await expect(page.locator(".role-item").filter({ hasText: roleName })).toBeVisible();

    const permissionSection = page.locator("details.policy-disclosure").filter({ hasText: "权限能力" });
    await permissionSection.locator("summary").click();
    await permissionSection.getByRole("checkbox", { name: /使用知识问答/ }).check();
    const limitSection = page.locator("details.policy-disclosure").filter({ hasText: "资源与访问限额" });
    await limitSection.locator("summary").click();
    await limitSection.getByLabel("每分钟请求次数设置方式").selectOption("limited");
    await limitSection.getByLabel("每分钟请求次数数值").fill("30");
    await limitSection.getByLabel("单个文件大小上限设置方式").selectOption("unlimited");
    const policySavedResponse = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/roles/${String(idleRole.id)}/policy`),
    );
    await page.getByRole("button", { name: "保存权限与限额" }).click();
    const policySaved = await policySavedResponse;
    assertStatus(policySaved.status(), 200, "save custom role policy through the admin UI");
    const savedPolicy = row(await policySaved.json(), "save custom role policy through the admin UI");
    expect(savedPolicy.permission_codes).toContain("chat:query");
    const savedLimits = row(savedPolicy.limits, "saved role limits");
    expect(savedLimits.requests_per_minute).toBe(30);
    expect(savedLimits.max_upload_bytes).toBeNull();
    await expect(page.getByRole("status")).toContainText("权限与限额已保存");

    await page.getByLabel("搜索角色目录").fill("");
    const resetRoleSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/roles?")
        && !new URL(response.url()).searchParams.has("q"),
    );
    await page.locator("form.role-catalog-toolbar").getByRole("button", { name: "搜索", exact: true }).click();
    assertStatus((await resetRoleSearchResponse).status(), 200, "reset role administration search");
    const systemRoleButton = page.locator(".role-item").filter({ hasText: "· 系统" }).first();
    await expect(systemRoleButton).toBeVisible();
    const systemRoleName = (await systemRoleButton.locator("strong").innerText()).trim();
    await systemRoleButton.click();
    const systemDetail = page.locator(".role-detail");
    await expect(systemDetail.getByRole("heading", { name: systemRoleName })).toBeVisible();
    await expect(systemDetail.getByRole("button", { name: "编辑角色" })).toHaveCount(0);
    await expect(systemDetail.getByRole("button", { name: "删除角色" })).toHaveCount(0);
    await expect(systemDetail).toContainText("系统角色始终只读");

    const roles = await bffRequest<Row[]>(page, "/api/v1/roles");
    assertStatus(roles.status, 200, "list roles for system immutability");
    const systemRole = Array.isArray(roles.body)
      ? roles.body.find((item) => item.is_system === true)
      : undefined;
    if (!systemRole) throw new Error("system role immutability: no system role returned");
    const systemUpdate = await bffRequest(page, `/api/v1/roles/${String(systemRole.id)}`, {
      method: "PATCH",
      body: {
        expected_version: rolePolicyVersion(systemRole, "system role immutability"),
        name: String(systemRole.name),
      },
    });
    assertStatus(systemUpdate.status, 403, "reject system role edit");
    const systemDelete = await bffRequest(
      page,
      `/api/v1/roles/${String(systemRole.id)}?expected_version=${rolePolicyVersion(systemRole, "system role immutability")}`,
      { method: "DELETE" },
    );
    assertStatus(systemDelete.status, 403, "reject system role delete");

    await page.getByLabel("搜索角色目录").fill(String(idleRole.name));
    const idleRoleSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/roles?")
        && new URL(response.url()).searchParams.get("q") === String(idleRole.name),
    );
    await page.locator("form.role-catalog-toolbar").getByRole("button", { name: "搜索", exact: true }).click();
    assertStatus((await idleRoleSearchResponse).status(), 200, "restore low-priority role through server search");
    const idleRoleButton = page.locator(".role-item").filter({ hasText: String(idleRole.name) });
    await idleRoleButton.click();
    await expect(page.getByRole("button", { name: "编辑角色" })).toBeEnabled();
    const editedName = `E2E 已编辑角色 [run_id=${enterprise.runId}] ${suffix(testInfo)}`;
    const editedDescription = `runtime edit verification; run_id=${enterprise.runId}`;
    await page.getByRole("button", { name: "编辑角色" }).click();
    const metadataEditor = page.getByRole("dialog", { name: "编辑角色资料" });
    await metadataEditor.getByLabel("角色名称").fill(editedName);
    await metadataEditor.getByLabel("描述").fill(editedDescription);
    await metadataEditor.getByLabel("优先级").fill("-8500");
    await metadataEditor.getByRole("button", { name: "保存角色资料" }).click();
    await expect(page.getByRole("status")).toContainText("名称、描述和优先级已保存");
    await expect(page.locator(".role-item").filter({ hasText: editedName })).toBeVisible();

    const current = await bffRequest<Row>(page, `/api/v1/roles/${String(idleRole.id)}`);
    assertStatus(current.status, 200, "load role before stale edit");
    const currentRole = row(current.body, "load role before stale edit");
    expect(currentRole.name).toBe(editedName);
    expect(currentRole.description).toBe(editedDescription);
    expect(currentRole.priority).toBe(-8_500);
    await page.getByRole("button", { name: "编辑角色" }).click();
    const staleMetadataEditor = page.getByRole("dialog", { name: "编辑角色资料" });
    const concurrentAdminPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAdmin(concurrentAdminPage, enterprise);
    const concurrentDescription = `concurrent runtime update; run_id=${enterprise.runId}`;
    const staleDescription = `stale browser draft; run_id=${enterprise.runId}`;
    const concurrentUpdate = await bffRequest<Row>(
      concurrentAdminPage,
      `/api/v1/roles/${String(idleRole.id)}`,
      {
        method: "PATCH",
        body: {
          expected_version: rolePolicyVersion(currentRole, "concurrent role update"),
          description: concurrentDescription,
        },
      },
    );
    assertStatus(concurrentUpdate.status, 200, "concurrent role update");
    const staleSaveResponse = page.waitForResponse(
      (response) => response.request().method() === "PATCH"
        && response.url().includes(`/api/v1/roles/${String(idleRole.id)}`),
    );
    await staleMetadataEditor.getByLabel("描述").fill(staleDescription);
    await staleMetadataEditor.getByRole("button", { name: "保存角色资料" }).click();
    assertStatus((await staleSaveResponse).status(), 409, "reject stale role metadata update");
    await expect(page.getByRole("status")).toContainText("旧编辑草稿已关闭");
    await expect(page.getByRole("dialog", { name: "编辑角色资料" })).toHaveCount(0);
    const winner = await bffRequest<Row>(page, `/api/v1/roles/${String(idleRole.id)}`);
    assertStatus(winner.status, 200, "load concurrent role winner");
    const winnerRole = row(winner.body, "load concurrent role winner");
    expect(winnerRole.description).toBe(concurrentDescription);
    expect(winnerRole.description).not.toBe(staleDescription);
    expect(rolePolicyVersion(winnerRole, "load concurrent role winner")).toBe(
      rolePolicyVersion(row(concurrentUpdate.body, "concurrent role update"), "concurrent role update"),
    );

    await page.locator(".role-item").filter({ hasText: editedName }).click();
    await page.getByRole("button", { name: "删除角色" }).click();
    const idleDeleteConfirmation = page.getByLabel(`请输入角色名称“${editedName}”确认`);
    const idleDeleteButton = page.getByRole("button", { name: "永久删除角色" });
    await expect(idleDeleteButton).toBeDisabled();
    await idleDeleteConfirmation.fill(`${editedName}-不匹配`);
    await expect(idleDeleteButton).toBeDisabled();
    await idleDeleteConfirmation.fill(editedName);
    await expect(idleDeleteButton).toBeEnabled();
    await idleDeleteButton.click();
    await expect(page.getByRole("status")).toContainText("已删除");
    await expect(page.locator(".role-item").filter({ hasText: editedName })).toHaveCount(0);

    referencedRole = await createRole(page, enterprise, testInfo, ["chat:query"]);
    referencedUser = await createUser(page, enterprise, testInfo, [String(referencedRole.id)]);
    referencedKnowledgeBase = await createKnowledgeBase(page, enterprise, testInfo);
    const referencedGrant = await bffRequest<Row>(
      page,
      `/api/v1/knowledge-bases/${String(referencedKnowledgeBase.id)}/role-grants`,
      {
        method: "PUT",
        body: {
          grants: [{ role_id: referencedRole.id, access_level: "reader" }],
          expected_version: roleGrantVersion(
            referencedKnowledgeBase,
            "create referenced knowledge base",
          ),
        },
      },
    );
    assertStatus(referencedGrant.status, 200, "grant referenced role to knowledge base");
    await page.goto("/admin/roles");
    await page.getByLabel("搜索角色目录").fill(String(referencedRole.name));
    const referencedRoleSearchResponse = page.waitForResponse(
      (response) => response.request().method() === "GET"
        && response.url().includes("/api/v1/roles?")
        && new URL(response.url()).searchParams.get("q") === String(referencedRole!.name),
    );
    await page.locator("form.role-catalog-toolbar").getByRole("button", { name: "搜索", exact: true }).click();
    assertStatus((await referencedRoleSearchResponse).status(), 200, "find referenced role beyond the first role page");
    await page.locator(".role-item").filter({ hasText: String(referencedRole.name) }).click();
    await page.getByRole("button", { name: "删除角色" }).click();
    await page.getByLabel(`请输入角色名称“${String(referencedRole.name)}”确认`).fill(String(referencedRole.name));
    const referencedDeleteResponse = page.waitForResponse(
      (response) => response.request().method() === "DELETE"
        && response.url().includes(`/api/v1/roles/${String(referencedRole!.id)}`),
    );
    await page.getByRole("button", { name: "永久删除角色" }).click();
    const referencedConflict = await referencedDeleteResponse;
    assertStatus(referencedConflict.status(), 409, "reject deletion of referenced role");
    const conflictPayload = row(await referencedConflict.json(), "referenced role delete conflict");
    const conflictError = row(conflictPayload.error, "referenced role delete error");
    const conflictDetails = row(conflictError.details, "referenced role delete details");
    const conflictReferences = row(
      conflictDetails.references,
      "referenced role delete references",
    );
    expect(conflictError.code).toBe("role_in_use");
    expect(conflictReferences.user_assignments).toBe(1);
    expect(conflictReferences.knowledge_base_grants).toBe(1);
    await expect(page.getByRole("alert")).toContainText("角色仍被 1 个成员账号和 1 项知识库授权");
    assertStatus(
      (await bffRequest(page, `/api/v1/roles/${String(referencedRole.id)}`)).status,
      200,
      "referenced role remains after conflict",
    );
    await retireSyntheticUser(page, referencedUser.user);
    await clearSyntheticKnowledgeGrants(page, referencedKnowledgeBase);
    const successfulDeleteResponse = page.waitForResponse(
      (response) => response.request().method() === "DELETE"
        && response.url().includes(`/api/v1/roles/${String(referencedRole!.id)}`),
    );
    await page.getByRole("button", { name: "永久删除角色" }).click();
    assertStatus((await successfulDeleteResponse).status(), 204, "delete unreferenced role");
    await expect(page.getByRole("status")).toContainText("已删除");
    assertStatus(
      (await bffRequest(page, `/api/v1/roles/${String(referencedRole.id)}`)).status,
      404,
      "deleted role is absent",
    );
  } finally {
    await cleanupSyntheticAccess(page, {
      users: [referencedUser?.user ?? null],
      knowledgeBases: [referencedKnowledgeBase],
      roles: [idleRoleForCleanup, referencedRole],
    });
  }
});

test("@enterprise knowledge grants are visible then fail closed immediately after revocation", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "knowledge_acl");
  await loginAdmin(page, enterprise);
  const role = await createRole(page, enterprise, testInfo, ["chat:query", "knowledge:read"]);
  const created = await createUser(page, enterprise, testInfo, [String(role.id)]);
  const knowledgeBase = await createKnowledgeBase(page, enterprise, testInfo);
  try {
    await page.goto("/admin/knowledge");
    await expect(page.getByRole("heading", { name: "知识库角色授权" })).toBeVisible();
    const knowledgeCandidateResponse = page.waitForResponse((response) => {
      if (response.request().method() !== "GET") return false;
      const url = new URL(response.url());
      return url.pathname.endsWith("/api/backend/api/v1/knowledge-bases")
        && url.searchParams.get("q") === String(knowledgeBase.name)
        && url.searchParams.get("minimum_access_level") === "manager";
    });
    await page.getByLabel("搜索可管理知识库").fill(String(knowledgeBase.name));
    assertStatus(
      (await knowledgeCandidateResponse).status(),
      200,
      "search manageable knowledge base through the grant UI",
    );
    const knowledgeSelect = page.getByLabel("选择要授权的知识库");
    await expect(knowledgeSelect.locator(`option[value="${String(knowledgeBase.id)}"]`)).toHaveCount(1);
    await knowledgeSelect.selectOption(String(knowledgeBase.id));
    const roleCandidateResponse = page.waitForResponse((response) => {
      if (response.request().method() !== "GET") return false;
      const url = new URL(response.url());
      return url.pathname.endsWith("/api/backend/api/v1/roles")
        && url.searchParams.get("q") === String(role.name);
    });
    await page.getByLabel("搜索角色").fill(String(role.name));
    assertStatus(
      (await roleCandidateResponse).status(),
      200,
      "search role through the grant UI",
    );
    const accessSelect = page.getByLabel(
      `${String(role.name)} 在 ${String(knowledgeBase.name)} 的访问等级`,
    );
    await expect(accessSelect).toBeEnabled();
    await accessSelect.selectOption("reader");
    const grantResponse = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/knowledge-bases/${String(knowledgeBase.id)}/role-grants`),
    );
    await page.getByRole("button", { name: "保存访问等级" }).click();
    assertStatus((await grantResponse).status(), 200, "grant knowledge access through the admin UI");
    await expect(accessSelect).toHaveValue("reader");

    const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(memberPage, created.credentials);
    assertStatus(
      (await bffRequest(memberPage, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}`)).status,
      200,
      "read UI-granted knowledge base",
    );

    await expect(accessSelect).toBeEnabled();
    await accessSelect.selectOption("none");
    const revokeResponse = page.waitForResponse(
      (response) => response.request().method() === "PUT"
        && response.url().includes(`/api/v1/knowledge-bases/${String(knowledgeBase.id)}/role-grants`),
    );
    await page.getByRole("button", { name: "保存访问等级" }).click();
    assertStatus((await revokeResponse).status(), 200, "revoke knowledge access through the admin UI");
    await expect(accessSelect).toHaveValue("none");
    assertStatus(
      (await bffRequest(memberPage, `/api/v1/knowledge-bases/${String(knowledgeBase.id)}`)).status,
      404,
      "conceal UI-revoked knowledge base",
    );
  } finally {
    await cleanupSyntheticAccess(page, {
      users: [created.user],
      knowledgeBases: [knowledgeBase],
      roles: [role],
    });
  }
});

test("@enterprise all nine document formats complete scan, OKF, approval, retrieval and cited chat", async ({ page, enterprise, enterpriseDocuments, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "file_upload_scan_okf_approval_download");
  await loginAdmin(page, enterprise);
  const knowledgeBase = await createKnowledgeBase(page, enterprise, testInfo);
  await uploadMultipartFixture(
    page,
    request,
    enterprise,
    String(knowledgeBase.id),
    testInfo,
  );
  await page.goto("/admin/files");
  const uploadCandidateResponse = page.waitForResponse((response) => {
    if (response.request().method() !== "GET") return false;
    const url = new URL(response.url());
    return url.pathname.endsWith("/api/backend/api/v1/knowledge-bases")
      && url.searchParams.get("q") === String(knowledgeBase.name)
      && url.searchParams.get("minimum_access_level") === "editor";
  });
  await page.getByLabel("搜索可编辑知识库").fill(String(knowledgeBase.name));
  assertStatus(
    (await uploadCandidateResponse).status(),
    200,
    "search editable upload knowledge base through the files UI",
  );
  await page.getByLabel("目标知识库").selectOption(String(knowledgeBase.id));
  expect(enterpriseDocuments).toHaveLength(9);
  for (const fixture of enterpriseDocuments) {
    await uploadApproveAndGroundFixture(
      page,
      enterprise,
      String(knowledgeBase.id),
      fixture,
    );
  }
  const searchTarget = enterpriseDocuments.at(-1);
  if (!searchTarget) throw new Error("enterprise document fixtures unexpectedly empty");
  const fileSearch = page.getByRole("search");
  await fileSearch.getByLabel("搜索文件名").fill(searchTarget.filename);
  const searchedFiles = page.waitForResponse(
    (response) => response.request().method() === "GET"
      && response.url().includes("/api/v1/files?")
      && new URL(response.url()).searchParams.get("search") === searchTarget.filename,
  );
  await fileSearch.getByRole("button", { name: "搜索" }).click();
  assertStatus((await searchedFiles).status(), 200, "search uploaded file through the admin UI");
  await expect(page.locator("tbody tr").filter({ hasText: searchTarget.filename })).toHaveCount(1);
});

test("@enterprise chat renders citations, no-answer, audited rejection and sourced table", async ({ page, enterprise, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "chat_citations_audit_table");
  const knowledgeBaseId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
  await loginAdmin(page, enterprise);
  const knowledgeBase = await bffRequest<Row>(
    page,
    `/api/v1/knowledge-bases/${knowledgeBaseId}`,
  );
  assertStatus(knowledgeBase.status, 200, "read seeded chat knowledge base");
  const knowledgeBaseNameValue = row(
    knowledgeBase.body,
    "seeded chat knowledge base",
  ).name;
  if (typeof knowledgeBaseNameValue !== "string" || !knowledgeBaseNameValue.trim()) {
    throw new Error("seeded chat knowledge base: response omitted a valid name");
  }
  const knowledgeBaseName = knowledgeBaseNameValue.trim();
  await page.goto("/chat");
  const catalogSearch = page.getByRole("search");
  await catalogSearch.getByLabel("搜索可问答知识库").fill(knowledgeBaseName);
  const searchedCatalog = page.waitForResponse((response) => {
    if (response.request().method() !== "GET" || !response.url().includes("/api/v1/knowledge-bases?")) {
      return false;
    }
    const parameters = new URL(response.url()).searchParams;
    return parameters.get("q") === knowledgeBaseName
      && parameters.get("minimum_access_level") === "reader";
  });
  await catalogSearch.getByRole("button", { name: "搜索" }).click();
  assertStatus((await searchedCatalog).status(), 200, "search chat knowledge catalog");
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
      idempotencyKey: `e2e-${enterprise.runId}-no-answer`,
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
  annotate(testInfo, "model_deepseek_success");
  annotate(testInfo, "model_qwen_success");
  annotate(testInfo, "model_minimax_success");
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
  const knowledgeBaseId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
  try {
    await setFaultMode(request, enterprise, "normal");
    for (const provider of requiredProviders) {
      const label = provider === "deepseek" ? "DeepSeek" : provider === "qwen" ? "Qwen 通义千问" : "MiniMax";
      const configuredProvider = providers.find((item) => item.provider === provider);
      if (!configuredProvider || typeof configuredProvider.model !== "string") {
        throw new Error(`E2E_BLOCKED: ${provider} model configuration is unavailable`);
      }
      await page.getByRole("button", { name: new RegExp(label) }).click();
      const response = page.waitForResponse(
        (candidate) =>
          candidate.request().method() === "PATCH" &&
          candidate.url().includes(`/api/backend/api/v1/llm/providers/${provider}`),
      );
      await page.getByRole("button", { name: new RegExp(`保存并切换到 ${label}`) }).click();
      assertStatus((await response).status(), 200, `switch UI to ${provider}`);
      await expect(page.getByRole("status")).toContainText(`已切换到 ${label}`);

      const generated = await bffRequest<Row>(page, "/api/v1/chat/query", {
        method: "POST",
        idempotencyKey: `e2e-${enterprise.runId}-${provider}-success`,
        body: {
          knowledge_base_id: knowledgeBaseId,
          message: "请基于验收样本给出有来源的简短总结",
          limit: 5,
        },
      });
      assertStatus(generated.status, 200, `${provider} successful chat`);
      const generatedBody = row(generated.body, `${provider} successful chat`);
      expect(generatedBody.knowledge_base_id).toBe(knowledgeBaseId);
      expect(generatedBody.provider).toBe(provider);
      expect(generatedBody.model).toBe(configuredProvider.model);
      expect(generatedBody.mode).toBe("rag");
      expect(row(generatedBody.answer_review, "answer review")).toMatchObject({
        status: "passed",
        reason: "semantic_verified",
      });
      const sourceStatus = row(generatedBody.source_status, "source status");
      expect(sourceStatus).toMatchObject({
        status: "grounded",
        strategy: "rag",
        reason: "llm_generated",
      });
      const citations = Array.isArray(generatedBody.citations)
        ? generatedBody.citations.map((item) => row(item, `${provider} citation`))
        : [];
      expect(citations.length).toBeGreaterThan(0);
      expect(sourceStatus.citation_count).toBe(citations.length);
      const citationNumbers = citations.map((citation) => Number(citation.citation_number));
      expect(citationNumbers.every((number) => Number.isSafeInteger(number) && number > 0)).toBe(true);
      expect(new Set(citationNumbers).size).toBe(citations.length);
      for (const citation of citations) {
        expect(citation.marker).toBe(`[${String(citation.citation_number)}]`);
        expect(String(citation.entry_id ?? "")).not.toBe("");
        expect(String(citation.source_file_id ?? "")).not.toBe("");
        expect(String(citation.excerpt ?? "").trim()).not.toBe("");
      }
    }

    await setFaultMode(request, enterprise, "provider_5xx");
    const unavailable = await bffRequest<Row>(page, "/api/v1/chat/query", { method: "POST", idempotencyKey: `e2e-${enterprise.runId}-provider-5xx`, body: { knowledge_base_id: knowledgeBaseId, message: "请总结验收样本", limit: 5 } });
    assertStatus(unavailable.status, 200, "provider 5xx fallback");
    expect(row(row(unavailable.body, "provider 5xx fallback").source_status, "source status").strategy).toBe("retrieval_fallback");
    await setFaultMode(request, enterprise, "provider_timeout");
    const timeout = await bffRequest<Row>(page, "/api/v1/chat/query", { method: "POST", idempotencyKey: `e2e-${enterprise.runId}-provider-timeout`, body: { knowledge_base_id: knowledgeBaseId, message: "请总结验收样本", limit: 5 } });
    assertStatus(timeout.status, 200, "provider timeout fallback");
    expect(row(row(timeout.body, "provider timeout fallback").source_status, "source status").strategy).toBe("retrieval_fallback");
  } finally {
    await setFaultMode(request, enterprise, "normal");
    assertStatus((await bffRequest(page, `/api/v1/llm/providers/${String(original.provider)}`, { method: "PATCH", body: { model: original.model, base_url: original.base_url, make_default: true } })).status, 200, "restore model provider");
    const restored = await bffRequest<Row>(page, "/api/v1/llm/providers");
    assertStatus(restored.status, 200, "verify restored model provider");
    const restoredBody = row(restored.body, "verify restored model provider");
    expect(restoredBody.default_provider).toBe(original.provider);
    const restoredProviders = Array.isArray(restoredBody.providers)
      ? restoredBody.providers.map((item) => row(item, "restored provider"))
      : [];
    const restoredDefault = restoredProviders.find(
      (item) => item.provider === original.provider,
    );
    expect(restoredDefault).toMatchObject({
      provider: original.provider,
      model: original.model,
      is_default: true,
    });
  }
});

test("@enterprise API key enforces knowledge scope, rate limit and revocation", async ({ page, enterprise, request, quality }, testInfo) => {
  void quality;
  annotate(testInfo, "api_key_lifecycle");
  annotate(testInfo, "error_loading_states");
  const allowedId = requiredEnv("KB_E2E_SEEDED_KNOWLEDGE_BASE_ID");
  const deniedId = requiredEnv("KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID");
  const keyName = `E2E API [run_id=${enterprise.runId}] ${suffix(testInfo)}`;
  let activeKeyId: string | null = null;
  await loginAdmin(page, enterprise);
  await page.goto("/admin/api-models");
  await expect(page.getByRole("heading", { name: "API 使用说明" })).toBeVisible();
  await expect(page.getByText("X-API-Key", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("cURL");
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("Python");
  await expect(page.getByRole("group", { name: "示例语言" })).toContainText("Node.js");
  const knowledgeBaseResponse = await bffRequest<Row>(page, `/api/v1/knowledge-bases/${allowedId}`);
  assertStatus(knowledgeBaseResponse.status, 200, "load API key knowledge scope fixture");
  const allowedName = String(row(knowledgeBaseResponse.body, "load API key knowledge scope fixture").name ?? "");
  if (!allowedName) throw new Error("API key knowledge scope fixture omitted its name");

  try {
    const candidateResponse = page.waitForResponse((response) => {
      if (response.request().method() !== "GET") return false;
      const url = new URL(response.url());
      return url.pathname.endsWith("/api/backend/api/v1/knowledge-bases")
        && url.searchParams.get("q") === allowedName;
    });
    await page.getByLabel("搜索知识库").fill(allowedName);
    assertStatus((await candidateResponse).status(), 200, "search API key knowledge scope through UI");

    await page.getByLabel("凭证名称").fill(keyName);
    await page.getByLabel("每分钟请求上限").fill("3");
    const permissionGroup = page.getByRole("group", { name: "接口权限" });
    const chatPermission = permissionGroup.getByRole("checkbox", { name: /知识问答/ });
    if (await chatPermission.isChecked()) await chatPermission.uncheck();
    await permissionGroup.getByRole("checkbox", { name: /知识检索/ }).check();
    await page.getByRole("group", { name: "允许访问的知识库" })
      .getByRole("checkbox", { name: allowedName })
      .check();

    const createResponse = page.waitForResponse(
      (response) => response.request().method() === "POST"
        && response.url().endsWith("/api/backend/api/v1/api-keys"),
    );
    await page.getByRole("button", { name: "生成 API Key" }).click();
    const createdResponse = await createResponse;
    assertStatus(createdResponse.status(), 201, "create API key through UI");
    const createdBody = row(await createdResponse.json(), "create API key through UI");
    const keyId = String(createdBody.id ?? "");
    const familyId = String(createdBody.credential_family_id ?? "");
    activeKeyId = keyId;
    if (!keyId || !familyId) {
      throw new Error("API key create UI response omitted id or credential family");
    }

    const issuedPanel = page.locator("[data-sensitive='true']");
    let key = "";
    try {
      await expect(issuedPanel).toContainText("请立即复制并安全保存");
      key = (await issuedPanel.locator("code").textContent())?.trim() ?? "";
      if (!key) throw new Error("API key create UI omitted its one-time secret");
    } finally {
      const closeSecret = issuedPanel.getByRole("button", { name: "我已保存，关闭明文" });
      if (await closeSecret.isVisible().catch(() => false)) await closeSecret.click();
    }
    await expect(issuedPanel).toHaveCount(0);
    const keyRow = page.locator("tbody tr").filter({ hasText: keyName });
    await expect(keyRow).toBeVisible();

    const headers = { "x-api-key": key };
    const denied = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${deniedId}/search`, { headers, data: { query: "test", limit: 1 } });
    assertStatus(denied.status(), 404, "API key knowledge scope");
    const limited = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers, data: { query: "E2E", limit: 1 } });
    assertStatus(limited.status(), 200, "API key allowed scope");

    page.once("dialog", async (dialog) => {
      expect(dialog.type()).toBe("confirm");
      expect(dialog.message()).toContain(keyName);
      await dialog.accept();
    });
    const rotateResponse = page.waitForResponse(
      (response) => response.request().method() === "POST"
        && response.url().endsWith(`/api/backend/api/v1/api-keys/${keyId}/rotate`),
    );
    await keyRow.getByRole("button", { name: `轮换 ${keyName}` }).click();
    const rotatedResponse = await rotateResponse;
    assertStatus(rotatedResponse.status(), 201, "rotate API key through UI");
    const rotatedBody = row(await rotatedResponse.json(), "rotate API key through UI");
    const rotatedKeyId = String(rotatedBody.id ?? "");
    expect(String(rotatedBody.credential_family_id ?? "")).toBe(familyId);
    expect(rotatedKeyId).not.toBe(keyId);
    activeKeyId = rotatedKeyId;
    if (!rotatedKeyId) throw new Error("API key rotation UI response omitted its id");

    let rotatedKey = "";
    try {
      await expect(issuedPanel).toContainText("轮换完成，请立即保存新 Key");
      rotatedKey = (await issuedPanel.locator("code").textContent())?.trim() ?? "";
      if (!rotatedKey) throw new Error("API key rotation UI omitted its one-time secret");
    } finally {
      const closeSecret = issuedPanel.getByRole("button", { name: "我已保存，关闭明文" });
      if (await closeSecret.isVisible().catch(() => false)) await closeSecret.click();
    }
    await expect(issuedPanel).toHaveCount(0);

    const oldKeyRejected = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers, data: { query: "E2E", limit: 1 } });
    assertStatus(oldKeyRejected.status(), 401, "rotated old API key");
    const rotatedHeaders = { "x-api-key": rotatedKey };
    const rotatedAllowed = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers: rotatedHeaders, data: { query: "E2E", limit: 1 } });
    assertStatus(rotatedAllowed.status(), 200, "rotated API key retains scope");
    const rateLimited = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers: rotatedHeaders, data: { query: "E2E", limit: 1 } });
    assertStatus(rateLimited.status(), 429, "API key rate limit");

    page.once("dialog", async (dialog) => {
      expect(dialog.type()).toBe("confirm");
      expect(dialog.message()).toContain(keyName);
      await dialog.accept();
    });
    const revokeResponse = page.waitForResponse(
      (response) => response.request().method() === "DELETE"
        && response.url().endsWith(`/api/backend/api/v1/api-keys/${rotatedKeyId}`),
    );
    await page.getByRole("button", { name: `撤销 ${keyName}` }).click();
    assertStatus((await revokeResponse).status(), 204, "revoke API key through UI");
    activeKeyId = null;
    await expect(page.locator("tbody tr").filter({ hasText: keyName })).toHaveCount(0);
    const revoked = await request.post(`${enterprise.publicApiOrigin}/api/v1/public/knowledge-bases/${allowedId}/search`, { headers: rotatedHeaders, data: { query: "E2E", limit: 1 } });
    assertStatus(revoked.status(), 401, "revoked API key");
  } finally {
    const issuedPanel = page.locator("[data-sensitive='true']");
    const closeSecret = issuedPanel.getByRole("button", { name: "我已保存，关闭明文" });
    if (await closeSecret.isVisible().catch(() => false)) await closeSecret.click();
    const cleanupIds = new Set<string>();
    if (activeKeyId) cleanupIds.add(activeKeyId);
    const activeKeys = await bffRequest<Row[]>(page, "/api/v1/api-keys?limit=100&offset=0");
    if (activeKeys.status === 200 && Array.isArray(activeKeys.body)) {
      for (const candidate of activeKeys.body) {
        if (candidate.name === keyName && candidate.id) cleanupIds.add(String(candidate.id));
      }
    }
    for (const cleanupId of cleanupIds) {
      const cleanup = await bffRequest(page, `/api/v1/api-keys/${cleanupId}`, { method: "DELETE" });
      if (![204, 404].includes(cleanup.status)) {
        throw new Error(
          `cleanup API key ${cleanupId}: expected HTTP 204 or 404, received ${cleanup.status}`,
        );
      }
    }
  }
});

test("@enterprise audit query, pagination, CSV export and permission revocation fail closed", async ({ page, enterprise, quality }, testInfo) => {
  annotate(testInfo, "audit_log_query_export");
  await loginAdmin(page, enterprise);
  await page.goto("/admin/audit");
  await expect(page.getByRole("heading", { name: "审计日志" })).toBeVisible();

  const actionInput = page.getByLabel("动作", { exact: true });
  const applyFilters = page.getByRole("button", { name: "应用筛选", exact: true });
  const auditRows = page.locator(".audit-log-panel tbody tr");
  const auditActions = page.locator(".audit-log-panel tbody .audit-action");
  const pagination = page.getByRole("navigation", { name: "审计日志分页" });

  await actionInput.fill(enterprise.auditPageAction);
  const firstPageResponsePromise = page.waitForResponse((response) => {
    if (!isAuditListResponse(response, enterprise.auditPageAction)) return false;
    return !new URL(response.url()).searchParams.has("cursor");
  });
  await applyFilters.click();
  const firstPageResponse = await firstPageResponsePromise;
  assertStatus(firstPageResponse.status(), 200, "load first dedicated audit fixture page");
  const firstFixturePage = requireAuditFixturePage(
    await firstPageResponse.json(),
    enterprise.auditPageAction,
    50,
    true,
  );
  expect(firstFixturePage.nextCursor).not.toBeNull();
  await expect(auditRows).toHaveCount(50);
  await expect(pagination).toContainText("第 1 页 · 本页 50 项");
  expect(await auditActions.allTextContents()).toEqual(
    Array.from({ length: 50 }, () => enterprise.auditPageAction),
  );

  const secondPageResponsePromise = page.waitForResponse((response) => {
    if (!isAuditListResponse(response, enterprise.auditPageAction)) return false;
    return new URL(response.url()).searchParams.has("cursor");
  });
  await pagination.getByRole("button", { name: "下一页" }).click();
  const secondPageResponse = await secondPageResponsePromise;
  assertStatus(secondPageResponse.status(), 200, "load second dedicated audit fixture page");
  requireAuditFixturePage(
    await secondPageResponse.json(),
    enterprise.auditPageAction,
    5,
    false,
  );
  await expect(auditRows).toHaveCount(5);
  await expect(pagination).toContainText("第 2 页 · 本页 5 项");
  await expect(pagination.getByRole("button", { name: "下一页" })).toBeDisabled();
  expect(await auditActions.allTextContents()).toEqual(
    Array.from({ length: 5 }, () => enterprise.auditPageAction),
  );

  const previousPageResponsePromise = page.waitForResponse((response) => {
    if (!isAuditListResponse(response, enterprise.auditPageAction)) return false;
    return !new URL(response.url()).searchParams.has("cursor");
  });
  await pagination.getByRole("button", { name: "上一页" }).click();
  const previousPageResponse = await previousPageResponsePromise;
  assertStatus(previousPageResponse.status(), 200, "return to first audit fixture page");
  requireAuditFixturePage(
    await previousPageResponse.json(),
    enterprise.auditPageAction,
    50,
    true,
  );
  await expect(auditRows).toHaveCount(50);
  await expect(pagination).toContainText("第 1 页 · 本页 50 项");

  const exportResponsePromise = page.waitForResponse((response) =>
    isAuditExportResponse(response, enterprise.auditPageAction),
  );
  const downloadPromise = page.waitForEvent("download");
  await page.getByLabel("导出当前筛选结果为 CSV").click();
  const [exportResponse, download] = await Promise.all([
    exportResponsePromise,
    downloadPromise,
  ]);
  assertStatus(exportResponse.status(), 200, "export dedicated audit fixture through UI");
  const exportHeaders = exportResponse.headers();
  expect(exportHeaders["content-type"]?.toLowerCase()).toContain("text/csv");
  expect(exportHeaders["content-disposition"]).toMatch(
    /attachment; filename="audit-logs-\d{8}T\d{6}Z\.csv"/u,
  );
  expect(exportHeaders["cache-control"]?.toLowerCase()).toContain("no-store");
  expect(exportHeaders["cache-control"]?.toLowerCase()).toContain("private");
  expect(exportHeaders["x-content-type-options"]?.toLowerCase()).toBe("nosniff");
  expect(download.suggestedFilename()).toMatch(/^audit-logs-\d{8}T\d{6}Z\.csv$/u);

  const csvPayload = await readDownloadPayload(download);
  expect(csvPayload.subarray(0, 3)).toEqual(Buffer.from([0xef, 0xbb, 0xbf]));
  const csvText = csvPayload.subarray(3).toString("utf8");
  const csvRows = parseRfc4180Csv(csvText);
  expect(csvRows).toHaveLength(56);
  expect(csvRows[0]).toEqual([
    "id",
    "created_at",
    "result",
    "action",
    "actor_id",
    "resource_type",
    "resource_id",
    "request_id",
  ]);
  expect(csvRows.every((csvRow) => csvRow.length === 8)).toBe(true);
  expect(csvRows.slice(1).every((csvRow) => csvRow[3] === enterprise.auditPageAction)).toBe(true);
  expect(csvText.toLowerCase()).not.toContain("details");
  expect(csvText.toLowerCase()).not.toContain("ip_address");
  expect(csvText).not.toContain(enterprise.auditRedactionSentinel);
  await expect(page.getByRole("status").filter({ hasText: "导出已完成" })).toBeVisible();

  await actionInput.fill(enterprise.auditOversizedAction);
  const oversizedListResponsePromise = page.waitForResponse((response) => {
    if (!isAuditListResponse(response, enterprise.auditOversizedAction)) return false;
    return !new URL(response.url()).searchParams.has("cursor");
  });
  await applyFilters.click();
  const oversizedListResponse = await oversizedListResponsePromise;
  assertStatus(oversizedListResponse.status(), 200, "load oversized audit fixture page");
  const oversizedBody = row(
    await oversizedListResponse.json(),
    "load oversized audit fixture page",
  );
  if (
    !Array.isArray(oversizedBody.items)
    || oversizedBody.items.length !== 50
    || oversizedBody.next_cursor === null
    || oversizedBody.items.some(
      (item) => row(item, "oversized audit fixture item").action
        !== enterprise.auditOversizedAction,
    )
  ) {
    throw new Error("E2E_BLOCKED: dedicated >5000 audit fixture is unavailable");
  }

  const oversizedExportResponsePromise = page.waitForResponse((response) =>
    isAuditExportResponse(response, enterprise.auditOversizedAction),
  );
  await page.getByLabel("导出当前筛选结果为 CSV").click();
  const oversizedExportResponse = await oversizedExportResponsePromise;
  if (oversizedExportResponse.status() !== 422) {
    throw new Error(
      "E2E_BLOCKED: dedicated >5000 audit fixture does not exceed the export limit",
    );
  }
  const oversizedProblem = row(
    await oversizedExportResponse.json(),
    "oversized audit export problem",
  );
  expect(row(oversizedProblem.error, "oversized audit export error").code).toBe(
    "audit_export_too_large",
  );
  const oversizedAlert = page.getByRole("alert").filter({ hasText: "导出失败" });
  await expect(oversizedAlert).toContainText("超过 5,000 条");
  await expect(oversizedAlert.getByRole("button", { name: "重试导出" })).toBeVisible();

  let auditRole: Row | null = null;
  let auditUser: SyntheticUser | null = null;
  try {
    auditRole = await createRole(page, enterprise, testInfo, ["audit:read", "chat:query"]);
    auditUser = await createUser(page, enterprise, testInfo, [String(auditRole.id)]);
    const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(memberPage, auditUser.credentials);
    await expect(memberPage).toHaveURL(/\/admin(?:\?|$)/);
    const memberInitialList = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname === "/api/backend/api/v1/audit-logs"
        && response.status() === 200,
    );
    await memberPage.goto("/admin/audit");
    await memberInitialList;
    await expect(memberPage.getByRole("heading", { name: "审计日志" })).toBeVisible();

    const currentRoleResponse = await bffRequest<Row>(
      page,
      `/api/v1/roles/${String(auditRole.id)}`,
    );
    assertStatus(currentRoleResponse.status, 200, "load audit role before permission revocation");
    const currentRole = row(currentRoleResponse.body, "load audit role before revocation");
    const permissionsRevoked = await bffRequest<Row>(
      page,
      `/api/v1/roles/${String(auditRole.id)}/permissions`,
      {
        method: "PUT",
        body: {
          permission_codes: ["chat:query"],
          expected_version: rolePolicyVersion(currentRole, "revoke audit permission"),
        },
      },
    );
    assertStatus(permissionsRevoked.status, 200, "revoke audit permission");

    const deniedListResponsePromise = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname === "/api/backend/api/v1/audit-logs"
        && response.status() === 403,
    );
    await memberPage.getByLabel("刷新审计日志").click();
    await deniedListResponsePromise;
    const deniedListAlert = memberPage.getByRole("alert").filter({
      hasText: "暂时无法加载",
    });
    await expect(deniedListAlert).toBeVisible();
    await expect(
      deniedListAlert.getByRole("button", { name: "重新加载审计日志" }),
    ).toBeVisible();

    const deniedExportResponsePromise = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname === "/api/backend/api/v1/audit-logs/export"
        && response.status() === 403,
    );
    await memberPage.getByLabel("导出当前筛选结果为 CSV").click();
    await deniedExportResponsePromise;
    const deniedExportAlert = memberPage.getByRole("alert").filter({ hasText: "导出失败" });
    await expect(deniedExportAlert).toBeVisible();
    await expect(
      deniedExportAlert.getByRole("button", { name: "重试导出" }),
    ).toBeVisible();

    const freshMemberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(freshMemberPage, auditUser.credentials);
    await expect(freshMemberPage).toHaveURL(/\/chat(?:\?|$)/);
    await expect(freshMemberPage.getByRole("link", { name: "审计日志" })).toHaveCount(0);
    await freshMemberPage.goto("/admin/audit");
    await expect(freshMemberPage).toHaveURL(/\/chat(?:\?|$)/);

    const deniedDirectList = await bffRequest(
      freshMemberPage,
      `/api/v1/audit-logs?action=${encodeURIComponent(enterprise.auditPageAction)}&limit=50`,
    );
    assertStatus(deniedDirectList.status, 403, "deny direct audit list HTTP request");
    const deniedDirectExport = await bffRequest(
      freshMemberPage,
      `/api/v1/audit-logs/export?action=${encodeURIComponent(enterprise.auditPageAction)}`,
    );
    assertStatus(deniedDirectExport.status, 403, "deny direct audit export HTTP request");
  } finally {
    await cleanupSyntheticAccess(page, {
      users: [auditUser?.user ?? null],
      roles: [auditRole],
    });
  }
});

test("@enterprise loading and 401/403/409/429/5xx/timeout states fail visibly", async ({ page, enterprise, request, quality }, testInfo) => {
  annotate(testInfo, "error_loading_states");
  quality.allowHttpStatus(503, "/api/backend/api/v1/knowledge-bases");
  quality.allowHttpStatus(504, "/api/backend/api/v1/knowledge-bases");
  await loginAdmin(page, enterprise);
  const loading = page.goto("/admin/users", { waitUntil: "commit" });
  await expect(page.locator("[aria-busy=true], .loading-rows").first()).toBeVisible();
  await loading;
  await page.goto("/admin/knowledge");
  const knowledgeSearch = page.getByRole("search");
  await expect(knowledgeSearch.getByLabel("搜索知识空间")).toBeVisible();

  const verifyVisibleBackendFailure = async (
    mode: "backend_5xx" | "backend_timeout",
    expectedStatus: 503 | 504,
  ) => {
    await setFaultMode(request, enterprise, mode);
    const failedResponse = page.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname.endsWith("/api/backend/api/v1/knowledge-bases")
        && response.status() === expectedStatus,
    );
    await knowledgeSearch.getByLabel("搜索知识空间").fill(
      `fault-${mode}-${Date.now().toString(36)}`,
    );
    await knowledgeSearch.getByRole("button", { name: "搜索" }).click();
    assertStatus((await failedResponse).status(), expectedStatus, `${mode} visible catalog failure`);
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("后台服务暂时不可用，请稍后重试。");
    await expect(alert.getByRole("button", { name: "重试" })).toBeVisible();

    await setFaultMode(request, enterprise, "normal");
    const recoveredResponse = page.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname.endsWith("/api/backend/api/v1/knowledge-bases")
        && response.status() === 200,
    );
    await alert.getByRole("button", { name: "重试" }).click();
    assertStatus((await recoveredResponse).status(), 200, `${mode} retry recovery`);
    await expect(page.getByRole("alert")).toHaveCount(0);
  };

  let role: Row | null = null;
  let created: SyntheticUser | null = null;
  try {
    await verifyVisibleBackendFailure("backend_5xx", 503);
    await verifyVisibleBackendFailure("backend_timeout", 504);

    role = await createRole(page, enterprise, testInfo, ["file:read"]);
    created = await createUser(page, enterprise, testInfo, [String(role.id)]);
    const memberPage = await quality.newIsolatedPage(enterprise.baseUrl);
    await loginAs(memberPage, created.credentials);
    await memberPage.goto("/admin/files");
    const fileCenter = memberPage.locator("article.panel").filter({
      has: memberPage.getByRole("heading", { name: "文件中心" }),
    });
    const refreshFiles = fileCenter.getByRole("button", { name: "刷新" });
    await expect(refreshFiles).toBeVisible();

    const permissionsRevoked = await bffRequest<Row>(
      page,
      `/api/v1/roles/${String(role.id)}/permissions`,
      {
        method: "PUT",
        body: {
          permission_codes: [],
          expected_version: rolePolicyVersion(role, "revoke file permission for visible 403"),
        },
      },
    );
    assertStatus(permissionsRevoked.status, 200, "revoke file permission for visible 403");
    const forbiddenResponse = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname.endsWith("/api/backend/api/v1/files")
        && response.status() === 403,
    );
    await refreshFiles.click();
    assertStatus((await forbiddenResponse).status(), 403, "visible forbidden file refresh");
    const forbiddenAlert = memberPage.getByRole("alert");
    await expect(forbiddenAlert).toContainText("当前账号没有访问此功能的权限。");
    await expect(forbiddenAlert.getByRole("button", { name: "重试" })).toBeVisible();

    const permissionsRestored = await bffRequest<Row>(
      page,
      `/api/v1/roles/${String(role.id)}/permissions`,
      {
        method: "PUT",
        body: {
          permission_codes: ["file:read"],
          expected_version: rolePolicyVersion(
            row(permissionsRevoked.body, "revoke file permission for visible 403"),
            "restore file permission after visible 403",
          ),
        },
      },
    );
    assertStatus(permissionsRestored.status, 200, "restore file permission after visible 403");
    role = row(permissionsRestored.body, "restore file permission after visible 403");
    const forbiddenRetryResponse = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname.endsWith("/api/backend/api/v1/files")
        && response.status() === 200,
    );
    await forbiddenAlert.getByRole("button", { name: "重试" }).click();
    assertStatus((await forbiddenRetryResponse).status(), 200, "forbidden retry recovery");
    await expect(memberPage.getByRole("alert")).toHaveCount(0);

    const disabled = await bffRequest<Row>(page, `/api/v1/users/${String(created.user.id)}`, {
      method: "PATCH",
      body: { status: "disabled" },
    });
    assertStatus(disabled.status, 200, "disable member for visible 401");
    created = { ...created, user: row(disabled.body, "disable member for visible 401") };
    const unauthorizedResponse = memberPage.waitForResponse((response) =>
      response.request().method() === "GET"
        && new URL(response.url()).pathname.endsWith("/api/backend/api/v1/files")
        && response.status() === 401,
    );
    await refreshFiles.click();
    assertStatus((await unauthorizedResponse).status(), 401, "visible expired-session file refresh");
    const unauthorizedAlert = memberPage.getByRole("alert");
    await expect(unauthorizedAlert).toContainText("登录状态已失效，请重新登录。");
    await expect(unauthorizedAlert.getByRole("button", { name: "重试" })).toBeVisible();
  } finally {
    await setFaultMode(request, enterprise, "normal");
    await cleanupSyntheticAccess(page, {
      users: [created?.user ?? null],
      roles: [role],
    });
  }
});
