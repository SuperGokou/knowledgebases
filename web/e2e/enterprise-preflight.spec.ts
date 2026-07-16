import { test, expect } from "./support/enterprise-fixtures";

test.describe("@enterprise 企业验收拓扑前置门禁", () => {
  test.describe.configure({ mode: "serial" });

  test("@enterprise preflight 真实前端、API 与故障控制面必须可达", async ({
    enterprise,
    enterpriseDocuments,
    page,
    request,
  }) => {
    expect(enterpriseDocuments.map((fixture) => fixture.extension)).toEqual([
      ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx",
    ]);
    const login = await page.goto("/login", { waitUntil: "domcontentloaded" });
    expect(login?.status(), "login page must be served by the target topology").toBe(200);
    await expect(page.getByLabel("工作邮箱")).toBeVisible();
    await expect(page.getByLabel("密码")).toBeVisible();

    const readiness = await request.get(`${enterprise.publicApiOrigin}/health/ready`, {
      failOnStatusCode: false,
    });
    expect(
      readiness.status(),
      "E2E_BLOCKED: the real API readiness endpoint is unavailable",
    ).toBe(200);

    const faultController = await request.post(
      `${enterprise.faultControlOrigin}/v1/runs/${enterprise.runId}/mode`,
      {
        failOnStatusCode: false,
        headers: { authorization: `Bearer ${enterprise.faultControlToken}` },
        data: { mode: "normal" },
      },
    );
    expect(
      faultController.status(),
      "E2E_BLOCKED: the private fault controller is unavailable or unauthorized",
    ).toBe(204);
  });
});
