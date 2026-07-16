import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("登录页在桌面和移动端可访问且没有横向溢出", async ({ page }) => {
  await page.goto("/login");

  await expect(page.getByRole("heading", { name: "登录知识工作台" })).toBeVisible();
  await expect(page.getByLabel("工作邮箱")).toBeVisible();
  await expect(page.getByLabel("密码")).toBeVisible();
  await expect(page.getByRole("button", { name: "安全登录" })).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const accessibility = await new AxeBuilder({ page }).analyze();
  const blockingViolations = accessibility.violations.filter(
    (violation) => violation.impact === "critical" || violation.impact === "serious",
  );
  expect(blockingViolations, JSON.stringify(blockingViolations, null, 2)).toEqual([]);
});
