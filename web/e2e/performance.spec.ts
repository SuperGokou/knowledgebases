import { expect, test } from "@playwright/test";

test("登录页满足本地生产构建性能预算", async ({ page }, testInfo) => {
  await page.goto("/login", { waitUntil: "networkidle" });

  const metrics = await page.evaluate(() => {
    const navigation = performance.getEntriesByType(
      "navigation",
    )[0] as PerformanceNavigationTiming;
    const resources = performance.getEntriesByType("resource") as PerformanceResourceTiming[];
    const firstContentfulPaint = performance
      .getEntriesByName("first-contentful-paint")
      .at(0)?.startTime ?? 0;
    return {
      ttfb_ms: navigation.responseStart - navigation.requestStart,
      fcp_ms: firstContentfulPaint,
      dom_complete_ms: navigation.domComplete - navigation.startTime,
      request_count: resources.length,
      total_transfer_bytes: resources.reduce((total, item) => total + item.transferSize, 0),
      js_transfer_bytes: resources
        .filter((item) => item.initiatorType === "script")
        .reduce((total, item) => total + item.transferSize, 0),
    };
  });

  testInfo.annotations.push({ type: "performance", description: JSON.stringify(metrics) });
  console.log(`[browser-performance:${testInfo.project.name}] ${JSON.stringify(metrics)}`);
  expect(metrics.ttfb_ms).toBeLessThan(1_000);
  expect(metrics.fcp_ms).toBeLessThan(2_500);
  expect(metrics.dom_complete_ms).toBeLessThan(3_000);
  expect(metrics.request_count).toBeLessThanOrEqual(60);
  expect(metrics.total_transfer_bytes).toBeLessThanOrEqual(3_000_000);
  expect(metrics.js_transfer_bytes).toBeLessThanOrEqual(1_500_000);
});
