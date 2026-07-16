import { defineConfig, devices } from "@playwright/test";

import { resolvePlaywrightProfile } from "./e2e/support/playwright-profile";

const profile = resolvePlaywrightProfile(process.env, __dirname);
const enterpriseProfile = profile.enterprise;
const [desktopProject, mobileProject] = profile.projects;
if (!desktopProject || !mobileProject || profile.projects.length !== 2) {
  throw new Error("Playwright profile must define exactly one desktop and one mobile project");
}

export const DEFAULT_ENTERPRISE_TEST_TIMEOUT_MS = 30 * 60_000;
export const LOCAL_MOCK_AUTH_BACKEND_URL = "http://127.0.0.1:3199";

export function resolveWebServerConfig(enterpriseProfile: boolean) {
  if (enterpriseProfile) return undefined;
  return [
    {
      command: "node e2e/support/mock-auth-backend.mjs",
      url: `${LOCAL_MOCK_AUTH_BACKEND_URL}/healthz`,
      reuseExistingServer: false,
      timeout: 10_000,
    },
    {
      command: "npm run build && node e2e/support/start-standalone.mjs",
      url: `${profile.baseURL}/login`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        FASTAPI_URL: LOCAL_MOCK_AUTH_BACKEND_URL,
        HOSTNAME: "127.0.0.1",
        NEXT_TELEMETRY_DISABLED: "1",
        PORT: "3100",
      },
    },
  ];
}

export function resolveEnterpriseTestTimeoutMs(
  env: Readonly<Record<string, string | undefined>>,
): number {
  const configured = env.KB_E2E_TEST_TIMEOUT_MS?.trim();
  if (!configured) return DEFAULT_ENTERPRISE_TEST_TIMEOUT_MS;
  if (!/^\d+$/.test(configured)) {
    throw new Error("KB_E2E_TEST_TIMEOUT_MS must be an integer number of milliseconds");
  }
  const timeoutMs = Number(configured);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 60_000) {
    throw new Error("KB_E2E_TEST_TIMEOUT_MS must be a safe integer of at least 60000");
  }
  return timeoutMs;
}

export default defineConfig({
  testDir: "./e2e",
  timeout: enterpriseProfile ? resolveEnterpriseTestTimeoutMs(process.env) : 30_000,
  fullyParallel: !enterpriseProfile,
  forbidOnly: Boolean(process.env.CI),
  retries: enterpriseProfile ? 0 : process.env.CI ? 2 : 0,
  workers: enterpriseProfile || process.env.CI ? 1 : undefined,
  reporter: enterpriseProfile
    ? [
        ["line"],
        [
          "./e2e/support/evidence-reporter.ts",
          {
            outputFile: profile.evidenceOutput,
            signingKeyPath: profile.signingKeyPath,
            challengePath: profile.challengePath,
          },
        ],
        ["html", { outputFolder: "playwright-report", open: "never" }],
      ]
    : [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  grep: profile.grep,
  grepInvert: profile.grepInvert,
  use: {
    baseURL: profile.baseURL,
    trace: enterpriseProfile ? "off" : "on-first-retry",
    screenshot: enterpriseProfile ? "off" : "only-on-failure",
    video: enterpriseProfile ? "off" : "retain-on-failure",
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
  },
  projects: [
    { name: desktopProject.name, use: { ...devices["Desktop Chrome"] } },
    { name: mobileProject.name, use: { ...devices["Pixel 5"] } },
  ],
  webServer: resolveWebServerConfig(enterpriseProfile),
});
