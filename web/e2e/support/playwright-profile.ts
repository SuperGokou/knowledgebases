import path from "node:path";

export type PlaywrightProfile = {
  readonly enterprise: boolean;
  readonly baseURL: string;
  readonly evidenceOutput: string;
  readonly signingKeyPath?: string;
  readonly challengePath?: string;
  readonly grep?: RegExp;
  readonly grepInvert?: RegExp;
  readonly projects: readonly { readonly name: string }[];
};

const ENTERPRISE_PROJECTS = [
  { name: "enterprise-desktop" },
  { name: "enterprise-mobile" },
] as const;

const SMOKE_PROJECTS = [
  { name: "desktop-chromium" },
  { name: "mobile-chromium" },
] as const;

export function resolvePlaywrightProfile(
  env: Readonly<Record<string, string | undefined>> = process.env,
  webRoot = process.cwd(),
): PlaywrightProfile {
  const requested = env.KB_E2E_PROFILE?.trim() || "smoke";
  if (!new Set(["smoke", "enterprise"]).has(requested)) {
    throw new Error("KB_E2E_PROFILE must be either smoke or enterprise");
  }

  const enterprise = requested === "enterprise";
  const evidenceOutput = env.KB_E2E_EVIDENCE_PATH
    ? path.resolve(webRoot, env.KB_E2E_EVIDENCE_PATH)
    : path.resolve(webRoot, "..", "artifacts", "acceptance", "functional", "browser-e2e.json");

  return {
    enterprise,
    baseURL: enterprise
      ? env.KB_E2E_BASE_URL ?? "http://127.0.0.1:9"
      : "http://127.0.0.1:3100",
    evidenceOutput,
    signingKeyPath: enterprise ? env.KB_E2E_SIGNING_KEY_PATH?.trim() : undefined,
    challengePath: enterprise ? env.KB_E2E_CHALLENGE_PATH?.trim() : undefined,
    grep: enterprise ? /@enterprise/ : undefined,
    grepInvert: enterprise ? undefined : /@enterprise/,
    projects: enterprise ? ENTERPRISE_PROJECTS : SMOKE_PROJECTS,
  };
}
