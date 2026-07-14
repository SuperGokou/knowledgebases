import { randomUUID } from "node:crypto";
import path from "node:path";

export const REQUIRED_ENTERPRISE_ENV = [
  "KB_E2E_BASE_URL",
  "KB_E2E_PUBLIC_API_ORIGIN",
  "KB_E2E_OBJECTS_ORIGIN",
  "KB_E2E_ADMIN_EMAIL",
  "KB_E2E_ADMIN_PASSWORD",
  "KB_E2E_FAULT_CONTROL_ORIGIN",
  "KB_E2E_FAULT_CONTROL_TOKEN",
  "KB_E2E_SEEDED_KNOWLEDGE_BASE_ID",
  "KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID",
  "KB_E2E_MULTIPART_BYTES",
  "KB_E2E_DOCUMENT_FIXTURE_ROOT",
  "KB_E2E_DOCUMENT_FIXTURE_MANIFEST",
  "KB_E2E_SIGNING_KEY_PATH",
  "KB_E2E_CHALLENGE_PATH",
] as const;

export type FaultMode =
  | "normal"
  | "provider_5xx"
  | "provider_timeout"
  | "review_reject"
  | "table_response"
  | "backend_5xx"
  | "backend_timeout";

export interface EnterpriseConfig {
  readonly baseUrl: string;
  readonly publicApiOrigin: string;
  readonly objectsOrigin: string;
  readonly adminEmail: string;
  readonly adminPassword: string;
  readonly faultControlOrigin: string;
  readonly faultControlToken: string;
  readonly seededKnowledgeBaseId: string;
  readonly unscopedKnowledgeBaseId: string;
  readonly jobTimeoutMs: number;
  readonly multipartBytes: number;
  readonly signingKeyPath: string;
  readonly challengePath: string;
  readonly runId: string;
  readonly documentFixtureRoot: string;
  readonly documentFixtureManifest: string;
}

export interface EnterpriseConfigProblem {
  readonly missing: string[];
  readonly invalid: string[];
}

function validatedOrigin(name: string, raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) origin`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`${name} must use HTTP(S)`);
  }
  if (
    parsed.username ||
    parsed.password ||
    raw.includes("?") ||
    raw.includes("#") ||
    parsed.pathname !== "/"
  ) {
    throw new Error(
      `${name} must be a bare origin without credentials, paths, query parameters, or fragments`,
    );
  }
  return parsed.origin;
}

export function validateObjectDownloadUrl(raw: string, configuredObjectsOrigin: string): string {
  const objectsOrigin = validatedOrigin("KB_E2E_OBJECTS_ORIGIN", configuredObjectsOrigin);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("download URL must be absolute");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    raw.includes("#") ||
    parsed.origin !== objectsOrigin
  ) {
    throw new Error(
      "download URL must match the configured object origin without credentials or fragments",
    );
  }
  return parsed.toString();
}

export function inspectEnterpriseConfig(
  env: Readonly<Record<string, string | undefined>> = process.env,
): EnterpriseConfigProblem {
  const missing = REQUIRED_ENTERPRISE_ENV.filter((name) => !env[name]?.trim());
  const invalid: string[] = [];

  for (const name of [
    "KB_E2E_BASE_URL",
    "KB_E2E_PUBLIC_API_ORIGIN",
    "KB_E2E_OBJECTS_ORIGIN",
    "KB_E2E_FAULT_CONTROL_ORIGIN",
  ] as const) {
    const value = env[name]?.trim();
    if (!value) continue;
    try {
      validatedOrigin(name, value);
    } catch {
      invalid.push(name);
    }
  }

  const jobTimeout = env.KB_E2E_JOB_TIMEOUT_MS?.trim();
  if (jobTimeout && (!/^\d+$/.test(jobTimeout) || Number(jobTimeout) < 30_000)) {
    invalid.push("KB_E2E_JOB_TIMEOUT_MS");
  }

  const multipartBytes = env.KB_E2E_MULTIPART_BYTES?.trim();
  if (
    multipartBytes &&
    (!/^\d+$/.test(multipartBytes) ||
      Number(multipartBytes) < 100 * 1024 * 1024 ||
      Number(multipartBytes) > 512 * 1024 * 1024)
  ) {
    invalid.push("KB_E2E_MULTIPART_BYTES");
  }

  for (const name of [
    "KB_E2E_DOCUMENT_FIXTURE_ROOT",
    "KB_E2E_DOCUMENT_FIXTURE_MANIFEST",
  ] as const) {
    const value = env[name]?.trim();
    if (value && !/^(?:[A-Za-z]:[\\/]|\/)/.test(value)) invalid.push(name);
  }

  for (const name of ["KB_E2E_SIGNING_KEY_PATH", "KB_E2E_CHALLENGE_PATH"] as const) {
    const value = env[name]?.trim();
    if (
      value &&
      (!path.isAbsolute(value) ||
        value.split(/[\\/]/u).some((part) => part.toLowerCase().startsWith(".env")))
    ) {
      invalid.push(name);
    }
  }
  if (
    env.KB_E2E_SIGNING_KEY_PATH?.trim() &&
    env.KB_E2E_SIGNING_KEY_PATH?.trim() === env.KB_E2E_CHALLENGE_PATH?.trim()
  ) {
    invalid.push("KB_E2E_CHALLENGE_PATH");
  }

  return { missing, invalid };
}

export function requireEnterpriseConfig(
  env: Readonly<Record<string, string | undefined>> = process.env,
): EnterpriseConfig {
  const problem = inspectEnterpriseConfig(env);
  if (problem.missing.length > 0 || problem.invalid.length > 0) {
    const details = [
      problem.missing.length ? `missing=${problem.missing.join(",")}` : "",
      problem.invalid.length ? `invalid=${problem.invalid.join(",")}` : "",
    ]
      .filter(Boolean)
      .join("; ");
    throw new Error(`E2E_BLOCKED: enterprise topology is incomplete (${details})`);
  }

  const runIdCandidate = env.KB_E2E_RUN_ID?.trim();
  const runId = runIdCandidate && /^[a-zA-Z0-9_-]{8,80}$/.test(runIdCandidate)
    ? runIdCandidate
    : randomUUID();

  return {
    baseUrl: validatedOrigin("KB_E2E_BASE_URL", env.KB_E2E_BASE_URL!),
    publicApiOrigin: validatedOrigin(
      "KB_E2E_PUBLIC_API_ORIGIN",
      env.KB_E2E_PUBLIC_API_ORIGIN!,
    ),
    objectsOrigin: validatedOrigin("KB_E2E_OBJECTS_ORIGIN", env.KB_E2E_OBJECTS_ORIGIN!),
    adminEmail: env.KB_E2E_ADMIN_EMAIL!.trim(),
    adminPassword: env.KB_E2E_ADMIN_PASSWORD!,
    faultControlOrigin: validatedOrigin(
      "KB_E2E_FAULT_CONTROL_ORIGIN",
      env.KB_E2E_FAULT_CONTROL_ORIGIN!,
    ),
    faultControlToken: env.KB_E2E_FAULT_CONTROL_TOKEN!,
    seededKnowledgeBaseId: env.KB_E2E_SEEDED_KNOWLEDGE_BASE_ID!.trim(),
    unscopedKnowledgeBaseId: env.KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID!.trim(),
    jobTimeoutMs: Number(env.KB_E2E_JOB_TIMEOUT_MS ?? 180_000),
    multipartBytes: Number(env.KB_E2E_MULTIPART_BYTES),
    signingKeyPath: env.KB_E2E_SIGNING_KEY_PATH!.trim(),
    challengePath: env.KB_E2E_CHALLENGE_PATH!.trim(),
    runId,
    documentFixtureRoot: env.KB_E2E_DOCUMENT_FIXTURE_ROOT!.trim(),
    documentFixtureManifest: env.KB_E2E_DOCUMENT_FIXTURE_MANIFEST!.trim(),
  };
}
