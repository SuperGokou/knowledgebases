import {
  createHash,
  createPrivateKey,
  sign as signPayload,
  type KeyObject,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  FullConfig,
  FullResult,
  Reporter,
  TestCase,
  TestError,
  TestResult,
} from "@playwright/test/reporter";

export const EVIDENCE_ID = "EXT-BROWSER-E2E-001";
export const EVIDENCE_COLLECTOR = {
  id: "heyi-browser-e2e",
  version: "1.0.0",
} as const;
export const EVIDENCE_KEY_ID = "browser-e2e-ed25519";

export const REQUIRED_CHECKS = [
  "login_role_routing",
  "account_lifecycle",
  "knowledge_acl",
  "file_upload_scan_okf_approval_download",
  "chat_citations_audit_table",
  "model_switch",
  "model_deepseek_success",
  "model_qwen_success",
  "model_minimax_success",
  "api_key_lifecycle",
  "audit_log_query_export",
  "error_loading_states",
  "tls_ca_trust",
  "tls_san_identity",
  "tls_validity_and_renewal",
  "tls_strict_client",
] as const;

export const REQUIRED_PROJECTS = ["enterprise-desktop", "enterprise-mobile"] as const;
const REQUIRED_ATTACHMENTS = ["e2e-a11y", "e2e-observability", "e2e-screenshot"] as const;
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;

type CheckId = (typeof REQUIRED_CHECKS)[number];
type ProjectId = (typeof REQUIRED_PROJECTS)[number];
type EvidenceStatus = "passed" | "failed" | "blocked";

type ReporterOptions = {
  readonly outputFile?: string;
  readonly signingKeyPath?: string;
  readonly challengePath?: string;
};

export type EvidenceTarget = {
  readonly git_head: string;
  readonly content_fingerprint: string;
  readonly run_id: string;
};

export type EvidenceArtifact = {
  readonly id: string;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
};

export type EvidenceCheck = {
  readonly status: "passed";
  readonly artifact_ids: readonly string[];
};

export type EvidenceChallenge = {
  readonly schema_version: 1;
  readonly challenge_id: string;
  readonly evidence_id: typeof EVIDENCE_ID;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly status: "issued";
  readonly target: EvidenceTarget;
};

export type CompleteEvidence = {
  readonly schema_version: 2;
  readonly evidence_id: typeof EVIDENCE_ID;
  readonly status: "complete";
  readonly collector: typeof EVIDENCE_COLLECTOR;
  readonly target: EvidenceTarget;
  readonly collected_at: string;
  readonly artifacts: readonly EvidenceArtifact[];
  readonly checks: Readonly<Record<CheckId, EvidenceCheck>>;
  readonly attestation: {
    readonly type: "ed25519-challenge-v1";
    readonly key_id: typeof EVIDENCE_KEY_ID;
    readonly challenge_id: string;
    readonly challenge_nonce: string;
    readonly signature: string;
  };
};

type PersistedArtifact = EvidenceArtifact & {
  readonly project: ProjectId;
  readonly check: CheckId;
};

type EvidenceRecord = {
  readonly test_id: string;
  readonly status: EvidenceStatus;
  readonly attachment_names: readonly string[];
  artifacts: PersistedArtifact[];
  persistence_failed: boolean;
};

const SECRET_KEY =
  /(?:password|passwd|secret|token|api[-_ ]?key|authorization|cookie|credential|session)/i;
const FULL_URL = /\bhttps?:\/\/[^\s"'<>]+/gi;
const AUTH_VALUE = /\b(?:bearer|basic)\s+[a-z0-9._~+/=-]+/gi;
const SECRET_ASSIGNMENT =
  /\b(password|passwd|secret|token|api[-_ ]?key|authorization|cookie|credential|session)\b(\s*[:=]\s*)([^\s,;]+)/gi;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GIT_HEAD_PATTERN = /^[0-9a-f]{40,64}$/;
const RUN_ID_PATTERN = /^[A-Za-z0-9_-]{8,80}$/;

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Buffer(value: Buffer): Buffer {
  return createHash("sha256").update(value).digest();
}

function isRequiredCheck(value: string): value is CheckId {
  return (REQUIRED_CHECKS as readonly string[]).includes(value);
}

function isRequiredProject(value: string): value is ProjectId {
  return (REQUIRED_PROJECTS as readonly string[]).includes(value);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
    return `{${entries
      .map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonicalEvidenceDigest(
  evidence: Omit<CompleteEvidence, "attestation"> | CompleteEvidence,
): string {
  const bound = {
    schema_version: evidence.schema_version,
    evidence_id: evidence.evidence_id,
    status: evidence.status,
    collector: evidence.collector,
    target: evidence.target,
    collected_at: evidence.collected_at,
    artifacts: evidence.artifacts,
    checks: evidence.checks,
  };
  return sha256(stableJson(bound));
}

export function signaturePayload(
  evidence: Omit<CompleteEvidence, "attestation"> | CompleteEvidence,
  binding: {
    readonly keyId: string;
    readonly challengeId: string;
    readonly challengeNonce: string;
  },
): Buffer {
  return Buffer.from(
    stableJson({
      evidence_sha256: canonicalEvidenceDigest(evidence),
      key_id: binding.keyId,
      challenge_id: binding.challengeId,
      challenge_nonce: binding.challengeNonce,
    }),
    "utf8",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function timestamp(value: unknown): number | null {
  if (
    typeof value !== "string" ||
    !/(?:Z|[+-]\d{2}:\d{2})$/u.test(value)
  ) {
    return null;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function parseEvidenceChallenge(
  value: unknown,
  expectedTarget: EvidenceTarget,
  now = new Date(),
): EvidenceChallenge {
  if (!isRecord(value) || !isRecord(value.target)) {
    throw new Error("invalid E2E signing challenge");
  }
  const expectedKeys = new Set([
    "schema_version",
    "challenge_id",
    "evidence_id",
    "nonce",
    "issued_at",
    "expires_at",
    "status",
    "target",
  ]);
  if (
    Object.keys(value).length !== expectedKeys.size ||
    Object.keys(value).some((key) => !expectedKeys.has(key)) ||
    value.schema_version !== 1 ||
    typeof value.challenge_id !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/u.test(value.challenge_id) ||
    value.evidence_id !== EVIDENCE_ID ||
    typeof value.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{32,256}$/u.test(value.nonce) ||
    value.status !== "issued" ||
    value.target.git_head !== expectedTarget.git_head ||
    value.target.content_fingerprint !== expectedTarget.content_fingerprint ||
    value.target.run_id !== expectedTarget.run_id ||
    !RUN_ID_PATTERN.test(expectedTarget.run_id) ||
    Object.keys(value.target).length !== 3
  ) {
    throw new Error("invalid E2E signing challenge binding");
  }
  const issuedAt = timestamp(value.issued_at);
  const expiresAt = timestamp(value.expires_at);
  const nowMs = now.getTime();
  if (
    issuedAt === null ||
    expiresAt === null ||
    !Number.isFinite(nowMs) ||
    issuedAt > nowMs + 5 * 60_000 ||
    expiresAt <= nowMs ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > 24 * 60 * 60_000
  ) {
    throw new Error("expired or invalid E2E signing challenge");
  }
  return value as EvidenceChallenge;
}

export function protectedFileMetadataIsValid(metadata: {
  readonly platform: string;
  readonly uid: number;
  readonly mode: number;
  readonly isFile: boolean;
  readonly isSymbolicLink: boolean;
}): boolean {
  const permissions = metadata.mode & 0o777;
  return (
    metadata.platform === "linux" &&
    metadata.uid === 0 &&
    metadata.isFile &&
    !metadata.isSymbolicLink &&
    (permissions === 0o400 || permissions === 0o600)
  );
}

function validateArtifact(artifact: EvidenceArtifact): void {
  const relative = artifact.path.replaceAll("\\", "/");
  if (
    !artifact.id ||
    path.posix.isAbsolute(relative) ||
    relative.split("/").some((part) => !part || part === "." || part === "..") ||
    relative.toLowerCase().includes(".env") ||
    !SHA256_PATTERN.test(artifact.sha256) ||
    !Number.isSafeInteger(artifact.bytes) ||
    artifact.bytes < 0 ||
    artifact.bytes > MAX_ARTIFACT_BYTES
  ) {
    throw new Error("invalid E2E evidence artifact");
  }
}

export function buildCompleteEvidence(input: {
  readonly target: EvidenceTarget;
  readonly collectedAt: string;
  readonly artifacts: readonly EvidenceArtifact[];
  readonly checks: Readonly<Record<string, EvidenceCheck>>;
  readonly signing: {
    readonly privateKey: KeyObject;
    readonly challenge: EvidenceChallenge;
  };
}): CompleteEvidence {
  if (
    !GIT_HEAD_PATTERN.test(input.target.git_head) ||
    !SHA256_PATTERN.test(input.target.content_fingerprint) ||
    !RUN_ID_PATTERN.test(input.target.run_id) ||
    Object.keys(input.target).length !== 3 ||
    !Number.isFinite(Date.parse(input.collectedAt)) ||
    input.artifacts.length === 0
  ) {
    throw new Error("invalid E2E evidence identity");
  }

  const artifactIds = new Set<string>();
  for (const artifact of input.artifacts) {
    validateArtifact(artifact);
    if (artifactIds.has(artifact.id)) throw new Error("duplicate E2E evidence artifact");
    artifactIds.add(artifact.id);
  }

  if (
    Object.keys(input.checks).length !== REQUIRED_CHECKS.length ||
    REQUIRED_CHECKS.some((check) => !Object.hasOwn(input.checks, check))
  ) {
    throw new Error("incomplete E2E evidence checks");
  }

  const referenced = new Set<string>();
  const checks = Object.fromEntries(
    REQUIRED_CHECKS.map((check) => {
      const record = input.checks[check];
      if (
        record?.status !== "passed" ||
        !Array.isArray(record.artifact_ids) ||
        record.artifact_ids.length === 0 ||
        record.artifact_ids.some((id) => !artifactIds.has(id))
      ) {
        throw new Error(`invalid E2E evidence check: ${check}`);
      }
      const unique = [...new Set(record.artifact_ids)].sort();
      for (const artifactId of unique) referenced.add(artifactId);
      return [check, { status: "passed" as const, artifact_ids: unique }];
    }),
  ) as unknown as Record<CheckId, EvidenceCheck>;

  if (referenced.size !== artifactIds.size) {
    throw new Error("unreferenced E2E evidence artifact");
  }

  const unsigned = {
    schema_version: 2 as const,
    evidence_id: EVIDENCE_ID as typeof EVIDENCE_ID,
    status: "complete" as const,
    collector: EVIDENCE_COLLECTOR,
    target: input.target,
    collected_at: input.collectedAt,
    artifacts: [...input.artifacts].sort((left, right) => left.id.localeCompare(right.id)),
    checks,
  };
  if (
    input.signing.privateKey.type !== "private" ||
    input.signing.privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("invalid E2E Ed25519 signing key");
  }
  const challenge = parseEvidenceChallenge(
    input.signing.challenge,
    input.target,
    new Date(input.collectedAt),
  );
  const payload = signaturePayload(unsigned, {
    keyId: EVIDENCE_KEY_ID,
    challengeId: challenge.challenge_id,
    challengeNonce: challenge.nonce,
  });
  return {
    ...unsigned,
    attestation: {
      type: "ed25519-challenge-v1",
      key_id: EVIDENCE_KEY_ID,
      challenge_id: challenge.challenge_id,
      challenge_nonce: challenge.nonce,
      signature: signPayload(null, payload, input.signing.privateKey).toString("base64"),
    },
  };
}

function splitNull(buffer: Buffer): Buffer[] {
  const values: Buffer[] = [];
  let start = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] !== 0) continue;
    if (index > start) values.push(buffer.subarray(start, index));
    start = index + 1;
  }
  if (start < buffer.length) values.push(buffer.subarray(start));
  return values;
}

function gitBuffer(repositoryRoot: string, ...args: string[]): Buffer {
  return execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "buffer",
    stdio: ["ignore", "pipe", "ignore"],
  });
}

function untrackedManifestHash(repositoryRoot: string): string {
  const rawPaths = splitNull(
    gitBuffer(repositoryRoot, "ls-files", "--others", "--exclude-standard", "-z"),
  ).sort(Buffer.compare);
  const digest = createHash("sha256");
  for (const rawPath of rawPaths) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(rawPath.length));
    digest.update(length);
    digest.update(rawPath);
    const candidate = path.join(repositoryRoot, rawPath.toString("utf8"));
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(candidate, { encoding: "buffer" });
      digest.update(Buffer.from("symlink\0", "ascii"));
      digest.update(sha256Buffer(target));
    } else if (stat.isFile()) {
      digest.update(Buffer.from("file\0", "ascii"));
      digest.update(sha256Buffer(readFileSync(candidate)));
    } else {
      digest.update(Buffer.from("special\0", "ascii"));
    }
  }
  return digest.digest("hex");
}

export function collectWorktreeTarget(
  cwd = process.cwd(),
  env: Readonly<Record<string, string | undefined>> = process.env,
): EvidenceTarget {
  const repositoryRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
  const gitHead = gitBuffer(repositoryRoot, "rev-parse", "HEAD").toString("ascii").trim();
  const trackedDiffHash = sha256(
    gitBuffer(repositoryRoot, "diff", "--binary", "HEAD", "--", "."),
  );
  const untrackedHash = untrackedManifestHash(repositoryRoot);
  const runId = env.KB_E2E_RUN_ID?.trim() ?? "";
  if (!RUN_ID_PATTERN.test(runId)) {
    throw new Error("KB_E2E_RUN_ID must be bound to formal browser evidence");
  }
  return {
    git_head: gitHead,
    content_fingerprint: sha256(`${gitHead}\0${trackedDiffHash}\0${untrackedHash}`),
    run_id: runId,
  };
}

function repositoryRoot(cwd = process.cwd()): string {
  return execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function pathIsInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}

function readRootProtectedFile(filePath: string, maximumBytes: number): Buffer {
  if (process.platform !== "linux" || !path.isAbsolute(filePath)) {
    throw new Error("protected E2E signing input requires an absolute Linux path");
  }
  const requested = path.resolve(filePath);
  const resolved = realpathSync(requested);
  if (resolved !== requested || pathIsInside(repositoryRoot(), resolved)) {
    throw new Error("protected E2E signing input must be outside the repository without symlinks");
  }
  const before = lstatSync(requested);
  if (
    !protectedFileMetadataIsValid({
      platform: process.platform,
      uid: before.uid,
      mode: before.mode,
      isFile: before.isFile(),
      isSymbolicLink: before.isSymbolicLink(),
    }) ||
    before.size <= 0 ||
    before.size > maximumBytes
  ) {
    throw new Error("protected E2E signing input has unsafe ownership, mode, or type");
  }

  const descriptor = openSync(requested, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (
      !protectedFileMetadataIsValid({
        platform: process.platform,
        uid: opened.uid,
        mode: opened.mode,
        isFile: opened.isFile(),
        isSymbolicLink: false,
      }) ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size <= 0 ||
      opened.size > maximumBytes
    ) {
      throw new Error("protected E2E signing input changed during validation");
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function loadSigningMaterial(
  signingKeyPath: string,
  challengePath: string,
  target: EvidenceTarget,
): { readonly privateKey: KeyObject; readonly challenge: EvidenceChallenge } {
  const privateKeyBytes = readRootProtectedFile(signingKeyPath, 32 * 1024);
  const privateKeyText = privateKeyBytes.toString("ascii");
  if (
    !privateKeyText.startsWith("-----BEGIN PRIVATE KEY-----\n") || // gitleaks:allow -- validates a PEM boundary, not key material
    !privateKeyText.trimEnd().endsWith("-----END PRIVATE KEY-----")
  ) {
    throw new Error("E2E signing key must be an unencrypted PKCS#8 PEM key");
  }
  const privateKey = createPrivateKey(privateKeyBytes);
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("E2E signing key is not Ed25519");
  }

  const challengeBytes = readRootProtectedFile(challengePath, 128 * 1024);
  let challengeValue: unknown;
  try {
    challengeValue = JSON.parse(challengeBytes.toString("utf8"));
  } catch {
    throw new Error("E2E signing challenge is not valid JSON");
  }
  const challenge = parseEvidenceChallenge(challengeValue, target);
  if (path.basename(challengePath) !== `${challenge.challenge_id}.json`) {
    throw new Error("E2E signing challenge filename does not match its id");
  }
  return { privateKey, challenge };
}

function redactString(value: string): string {
  return value
    .replace(FULL_URL, "<redacted-url>")
    .replace(AUTH_VALUE, "<redacted-authorization>")
    .replace(SECRET_ASSIGNMENT, "$1$2<redacted>");
}

function redactJson(value: unknown, key = ""): unknown {
  if (SECRET_KEY.test(key)) return "<redacted>";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((item) => redactJson(item));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactJson(childValue, childKey),
      ]),
    );
  }
  return value;
}

function sanitizeTextAttachment(body: Buffer): Buffer {
  const text = body.toString("utf8");
  try {
    return Buffer.from(JSON.stringify(redactJson(JSON.parse(text)), null, 2), "utf8");
  } catch {
    return Buffer.from(redactString(text), "utf8");
  }
}

function isTextContentType(contentType: string): boolean {
  const normalized = contentType.toLowerCase();
  return (
    normalized.startsWith("text/") ||
    normalized.includes("json") ||
    normalized.includes("xml") ||
    normalized.includes("javascript")
  );
}

function safeAttachmentName(name: string): string {
  if (SECRET_KEY.test(name)) return "e2e-redacted";
  const safe = name.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").slice(0, 80);
  return safe || "e2e-artifact";
}

function safeContentType(contentType: string): string {
  const mime = contentType.split(";", 1)[0].trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mime)
    ? mime
    : "application/octet-stream";
}

function defaultOutputFile(): string {
  const cwd = process.cwd();
  const webRoot = path.basename(cwd).toLowerCase() === "web" ? cwd : path.join(cwd, "web");
  return path.resolve(webRoot, "..", "artifacts", "acceptance", "functional", "browser-e2e.json");
}

function resultText(result: TestResult): string {
  const chunks: string[] = [];
  if (result.error?.message) chunks.push(result.error.message);
  for (const error of result.errors) if (error.message) chunks.push(error.message);
  for (const output of [...result.stdout, ...result.stderr]) {
    chunks.push(Buffer.isBuffer(output) ? output.toString("utf8") : output);
  }
  return chunks.join("\n");
}

function classifyResult(result: TestResult): EvidenceStatus {
  if (resultText(result).includes("E2E_BLOCKED")) return "blocked";
  if (result.status === "failed" || result.status === "timedOut") return "failed";
  if (result.status !== "passed") return "blocked";
  return "passed";
}

function attachmentPresent(names: readonly string[], required: string): boolean {
  return names.some((name) => name === required || name.startsWith(`${required}-`));
}

async function writeJsonAtomic(destination: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rm(destination, { force: true });
  await rename(temporary, destination);
}

export default class EnterpriseEvidenceReporter implements Reporter {
  private readonly outputFile: string;
  private readonly signingKeyPath: string | undefined;
  private readonly challengePath: string | undefined;
  private readonly records = new Map<string, EvidenceRecord[]>();
  private readonly persistenceTasks: Promise<void>[] = [];
  private readonly configuredProjects = new Set<string>();
  private readonly runStatuses: EvidenceStatus[] = [];
  private readonly reporterErrors: EvidenceStatus[] = [];

  constructor(options: ReporterOptions = {}) {
    this.outputFile = path.resolve(options.outputFile ?? defaultOutputFile());
    this.signingKeyPath = options.signingKeyPath?.trim() || undefined;
    this.challengePath = options.challengePath?.trim() || undefined;
  }

  printsToStdio(): boolean {
    return false;
  }

  onBegin(config: FullConfig): void {
    rmSync(this.outputFile, { force: true });
    for (const project of config.projects) this.configuredProjects.add(project.name);
  }

  onError(error: TestError): void {
    this.reporterErrors.push(error.message?.includes("E2E_BLOCKED") ? "blocked" : "failed");
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    const status = classifyResult(result);
    this.runStatuses.push(status);
    const projectName = test.parent.project()?.name ?? "";
    if (!isRequiredProject(projectName)) return;

    const checks = test.annotations
      .filter((annotation) => annotation.type === "evidence-check")
      .map((annotation) => annotation.description ?? "")
      .filter(isRequiredCheck);
    for (const check of checks) {
      const attachmentNames = result.attachments
        .map((attachment) => attachment.name)
        .filter((name) => name.startsWith("e2e-"));
      const record: EvidenceRecord = {
        test_id: sha256(`${projectName}\0${test.id}`).slice(0, 24),
        status,
        attachment_names: [...new Set(attachmentNames)].sort(),
        artifacts: [],
        persistence_failed: false,
      };
      const key = `${check}\0${projectName}`;
      this.records.set(key, [...(this.records.get(key) ?? []), record]);
      this.persistenceTasks.push(this.persistAttachments(result, projectName, check, record));
    }
  }

  async onEnd(result: FullResult): Promise<void> {
    await Promise.all(this.persistenceTasks);
    const allArtifacts: PersistedArtifact[] = [];
    const checks: Partial<Record<CheckId, EvidenceCheck>> = {};
    let checksComplete = true;

    for (const check of REQUIRED_CHECKS) {
      const artifactIds: string[] = [];
      for (const project of REQUIRED_PROJECTS) {
        const records = this.records.get(`${check}\0${project}`) ?? [];
        const complete =
          this.configuredProjects.has(project) &&
          records.length > 0 &&
          records.every(
            (record) =>
              record.status === "passed" &&
              !record.persistence_failed &&
              REQUIRED_ATTACHMENTS.every((name) =>
                attachmentPresent(record.attachment_names, name),
              ),
          );
        if (!complete) checksComplete = false;
        for (const record of records) {
          allArtifacts.push(...record.artifacts);
          artifactIds.push(...record.artifacts.map((artifact) => artifact.id));
        }
      }
      if (artifactIds.length > 0) {
        checks[check] = { status: "passed", artifact_ids: [...new Set(artifactIds)].sort() };
      }
    }

    const explicitBlocked =
      this.reporterErrors.includes("blocked") || this.runStatuses.includes("blocked");
    const executionFailed =
      this.reporterErrors.includes("failed") ||
      this.runStatuses.includes("failed") ||
      result.status === "failed" ||
      result.status === "timedout";
    const formalComplete =
      result.status === "passed" &&
      !explicitBlocked &&
      !executionFailed &&
      checksComplete;
    const diagnosticFile = this.outputFile.replace(/\.json$/i, ".blocked.json");

    if (!formalComplete) {
      await rm(this.outputFile, { force: true });
      await writeJsonAtomic(diagnosticFile, {
        diagnostic_version: 1,
        kind: "browser-e2e-diagnostic",
        status: executionFailed && !explicitBlocked ? "failed" : "blocked",
        collected_at: new Date().toISOString(),
        required_projects: REQUIRED_PROJECTS,
        required_checks: REQUIRED_CHECKS,
        reason: explicitBlocked
          ? "E2E_BLOCKED: required enterprise topology or scenario evidence is unavailable"
          : "enterprise browser evidence is incomplete or failed",
      });
      return;
    }

    let target: EvidenceTarget;
    try {
      target = collectWorktreeTarget();
    } catch {
      await rm(this.outputFile, { force: true });
      await writeJsonAtomic(diagnosticFile, {
        diagnostic_version: 1,
        kind: "browser-e2e-diagnostic",
        status: "blocked",
        collected_at: new Date().toISOString(),
        reason: "E2E_BLOCKED: Git/content fingerprint could not be collected",
      });
      return;
    }

    const uniqueArtifacts = [...allArtifacts]
      .sort((left, right) => left.id.localeCompare(right.id))
      .filter((artifact, index, values) => index === 0 || artifact.id !== values[index - 1].id)
      .map(({ id, path: artifactPath, sha256: digest, bytes }) => ({
        id,
        path: artifactPath,
        sha256: digest,
        bytes,
      }));
    try {
      if (!this.signingKeyPath || !this.challengePath) {
        throw new Error("E2E signing paths are required");
      }
      const signing = loadSigningMaterial(
        this.signingKeyPath,
        this.challengePath,
        target,
      );
      const evidence = buildCompleteEvidence({
        target,
        collectedAt: new Date().toISOString(),
        artifacts: uniqueArtifacts,
        checks: checks as Record<CheckId, EvidenceCheck>,
        signing,
      });
      await writeJsonAtomic(this.outputFile, evidence);
      await rm(diagnosticFile, { force: true });
    } catch {
      await rm(this.outputFile, { force: true });
      await writeJsonAtomic(diagnosticFile, {
        diagnostic_version: 1,
        kind: "browser-e2e-diagnostic",
        status: "blocked",
        collected_at: new Date().toISOString(),
        reason: "E2E_BLOCKED: Ed25519 signing key or one-time challenge is unavailable or invalid",
      });
    }
  }

  private async persistAttachments(
    result: TestResult,
    project: ProjectId,
    check: CheckId,
    record: EvidenceRecord,
  ): Promise<void> {
    const evidenceDirectory = path.join(path.dirname(this.outputFile), "e2e-artifacts");
    try {
      mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
      for (const attachment of result.attachments) {
        if (!attachment.name.startsWith("e2e-")) continue;
        let body: Buffer;
        if (attachment.body !== undefined) {
          body = attachment.body;
        } else if (attachment.path) {
          if (/(?:^|[\\/])\.env(?:\.|$)|(?:secret|credential|private[-_]?key)/i.test(attachment.path)) {
            throw new Error("sensitive attachment path rejected");
          }
          const attachmentStat = lstatSync(attachment.path);
          if (!attachmentStat.isFile() || attachmentStat.isSymbolicLink()) {
            throw new Error("non-regular attachment rejected");
          }
          body = await readFile(attachment.path);
        } else {
          throw new Error("attachment has no persisted content");
        }
        if (body.length > MAX_ARTIFACT_BYTES) throw new Error("attachment exceeds evidence limit");

        const contentType = safeContentType(attachment.contentType);
        const persistedBody = isTextContentType(contentType)
          ? sanitizeTextAttachment(body)
          : body;
        const digest = sha256(persistedBody);
        const safeName = safeAttachmentName(attachment.name);
        const extension = contentType === "image/png" ? ".png" : ".bin";
        const filename = `${digest}-${safeName}${extension}`;
        const destination = path.join(evidenceDirectory, filename);
        await writeFile(destination, persistedBody, { mode: 0o600 });
        record.artifacts.push({
          id: `e2e-${sha256(`${project}\0${check}\0${safeName}\0${digest}`)}`,
          project,
          check,
          path: path.posix.join("e2e-artifacts", filename),
          sha256: digest,
          bytes: persistedBody.length,
        });
      }
    } catch {
      record.persistence_failed = true;
    }
  }
}
