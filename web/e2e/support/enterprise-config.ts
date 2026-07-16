import path from "node:path";
import { isIP } from "node:net";
import {
  checkServerIdentity,
  connect as connectTls,
  type ConnectionOptions,
  type DetailedPeerCertificate,
  type TLSSocket,
} from "node:tls";

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
  "KB_E2E_RUN_ID",
  "KB_E2E_AUDIT_PAGE_ACTION",
  "KB_E2E_AUDIT_OVERSIZED_ACTION",
  "KB_E2E_AUDIT_REDACTION_SENTINEL",
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
  readonly auditPageAction: string;
  readonly auditOversizedAction: string;
  readonly auditRedactionSentinel: string;
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

function validatedEnterpriseTlsOrigin(name: string, raw: string): string {
  const origin = validatedOrigin(name, raw);
  if (new URL(origin).protocol !== "https:") {
    throw new Error(`${name} must use HTTPS for enterprise acceptance`);
  }
  return origin;
}

function isExplicitLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  if (normalized === "localhost" || normalized === "::1") return true;
  return isIP(normalized) === 4 && normalized.split(".")[0] === "127";
}

function validatedFaultControlOrigin(name: string, raw: string): string {
  const origin = validatedOrigin(name, raw);
  const parsed = new URL(origin);
  if (parsed.protocol === "http:" && !isExplicitLoopbackHostname(parsed.hostname)) {
    throw new Error(`${name} must use HTTPS unless it is an explicit loopback origin`);
  }
  return origin;
}

export type EnterpriseTlsEvidence = {
  readonly ca_trusted: true;
  readonly san_identity: true;
  readonly currently_valid: true;
  readonly issuer_chain_present: true;
  readonly remaining_validity_seconds: number;
  readonly certificate_lifetime_seconds: number;
  readonly protocol: string;
};

const MINIMUM_TLS_REMAINING_VALIDITY_MS = 60 * 60 * 1_000;
const MAXIMUM_TLS_NOT_BEFORE_SKEW_MS = 5 * 60 * 1_000;
const MINIMUM_TLS_LEAF_LIFETIME_MS = 2 * 60 * 60 * 1_000;
const MAXIMUM_TLS_LEAF_LIFETIME_MS = 398 * 24 * 60 * 60 * 1_000;
const MINIMUM_TLS_PROBE_TIMEOUT_MS = 100;
const MAXIMUM_TLS_PROBE_TIMEOUT_MS = 60_000;

export interface EnterpriseTlsProbeSocket {
  readonly authorized: boolean;
  getPeerCertificate(detailed: true): DetailedPeerCertificate;
  getProtocol(): string | null;
  once(event: "error", callback: (error: Error) => void): EnterpriseTlsProbeSocket;
  end(): EnterpriseTlsProbeSocket;
  destroy(error?: Error): EnterpriseTlsProbeSocket;
}

export type EnterpriseTlsConnector = (
  options: ConnectionOptions,
  onSecureConnect: (socket: EnterpriseTlsProbeSocket) => void,
) => EnterpriseTlsProbeSocket;

export interface EnterpriseTlsDeadlineScheduler {
  schedule(callback: () => void, timeoutMs: number): unknown;
  cancel(handle: unknown): void;
}

const defaultEnterpriseTlsConnector: EnterpriseTlsConnector = (options, onSecureConnect) =>
  connectTls(options, function onConnected(this: TLSSocket) {
    onSecureConnect(this);
  });

const defaultEnterpriseTlsDeadlineScheduler: EnterpriseTlsDeadlineScheduler = {
  schedule: (callback, timeoutMs) => setTimeout(callback, timeoutMs),
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

function validatedTlsProbeTimeout(timeoutMs: number): number {
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < MINIMUM_TLS_PROBE_TIMEOUT_MS
    || timeoutMs > MAXIMUM_TLS_PROBE_TIMEOUT_MS
  ) {
    throw new Error("E2E_BLOCKED: TLS identity probe timeout is outside the safe range");
  }
  return timeoutMs;
}

export function validateEnterpriseTlsEvidence(
  hostname: string,
  certificate: DetailedPeerCertificate,
  protocol: string | null,
  nowMs: number,
): EnterpriseTlsEvidence {
  if (!certificate.subjectaltname?.trim()) {
    throw new Error("E2E_BLOCKED: TLS SAN identity mismatch");
  }
  let identityError: Error | undefined;
  try {
    identityError = checkServerIdentity(hostname, certificate);
  } catch {
    throw new Error("E2E_BLOCKED: TLS SAN identity mismatch");
  }
  if (identityError) {
    throw new Error("E2E_BLOCKED: TLS SAN identity mismatch");
  }
  const expiresAt = Date.parse(certificate.valid_to);
  const validFrom = Date.parse(certificate.valid_from);
  if (!Number.isFinite(validFrom) || !Number.isFinite(expiresAt)) {
    throw new Error("E2E_BLOCKED: TLS certificate validity window is unavailable");
  }
  if (validFrom - nowMs > MAXIMUM_TLS_NOT_BEFORE_SKEW_MS) {
    throw new Error("E2E_BLOCKED: TLS certificate notBefore exceeds the clock-skew allowance");
  }
  if (expiresAt - nowMs < MINIMUM_TLS_REMAINING_VALIDITY_MS) {
    throw new Error("E2E_BLOCKED: TLS certificate has less than one hour of validity remaining");
  }
  const lifetimeMs = expiresAt - validFrom;
  if (
    lifetimeMs < MINIMUM_TLS_LEAF_LIFETIME_MS
    || lifetimeMs > MAXIMUM_TLS_LEAF_LIFETIME_MS
  ) {
    throw new Error("E2E_BLOCKED: TLS leaf certificate lifetime is outside the safe range");
  }
  const issuerCertificate = certificate.issuerCertificate;
  if (
    !certificate.issuer
    || Object.keys(certificate.issuer).length === 0
    || !issuerCertificate
    || issuerCertificate === certificate
    || !issuerCertificate.subject
    || Object.keys(issuerCertificate.subject).length === 0
  ) {
    throw new Error("E2E_BLOCKED: TLS issuer chain is unavailable");
  }
  const issuerValidFrom = Date.parse(issuerCertificate.valid_from);
  const issuerExpiresAt = Date.parse(issuerCertificate.valid_to);
  if (
    !Number.isFinite(issuerValidFrom)
    || !Number.isFinite(issuerExpiresAt)
    || issuerValidFrom - validFrom > MAXIMUM_TLS_NOT_BEFORE_SKEW_MS
    || issuerExpiresAt < expiresAt
  ) {
    throw new Error("E2E_BLOCKED: TLS issuer validity does not cover the leaf certificate");
  }
  if (!protocol || !["TLSv1.2", "TLSv1.3"].includes(protocol)) {
    throw new Error("E2E_BLOCKED: enterprise TLS must negotiate TLS 1.2 or TLS 1.3");
  }
  return {
    ca_trusted: true,
    san_identity: true,
    currently_valid: true,
    issuer_chain_present: true,
    remaining_validity_seconds: Math.floor((expiresAt - nowMs) / 1_000),
    certificate_lifetime_seconds: Math.floor(lifetimeMs / 1_000),
    protocol,
  };
}

export async function probeEnterpriseTlsOrigin(
  rawOrigin: string,
  timeoutMs = 10_000,
  connector: EnterpriseTlsConnector = defaultEnterpriseTlsConnector,
  scheduler: EnterpriseTlsDeadlineScheduler = defaultEnterpriseTlsDeadlineScheduler,
): Promise<EnterpriseTlsEvidence> {
  const origin = validatedEnterpriseTlsOrigin("enterprise acceptance origin", rawOrigin);
  const parsed = new URL(origin);
  const hostname = parsed.hostname;
  const port = parsed.port ? Number(parsed.port) : 443;
  const boundedTimeoutMs = validatedTlsProbeTimeout(timeoutMs);

  return new Promise((resolve, reject) => {
    let settled = false;
    let socket: EnterpriseTlsProbeSocket | undefined;
    let pendingSecureSocket: EnterpriseTlsProbeSocket | undefined;
    let connectorReturned = false;
    let deadlineHandle: unknown;
    let deadlineScheduled = false;
    const closedSockets = new WeakSet<object>();

    const closeOnce = (
      target: EnterpriseTlsProbeSocket,
      operation: "end" | "destroy",
    ): void => {
      if (closedSockets.has(target)) return;
      closedSockets.add(target);
      try {
        target[operation]();
      } catch {
        // The acceptance outcome is already settled; never leak transport internals.
      }
    };

    const clearDeadline = (): void => {
      if (!deadlineScheduled) return;
      deadlineScheduled = false;
      try {
        scheduler.cancel(deadlineHandle);
      } catch {
        // A scheduler cleanup failure cannot change the already-settled probe outcome.
      }
    };

    const fail = (error: Error, targets: readonly EnterpriseTlsProbeSocket[] = []): void => {
      if (!settled) {
        // Mark settled before cleanup so synchronous close events cannot win a race.
        settled = true;
        clearDeadline();
        for (const target of targets) closeOnce(target, "destroy");
        reject(error);
        return;
      }
      for (const target of targets) closeOnce(target, "destroy");
    };

    const succeed = (
      evidence: EnterpriseTlsEvidence,
      target: EnterpriseTlsProbeSocket,
    ): void => {
      if (settled) {
        closeOnce(target, "destroy");
        return;
      }
      settled = true;
      clearDeadline();
      closeOnce(target, "end");
      resolve(evidence);
    };

    const processSecureConnect = (connectedSocket: EnterpriseTlsProbeSocket): void => {
      if (settled) {
        closeOnce(connectedSocket, "destroy");
        return;
      }
      if (!socket || connectedSocket !== socket) {
        fail(
          new Error("E2E_BLOCKED: TLS certificate validation failed"),
          socket ? [connectedSocket, socket] : [connectedSocket],
        );
        return;
      }
      try {
        if (!connectedSocket.authorized) {
          throw new Error("E2E_BLOCKED: TLS certificate authority is not trusted");
        }
        const certificate = connectedSocket.getPeerCertificate(true);
        if (!certificate || Object.keys(certificate).length === 0) {
          throw new Error("E2E_BLOCKED: TLS peer certificate is unavailable");
        }
        const evidence = validateEnterpriseTlsEvidence(
          hostname,
          certificate,
          connectedSocket.getProtocol(),
          Date.now(),
        );
        succeed(evidence, connectedSocket);
      } catch (error) {
        fail(
          error instanceof Error
            ? error
            : new Error("E2E_BLOCKED: TLS certificate validation failed"),
          [connectedSocket],
        );
      }
    };

    const onSecureConnect = (connectedSocket: EnterpriseTlsProbeSocket): void => {
      if (!connectorReturned) {
        pendingSecureSocket = connectedSocket;
        return;
      }
      processSecureConnect(connectedSocket);
    };

    try {
      deadlineHandle = scheduler.schedule(() => {
        fail(
          new Error("E2E_BLOCKED: TLS identity probe timed out"),
          [socket, pendingSecureSocket].filter(
            (target): target is EnterpriseTlsProbeSocket => target !== undefined,
          ),
        );
      }, boundedTimeoutMs);
      deadlineScheduled = true;
      if (settled) clearDeadline();
    } catch {
      fail(new Error("E2E_BLOCKED: TLS certificate validation failed"));
      return;
    }

    if (settled) return;

    try {
      socket = connector(
        {
          host: hostname,
          port,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          maxVersion: "TLSv1.3",
          ...(isIP(hostname) === 0 ? { servername: hostname } : {}),
        },
        onSecureConnect,
      );
      if (settled) {
        closeOnce(socket, "destroy");
        return;
      }
      socket.once("error", () => {
        fail(
          new Error("E2E_BLOCKED: TLS certificate validation failed"),
          socket ? [socket] : [],
        );
      });
      connectorReturned = true;
      if (pendingSecureSocket) {
        const connectedSocket = pendingSecureSocket;
        pendingSecureSocket = undefined;
        processSecureConnect(connectedSocket);
      }
    } catch {
      fail(
        new Error("E2E_BLOCKED: TLS certificate validation failed"),
        [socket, pendingSecureSocket].filter(
          (target): target is EnterpriseTlsProbeSocket => target !== undefined,
        ),
      );
    }
  });
}

export function validateObjectDownloadUrl(raw: string, configuredObjectsOrigin: string): string {
  const objectsOrigin = validatedEnterpriseTlsOrigin(
    "KB_E2E_OBJECTS_ORIGIN",
    configuredObjectsOrigin,
  );
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("download URL must be absolute");
  }
  if (
    parsed.protocol !== "https:" ||
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
      if (name === "KB_E2E_FAULT_CONTROL_ORIGIN") validatedFaultControlOrigin(name, value);
      else validatedEnterpriseTlsOrigin(name, value);
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

  const runId = env.KB_E2E_RUN_ID?.trim();
  if (runId && !/^[a-zA-Z0-9_-]{8,80}$/.test(runId)) {
    invalid.push("KB_E2E_RUN_ID");
  }

  for (const name of [
    "KB_E2E_AUDIT_PAGE_ACTION",
    "KB_E2E_AUDIT_OVERSIZED_ACTION",
    "KB_E2E_AUDIT_REDACTION_SENTINEL",
  ] as const) {
    const value = env[name]?.trim();
    if (value && !/^[A-Za-z0-9_.:-]{8,150}$/u.test(value)) invalid.push(name);
  }
  if (
    env.KB_E2E_AUDIT_PAGE_ACTION?.trim() &&
    env.KB_E2E_AUDIT_PAGE_ACTION?.trim() === env.KB_E2E_AUDIT_OVERSIZED_ACTION?.trim()
  ) {
    invalid.push("KB_E2E_AUDIT_OVERSIZED_ACTION");
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

  return {
    baseUrl: validatedEnterpriseTlsOrigin("KB_E2E_BASE_URL", env.KB_E2E_BASE_URL!),
    publicApiOrigin: validatedEnterpriseTlsOrigin(
      "KB_E2E_PUBLIC_API_ORIGIN",
      env.KB_E2E_PUBLIC_API_ORIGIN!,
    ),
    objectsOrigin: validatedEnterpriseTlsOrigin(
      "KB_E2E_OBJECTS_ORIGIN",
      env.KB_E2E_OBJECTS_ORIGIN!,
    ),
    adminEmail: env.KB_E2E_ADMIN_EMAIL!.trim(),
    adminPassword: env.KB_E2E_ADMIN_PASSWORD!,
    faultControlOrigin: validatedFaultControlOrigin(
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
    runId: env.KB_E2E_RUN_ID!.trim(),
    auditPageAction: env.KB_E2E_AUDIT_PAGE_ACTION!.trim(),
    auditOversizedAction: env.KB_E2E_AUDIT_OVERSIZED_ACTION!.trim(),
    auditRedactionSentinel: env.KB_E2E_AUDIT_REDACTION_SENTINEL!.trim(),
    documentFixtureRoot: env.KB_E2E_DOCUMENT_FIXTURE_ROOT!.trim(),
    documentFixtureManifest: env.KB_E2E_DOCUMENT_FIXTURE_MANIFEST!.trim(),
  };
}
